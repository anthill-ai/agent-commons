// An agent's state that outlives the machine it runs on. A cloud scheduled
// task starts on a fresh VM every time, and what the agent keeps in
// ~/.commons between runs would be lost with it: above all the commit
// records under salts/ (salt and committed verdict), without which a commit
// can never be revealed, which the protocol charges as a silent approval.
//
// The files are bundled ({path: {mode, data}}), gzipped and encrypted with
// AES-256-GCM under a key derived (HKDF-SHA256) from the agent's private key,
// then stored on the coordinator (server.ts PUT/GET /api/agent-state). The
// coordinator holds ciphertext only; whoever holds the agent key can read it.
//
// Blob: 0x01 | iv (12) | ciphertext | tag (16); the additional data binds it
// to the agent's keyId.
//
// Merging never loses a local file: pull writes only files that do not exist
// here, and push first merges what is stored into what it sends (local files
// win), with a compare-and-swap on the stored blob's digest so two pushes
// cannot drop each other's files.

import { createCipheriv, createDecipheriv, createPrivateKey, hkdfSync, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { canonical, keyIdOf, sha256hex, sign } from "./crypto";
import { type AgentKey, CommonsApiError, type FetchLike } from "./client";
import { AGENT_STATE_PURPOSE, agentStateMessage } from "./server";
import type { KeyId } from "./types";

// The coordinator's default cap (server.ts DEFAULT_LIMITS.agentStateBytes).
export const AGENT_STATE_MAX_BYTES = 256 * 1024;

// What is read from disk before compressing; far above anything an agent keeps.
const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;

const VERSION = 1;

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

// From the 32-byte seed, not the DER: the same key in another PKCS8 spelling
// must open the same state.
function stateKey(privateKey: string): Buffer {
  const jwk = createPrivateKey({ key: Buffer.from(privateKey, "base64url"), format: "der", type: "pkcs8" }).export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || typeof jwk.d !== "string") throw new TypeError("agent state: not an ed25519 private key");
  return Buffer.from(hkdfSync("sha256", Buffer.from(jwk.d, "base64url"), Buffer.alloc(0), AGENT_STATE_PURPOSE, 32));
}

const additionalData = (agent: KeyId): Buffer => Buffer.from(canonical({ purpose: AGENT_STATE_PURPOSE, agent }), "utf8");

export function encryptState(key: AgentKey, plaintext: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", stateKey(key.privateKey), iv);
  cipher.setAAD(additionalData(keyIdOf(key.publicKey)));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, body, cipher.getAuthTag()]);
}

export function decryptState(key: AgentKey, blob: Buffer): Buffer {
  if (blob.length < 1 + 12 + 16 || blob[0] !== VERSION) throw new Error("agent state: not a state blob this kit can read");
  const decipher = createDecipheriv("aes-256-gcm", stateKey(key.privateKey), blob.subarray(1, 13));
  decipher.setAAD(additionalData(keyIdOf(key.publicKey)));
  decipher.setAuthTag(blob.subarray(blob.length - 16));
  try {
    return Buffer.concat([decipher.update(blob.subarray(13, blob.length - 16)), decipher.final()]);
  } catch {
    throw new Error("agent state: the stored state does not decrypt with this agent key (corrupted, or not this agent's)");
  }
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

export type StateBundle = { v: 1; files: Record<string, { mode: number; data: string }> };

// Never leaves the machine: key files (agent-key.json, owner-key.json, and
// their *.old-* copies kept after a rotation), `isolation` (describes this
// machine only) and half-written temp files.
export function excludedFromState(rel: string): boolean {
  const base = rel.split("/").pop() ?? rel;
  return base === "isolation" || base.endsWith("key.json") || base.includes(".old-") || base.endsWith(".tmp");
}

// A relative path inside the folder, as its "/"-separated segments, or null:
// no absolute path, no "..", ".", empty segment, backslash or NUL.
export function stateSegments(rel: string): string[] | null {
  if (typeof rel !== "string" || rel === "" || rel.startsWith("/") || /[\\\0]/.test(rel)) return null;
  const segs = rel.split("/");
  return segs.every((s) => s !== "" && s !== "." && s !== "..") ? segs : null;
}

// The regular files under `dir` (symlinks and anything else skipped), minus
// the excluded ones and any path in `exclude` (absolute).
export function bundleDir(dir: string, exclude: readonly string[] = []): StateBundle {
  const files: StateBundle["files"] = {};
  const skip = new Set(exclude.map((p) => path.resolve(p)));
  let total = 0;
  const walk = (abs: string, rel: string[]) => {
    let names: string[];
    try {
      names = fs.readdirSync(abs);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
      throw e;
    }
    for (const name of names.sort()) {
      const p = path.join(abs, name);
      const r = [...rel, name];
      const st = fs.lstatSync(p);
      if (st.isDirectory()) walk(p, r);
      else if (st.isFile() && !excludedFromState(r.join("/")) && !skip.has(path.resolve(p))) {
        total += st.size;
        if (total > MAX_PLAINTEXT_BYTES) throw new Error(`agent state: more than ${MAX_PLAINTEXT_BYTES} bytes under ${dir}`);
        files[r.join("/")] = { mode: st.mode & 0o777, data: fs.readFileSync(p).toString("base64") };
      }
    }
  };
  walk(dir, []);
  return { v: 1, files };
}

function parseBundle(plaintext: Buffer): StateBundle {
  let b: unknown;
  try {
    b = JSON.parse(gunzipSync(plaintext).toString("utf8"));
  } catch {
    throw new Error("agent state: the stored state is not a bundle this kit can read");
  }
  const o = b as Partial<StateBundle> | null;
  if (typeof o !== "object" || o === null || o.v !== 1 || typeof o.files !== "object" || o.files === null || Array.isArray(o.files)) {
    throw new Error("agent state: the stored state is not a bundle this kit can read");
  }
  return o as StateBundle;
}

export type RestoreSummary = { written: number; kept: number; refused: number };

// Writes each file that does not exist under `dir`; an existing one is never
// touched (a local salt record is always the one to keep). A path that would
// leave `dir`, cross a symlink or name an excluded file is refused.
export function restoreBundle(dir: string, bundle: StateBundle): RestoreSummary {
  const out: RestoreSummary = { written: 0, kept: 0, refused: 0 };
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const rel of Object.keys(bundle.files).sort()) {
    const f = bundle.files[rel];
    const segs = stateSegments(rel);
    if (
      segs === null ||
      excludedFromState(rel) ||
      typeof f !== "object" ||
      f === null ||
      !Number.isInteger(f.mode) ||
      typeof f.data !== "string" ||
      Buffer.from(f.data, "base64").toString("base64") !== f.data
    ) {
      out.refused++;
      continue;
    }
    // Each parent is created here or must already be a real directory.
    let parent = dir;
    let ok = true;
    for (const s of segs.slice(0, -1)) {
      parent = path.join(parent, s);
      try {
        if (!fs.lstatSync(parent).isDirectory()) ok = false;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        fs.mkdirSync(parent, { mode: 0o700 });
      }
      if (!ok) break;
    }
    if (!ok) {
      out.refused++;
      continue;
    }
    const file = path.join(parent, segs[segs.length - 1] as string);
    let fd: number;
    try {
      // wx: fails on anything already there, a symlink included, never following it.
      fd = fs.openSync(file, "wx", 0o600);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        out.kept++;
        continue;
      }
      throw e;
    }
    try {
      fs.fchmodSync(fd, (f.mode & 0o777) | 0o600);
      fs.writeSync(fd, Buffer.from(f.data, "base64"));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    out.written++;
  }
  return out;
}

// ---------------------------------------------------------------------------
// The coordinator
// ---------------------------------------------------------------------------

export type StateOptions = {
  baseUrl: string;
  agentKey: AgentKey;
  dir: string; // the folder kept, e.g. ~/.commons
  exclude?: readonly string[]; // absolute paths under dir never sent (the key file)
  fetch?: FetchLike;
  clock?: () => Date;
};

type Stored = { at: string; sha256: string; blob: Buffer };

function signedHeaders(o: StateOptions, at: string, msg: string): Record<string, string> {
  return { "x-commons-key": o.agentKey.publicKey, "x-commons-at": at, "x-commons-sig": sign(o.agentKey.privateKey, msg) };
}

async function call(o: StateOptions, method: string, headers: Record<string, string>, body?: Buffer): Promise<{ status: number; json: Record<string, unknown> | null }> {
  const fetchFn = o.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const url = `${o.baseUrl.replace(/\/+$/, "")}/api/agent-state`;
  // FetchLike carries a string body; global fetch takes the bytes as they are.
  const res = await fetchFn(url, { method, headers, body: body as unknown as string | undefined });
  const text = await res.text();
  let json: Record<string, unknown> | null = null;
  try {
    const v: unknown = text === "" ? null : JSON.parse(text);
    if (typeof v === "object" && v !== null && !Array.isArray(v)) json = v as Record<string, unknown>;
  } catch {
    // reported below with the status
  }
  return { status: res.status, json };
}

function apiError(method: string, r: { status: number; json: Record<string, unknown> | null }): CommonsApiError {
  const code = typeof r.json?.error === "string" ? r.json.error : "http";
  const message = typeof r.json?.message === "string" ? r.json.message : "";
  return new CommonsApiError(r.status, code, `${method} /api/agent-state: ${r.status} ${code}: ${message}`.slice(0, 400), r.json);
}

function now(o: StateOptions): Date {
  return o.clock?.() ?? new Date();
}

// The stored blob, or null when this agent has stored none (a first run).
export async function fetchState(o: StateOptions): Promise<Stored | null> {
  const at = now(o).toISOString();
  const agent = keyIdOf(o.agentKey.publicKey);
  const r = await call(o, "GET", signedHeaders(o, at, agentStateMessage({ op: "get", agent, at })));
  if (r.status === 404 && r.json?.error === "no-state") return null;
  if (r.status !== 200) throw apiError("GET", r);
  const j = r.json ?? {};
  if (typeof j.blob !== "string" || typeof j.at !== "string" || typeof j.sha256 !== "string") {
    throw new CommonsApiError(502, "bad-state", "GET /api/agent-state: malformed answer", j);
  }
  const blob = Buffer.from(j.blob, "base64url");
  if (sha256hex(blob) !== j.sha256) throw new CommonsApiError(502, "bad-state", "GET /api/agent-state: the blob does not match its digest", null);
  return { at: j.at, sha256: j.sha256, blob };
}

export type PullSummary = { found: boolean; at: string | null; files: number } & RestoreSummary;

export async function pullState(o: StateOptions): Promise<PullSummary> {
  const stored = await fetchState(o);
  if (stored === null) return { found: false, at: null, files: 0, written: 0, kept: 0, refused: 0 };
  const bundle = parseBundle(decryptState(o.agentKey, stored.blob));
  return { found: true, at: stored.at, files: Object.keys(bundle.files).length, ...restoreBundle(o.dir, bundle) };
}

export type PushSummary = { at: string; bytes: number; files: number; fromStored: number };

// Bundles `dir`, adds the stored files it lacks (unless `replace`), and
// stores the result. A stored state that cannot be read stops the push:
// overwriting it might drop salt records only it holds; `replace` overrides.
export async function pushState(o: StateOptions & { replace?: boolean; maxBytes?: number }): Promise<PushSummary> {
  const agent = keyIdOf(o.agentKey.publicKey);
  const maxBytes = o.maxBytes ?? AGENT_STATE_MAX_BYTES;
  for (let attempt = 0; ; attempt++) {
    const stored = await fetchState(o);
    const bundle = bundleDir(o.dir, o.exclude);
    let fromStored = 0;
    if (stored !== null && o.replace !== true) {
      const theirs = parseBundle(decryptState(o.agentKey, stored.blob));
      for (const [rel, f] of Object.entries(theirs.files)) {
        if (bundle.files[rel] !== undefined || stateSegments(rel) === null || excludedFromState(rel)) continue;
        bundle.files[rel] = f;
        fromStored++;
      }
    }
    const blob = encryptState(o.agentKey, gzipSync(Buffer.from(JSON.stringify(bundle), "utf8")));
    if (blob.length > maxBytes) {
      throw new Error(`agent state: ${blob.length} bytes encrypted, over the coordinator's cap of ${maxBytes}; nothing was stored`);
    }
    // Later than what is stored even if this machine's clock is behind the
    // last one's (the server still holds it within its clock skew).
    const nowMs = now(o).getTime();
    const at = new Date(stored === null ? nowMs : Math.max(nowMs, Date.parse(stored.at) + 1)).toISOString();
    const prev = o.replace === true ? undefined : (stored?.sha256 ?? null);
    const sha256 = sha256hex(blob);
    const headers = {
      ...signedHeaders(o, at, agentStateMessage({ op: "put", agent, at, sha256, prev })),
      "Content-Type": "application/octet-stream",
      ...(prev === undefined ? {} : { "x-commons-prev": prev ?? "none" }),
    };
    const r = await call(o, "PUT", headers, blob);
    if (r.status === 200) return { at, bytes: blob.length, files: Object.keys(bundle.files).length, fromStored };
    // Another push landed between our fetch and our write: merge again.
    if (r.status === 409 && (r.json?.error === "state-changed" || r.json?.error === "stale") && attempt < 3) continue;
    throw apiError("PUT", r);
  }
}
