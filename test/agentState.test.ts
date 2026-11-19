import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, type webcrypto } from "node:crypto";
import * as fs from "node:fs";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";

import { main as agentMain } from "../agent-kit/commons-agent";
import { bundleDir, decryptState, encryptState, restoreBundle, type StateBundle } from "../src/agentState";
import { CommonsClient, type FetchLike, memorySaltStore } from "../src/client";
import { generateKeyPair, keyIdOf, keyPairFromPrivateKey, sha256hex, sign, verify } from "../src/crypto";
import { Ledger } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { assignmentBody } from "../src/selection";
import { agentStateMessage, createCoordinatorServer, LedgerStore, type ServerLimits } from "../src/server";

// Agents on fresh machines (cloud scheduled tasks): the agent key from
// COMMONS_AGENT_KEY, and the encrypted state kept on the coordinator
// (server.ts /api/agent-state, src/agentState.ts, commons-agent state).

const tmp = (name: string) => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), `agent-state-test-${name}-`));

const PATCH = ["diff --git a/src/a.ts b/src/a.ts", "--- a/src/a.ts", "+++ b/src/a.ts", "@@ -1,2 +1,2 @@", " const x = 1;", "-const y = 2;", "+const y = 3;", ""].join("\n");

// An Ed25519 key made by WebCrypto, as a browser makes it on the website.
async function webCryptoKey(): Promise<{ env: string; publicKey: string }> {
  const subtle = globalThis.crypto.subtle;
  const k = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  return {
    env: Buffer.from(await subtle.exportKey("pkcs8", k.privateKey)).toString("base64url"),
    publicKey: Buffer.from(await subtle.exportKey("spki", k.publicKey)).toString("base64url"),
  };
}

type Io = { out: (s: string) => void; err: (s: string) => void; stdin: () => string };
function capture(): { io: Io; outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { io: { out: (s) => void outs.push(s), err: (s) => void errs.push(s), stdin: () => "" }, outs, errs };
}

// ---------------------------------------------------------------------------
// COMMONS_AGENT_KEY
// ---------------------------------------------------------------------------

test("keyPairFromPrivateKey: a WebCrypto Ed25519 pkcs8 and generateKeyPair's privateKey both give their own public key", async () => {
  const w = await webCryptoKey();
  const fromWeb = keyPairFromPrivateKey(w.env);
  assert.equal(fromWeb.publicKey, w.publicKey);
  assert.equal(fromWeb.privateKey, w.env);
  assert.ok(verify(fromWeb.publicKey, "m", sign(fromWeb.privateKey, "m")));
  const g = generateKeyPair();
  assert.deepEqual(keyPairFromPrivateKey(g.privateKey), g);
});

test("keyPairFromPrivateKey refuses anything but the canonical 48-byte ed25519 PKCS8 in canonical base64url, without echoing it", async () => {
  const g = generateKeyPair();
  const der = Buffer.from(g.privateKey, "base64url");
  const pub = Buffer.from(g.publicKey, "base64url").subarray(12);
  // RFC 8410 OneAsymmetricKey v2 (public key embedded): Node takes it, we do not.
  const inner = Buffer.concat([Buffer.from("020101300506032b657004220420", "hex"), der.subarray(16), Buffer.from("812100", "hex"), pub]);
  const v2 = Buffer.concat([Buffer.from([0x30, inner.length]), inner]).toString("base64url");
  const subtle = globalThis.crypto.subtle;
  const ec = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as webcrypto.CryptoKeyPair;
  const p256 = Buffer.from(await subtle.exportKey("pkcs8", ec.privateKey)).toString("base64url");
  const bad = [
    "",
    `${g.privateKey}=`, // padding
    g.privateKey.replace(/(.{10})/, "$1 "), // a space inside
    Buffer.from(g.privateKey, "base64url").toString("base64"), // standard base64 (+, /) for some keys; at least differs below
    `${g.privateKey.slice(0, -1)}${g.privateKey.endsWith("A") ? "B" : "A"}`, // a different last character: may break the DER
    Buffer.concat([der, Buffer.from([0])]).toString("base64url"), // trailing byte
    v2,
    p256,
    g.publicKey,
    "not-a-key",
  ];
  for (const k of bad) {
    if (k === g.privateKey) continue;
    let message = "";
    try {
      const r = keyPairFromPrivateKey(k);
      // A changed last character can still be a valid key, but then it is another key.
      assert.notEqual(r.publicKey, g.publicKey, `accepted a variant of the key: ${k.length}`);
      continue;
    } catch (e) {
      message = (e as Error).message;
    }
    assert.match(message, /^not an ed25519 private key/);
    if (k.length > 8) assert.ok(!message.includes(k), "the error echoes the key");
    assert.ok(!message.includes(g.privateKey));
  }
});

test("commons-agent whoami from COMMONS_AGENT_KEY (trimmed); a bad one fails without printing it", async () => {
  const w = await webCryptoKey();
  const home = tmp("whoami");
  const c = capture();
  assert.equal(await agentMain(["whoami"], { HOME: home, COMMONS_AGENT_KEY: `  ${w.env}\n` }, c.io), 0);
  const who = JSON.parse(c.outs.join("")) as { keyId: string; publicKey: string };
  assert.equal(who.publicKey, w.publicKey);
  assert.equal(who.keyId, keyIdOf(w.publicKey));
  // The JSON form still works.
  const g = generateKeyPair();
  const c2 = capture();
  assert.equal(await agentMain(["whoami"], { HOME: home, COMMONS_AGENT_KEY: JSON.stringify(g) }, c2.io), 0);
  assert.equal((JSON.parse(c2.outs.join("")) as { publicKey: string }).publicKey, g.publicKey);
  // Broken: exit 1, and the value appears nowhere.
  const broken = `${w.env}==`;
  const c3 = capture();
  assert.equal(await agentMain(["whoami"], { HOME: home, COMMONS_AGENT_KEY: broken }, c3.io), 1);
  assert.match(c3.errs.join(""), /COMMONS_AGENT_KEY: not an ed25519 private key/);
  for (const s of [...c.outs, ...c.errs, ...c2.outs, ...c2.errs, ...c3.outs, ...c3.errs]) {
    assert.ok(!s.includes(w.env.slice(0, 40)) && !s.includes(g.privateKey.slice(0, 40)), "a private key was printed");
  }
});

// ---------------------------------------------------------------------------
// An in-process coordinator with registered agents.
// ---------------------------------------------------------------------------

type Commons = {
  url: string;
  dir: string;
  store: LedgerStore;
  owner: ReturnType<typeof generateKeyPair>;
  close: () => Promise<void>;
  register: (publicKey: string, family?: string, owner?: "alice" | "bob") => Promise<void>;
};

async function commons(o: { basePath?: string; limits?: Partial<ServerLimits> } = {}): Promise<Commons> {
  const dir = tmp("coord");
  const admin = generateKeyPair();
  const coord = generateKeyPair();
  const owner = generateKeyPair();
  const bob = generateKeyPair();
  const clock = () => new Date().toISOString();
  const ledger = Ledger.create(
    path.join(dir, "ledger.jsonl"),
    { kind: "genesis", project: "demo", admins: [admin.publicKey], coordinator: coord.publicKey, rules: defaultRules() },
    new Date(Date.now() - 60_000).toISOString(),
  );
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: owner.publicKey, inviter: null }, admin, new Date(Date.now() - 30_000).toISOString());
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: bob.publicKey, inviter: null }, admin, new Date(Date.now() - 30_000).toISOString());
  const store = new LedgerStore(ledger, coord, clock);
  const server = createCoordinatorServer({
    store,
    coordinatorKey: coord,
    clock,
    patchesDir: path.join(dir, "patches"),
    policy: { submitCredits: () => 1, prSlots: () => 10, claimStake: () => 15 },
    ...(o.basePath === undefined ? {} : { basePath: o.basePath }),
    ...(o.limits === undefined ? {} : { limits: o.limits }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}${o.basePath ?? ""}`;
  const owners = {
    alice: new CommonsClient({ baseUrl: url, agentKey: owner, saltStore: memorySaltStore() }),
    bob: new CommonsClient({ baseUrl: url, agentKey: bob, saltStore: memorySaltStore() }),
  };
  return {
    url,
    dir,
    store,
    owner,
    close: () => new Promise((r) => server.close(() => r())),
    register: async (publicKey, family = "claude", who = "alice") => void (await owners[who].registerAgent(who, publicKey, family, "claude-code")),
  };
}

// A raw signed request to /api/agent-state.
async function raw(
  url: string,
  key: { publicKey: string; privateKey: string },
  method: "GET" | "PUT",
  o: { body?: Buffer; at?: string; prev?: string | null; sig?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const at = o.at ?? new Date().toISOString();
  const agent = keyIdOf(key.publicKey);
  const body = o.body ?? Buffer.from("x");
  const msg =
    method === "GET" ? agentStateMessage({ op: "get", agent, at }) : agentStateMessage({ op: "put", agent, at, sha256: sha256hex(body), prev: o.prev });
  const headers: Record<string, string> = {
    "x-commons-key": key.publicKey,
    "x-commons-at": at,
    "x-commons-sig": o.sig ?? sign(key.privateKey, msg),
    ...(o.prev === undefined ? {} : { "x-commons-prev": o.prev ?? "none" }),
    ...o.headers,
  };
  const res = await fetch(`${url}/api/agent-state`, { method, headers, ...(method === "PUT" ? { body } : {}) });
  const text = await res.text();
  return { status: res.status, body: text === "" ? {} : (JSON.parse(text) as Record<string, unknown>) };
}

function writeFiles(dir: string, files: Record<string, string>, mode = 0o600): void {
  for (const [rel, data] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, rel), data, { mode });
  }
}

test("state push / pull: a fresh machine gets back what the last one kept, never key files or isolation; the coordinator holds ciphertext only", async () => {
  const c = await commons();
  const w = await webCryptoKey();
  await c.register(w.publicKey);
  const env = (home: string) => ({ HOME: home, COMMONS_URL: c.url, COMMONS_AGENT_KEY: w.env });
  const seen: string[] = [];
  const run = async (args: string[], home: string): Promise<{ code: number; out: Record<string, unknown> }> => {
    const k = capture();
    const code = await agentMain(args, env(home), k.io);
    seen.push(...k.outs, ...k.errs);
    return { code, out: code === 0 ? (JSON.parse(k.outs.join("")) as Record<string, unknown>) : {} };
  };
  try {
    // First run: nothing stored yet.
    const first = tmp("home1");
    assert.deepEqual((await run(["state", "pull"], first)).out, { found: false, at: null, files: 0, written: 0, kept: 0, refused: 0 });

    const commonsDir = path.join(first, ".commons");
    const salt = "f".repeat(64);
    writeFiles(commonsDir, {
      "salts/s-1.json": JSON.stringify({ kind: "review", subjectId: "s-1", salt }),
      "salts/snapshots/snap-1.json": "{\"kind\":\"attest\"}",
      "last-iteration": "2026-11-19T10:00:00Z\n",
      "ledger-summary.json": "{\"seq\":12}",
      isolation: "this machine only",
      "agent-key.json": JSON.stringify(generateKeyPair()),
      "agent-key.json.old-20261118": "old key",
      "owner-key.json": "owner",
    });
    fs.symlinkSync("/etc/hosts", path.join(commonsDir, "hosts-link"));
    const pushed = await run(["state", "push"], first);
    assert.equal(pushed.code, 0);
    assert.equal(pushed.out.files, 4);
    assert.equal(pushed.out.fromStored, 0);

    // On the coordinator: <dir>/agent-state/<keyId>.json, 0600 in a 0700 folder, no plaintext.
    const stored = path.join(c.dir, "agent-state", `${keyIdOf(w.publicKey)}.json`);
    assert.equal(fs.statSync(stored).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(stored)).mode & 0o777, 0o700);
    const onDisk = fs.readFileSync(stored, "utf8");
    for (const plain of [salt, "s-1", "last-iteration", "seq", Buffer.from(salt).toString("base64")]) assert.ok(!onDisk.includes(plain), `plaintext ${plain} on the coordinator`);
    // ...and nothing in the ledger.
    assert.ok(!fs.readFileSync(path.join(c.dir, "ledger.jsonl"), "utf8").includes(JSON.parse(onDisk).blob.slice(0, 40)));

    // A fresh machine.
    const second = tmp("home2");
    const pulled = await run(["state", "pull"], second);
    assert.equal(pulled.code, 0);
    assert.deepEqual({ ...pulled.out, at: null }, { found: true, at: null, files: 4, written: 4, kept: 0, refused: 0 });
    const got = path.join(second, ".commons");
    assert.equal(fs.readFileSync(path.join(got, "salts/s-1.json"), "utf8"), fs.readFileSync(path.join(commonsDir, "salts/s-1.json"), "utf8"));
    assert.equal(fs.readFileSync(path.join(got, "last-iteration"), "utf8"), "2026-11-19T10:00:00Z\n");
    assert.equal(fs.statSync(path.join(got, "salts/s-1.json")).mode & 0o777, 0o600);
    for (const gone of ["isolation", "agent-key.json", "agent-key.json.old-20261118", "owner-key.json", "hosts-link"]) {
      assert.equal(fs.existsSync(path.join(got, gone)), false, `${gone} was restored`);
    }

    // Pull never overwrites: a local file, salt or not, is kept.
    fs.writeFileSync(path.join(got, "last-iteration"), "local");
    fs.writeFileSync(path.join(got, "salts/s-1.json"), "local salt");
    const again = await run(["state", "pull"], second);
    assert.deepEqual({ written: again.out.written, kept: again.out.kept }, { written: 0, kept: 4 });
    assert.equal(fs.readFileSync(path.join(got, "salts/s-1.json"), "utf8"), "local salt");

    // A third machine that did not pull: its push keeps what is stored and adds its own.
    const third = tmp("home3");
    writeFiles(path.join(third, ".commons"), { "salts/s-2.json": "{\"kind\":\"review\"}" });
    const merged = await run(["state", "push"], third);
    assert.deepEqual({ files: merged.out.files, fromStored: merged.out.fromStored }, { files: 5, fromStored: 4 });
    const fourth = tmp("home4");
    assert.equal((await run(["state", "pull"], fourth)).out.written, 5);
    assert.ok(fs.existsSync(path.join(fourth, ".commons", "salts/s-1.json")) && fs.existsSync(path.join(fourth, ".commons", "salts/s-2.json")));

    // --replace stores only what is here.
    assert.deepEqual((await run(["state", "push", "--replace"], third)).out.fromStored, 0);
    const fifth = tmp("home5");
    assert.equal((await run(["state", "pull"], fifth)).out.written, 1);

    for (const s of seen) assert.ok(!s.includes(w.env.slice(0, 40)), "the private key was printed");
  } finally {
    await c.close();
  }
});

test("agent state works under a base path, as the other routes do", async () => {
  const c = await commons({ basePath: "/commons/builders" });
  const k = generateKeyPair();
  await c.register(k.publicKey);
  try {
    const home = tmp("base");
    writeFiles(path.join(home, ".commons"), { "last-iteration": "x" });
    const env = { HOME: home, COMMONS_URL: c.url, COMMONS_AGENT_KEY: k.privateKey };
    assert.equal(await agentMain(["state", "push"], env, capture().io), 0);
    const fresh = tmp("base2");
    const k2 = capture();
    assert.equal(await agentMain(["state", "pull"], { ...env, HOME: fresh }, k2.io), 0);
    assert.equal(JSON.parse(k2.outs.join("")).written, 1);
  } finally {
    await c.close();
  }
});

test("/api/agent-state refuses: no or bad signature, clock skew, replay, rollback, a lost update, too large, unknown, owner and revoked keys", async () => {
  const c = await commons({ limits: { agentStateBytes: 1024 } });
  const a = generateKeyPair();
  await c.register(a.publicKey);
  try {
    // Unsigned, and a signature over something else.
    const bare = await fetch(`${c.url}/api/agent-state`);
    assert.equal(bare.status, 401);
    assert.equal((await raw(c.url, a, "GET", { sig: sign(a.privateKey, "x") })).status, 401);
    // A put's signature does not fetch, and a fetch's does not store.
    const at = new Date().toISOString();
    const putSig = sign(a.privateKey, agentStateMessage({ op: "put", agent: keyIdOf(a.publicKey), at, sha256: sha256hex(Buffer.from("x")) }));
    assert.equal((await raw(c.url, a, "GET", { at, sig: putSig })).status, 401);
    assert.equal((await raw(c.url, a, "PUT", { at, sig: sign(a.privateKey, agentStateMessage({ op: "get", agent: keyIdOf(a.publicKey), at })) })).status, 401);
    // Nothing stored yet.
    assert.deepEqual((await raw(c.url, a, "GET")).body.error, "no-state");
    // Clock skew, either way; and a time in another spelling.
    assert.equal((await raw(c.url, a, "PUT", { at: new Date(Date.now() - 10 * 60_000).toISOString() })).body.error, "clock-skew");
    assert.equal((await raw(c.url, a, "GET", { at: new Date(Date.now() + 10 * 60_000).toISOString() })).body.error, "clock-skew");
    assert.equal((await raw(c.url, a, "PUT", { at: new Date().toUTCString() })).body.error, "time");

    // A write, then the very same request again: a replay.
    const t1 = new Date().toISOString();
    const body1 = Buffer.from("first");
    const sig1 = sign(a.privateKey, agentStateMessage({ op: "put", agent: keyIdOf(a.publicKey), at: t1, sha256: sha256hex(body1) }));
    const first = await raw(c.url, a, "PUT", { at: t1, body: body1, sig: sig1 });
    assert.equal(first.status, 200);
    assert.deepEqual(first.body, { agent: keyIdOf(a.publicKey), at: t1, sha256: sha256hex(body1), bytes: 5 });
    assert.equal((await raw(c.url, a, "PUT", { at: t1, body: body1, sig: sig1 })).body.error, "stale");
    // Rollback: an older time, freshly signed.
    const older = new Date(Date.parse(t1) - 1000).toISOString();
    const rolled = await raw(c.url, a, "PUT", { at: older, body: Buffer.from("older") });
    assert.equal(rolled.status, 409);
    assert.equal(rolled.body.storedAt, t1);
    // A lost update: prev must be the stored digest.
    const t2 = new Date(Date.parse(t1) + 1).toISOString();
    assert.equal((await raw(c.url, a, "PUT", { at: t2, prev: null, body: Buffer.from("second") })).body.error, "state-changed");
    assert.equal((await raw(c.url, a, "PUT", { at: t2, prev: "0".repeat(64), body: Buffer.from("second") })).body.error, "state-changed");
    assert.equal((await raw(c.url, a, "PUT", { at: t2, prev: sha256hex(body1), body: Buffer.from("second") })).status, 200);
    const got = await raw(c.url, a, "GET");
    assert.equal(got.status, 200);
    assert.equal(Buffer.from(got.body.blob as string, "base64url").toString(), "second");
    assert.equal(got.body.at, t2);
    // Too large.
    const t3 = new Date(Date.parse(t2) + 1).toISOString();
    assert.equal((await raw(c.url, a, "PUT", { at: t3, body: Buffer.alloc(1025) })).status, 413);
    assert.equal((await raw(c.url, a, "PUT", { at: t3, body: Buffer.alloc(1024) })).status, 200);

    // Not an agent of this commons: a stranger, and an owner key.
    const stranger = generateKeyPair();
    assert.equal((await raw(c.url, stranger, "PUT")).body.error, "unauthorised");
    assert.equal((await raw(c.url, stranger, "GET")).body.error, "unauthorised");
    assert.equal((await raw(c.url, c.owner, "PUT")).body.error, "unauthorised");
    assert.equal(fs.existsSync(path.join(c.dir, "agent-state", `${keyIdOf(stranger.publicKey)}.json`)), false);

    // Revoked: refused, and what it stored is deleted.
    const file = path.join(c.dir, "agent-state", `${keyIdOf(a.publicKey)}.json`);
    assert.ok(fs.existsSync(file));
    await new CommonsClient({ baseUrl: c.url, agentKey: c.owner, saltStore: memorySaltStore() }).revokeAgent(keyIdOf(a.publicKey), "lost");
    assert.equal((await raw(c.url, a, "GET")).body.error, "signer-revoked");
    assert.equal(fs.existsSync(file), false);
    assert.equal((await raw(c.url, a, "PUT", { at: new Date(Date.now() + 1000).toISOString() })).body.error, "signer-revoked");
    assert.equal(fs.existsSync(file), false);
  } finally {
    await c.close();
  }
});

test("state push refuses a state over the cap and one it cannot decrypt (unless --replace)", async () => {
  const c = await commons({ limits: { agentStateBytes: 4096 } });
  const k = generateKeyPair();
  await c.register(k.publicKey);
  try {
    const home = tmp("cap");
    writeFiles(path.join(home, ".commons"), { "big.bin": "" });
    fs.writeFileSync(path.join(home, ".commons", "big.bin"), randomBytes(300_000));
    const env = { HOME: home, COMMONS_URL: c.url, COMMONS_AGENT_KEY: k.privateKey };
    const big = capture();
    assert.equal(await agentMain(["state", "push"], env, big.io), 1);
    assert.match(big.errs.join(""), /over the coordinator's cap/);
    // A blob that is not this agent's state.
    fs.rmSync(path.join(home, ".commons", "big.bin"));
    writeFiles(path.join(home, ".commons"), { "salts/s-1.json": "{}" });
    assert.equal((await raw(c.url, k, "PUT", { body: Buffer.from("garbage") })).status, 200);
    const refused = capture();
    assert.equal(await agentMain(["state", "push"], env, refused.io), 1);
    assert.match(refused.errs.join(""), /not a state blob/);
    assert.equal(await agentMain(["state", "pull"], env, capture().io), 1);
    const replaced = capture();
    assert.equal(await agentMain(["state", "push", "--replace"], env, replaced.io), 0);
    assert.equal(JSON.parse(replaced.outs.join("")).files, 1);
  } finally {
    await c.close();
  }
});

// ---------------------------------------------------------------------------
// Restore: nothing outside the folder
// ---------------------------------------------------------------------------

test("restore refuses paths that leave the folder, cross a symlink or name key files", () => {
  const root = tmp("restore");
  const dir = path.join(root, "commons");
  const outside = path.join(root, "outside");
  fs.mkdirSync(outside);
  fs.mkdirSync(dir);
  fs.symlinkSync(outside, path.join(dir, "link"));
  fs.symlinkSync(path.join(outside, "target"), path.join(dir, "dangling"));
  const file = (s: string) => ({ mode: 0o600, data: Buffer.from(s).toString("base64") });
  const bundle: StateBundle = {
    v: 1,
    files: {
      "../escape": file("x"),
      "/abs": file("x"),
      "salts/../../escape2": file("x"),
      "salts/./x": file("x"),
      "a//b": file("x"),
      "a\\..\\b": file("x"),
      "link/x": file("x"),
      dangling: file("x"),
      isolation: file("x"),
      "agent-key.json": file("x"),
      "salts/agent-key.json.old-1": file("x"),
      "bad-data": { mode: 0o600, data: "not base64!" },
      "salts/ok.json": file("ok"),
    },
  };
  assert.deepEqual(restoreBundle(dir, bundle), { written: 1, kept: 1, refused: 11 });
  assert.equal(fs.readFileSync(path.join(dir, "salts/ok.json"), "utf8"), "ok");
  assert.deepEqual(fs.readdirSync(outside), []);
  assert.equal(fs.existsSync(path.join(root, "escape")), false);
  assert.equal(fs.existsSync(path.join(root, "escape2")), false);
  assert.equal(fs.existsSync("/abs"), false);
});

test("the state key is per agent: another key cannot decrypt, and a bundle never takes symlinks", () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  const blob = encryptState(a, Buffer.from("secret"));
  assert.equal(decryptState(a, blob).toString(), "secret");
  assert.throws(() => decryptState(b, blob), /does not decrypt with this agent key/);
  const flipped = Buffer.from(blob);
  flipped[20] = (flipped[20] ?? 0) ^ 1;
  assert.throws(() => decryptState(a, flipped), /does not decrypt/);
  const dir = tmp("bundle");
  writeFiles(dir, { "x/y": "1" });
  fs.symlinkSync("/etc", path.join(dir, "etc"));
  assert.deepEqual(Object.keys(bundleDir(dir).files), ["x/y"]);
});

// ---------------------------------------------------------------------------
// Automatic push after a commit
// ---------------------------------------------------------------------------

test("commit-review from COMMONS_AGENT_KEY pushes the salt record; a fresh machine pulls it and reveals; a failed push is loud and keeps the commit", async () => {
  const c = await commons();
  const author = generateKeyPair();
  const w = await webCryptoKey();
  await c.register(author.publicKey, "claude");
  await c.register(w.publicKey, "qwen", "bob");
  const seen: string[] = [];
  try {
    const authorClient = new CommonsClient({ baseUrl: c.url, agentKey: author, saltStore: memorySaltStore() });
    await authorClient.submit({ id: "s-1", taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40) }, PATCH);
    await authorClient.submit({ id: "s-2", taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40) }, PATCH);
    await c.store.appendAsCoordinator((st) => assignmentBody(st, "s-1", [keyIdOf(w.publicKey)], "e1"));
    await c.store.appendAsCoordinator((st) => assignmentBody(st, "s-2", [keyIdOf(w.publicKey)], "e2"));

    const machine1 = tmp("m1");
    const verdictFile = path.join(machine1, "verdict.json");
    fs.writeFileSync(verdictFile, JSON.stringify({ defectProbability: 0.1, summary: "fine", findingIds: [] }));
    const env = (home: string) => ({ HOME: home, COMMONS_URL: c.url, COMMONS_AGENT_KEY: w.env });
    const k = capture();
    assert.equal(await agentMain(["commit-review", "s-1", verdictFile], env(machine1), k.io), 0);
    seen.push(...k.outs, ...k.errs);
    const out = JSON.parse(k.outs.join("")) as { saltStored: boolean; stateSync: { pushed: boolean; files: number } };
    assert.equal(out.saltStored, true);
    assert.equal(out.stateSync.pushed, true);
    assert.equal(out.stateSync.files, 1);

    // The machine is gone; the next run starts empty, pulls, and reveals.
    const machine2 = tmp("m2");
    const p = capture();
    assert.equal(await agentMain(["state", "pull"], env(machine2), p.io), 0);
    seen.push(...p.outs, ...p.errs);
    assert.ok(fs.existsSync(path.join(machine2, ".commons", "salts", "s-1.json")));
    const r = capture();
    assert.equal(await agentMain(["reveal-review", "s-1"], env(machine2), r.io), 0, r.errs.join(""));
    seen.push(...r.outs, ...r.errs);
    assert.equal(JSON.parse(r.outs.join("")).verdict.summary, "fine");

    // A push that fails: the commit stands (exit 0, salt kept locally), and it says so loudly.
    const failing: FetchLike = async (url, init) => {
      if (url.endsWith("/api/agent-state")) throw new Error("network down");
      return (globalThis.fetch as unknown as FetchLike)(url, init);
    };
    const f = capture();
    assert.equal(await agentMain(["commit-review", "s-2", verdictFile], env(machine2), f.io, failing), 0);
    seen.push(...f.outs, ...f.errs);
    const fout = JSON.parse(f.outs.join("")) as { seq: number; stateSync: { pushed: boolean; error: string } };
    assert.equal(fout.stateSync.pushed, false);
    assert.match(fout.stateSync.error, /network down/);
    assert.match(f.errs.join(""), /WARNING: the commit landed, but its salt record was NOT saved[\s\S]*commons-agent state push/);
    assert.ok(fs.existsSync(path.join(machine2, ".commons", "salts", "s-2.json")));
    assert.equal(c.store.ledger.entries()[fout.seq]?.body.kind, "reviewCommit");
    // The manual push afterwards saves it.
    const m = capture();
    assert.equal(await agentMain(["state", "push"], env(machine2), m.io), 0);
    seen.push(...m.outs, ...m.errs);

    // A key file: no automatic push unless COMMONS_STATE_SYNC=1.
    const keyFile = path.join(machine1, "k.json");
    fs.writeFileSync(keyFile, JSON.stringify(keyPairFromPrivateKey(w.env)));
    await authorClient.submit({ id: "s-3", taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40) }, PATCH);
    await authorClient.submit({ id: "s-4", taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40) }, PATCH);
    await c.store.appendAsCoordinator((st) => assignmentBody(st, "s-3", [keyIdOf(w.publicKey)], "e3"));
    await c.store.appendAsCoordinator((st) => assignmentBody(st, "s-4", [keyIdOf(w.publicKey)], "e4"));
    const fileEnv = { HOME: machine1, COMMONS_URL: c.url, COMMONS_KEY_FILE: keyFile };
    const nf = capture();
    assert.equal(await agentMain(["commit-review", "s-3", verdictFile], fileEnv, nf.io), 0);
    assert.equal(JSON.parse(nf.outs.join("")).stateSync, undefined);
    const yf = capture();
    assert.equal(await agentMain(["commit-review", "s-4", verdictFile], { ...fileEnv, COMMONS_STATE_SYNC: "1" }, yf.io), 0);
    assert.equal(JSON.parse(yf.outs.join("")).stateSync.pushed, true);

    for (const s of seen) assert.ok(!s.includes(w.env.slice(0, 40)), "the private key was printed");
  } finally {
    await c.close();
  }
});
