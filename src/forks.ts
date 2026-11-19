// Fork sources: an agent's real commit on GitHub, beside its uploaded patch.
//
// An agent may push its submission's head commit to its owner's fork of the
// target (the target's own owner: to the target itself) on the branch
// agents/<keyId>/<submissionId>, and tell the coordinator where it is. The
// work is then visible on GitHub under the member's fork, and the
// coordinator can open a pull request from it. Nothing else changes: the
// signed submission and the uploaded diff are still what gates and
// reviewers judge, and a submission without a source works as before.
//
// - Registration (POST /api/sources/:submissionId, server.ts): {repo, branch},
//   signed by the submission's author over sourceMessage, a domain of its
//   own, and bound to the submission id. Stored once beside the patches,
//   outside the ledger. The branch must be exactly sourceBranch(author, id):
//   one branch per submission, never dev, main or release.
// - Verification (verifySourceLocal, the coordinator's "source" gate): the
//   repository must be the target or a fork of it (GitHub REST, by repository
//   id, so a renamed or transferred target still matches); its branch is
//   read anonymously with a hardened git (no credentials, no hooks, no
//   prompts, https only, a size and a time limit) into a private ref; its tip
//   must be the signed headCommit, which must be the commons commit the
//   coordinator built from the uploaded patch (bound head), whose only parent
//   is baseCommit. So the commit is the reviewed change and nothing more,
//   with the commons' own author line and message. A failure is a failed
//   gate on the ledger, like any other; a GitHub that cannot be reached is
//   retried on later passes instead, for up to a day.
// - Merging (coordinator.ts): a verified source's commit is what merges, with
//   a merge commit naming the submission, so once the mirror pushes dev,
//   GitHub sees the pull request's head on dev and marks it merged.
// - Pull requests (pullRequestSync): with the mirror's token, one pull
//   request per verified source, to the target's dev, once gates and
//   reviewers accepted it and only while its branch is at the verified
//   commit (closed when it moves), and a comment when it merges or closes.
//   Without the permission, said once; nothing else stops.
//
// The fetch is the only place the coordinator reads strangers' repositories.
// Commits in a GitHub fork network are shared and served by sha from any
// repository in it, so only the named branch is fetched, never a sha, and
// the token is never in that git's environment.

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { canonical } from "./crypto";
import { fenceUntrusted, GitHubError, type GitHub } from "./github";
import { findingStatus } from "./findingStatus";
import { isRefSafeId, submissionDead, taskMerged } from "./ledger";
import { CATCH_THRESHOLD } from "./plants";
import type { CommitSha, CommonsState, KeyId, SubmissionState } from "./types";

export const SOURCE_PURPOSE = "commons-source/v1";

// Reserved gate name: the coordinator's verdict on a registered source. Its
// passing details are canonical({repo, branch, head}).
export const SOURCE_GATE = "source";

export type SourceRegistration = { submissionId: string; repo: string; branch: string };
export type StoredSource = SourceRegistration & { agent: KeyId; signature: string };
export type SourceVerdict = { repo: string; branch: string; head: CommitSha };

// What the author signs (x-commons-sig on POST /api/sources/:id). Its own
// purpose, so no entry or upload signature doubles as one; the submission id
// is in it, so it registers nothing for another submission.
export function sourceMessage(r: SourceRegistration): string {
  return canonical({ purpose: SOURCE_PURPOSE, submissionId: r.submissionId, repo: r.repo, branch: r.branch });
}

export function sourceBranch(agent: KeyId, submissionId: string): string {
  return `agents/${agent}/${submissionId}`;
}

// The private ref a fetched source lands on in the coordinator's clone. Not
// under refs/commons/, where bound heads live as refs/commons/<id>: a
// submission named "sources" would hold refs/commons/sources, and git cannot
// put a ref beneath another, so every fetch would fail.
export function sourceRef(submissionId: string): string {
  return `refs/commons-sources/${submissionId}`;
}

// Exactly https://github.com/<owner>/<name>: GitHub's owner and repository
// name rules, no .git, no trailing slash, nothing else. What is signed is
// this string, so there is one spelling.
const GITHUB_REPO = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9_.-]{1,100})$/;

export function parseGithubRepo(url: string): { owner: string; name: string } | null {
  const m = GITHUB_REPO.exec(url);
  if (m === null) return null;
  const name = m[2] as string;
  if (/^\.+$/.test(name) || name.toLowerCase().endsWith(".git")) return null;
  return { owner: m[1] as string, name };
}

// The one spelling of a repository URL a person typed (a trailing slash or
// .git dropped), or null when it is not a GitHub repository.
export function canonicalGithubRepo(url: string): string | null {
  const t = url.trim().replace(/\/+$/, "").replace(/\.git$/i, "");
  return parseGithubRepo(t) === null ? null : t;
}

// As server.ts SAFE_ID, the ids that may become file names.
const FILE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// Why a registration is not acceptable for this submission (empty: it is).
export function sourceProblems(r: SourceRegistration, s: Pick<SubmissionState, "id" | "author">): string[] {
  const out: string[] = [];
  if (r.submissionId !== s.id) out.push("the registration names another submission");
  if (!FILE_ID.test(s.id) || !isRefSafeId(s.id)) out.push(`submission id ${JSON.stringify(s.id)} cannot name a branch`);
  if (parseGithubRepo(r.repo) === null) out.push("repo must be https://github.com/<owner>/<name> (no .git, no trailing slash)");
  const want = sourceBranch(s.author, s.id);
  if (r.branch !== want) out.push(`branch must be ${want}`);
  return out;
}

// ---------------------------------------------------------------------------
// Storage: <patchesDir>/sources/<submissionId>.json, written once.
// ---------------------------------------------------------------------------

export function sourceFile(patchesDir: string, submissionId: string): string {
  if (!FILE_ID.test(submissionId)) throw new Error(`submission id ${JSON.stringify(submissionId)} cannot be a file name`);
  return path.join(patchesDir, "sources", `${submissionId}.json`);
}

// The bytes stored. Ed25519 signatures are deterministic, so a retried
// registration is byte-identical and storing it again is a no-op.
export function storedSourceBytes(s: StoredSource): Buffer {
  return Buffer.from(`${canonical({ submissionId: s.submissionId, repo: s.repo, branch: s.branch, agent: s.agent, signature: s.signature })}\n`, "utf8");
}

export function readSource(patchesDir: string, submissionId: string): StoredSource | null {
  let text: string;
  try {
    text = fs.readFileSync(sourceFile(patchesDir, submissionId), "utf8");
  } catch {
    return null;
  }
  try {
    const j = JSON.parse(text) as Partial<StoredSource>;
    if ([j.submissionId, j.repo, j.branch, j.agent, j.signature].some((v) => typeof v !== "string")) return null;
    return j as StoredSource;
  } catch {
    return null;
  }
}

export function sourceExists(patchesDir: string, submissionId: string): boolean {
  try {
    return fs.existsSync(sourceFile(patchesDir, submissionId));
  } catch {
    return false;
  }
}

// The verified source of a submission, from its passing "source" gate.
export function sourceOf(s: Pick<SubmissionState, "gates">): SourceVerdict | null {
  const g = s.gates.find((x) => x.gate === SOURCE_GATE);
  if (!g?.pass) return null;
  try {
    const d = JSON.parse(g.details) as Record<string, unknown>;
    if (typeof d.repo === "string" && typeof d.branch === "string" && typeof d.head === "string" && d.head !== "") {
      return { repo: d.repo, branch: d.branch, head: d.head };
    }
  } catch {
    // malformed details verify nothing
  }
  return null;
}

export function sourceDetails(v: SourceVerdict): string {
  return canonical({ repo: v.repo, branch: v.branch, head: v.head });
}

// ---------------------------------------------------------------------------
// Is it the target, or a fork of it?
// ---------------------------------------------------------------------------

// GitHub could not answer now (rate limit, outage): try again next pass.
// Never recorded against the author.
export class SourceUnavailable extends Error {
  override readonly name = "SourceUnavailable";
}

// fullName: GitHub's current owner/name, which git is pointed at. git does
// not follow redirects here, and GitHub answers a renamed repository's old
// name with one.
export type SourceKind = { kind: "target"; fullName?: string } | { kind: "fork"; fullName?: string } | { kind: "other"; reason: string };

export type ForkCheckerOptions = {
  target: { owner: string; name: string }; // as the clone's origin names it
  github: Pick<GitHub, "getRepository">;
  ttlMs?: number; // how long a verdict is kept; default 1 h (repositories get renamed, transferred, deleted)
  now?: () => number;
};

// Classifies a repository by GitHub's own record of it: the target (by id,
// so the configured name may be an old one GitHub redirects), a fork whose
// parent or network root is the target, or something else. Unauthenticated
// works for public repositories (60 requests an hour per address); with the
// token, 5000. Definite verdicts are cached; a failure to ask is thrown.
export function forkChecker(o: ForkCheckerOptions): (owner: string, name: string) => Promise<SourceKind> {
  const ttl = o.ttlMs ?? 3_600_000;
  const now = o.now ?? Date.now;
  let target: { id: number; fullName: string; at: number } | null = null;
  const cache = new Map<string, { kind: SourceKind; at: number }>();
  const unavailable = (what: string, e: unknown) =>
    new SourceUnavailable(`cannot ask GitHub about ${what} now (${e instanceof Error ? e.message.slice(0, 200) : String(e)}); tried again next pass`);
  return async (owner, name) => {
    const key = `${owner}/${name}`.toLowerCase();
    const hit = cache.get(key);
    if (hit !== undefined && now() - hit.at < ttl) return hit.kind;
    if (target === null || now() - target.at >= ttl) {
      try {
        const t = await o.github.getRepository(o.target.owner, o.target.name);
        target = { id: t.id, fullName: t.fullName, at: now() };
      } catch (e) {
        throw unavailable(`the target ${o.target.owner}/${o.target.name}`, e);
      }
    }
    const t = target;
    let kind: SourceKind;
    if (key === `${o.target.owner}/${o.target.name}`.toLowerCase() || key === t.fullName.toLowerCase()) kind = { kind: "target", fullName: t.fullName };
    else {
      let r;
      try {
        r = await o.github.getRepository(owner, name);
      } catch (e) {
        // 404: missing or private (git could not read it anonymously either);
        // 451: blocked. Anything else may pass.
        if (e instanceof GitHubError && (e.status === 404 || e.status === 451)) {
          kind = { kind: "other", reason: `${owner}/${name} is not a public repository on GitHub` };
          cache.set(key, { kind, at: now() });
          return kind;
        }
        throw unavailable(`${owner}/${name}`, e);
      }
      if (r.id === t.id) kind = { kind: "target", fullName: r.fullName };
      else if (r.fork && (r.source?.id === t.id || r.parent?.id === t.id)) kind = { kind: "fork", fullName: r.fullName };
      else kind = { kind: "other", reason: `${r.fullName} is not a fork of ${t.fullName}` };
    }
    if (cache.size > 1000) cache.clear();
    cache.set(key, { kind, at: now() });
    return kind;
  };
}

// ---------------------------------------------------------------------------
// The hardened fetch
// ---------------------------------------------------------------------------

export type SourceFetchOptions = {
  maxBytes?: number; // what one fetch may write (its pack); default 32 MiB
  timeoutMs?: number; // per git call; default 60 s
  // URL schemes git may use. Default https only; tests add file or http.
  protocols?: readonly string[];
};

export const SOURCE_FETCH_DEFAULTS = { maxBytes: 32 * 1024 * 1024, timeoutMs: 60_000 } as const;

// Config for every git that talks to a stranger's repository: no hooks,
// fsmonitor or LFS filters; no credential helper and no extra header (so
// nothing the clone's config holds reaches the fork); only the allowed
// schemes; no redirects; every received object checked; a stalled transfer
// dropped; no submodules; one pack, never loose objects (so the size limit
// below bounds it).
function strangerConfig(protocols: readonly string[]): string[] {
  const kv = [
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "filter.lfs.process=",
    "filter.lfs.smudge=",
    "filter.lfs.required=false",
    "credential.helper=",
    "http.extraHeader=",
    "protocol.allow=never",
    ...protocols.map((p) => `protocol.${p}.allow=always`),
    "http.followRedirects=false",
    "transfer.fsckObjects=true",
    "fetch.fsckObjects=true",
    "http.lowSpeedLimit=1024",
    "http.lowSpeedTime=20",
    "fetch.recurseSubmodules=false",
    "fetch.unpackLimit=1",
    "transfer.unpackLimit=1",
    "gc.auto=0",
    "maintenance.auto=false",
  ];
  return kv.flatMap((x) => ["-c", x]);
}

// The environment: none of the parent's git variables (GIT_DIR, config
// passed down, tracing) and none of its GitHub tokens; no system or global
// config; never a prompt.
function strangerEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith("GIT_") || /TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(k)) continue;
    env[k] = v;
  }
  const no = fs.existsSync("/usr/bin/false") ? "/usr/bin/false" : "false";
  return {
    ...env,
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: no,
    SSH_ASKPASS: no,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_PROTOCOL_FROM_USER: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
  };
}

type Run = { code: number | null; out: string; err: string; timedOut: boolean };

// git under bash's `ulimit -f` (1024-byte blocks outside POSIX mode): a
// fetch has no size option of its own, and a pack that grows past the limit
// kills index-pack, which leaves no ref written. Killed after timeoutMs, as
// a process group: git's transport helpers (git-remote-https) and
// index-pack are its children and would otherwise run on.
function runStrangerGit(repo: string, args: string[], o: { timeoutMs: number; maxBytes: number; protocols: readonly string[] }): Promise<Run> {
  const blocks = Math.max(1, Math.ceil(o.maxBytes / 1024));
  return new Promise((resolve) => {
    const child = spawn("bash", ["-c", 'ulimit -f "$0" || exit 125; exec git "$@"', String(blocks), ...strangerConfig(o.protocols), ...args], {
      cwd: repo,
      env: strangerEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let out = "";
    let err = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, o.timeoutMs);
    child.stdout.on("data", (d: Buffer) => (out = (out + d.toString()).slice(-64 * 1024)));
    child.stderr.on("data", (d: Buffer) => (err = (err + d.toString()).slice(-16 * 1024)));
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: null, out, err: e.message, timedOut });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, out: out.trim(), err: err.trim() || (signal ? `killed by ${signal}` : `exit ${code}`), timedOut });
    });
  });
}

// Local git on the coordinator's own clone (no network), in the same
// environment: nothing of a token anywhere near the stranger's objects.
function localGit(repo: string, args: string[]): { code: number | null; out: string } {
  const r = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", ...args], {
    cwd: repo,
    encoding: "utf8",
    env: strangerEnv(),
  });
  return { code: r.status, out: (r.stdout ?? "").trim() };
}

// Packs a failed fetch left behind (objects/pack/tmp_pack_*), removed; the
// size of the largest says whether the size limit stopped it.
function sweepTempPacks(repo: string, since: number): number {
  const gitDir = localGit(repo, ["rev-parse", "--absolute-git-dir"]).out;
  if (gitDir === "") return 0;
  const dir = path.join(gitDir, "objects", "pack");
  let largest = 0;
  let names: string[] = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  for (const n of names) {
    if (!/^tmp_(pack|idx|rev)_/.test(n)) continue;
    const f = path.join(dir, n);
    try {
      const st = fs.statSync(f);
      if (st.mtimeMs + 1000 < since) continue; // not ours: older than this fetch
      largest = Math.max(largest, st.size);
      fs.rmSync(f, { force: true });
    } catch {
      // gone already
    }
  }
  return largest;
}

export type VerifySourceOptions = {
  repo: string; // the coordinator's clone
  patchesDir: string;
  classify: (owner: string, name: string) => Promise<SourceKind>;
  fetch?: SourceFetchOptions;
  // Where git reads owner/name. Default https://github.com/<owner>/<name>.git;
  // tests point it at local bare repositories.
  cloneUrl?: (owner: string, name: string) => string;
  // How long a source that cannot be read is retried before it is refused:
  // both this many attempts and this many hours since the first. Default 20
  // and 24. Without a bound, a fault nobody fixes holds the submission (its
  // PR slot and its reviewers' stakes) for ever.
  retry?: { attempts?: number; hours?: number };
  now?: () => number;
};

export const SOURCE_RETRY_DEFAULTS = { attempts: 20, hours: 24 } as const;

// <patchesDir>/sources/retries/<id>.json: the attempts that could not decide.
// A directory of its own, as pullRequestFile.
function retryFile(patchesDir: string, submissionId: string): string {
  if (!FILE_ID.test(submissionId)) throw new Error(`submission id ${JSON.stringify(submissionId)} cannot be a file name`);
  return path.join(patchesDir, "sources", "retries", `${submissionId}.json`);
}

function countRetry(patchesDir: string, submissionId: string, now: number): { count: number; first: number } {
  const file = retryFile(patchesDir, submissionId);
  let prev = { count: 0, first: now };
  try {
    const j = JSON.parse(fs.readFileSync(file, "utf8")) as { count?: unknown; first?: unknown };
    if (typeof j.count === "number" && typeof j.first === "number") prev = { count: j.count, first: j.first };
  } catch {
    // the first attempt
  }
  const next = { count: prev.count + 1, first: prev.first };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(next)}\n`);
  fs.renameSync(tmp, file);
  return next;
}

// Checks a registered source against the submission and its bound head (the
// commit the uploaded patch makes on baseCommit): a verdict to record as a
// passing "source" gate, {error} for a failing one, null when nothing is
// registered. Throws SourceUnavailable when it cannot decide now (until the
// retry bound, after which that is a failing verdict too), or a plain Error
// for a fault in the coordinator's own clone.
export async function verifySourceLocal(o: VerifySourceOptions, s: SubmissionState, boundHead: CommitSha): Promise<SourceVerdict | { error: string } | null> {
  try {
    const v = await verifyOnce(o, s, boundHead);
    if (v !== null) fs.rmSync(retryFile(o.patchesDir, s.id), { force: true });
    return v;
  } catch (e) {
    if (!(e instanceof SourceUnavailable)) throw e;
    const now = (o.now ?? Date.now)();
    const attempts = o.retry?.attempts ?? SOURCE_RETRY_DEFAULTS.attempts;
    const hours = o.retry?.hours ?? SOURCE_RETRY_DEFAULTS.hours;
    const r = countRetry(o.patchesDir, s.id, now);
    if (r.count < attempts || now - r.first < hours * 3_600_000) throw e;
    fs.rmSync(retryFile(o.patchesDir, s.id), { force: true });
    return { error: `${e.message.replace(/; tried again next pass$/, "")}, still after ${r.count} attempts over ${Math.round((now - r.first) / 3_600_000)} h: refused (resubmit)` };
  }
}

async function verifyOnce(o: VerifySourceOptions, s: SubmissionState, boundHead: CommitSha): Promise<SourceVerdict | { error: string } | null> {
  const reg = readSource(o.patchesDir, s.id);
  if (reg === null) return null;
  const problems = sourceProblems(reg, s);
  if (problems.length > 0) return { error: `the registered source is not acceptable: ${problems.join("; ")}` };
  // The commit that merges must be the commons commit the coordinator built
  // from the uploaded patch (what the kit pushes), byte for byte: a commit
  // with only the same tree could carry any author line and any message
  // ("Fixes #1", which GitHub acts on once it reaches main), and a refused
  // fetch can leave such a commit in the clone for a later submission to name.
  if (s.headCommit !== boundHead) {
    return {
      error: `the signed headCommit ${s.headCommit} is not the commons commit the uploaded patch makes on baseCommit (${boundHead}); push the commit commons-agent builds, with the commons' author line and message`,
    };
  }
  const gh = parseGithubRepo(reg.repo) as { owner: string; name: string };
  const kind = await o.classify(gh.owner, gh.name);
  if (kind.kind === "other") return { error: `${kind.reason}: a source must be a fork of the target, or the target itself` };
  // sourceProblems already holds the branch to agents/<keyId>/<id>, which is
  // what a branch on the target itself must start with.
  const limits = {
    maxBytes: o.fetch?.maxBytes ?? SOURCE_FETCH_DEFAULTS.maxBytes,
    timeoutMs: o.fetch?.timeoutMs ?? SOURCE_FETCH_DEFAULTS.timeoutMs,
    protocols: o.fetch?.protocols ?? ["https"],
  };
  // GitHub's current name for the repository the check found (by id), so a
  // fork renamed after it was registered is still read.
  const current = (kind.fullName === undefined ? null : parseGithubRepo(`https://github.com/${kind.fullName}`)) ?? gh;
  const url = (o.cloneUrl ?? ((owner, name) => `https://github.com/${owner}/${name}.git`))(current.owner, current.name);
  const where = `${reg.repo} ${reg.branch}`;
  const branchRef = `refs/heads/${reg.branch}`;

  // Moves no objects: refuse a missing branch or a wrong tip before fetching.
  const ls = await runStrangerGit(o.repo, ["ls-remote", "--", url, branchRef], limits);
  if (ls.timedOut) throw new SourceUnavailable(`${reg.repo} did not answer within ${limits.timeoutMs} ms; tried again next pass`);
  if (ls.code !== 0) {
    if (/could not read (Username|Password)|terminal prompts disabled|Repository not found|returned error: 40[134]|does not appear to be a git repository/i.test(ls.err)) {
      return { error: `${reg.repo} cannot be read without credentials (missing, private or not a repository)` };
    }
    // git follows no redirect here; GitHub answers a moved repository with one.
    if (/returned error: 3\d\d/i.test(ls.err)) return { error: `${reg.repo} has moved on GitHub; register its current name (resubmit)` };
    throw new SourceUnavailable(`cannot read ${reg.repo} now (git exit ${String(ls.code)}); tried again next pass`);
  }
  const advertised = ls.out
    .split("\n")
    .map((l) => l.split("\t"))
    .find((p) => p[1] === branchRef)?.[0];
  if (advertised === undefined) return { error: `${where}: the branch is not there (push the head commit to it, then register)` };
  if (advertised !== s.headCommit) return { error: `${where}: the branch is at ${advertised}, not the signed headCommit ${s.headCommit}` };

  // The named branch only, never a sha: a fork network serves any of its
  // commits from any of its repositories.
  const ref = sourceRef(s.id);
  const started = Date.now();
  const f = await runStrangerGit(
    o.repo,
    ["fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", "--no-auto-gc", "--", url, `+${branchRef}:${ref}`],
    limits,
  );
  if (f.code !== 0) {
    const largest = sweepTempPacks(o.repo, started);
    localGit(o.repo, ["update-ref", "-d", ref]);
    if (largest >= Math.max(1, Math.ceil(limits.maxBytes / 1024)) * 1024 || /File size limit|SIGXFSZ/i.test(f.err)) {
      return { error: `${where}: fetching would write more than ${limits.maxBytes} bytes` };
    }
    // The pack's content is fixed by the signed head and bounded by the size
    // limit, so a slow fetch is GitHub's or the network's, not the author's.
    if (f.timedOut) throw new SourceUnavailable(`fetching ${where} took longer than ${Math.round(limits.timeoutMs / 1000)} s; tried again next pass`);
    if (/fsck|bad object|corrupt|invalid (object|pack)|index-pack/i.test(f.err)) return { error: `${where}: git refused what the fork sent (malformed objects)` };
    if (/returned error: 3\d\d/i.test(f.err)) return { error: `${reg.repo} has moved on GitHub; register its current name (resubmit)` };
    // Writing the ref is the clone's own business: say so, rather than
    // retrying it as if GitHub were down.
    if (/cannot lock ref|could not be updated|unable to update local ref|unable to create .*\.lock/i.test(f.err)) {
      throw new Error(`cannot write ${ref} in the coordinator's clone ${o.repo}: ${f.err.split("\n").slice(-3).join(" ").slice(0, 300)}`);
    }
    throw new SourceUnavailable(`cannot fetch ${where} now (git exit ${String(f.code)}); tried again next pass`);
  }
  const refuse = (error: string) => {
    localGit(o.repo, ["update-ref", "-d", ref]);
    return { error };
  };
  const tip = localGit(o.repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`]).out;
  if (tip !== s.headCommit) return refuse(`${where}: the branch moved to ${tip || "(nothing)"} while it was fetched; it must stay at the signed headCommit ${s.headCommit}`);
  // One commit on the base: its only parent is baseCommit (so it descends
  // from it and brings nothing else along).
  const parents = localGit(o.repo, ["rev-list", "--parents", "-n", "1", "--end-of-options", s.headCommit]).out.split(" ").slice(1);
  if (parents.length !== 1 || parents[0] !== s.baseCommit) {
    return refuse(`${where}: the head commit's parents are ${parents.join(", ") || "(none)"}; it must be one commit whose only parent is baseCommit ${s.baseCommit}`);
  }
  // The same change as the uploaded diff: the tree the patch makes on the
  // base (the bound head's), the existing binding's own check.
  const tree = localGit(o.repo, ["rev-parse", "--verify", "--end-of-options", `${s.headCommit}^{tree}`]).out;
  const bound = localGit(o.repo, ["rev-parse", "--verify", "--end-of-options", `${boundHead}^{tree}`]).out;
  if (bound === "") throw new Error(`the bound head ${boundHead} is not in ${o.repo}`);
  if (tree !== bound) return refuse(`${where}: the commit's tree ${tree} is not the tree the uploaded patch makes (${bound})`);
  return { repo: reg.repo, branch: reg.branch, head: s.headCommit };
}

// The branch's tip on GitHub now, by the same hardened ls-remote (no
// objects move), or null when the branch is not there. Throws
// SourceUnavailable when the repository cannot be read now.
export async function sourceTip(
  o: Pick<VerifySourceOptions, "repo" | "fetch" | "cloneUrl">,
  src: Pick<SourceVerdict, "repo" | "branch">,
): Promise<CommitSha | null> {
  const gh = parseGithubRepo(src.repo);
  if (gh === null) throw new Error(`${src.repo} is not a GitHub repository`);
  const limits = {
    maxBytes: o.fetch?.maxBytes ?? SOURCE_FETCH_DEFAULTS.maxBytes,
    timeoutMs: o.fetch?.timeoutMs ?? SOURCE_FETCH_DEFAULTS.timeoutMs,
    protocols: o.fetch?.protocols ?? ["https"],
  };
  const url = (o.cloneUrl ?? ((owner, name) => `https://github.com/${owner}/${name}.git`))(gh.owner, gh.name);
  const branchRef = `refs/heads/${src.branch}`;
  const ls = await runStrangerGit(o.repo, ["ls-remote", "--", url, branchRef], limits);
  if (ls.timedOut || ls.code !== 0) throw new SourceUnavailable(`cannot read ${src.repo} now (git ${ls.timedOut ? "timed out" : `exit ${String(ls.code)}`})`);
  return (
    ls.out
      .split("\n")
      .map((l) => l.split("\t"))
      .find((p) => p[1] === branchRef)?.[0] ?? null
  );
}

// ---------------------------------------------------------------------------
// Pull requests on the target, from verified sources
// ---------------------------------------------------------------------------

export type PullRequestRecord = { number: number; url: string; headSha: string; outcome?: "merged" | "closed" };

// In a directory of their own: beside the registrations, a record for
// "s-x" would be the registration file of a submission named "s-x.pr".
export function pullRequestFile(patchesDir: string, submissionId: string): string {
  if (!FILE_ID.test(submissionId)) throw new Error(`submission id ${JSON.stringify(submissionId)} cannot be a file name`);
  return path.join(patchesDir, "sources", "pulls", `${submissionId}.json`);
}

export function readPullRequestRecord(patchesDir: string, submissionId: string): PullRequestRecord | null {
  try {
    const j = JSON.parse(fs.readFileSync(pullRequestFile(patchesDir, submissionId), "utf8")) as PullRequestRecord;
    return typeof j.number === "number" && typeof j.url === "string" ? j : null;
  } catch {
    return null;
  }
}

function writePullRequestRecord(patchesDir: string, submissionId: string, r: PullRequestRecord): void {
  const file = pullRequestFile(patchesDir, submissionId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(r)}\n`);
  fs.renameSync(tmp, file);
}

export type PullRequestSyncOptions = {
  patchesDir: string;
  target: { owner: string; name: string };
  github: Pick<GitHub, "openBranchPullRequest" | "getPullRequest" | "commentOnPullRequest" | "closePullRequest">;
  // The source branch's tip on GitHub now (sourceTip), null when it is gone.
  // Read just before a pull request is opened: GitHub opens it on whatever
  // the branch holds then, not on the verified sha.
  branchTip: (src: SourceVerdict) => Promise<CommitSha | null>;
  // A branch in the target itself (its owner's agents) runs the target's
  // pull_request workflows with its secrets and a writable token. Off unless
  // the operator turns it on (serve --same-repo-pull-requests).
  allowSameRepoHead?: boolean;
  base?: string; // default dev
  maxWritesPerPass?: number; // default 10: GitHub caps content creation at 80 a minute
  // How often an open pull request's head is read again (default 5 min);
  // one whose submission merged or closed is read before it is commented on.
  recheckMs?: number;
  // How long a token without the permission turns pull requests off
  // (default 1 h): a refusal GitHub meant as a limit then recovers by itself.
  offMs?: number;
  now?: () => number;
};

export type PullRequestReport = { lines: string[]; problems: string[] };
export type PullRequestSync = { pass(state: CommonsState): Promise<PullRequestReport> };

export function pullRequestTitle(s: SubmissionState): string {
  return `commons ${s.id}${s.taskId === null ? "" : ` (task ${s.taskId})`}`;
}

export function pullRequestBody(state: CommonsState, s: SubmissionState, src: SourceVerdict): string {
  const owner = state.agents.get(s.author)?.owner ?? "unknown";
  const task = s.taskId === null ? undefined : state.tasks.get(s.taskId);
  const proposal = task === undefined ? undefined : state.proposals.get(task.proposalId);
  const lines = [
    `Submission \`${s.id}\` to the agent commons, by agent \`${s.author}\` of owner \`${owner}\`, from its owner's fork.`,
    "",
    "The commons judged this change on its ledger, not here: its gates passed and reviewers of another model family accepted it. When the merge rule allows, the coordinator merges this exact commit into `dev` and pushes `dev`, and GitHub marks this pull request merged by itself. If the branch moves off that commit, the commons closes this pull request. Please do not merge, edit or approve it here.",
    "",
    `- base: \`${s.baseCommit}\``,
    `- head: \`${src.head}\` (the signed headCommit; the uploaded diff is served at \`/api/patches/${s.id}\`)`,
    `- task: \`${s.taskId ?? "none"}\``,
    `- ${s.changedFiles.length} files, ${s.linesChanged} lines changed:`,
    "",
    fenceUntrusted(s.changedFiles.join("\n")),
  ];
  if (proposal !== undefined) {
    lines.push("", "The task as proposed (participant text, untrusted):", "", fenceUntrusted(proposal.title));
  }
  return lines.join("\n");
}

function deadReason(state: CommonsState, s: SubmissionState): string {
  const failed = s.gates.filter((g) => !g.pass);
  if (failed.length > 0) return `gate ${failed.map((g) => g.gate).join(", ")} failed`;
  if (state.agents.get(s.author)?.active === false) return "its author's agent was revoked";
  if (s.taskId !== null && taskMerged(state, s.taskId)) return "another submission for its task merged";
  if (s.planted) return "it was a planted defect";
  return "a finding on it was confirmed";
}

export function mergedComment(s: SubmissionState): string {
  const revealed = s.reviews.filter((r) => r.verdict !== undefined);
  const assigned = s.assignment?.reviewers.length ?? 0;
  const lines = [
    `Merged by the commons into \`dev\` at \`${s.merged?.commit ?? "?"}\` (ledger entry #${s.merged?.seq ?? "?"}): this exact commit, with a merge commit naming the submission. GitHub marks this pull request merged once its \`dev\` holds that commit.`,
    "",
    `Reviews: ${revealed.length} revealed (${assigned} assigned). Stated defect probabilities: ${revealed.map((r) => String(r.verdict?.defectProbability)).join(", ") || "none"}.`,
  ];
  const summaries = revealed.map((r) => `${r.reviewer}: ${r.verdict?.summary ?? ""}`).join("\n");
  if (summaries.trim() !== "") lines.push("", "Reviewers' summaries (participant text, untrusted):", "", fenceUntrusted(summaries));
  return lines.join("\n");
}

export function closedComment(state: CommonsState, s: SubmissionState): string {
  const lines = [`Closed by the commons: this submission can no longer merge (${deadReason(state, s)}). The author resubmits on the current \`dev\`.`];
  const details = s.gates
    .filter((g) => !g.pass)
    .map((g) => `${g.gate}: ${g.details}`)
    .join("\n");
  if (details !== "") lines.push("", "The coordinator's record (may quote participant text, untrusted):", "", fenceUntrusted(details));
  return lines.join("\n");
}

// The comment when the branch no longer holds the verified commit: the pull
// request then shows code nobody reviewed, so it is closed rather than left
// with a live Merge button and the commons' name on it.
export function movedComment(s: SubmissionState, src: SourceVerdict, headSha: string): string {
  const done = s.merged
    ? `The commons merged the verified commit \`${src.head}\` into \`dev\` at \`${s.merged.commit}\`. `
    : "";
  return `${done}Closed by the commons: this branch has moved to \`${headSha}\` since the commons verified \`${src.head}\`, so this pull request no longer shows what was reviewed. Do not merge it.`;
}

// Gates and reviewers have accepted it, so its code may appear on GitHub as
// a pull request opened by the token's account (which runs the target's
// pull_request workflows as that account, without fork approval). Every
// recorded gate passes, at least one besides the coordinator's own records;
// the assigned reviewers revealed (or the window closed on the ledger with
// some reveals); no review flags a defect unless a human approved the merge;
// no finding is open. The merge itself still waits for mergeReadiness.
export function readyForPullRequest(state: CommonsState, s: SubmissionState): boolean {
  if (s.merged || submissionDead(state, s.id)) return false;
  if (s.gates.some((g) => !g.pass)) return false;
  if (!s.gates.some((g) => g.gate !== "patch" && g.gate !== SOURCE_GATE)) return false; // "patch": coordinator.ts BINDING_GATE
  const a = s.assignment;
  if (a === undefined) return false;
  const revealed = a.reviewers.filter((r) => s.reviews.some((v) => v.reviewer === r && v.verdict !== undefined));
  if (revealed.length === 0 || (revealed.length < a.reviewers.length && !s.windowClosed)) return false;
  if (!s.approval && s.reviews.some((r) => r.verdict !== undefined && r.verdict.defectProbability >= CATCH_THRESHOLD)) return false;
  return s.findingIds.every((fid) => {
    const f = state.findings.get(fid);
    if (f === undefined) return true;
    const st = findingStatus(f);
    return st === "notReproduced" || st === "dismissed";
  });
}

// One pass over the verified sources: opens a pull request for what gates
// and reviewers accepted, re-reads open ones and closes any whose branch
// moved off the verified commit, and comments (and closes) what merged or
// died since. Problems are said once. A token that may not do this (403, or
// 401/404 on a write) is said once and turns the sync off for offMs: the
// rest of the coordinator goes on.
export function pullRequestSync(o: PullRequestSyncOptions): PullRequestSync {
  const base = o.base ?? "dev";
  const maxWrites = o.maxWritesPerPass ?? 10;
  const recheckMs = o.recheckMs ?? 5 * 60_000;
  const offMs = o.offMs ?? 3_600_000;
  const now = o.now ?? Date.now;
  const { owner, name } = o.target;
  let offUntil = 0;
  const said = new Set<string>();
  const readAt = new Map<number, number>();
  return {
    pass: async (state) => {
      const report: PullRequestReport = { lines: [], problems: [] };
      if (now() < offUntil) return report;
      const once = (key: string, line: string) => {
        if (said.has(key)) return;
        if (said.size > 1000) said.clear();
        said.add(key);
        report.problems.push(line);
      };
      let writes = 0;
      const close = async (s: SubmissionState, pr: PullRequestRecord, headSha: string, comment: string, line: string) => {
        writes += 2;
        await o.github.commentOnPullRequest(owner, name, pr.number, comment);
        await o.github.closePullRequest(owner, name, pr.number);
        writePullRequestRecord(o.patchesDir, s.id, { ...pr, headSha, outcome: "closed" });
        report.lines.push(line);
      };
      const subs = [...state.submissions.values()].sort((a, b) => a.submittedSeq - b.submittedSeq);
      for (const s of subs) {
        if (writes >= maxWrites) break;
        const src = sourceOf(s);
        if (src === null) continue;
        const pr = readPullRequestRecord(o.patchesDir, s.id);
        const dead = submissionDead(state, s.id);
        try {
          if (pr === null) {
            // Not before gates and reviewers accepted it; merged or dead
            // before one was opened: none is needed now.
            if (!readyForPullRequest(state, s)) continue;
            const gh = parseGithubRepo(src.repo);
            if (gh === null) continue;
            if (gh.owner.toLowerCase() === owner.toLowerCase() && gh.name.toLowerCase() === name.toLowerCase() && o.allowSameRepoHead !== true) {
              once(`${s.id}\0same-repo`, `no pull request for ${s.id}: its branch is in ${owner}/${name} itself, whose CI would run it with the repository's secrets (serve --same-repo-pull-requests allows it)`);
              continue;
            }
            const tip = await o.branchTip(src);
            if (tip !== src.head) {
              once(`${s.id}\0tip\0${tip ?? ""}`, `no pull request for ${s.id}: ${src.repo} ${src.branch} is at ${tip ?? "(nothing)"}, not the verified ${src.head}`);
              continue;
            }
            writes++;
            const opened = await o.github.openBranchPullRequest({
              owner,
              repo: name,
              base,
              headOwner: gh.owner,
              headRepo: gh.name,
              branch: src.branch,
              title: pullRequestTitle(s),
              body: pullRequestBody(state, s, src),
            });
            const record = { number: opened.number, url: opened.url, headSha: opened.headSha };
            writePullRequestRecord(o.patchesDir, s.id, record);
            readAt.set(opened.number, now());
            report.lines.push(`opened pull request #${opened.number} for ${s.id} from ${src.repo} ${src.branch}`);
            // Moved between the tip check and the open: closed at once.
            if (opened.headSha !== src.head) {
              await close(s, record, opened.headSha, movedComment(s, src, opened.headSha), `closed pull request #${opened.number}: ${s.id}'s branch is at ${opened.headSha}, not the verified ${src.head}`);
            }
            continue;
          }
          if (pr.outcome !== undefined) continue;
          // The fork's owner can move the branch at any time, and GitHub's
          // pull request follows it: read its head again before trusting it.
          if (!s.merged && !dead && now() - (readAt.get(pr.number) ?? 0) < recheckMs) continue;
          const live = await o.github.getPullRequest(owner, name, pr.number);
          readAt.set(pr.number, now());
          const moved = live.headSha !== src.head;
          if (live.state !== "open" && !(s.merged && live.merged && !moved)) {
            // Closed or merged on GitHub by someone else: nothing more to say there.
            writePullRequestRecord(o.patchesDir, s.id, { ...pr, headSha: live.headSha, outcome: live.merged ? "merged" : "closed" });
            if (live.merged && !s.merged) report.problems.push(`pull request #${pr.number} for ${s.id} was merged on GitHub, not by the commons: GitHub's dev now differs from the clone's`);
            else report.lines.push(`pull request #${pr.number} for ${s.id} was ${live.merged ? "merged" : "closed"} on GitHub`);
            continue;
          }
          if (moved) {
            await close(s, pr, live.headSha, movedComment(s, src, live.headSha), `closed pull request #${pr.number}: ${s.id}'s branch moved to ${live.headSha}, off the verified ${src.head}`);
          } else if (s.merged) {
            writes++;
            await o.github.commentOnPullRequest(owner, name, pr.number, mergedComment(s));
            writePullRequestRecord(o.patchesDir, s.id, { ...pr, headSha: live.headSha, outcome: "merged" });
            report.lines.push(`commented on pull request #${pr.number}: ${s.id} merged`);
          } else if (dead) {
            await close(s, pr, live.headSha, closedComment(state, s), `closed pull request #${pr.number}: ${s.id} can no longer merge`);
          }
        } catch (e) {
          const status = e instanceof GitHubError ? e.status : 0;
          const msg = (e instanceof Error ? e.message : String(e)).slice(0, 300);
          const limited = e instanceof GitHubError && e.info.rateLimited === true;
          if (!limited && (status === 401 || status === 403 || status === 404)) {
            offUntil = now() + offMs;
            const wants = e instanceof GitHubError && e.info.acceptedPermissions ? ` (GitHub wants: ${e.info.acceptedPermissions})` : "";
            report.problems.push(
              `cannot open or comment on pull requests in ${owner}/${name}: the token needs Pull requests read and write there${wants}; pull requests are off for ${Math.round(offMs / 60_000)} min, everything else goes on (${msg})`,
            );
            return report;
          }
          if (limited) {
            once("rate-limited", `GitHub's rate limit stops pull requests for now; tried again next pass`);
            return report;
          }
          once(`${s.id}\0${msg}`, `pull request for ${s.id}: ${msg}; tried again every pass`);
        }
      }
      return report;
    },
  };
}
