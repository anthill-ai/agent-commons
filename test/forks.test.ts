// Fork sources (src/forks.ts): an agent pushes its head commit to its owner's
// fork and registers the branch; the coordinator fetches it with a hardened
// git, checks it is the reviewed change, merges that very commit, and opens
// and closes pull requests on GitHub. No network: local bare repositories
// stand in for GitHub's target and forks, a local http server for a slow
// one, and an injected fetch for GitHub's REST API.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";
import { main as agentMain, pushRefProblem } from "../agent-kit/commons-agent";
import { bindPatchLocal, localGitBridge } from "../src/cli";
import { commonsCommit } from "../src/client";
import { MergeConflictError } from "../src/coordinator";
import { generateKeyPair, keyIdOf, sign } from "../src/crypto";

type KeyPair = ReturnType<typeof generateKeyPair>;
import {
  canonicalGithubRepo,
  forkChecker,
  parseGithubRepo,
  pullRequestSync,
  readPullRequestRecord,
  SOURCE_GATE,
  sourceBranch,
  sourceDetails,
  sourceFile,
  sourceMessage,
  sourceProblems,
  sourceRef,
  SourceUnavailable,
  storedSourceBytes,
  verifySourceLocal,
  type SourceKind,
} from "../src/forks";
import { createGitHub, type FetchLike } from "../src/github";
import { gitServer } from "../src/gitHost";
import { Ledger } from "../src/ledger";
import { githubMirror } from "../src/mirror";
import { defaultRules } from "../src/rules";
import { createCoordinatorServer, patchFile, type CoordinatorServer } from "../src/server";
import type { CommonsState, SubmissionState } from "../src/types";

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "forks-"));
  dirs.push(d);
  return d;
};
const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", "-c", "commit.gpgSign=false", ...args], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  })
    .toString()
    .trim();

// GitHub, locally: <gh>/<owner>/<name>.git. The target anthill-ai/agent-commons,
// alice's fork of it, the coordinator's clone (with dev) and an agent's checkout.
function world() {
  const dir = tmp();
  const gh = path.join(dir, "gh");
  const bare = (owner: string, name: string) => path.join(gh, owner, `${name}.git`);
  const seed = path.join(dir, "seed");
  fs.mkdirSync(path.join(seed, "src"), { recursive: true });
  git(seed, "init", "-q");
  fs.writeFileSync(path.join(seed, "src", "x.ts"), "export const a = 1;\nexport const b = 2;\n");
  fs.writeFileSync(path.join(seed, "src", "y.ts"), "export const y = 1;\n");
  git(seed, "add", ".");
  git(seed, "commit", "-qm", "base");
  const target = bare("anthill-ai", "agent-commons");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  git(dir, "clone", "-q", "--bare", seed, target);
  const fork = bare("alice", "agent-commons");
  fs.mkdirSync(path.dirname(fork), { recursive: true });
  git(dir, "clone", "-q", "--bare", target, fork);
  const clone = path.join(dir, "clone");
  git(dir, "clone", "-q", target, clone);
  git(clone, "branch", "dev");
  const work = path.join(dir, "work");
  git(dir, "clone", "-q", target, work);
  const base = git(clone, "rev-parse", "main");
  // The change: one line of src/x.ts, as `git diff` writes it.
  fs.writeFileSync(path.join(work, "src", "x.ts"), "export const a = 1;\nexport const b = 3;\n");
  const patch = `${git(work, "diff")}\n`;
  git(work, "checkout", "--", ".");
  const patchesDir = path.join(dir, "patches");
  fs.mkdirSync(patchesDir, { recursive: true });
  return {
    dir,
    gh,
    target,
    fork,
    clone,
    work,
    base,
    patch,
    patchesDir,
    bare,
    cloneUrl: (owner: string, name: string) => `file://${bare(owner, name)}`,
  };
}
type World = ReturnType<typeof world>;

const agent = generateKeyPair();
const AGENT = keyIdOf(agent.publicKey);
const FORK_URL = "https://github.com/alice/agent-commons";
const TARGET_URL = "https://github.com/anthill-ai/agent-commons";

function submission(w: World, sid: string, head: string, over: Partial<SubmissionState> = {}): SubmissionState {
  return {
    id: sid,
    author: AGENT,
    taskId: null,
    baseCommit: w.base,
    headCommit: head,
    changedFiles: ["src/x.ts"],
    linesChanged: 2,
    submittedSeq: 7,
    submittedAt: new Date().toISOString(),
    gates: [],
    reviews: [],
    findingIds: [],
    ...over,
  };
}

function register(w: World, sid: string, repo = FORK_URL, branch = sourceBranch(AGENT, sid), key: KeyPair = agent): void {
  const file = sourceFile(w.patchesDir, sid);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const signature = sign(key.privateKey, sourceMessage({ submissionId: sid, repo, branch }));
  fs.writeFileSync(file, storedSourceBytes({ submissionId: sid, repo, branch, agent: AGENT, signature }));
}

// The agent's commons commit, pushed to its fork's branch; the bound head the
// coordinator builds from the same patch (the same sha).
function pushed(w: World, sid: string): { head: string; bound: string } {
  const { head } = commonsCommit({ repoDir: w.work, baseCommit: w.base, patch: w.patch, submissionId: sid });
  git(w.work, "push", "-q", w.fork, `${head}:refs/heads/${sourceBranch(AGENT, sid)}`);
  const bound = commonsCommit({ repoDir: w.clone, baseCommit: w.base, patch: w.patch, submissionId: sid }).head;
  return { head, bound };
}

// A commit in the agent's checkout: `files` written on `parent`.
function commitOn(w: World, parent: string, files: Record<string, string>): string {
  git(w.work, "checkout", "-q", "--detach", parent);
  for (const [f, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(w.work, f)), { recursive: true });
    fs.writeFileSync(path.join(w.work, f), text);
  }
  git(w.work, "add", ".");
  git(w.work, "commit", "-qm", "other");
  return git(w.work, "rev-parse", "HEAD");
}

const fork: () => Promise<SourceKind> = async () => ({ kind: "fork" });
const verify = (w: World, s: SubmissionState, bound: string, extra: Partial<Parameters<typeof verifySourceLocal>[0]> = {}) =>
  verifySourceLocal({ repo: w.clone, patchesDir: w.patchesDir, classify: fork, cloneUrl: w.cloneUrl, fetch: { protocols: ["file"] }, ...extra }, s, bound);

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

test("sources: one spelling of a GitHub repository, and the branch is exactly agents/<author>/<id>", () => {
  assert.deepEqual(parseGithubRepo(FORK_URL), { owner: "alice", name: "agent-commons" });
  for (const bad of [
    "https://github.com/alice/agent-commons.git",
    "https://github.com/alice/agent-commons/",
    "http://github.com/alice/agent-commons",
    "https://gitlab.com/alice/agent-commons",
    "https://github.com.evil.example/alice/agent-commons",
    "https://user@github.com/alice/agent-commons",
    "https://github.com/alice",
    "https://github.com/alice/..",
    "file:///tmp/x.git",
    "git@github.com:alice/agent-commons.git",
  ]) {
    assert.equal(parseGithubRepo(bad), null, bad);
  }
  assert.equal(canonicalGithubRepo(" https://github.com/alice/agent-commons.git/ "), FORK_URL);
  assert.equal(canonicalGithubRepo("https://gitlab.com/a/b"), null);
  const s = { id: "s-0123456789abcdef", author: AGENT };
  const ok = { submissionId: s.id, repo: FORK_URL, branch: sourceBranch(AGENT, s.id) };
  assert.deepEqual(sourceProblems(ok, s), []);
  assert.match(sourceProblems({ ...ok, branch: "dev" }, s).join(), /branch must be agents\//);
  assert.match(sourceProblems({ ...ok, branch: `agents/${"0".repeat(32)}/${s.id}` }, s).join(), /branch must be/, "another agent's branch");
  assert.match(sourceProblems({ ...ok, repo: "https://gitlab.com/a/b" }, s).join(), /repo must be/);
  assert.match(sourceProblems({ ...ok, submissionId: "s-other" }, s).join(), /another submission/);
  // The message is its own domain and names the submission.
  assert.match(sourceMessage(ok), /"purpose":"commons-source\/v1"/);
  assert.notEqual(sourceMessage(ok), sourceMessage({ ...ok, submissionId: "s-other" }));
});

// ---------------------------------------------------------------------------
// Registration on the server
// ---------------------------------------------------------------------------

type Coord = { url: string; dir: string; patchesDir: string; ledgerPath: string; server: CoordinatorServer; coord: KeyPair; close: () => Promise<void> };

async function coordinator(opts: { sources?: boolean; submissions?: { id: string; base: string; head: string }[]; dead?: string[] } = {}): Promise<Coord> {
  const dir = tmp();
  const ledgerPath = path.join(dir, "ledger.jsonl");
  const patchesDir = path.join(dir, "patches");
  const admin = generateKeyPair();
  const coord = generateKeyPair();
  const alice = generateKeyPair();
  let t = Date.now() - 60_000;
  const at = () => new Date((t += 10)).toISOString();
  const ledger = Ledger.create(ledgerPath, { kind: "genesis", project: "demo", admins: [admin.publicKey], coordinator: coord.publicKey, rules: defaultRules() }, at());
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: alice.publicKey, inviter: null }, admin, at());
  ledger.append({ kind: "agentRegistered", owner: "alice", publicKey: agent.publicKey, modelFamily: "claude", harness: "cli" }, alice, at());
  for (const s of opts.submissions ?? []) {
    ledger.append({ kind: "submission", id: s.id, taskId: null, baseCommit: s.base, headCommit: s.head, changedFiles: ["src/x.ts"], linesChanged: 2 }, agent, at());
  }
  for (const sid of opts.dead ?? []) ledger.append({ kind: "gateResult", submissionId: sid, gate: "size", pass: false, details: "too big" }, coord, at());
  const server = createCoordinatorServer({
    ledgerPath,
    coordinatorKey: coord,
    clock: () => new Date().toISOString(),
    patchesDir,
    policy: { submitCredits: () => 5, prSlots: () => 5, claimStake: () => 1 },
    sources: opts.sources ?? true,
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, dir, patchesDir, ledgerPath, server, coord, close: () => new Promise((r) => server.close(() => r())) };
}

async function postSource(c: Coord, sid: string, body: unknown, key: KeyPair = agent, signed?: { submissionId: string; repo: string; branch: string }) {
  const b = body as { repo: string; branch: string };
  const msg = sourceMessage(signed ?? { submissionId: sid, repo: b.repo, branch: b.branch });
  const r = await fetch(`${c.url}/api/sources/${sid}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-commons-key": key.publicKey, "x-commons-sig": sign(key.privateKey, msg) },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

test("source registration: only the author, over this submission's message, once; a captured one is good for nothing else", async () => {
  const sha = (c: string) => c.repeat(40);
  const c = await coordinator({
    submissions: [
      { id: "s-one", base: sha("a"), head: sha("b") },
      { id: "s-two", base: sha("a"), head: sha("c") },
      { id: "s-dead", base: sha("a"), head: sha("d") },
    ],
    dead: ["s-dead"],
  });
  try {
    const good = { repo: FORK_URL, branch: sourceBranch(AGENT, "s-one") };
    // Not the author's key: refused before the body is read.
    const stranger = generateKeyPair();
    assert.equal((await postSource(c, "s-one", good, stranger)).status, 403);
    // The author's key over another submission's message (a captured signature).
    const other = await postSource(c, "s-one", good, agent, { submissionId: "s-two", repo: good.repo, branch: good.branch });
    assert.deepEqual([other.status, other.body.error], [401, "signature"]);
    // Over a different repo than the body says.
    const swapped = await postSource(c, "s-one", good, agent, { submissionId: "s-one", repo: "https://github.com/mallory/agent-commons", branch: good.branch });
    assert.deepEqual([swapped.status, swapped.body.error], [401, "signature"]);
    // Bad shapes are refused with the reason.
    for (const [body, why] of [
      [{ repo: "https://gitlab.com/alice/agent-commons", branch: good.branch }, /repo must be/],
      [{ repo: TARGET_URL, branch: "dev" }, /branch must be agents\//],
      [{ repo: FORK_URL, branch: "main" }, /branch must be agents\//],
      [{ repo: FORK_URL, branch: sourceBranch(AGENT, "s-two") }, /branch must be/],
    ] as const) {
      const r = await postSource(c, "s-one", body);
      assert.equal(r.status, 400, JSON.stringify(body));
      assert.match(String(r.body.message), why);
    }
    const extra = await postSource(c, "s-one", { ...good, sha: "x" });
    assert.deepEqual([extra.status, extra.body.error], [400, "malformed"]);
    // The real one, then the same again (a retry, or a replay): stored once.
    const first = await postSource(c, "s-one", good);
    assert.deepEqual([first.status, first.body.created], [201, true]);
    const again = await postSource(c, "s-one", good);
    assert.deepEqual([again.status, again.body.created], [201, false]);
    // Another source for the same submission: refused.
    const moved = await postSource(c, "s-one", { repo: TARGET_URL, branch: good.branch });
    assert.deepEqual([moved.status, moved.body.error], [409, "exists"]);
    // A closed submission takes none; an unknown one is a 404.
    assert.deepEqual((await postSource(c, "s-dead", { repo: FORK_URL, branch: sourceBranch(AGENT, "s-dead") })).body.error, "closed");
    assert.equal((await postSource(c, "s-nope", good)).status, 404);
    // GET shows it, with no verdict yet.
    const got = (await (await fetch(`${c.url}/api/sources/s-one`)).json()) as Record<string, unknown>;
    assert.deepEqual(got, { submissionId: "s-one", repo: FORK_URL, branch: good.branch, agent: AGENT, check: null, pullRequest: null });
    assert.equal((await fetch(`${c.url}/api/sources/s-two`)).status, 404);
  } finally {
    await c.close();
  }
  const off = await coordinator({ sources: false, submissions: [{ id: "s-one", base: sha("a"), head: sha("b") }] });
  try {
    const r = await postSource(off, "s-one", { repo: FORK_URL, branch: sourceBranch(AGENT, "s-one") });
    assert.deepEqual([r.status, r.body.error], [404, "no-sources"]);
    assert.equal(fs.existsSync(path.join(off.patchesDir, "sources")), false);
  } finally {
    await off.close();
  }
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

test("verify: the fork's branch at the signed head, one commit on the base with the patch's tree, passes; the commit lands on a private ref", async () => {
  const w = world();
  const sid = "s-good";
  const { head, bound } = pushed(w, sid);
  assert.equal(head, bound, "the commons commit is the same sha anywhere");
  register(w, sid);
  const v = await verify(w, submission(w, sid, head), bound);
  assert.deepEqual(v, { repo: FORK_URL, branch: sourceBranch(AGENT, sid), head });
  assert.equal(git(w.clone, "rev-parse", sourceRef(sid)), head);
  // Nothing else of the fork is fetched: no branch, no tag, no FETCH_HEAD.
  assert.equal(git(w.clone, "for-each-ref", "--format=%(refname)", "refs/remotes", "refs/tags").split("\n").filter((r) => r.includes("agents")).length, 0);
  assert.equal(fs.existsSync(path.join(w.clone, ".git", "FETCH_HEAD")), false);
  // No registration: nothing to verify.
  assert.equal(await verify(w, submission(w, "s-none", head), bound), null);
});

test("verify refuses: a tip that is not the signed head, a missing branch, a head not one commit on the base, a different change, a non-fork, a bad registration", async () => {
  const w = world();

  // The branch holds another commit than the signed head.
  const a = pushed(w, "s-tip");
  register(w, "s-tip");
  const other = commitOn(w, w.base, { "src/x.ts": "export const a = 9;\n" });
  const tipped = await verify(w, submission(w, "s-tip", other), a.bound);
  assert.match((tipped as { error: string }).error, /the branch is at [0-9a-f]{40}, not the signed headCommit/);

  // Registered, never pushed.
  register(w, "s-missing");
  const missing = await verify(w, submission(w, "s-missing", a.head), a.bound);
  assert.match((missing as { error: string }).error, /the branch is not there/);

  // The signed head is on the branch, but it is not one commit on the base.
  const child = commitOn(w, w.base, { "src/y.ts": "export const y = 2;\n" });
  const boundTree = git(w.clone, "rev-parse", `${a.bound}^{tree}`);
  git(w.work, "fetch", "-q", w.clone, `${a.bound}:refs/tmp/bound`);
  const grand = git(w.work, "commit-tree", boundTree, "-p", child, "-m", "two commits");
  git(w.work, "push", "-q", w.fork, `${grand}:refs/heads/${sourceBranch(AGENT, "s-deep")}`);
  register(w, "s-deep");
  const deep = await verify(w, submission(w, "s-deep", grand), a.bound);
  assert.match((deep as { error: string }).error, /parents are [0-9a-f]{40}; it must be one commit whose only parent is baseCommit/);
  assert.equal(spawnSync("git", ["rev-parse", "--verify", "--quiet", sourceRef("s-deep")], { cwd: w.clone }).status, 1, "a refused source keeps no ref");
  const orphan = git(w.work, "commit-tree", boundTree, "-m", "no parent");
  git(w.work, "push", "-q", w.fork, `${orphan}:refs/heads/${sourceBranch(AGENT, "s-orphan")}`);
  register(w, "s-orphan");
  assert.match(((await verify(w, submission(w, "s-orphan", orphan), a.bound)) as { error: string }).error, /parents are \(none\)/);

  // One commit on the base, but not the uploaded diff's change.
  const wrong = commitOn(w, w.base, { "src/x.ts": "export const a = 1;\nexport const b = 4;\n" });
  git(w.work, "push", "-q", w.fork, `${wrong}:refs/heads/${sourceBranch(AGENT, "s-diff")}`);
  register(w, "s-diff");
  const diff = await verify(w, submission(w, "s-diff", wrong), a.bound);
  assert.match((diff as { error: string }).error, /the commit's tree [0-9a-f]{40} is not the tree the uploaded patch makes/);

  // Not a fork of the target: refused before any git runs.
  const b = pushed(w, "s-stranger");
  register(w, "s-stranger");
  const notFork = await verify(w, submission(w, "s-stranger", b.head), b.bound, {
    classify: async () => ({ kind: "other", reason: "alice/agent-commons is not a fork of anthill-ai/agent-commons" }),
    cloneUrl: () => {
      throw new Error("must not be fetched");
    },
  });
  assert.match((notFork as { error: string }).error, /is not a fork of anthill-ai\/agent-commons: a source must be a fork of the target, or the target itself/);

  // A registration file that is not acceptable (written around the server).
  register(w, "s-branch", TARGET_URL, "dev");
  assert.match(((await verify(w, submission(w, "s-branch", b.head), b.bound)) as { error: string }).error, /branch must be agents\//);
  register(w, "s-url", "https://gitlab.com/alice/agent-commons");
  assert.match(((await verify(w, submission(w, "s-url", b.head), b.bound)) as { error: string }).error, /repo must be/);

  // A missing or private repository (git cannot read it without credentials).
  register(w, "s-gone", "https://github.com/nobody/agent-commons");
  assert.match(((await verify(w, submission(w, "s-gone", b.head), b.bound)) as { error: string }).error, /cannot be read without credentials/);

  // Only the schemes allowed: a file: URL is refused unless the test allows it.
  register(w, "s-scheme");
  git(w.work, "push", "-q", w.fork, `${b.head}:refs/heads/${sourceBranch(AGENT, "s-scheme")}`);
  await assert.rejects(verify(w, submission(w, "s-scheme", b.head), b.bound, { fetch: { protocols: ["https"] } }), /cannot read/);
});

test("verify: an oversized fetch is cut off by the size limit (no ref, no leftover pack), a fork that stalls by the time limit", async () => {
  const w = world();
  const big = commitOn(w, w.base, { "src/big.txt": randomBytes(1_500_000).toString("base64") });
  git(w.work, "push", "-q", w.fork, `${big}:refs/heads/${sourceBranch(AGENT, "s-big")}`);
  register(w, "s-big");
  const bound = pushed(w, "s-unused").bound;
  const r = await verify(w, submission(w, "s-big", big), bound, { fetch: { protocols: ["file"], maxBytes: 64 * 1024 } });
  assert.match((r as { error: string }).error, /fetching would write more than 65536 bytes/);
  assert.equal(spawnSync("git", ["rev-parse", "--verify", "--quiet", sourceRef("s-big")], { cwd: w.clone }).status, 1);
  assert.deepEqual(fs.readdirSync(path.join(w.clone, ".git", "objects", "pack")).filter((n) => n.startsWith("tmp_")), []);
  assert.notEqual(spawnSync("git", ["cat-file", "-e", big], { cwd: w.clone }).status, 0, "none of its objects were kept");

  // A fork that answers the ref listing, then never sends the pack.
  const { head } = pushed(w, "s-slow");
  register(w, "s-slow");
  const serve = gitServer({ repo: w.fork, refs: [`refs/heads/${sourceBranch(AGENT, "s-slow")}`] });
  let adverts = 0;
  const hung: http.ServerResponse[] = [];
  const server = http.createServer((req, res) => {
    if ((req.url ?? "").includes("/info/refs") && ++adverts >= 2) {
      hung.push(res);
      return; // the fetch's own listing: never answered
    }
    serve(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const port = (server.address() as AddressInfo).port;
    const started = Date.now();
    const slow = await verify(w, submission(w, "s-slow", head), head, {
      cloneUrl: () => `http://127.0.0.1:${port}/api/git`,
      fetch: { protocols: ["http"], timeoutMs: 1500 },
    });
    assert.match((slow as { error: string }).error, /fetching took longer than 2 s/);
    assert.ok(Date.now() - started < 10_000);
    assert.equal(spawnSync("git", ["rev-parse", "--verify", "--quiet", sourceRef("s-slow")], { cwd: w.clone }).status, 1);
  } finally {
    for (const res of hung) res.destroy();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("verify: the fetch never carries a token or the clone's headers, and runs no hook", async () => {
  const w = world();
  const { head, bound } = pushed(w, "s-env");
  register(w, "s-env");
  // A header the clone's own config would send, and a hook that would run.
  git(w.clone, "config", "http.extraHeader", "Authorization: Basic c2VjcmV0");
  fs.writeFileSync(path.join(w.clone, ".git", "hooks", "reference-transaction"), "#!/bin/sh\ntouch \"$GIT_DIR/hook-ran\"\n", { mode: 0o755 });
  // A fake git first on PATH records the environment and arguments it was given.
  const bin = path.join(w.dir, "bin");
  fs.mkdirSync(bin);
  const real = execFileSync("bash", ["-c", "command -v git"]).toString().trim();
  const log = path.join(w.dir, "git.log");
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\n{ env; echo "ARGS $*"; } >> "${log}"\nexec "${real}" "$@"\n`, { mode: 0o755 });
  const saved = { PATH: process.env.PATH, COMMONS_GITHUB_TOKEN: process.env.COMMONS_GITHUB_TOKEN, GIT_CONFIG_PARAMETERS: process.env.GIT_CONFIG_PARAMETERS };
  process.env.PATH = `${bin}:${process.env.PATH}`;
  process.env.COMMONS_GITHUB_TOKEN = "github_pat_TESTONLY_never_sent";
  process.env.GIT_CONFIG_PARAMETERS = "'http.extraheader=Authorization: Bearer leak'";
  try {
    assert.ok(!("error" in ((await verify(w, submission(w, "s-env", head), bound)) ?? { error: "null" })));
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  const text = fs.readFileSync(log, "utf8");
  assert.ok(!text.includes("TESTONLY") && !text.includes("leak"), "no token, no inherited config");
  for (const want of ["GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_PROTOCOL_FROM_USER=0"]) assert.ok(text.includes(want), want);
  for (const want of ["credential.helper=", "http.extraHeader=", "protocol.allow=never", "http.followRedirects=false", "transfer.fsckObjects=true", "core.hooksPath=/dev/null", "--no-write-fetch-head"]) {
    assert.ok(text.includes(want), want);
  }
  assert.equal(fs.existsSync(path.join(w.clone, ".git", "hook-ran")), false);
});

// ---------------------------------------------------------------------------
// Is it a fork? GitHub REST through an injected fetch.
// ---------------------------------------------------------------------------

type Call = { method: string; url: string; headers: Record<string, string>; body?: string };
type Reply = { status: number; body?: unknown; headers?: Record<string, string> };
function fakeGitHub(handler: (c: Call) => Reply) {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    const c: Call = { method: init.method, url, headers: init.headers, ...(init.body === undefined ? {} : { body: init.body }) };
    calls.push(c);
    const r = handler(c);
    const headers = new Map(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return { status: r.status, headers: { get: (n: string) => headers.get(n.toLowerCase()) ?? null }, text: async () => (r.body === undefined ? "" : JSON.stringify(r.body)) };
  };
  return { fetch, calls };
}

test("fork check: by GitHub's repository id, following the target's move; forks of forks count; unauthenticated; definite verdicts cached, outages thrown", async () => {
  const TARGET_ID = 1453295182;
  const repo = (id: number, fullName: string, over: Record<string, unknown> = {}) => ({ id, full_name: fullName, fork: false, ...over });
  let limited = false;
  const gh = fakeGitHub((c): Reply => {
    const p = c.url.replace("https://api.github.com", "");
    if (limited) return { status: 403, body: { message: "API rate limit exceeded" }, headers: { "x-ratelimit-remaining": "0" } };
    if (p === "/repos/kelemeno/agent-commons") return { status: 301, headers: { location: `https://api.github.com/repositories/${TARGET_ID}` } };
    if (p === `/repositories/${TARGET_ID}`) return { status: 200, body: repo(TARGET_ID, "anthill-ai/agent-commons") };
    if (p === "/repos/alice/agent-commons") return { status: 200, body: repo(7, "alice/agent-commons", { fork: true, parent: { id: TARGET_ID, full_name: "anthill-ai/agent-commons" }, source: { id: TARGET_ID, full_name: "anthill-ai/agent-commons" } }) };
    if (p === "/repos/carol/agent-commons") return { status: 200, body: repo(8, "carol/agent-commons", { fork: true, parent: { id: 7, full_name: "alice/agent-commons" }, source: { id: TARGET_ID, full_name: "anthill-ai/agent-commons" } }) };
    if (p === "/repos/mallory/agent-commons") return { status: 200, body: repo(9, "mallory/agent-commons", { fork: true, parent: { id: 99, full_name: "other/thing" }, source: { id: 99, full_name: "other/thing" } }) };
    if (p === "/repos/mallory/copy") return { status: 200, body: repo(10, "mallory/copy") };
    if (p === "/repos/kelemeno/renamed-old") return { status: 301, headers: { location: `https://api.github.com/repositories/${TARGET_ID}` } };
    if (p === "/repos/evil/redirect") return { status: 301, headers: { location: "https://evil.example/repositories/1" } };
    return { status: 404, body: { message: "Not Found" } };
  });
  let clock = 0;
  const check = forkChecker({ target: { owner: "kelemeno", name: "agent-commons" }, github: createGitHub({ token: "", anonymous: true, fetch: gh.fetch }), now: () => clock });
  assert.deepEqual(await check("alice", "agent-commons"), { kind: "fork" });
  assert.ok(gh.calls.every((c) => c.headers.Authorization === undefined && c.method === "GET"), "unauthenticated reads");
  assert.deepEqual(await check("carol", "agent-commons"), { kind: "fork" }, "a fork of a fork: its network's root is the target");
  assert.deepEqual(await check("Anthill-AI", "Agent-Commons"), { kind: "target" }, "the target by its current name");
  assert.deepEqual(await check("kelemeno", "renamed-old"), { kind: "target" }, "the target by an old name GitHub redirects");
  assert.match(JSON.stringify(await check("mallory", "agent-commons")), /is not a fork of anthill-ai\/agent-commons/);
  assert.match(JSON.stringify(await check("mallory", "copy")), /is not a fork/);
  assert.match(JSON.stringify(await check("nobody", "x")), /not a public repository/);
  await assert.rejects(check("evil", "redirect"), SourceUnavailable, "a redirect off the API host is not followed");
  const n = gh.calls.length;
  assert.deepEqual(await check("alice", "agent-commons"), { kind: "fork" });
  assert.equal(gh.calls.length, n, "cached");
  // An outage or the rate limit: thrown (retried next pass), never cached.
  limited = true;
  await assert.rejects(check("dave", "agent-commons"), SourceUnavailable);
  clock += 2 * 3_600_000;
  await assert.rejects(check("alice", "agent-commons"), /rate limit/);
  limited = false;
  assert.deepEqual(await check("alice", "agent-commons"), { kind: "fork" });
});

// ---------------------------------------------------------------------------
// Merge: the agent's own commit, reachable from GitHub's dev after the mirror
// ---------------------------------------------------------------------------

test("merge: the verified commit itself lands with a merge commit naming the submission; the mirror's push makes the PR head reachable from GitHub's dev; a conflicting dev is refused, never forced", async () => {
  const w = world();
  const sid = "s-merge";
  const { head } = commonsCommit({ repoDir: w.work, baseCommit: w.base, patch: w.patch, submissionId: sid });
  git(w.work, "push", "-q", w.fork, `${head}:refs/heads/${sourceBranch(AGENT, sid)}`);
  fs.writeFileSync(patchFile(w.patchesDir, sid), w.patch);
  const s = submission(w, sid, head);
  const b = bindPatchLocal(w.clone, w.patchesDir, s, "refs/heads/dev");
  assert.ok(b !== null && !("error" in b), JSON.stringify(b));
  register(w, sid);
  const v = await verify(w, s, b.head);
  assert.ok(v !== null && !("error" in v), JSON.stringify(v));
  const verified = { ...s, gates: [{ gate: SOURCE_GATE, pass: true, details: sourceDetails(v) }] };

  // dev moved since the base (another merge): a merge commit, both parents kept.
  git(w.clone, "checkout", "-q", "dev");
  fs.writeFileSync(path.join(w.clone, "src", "y.ts"), "export const y = 5;\n");
  git(w.clone, "commit", "-qam", "another merge");
  const devBefore = git(w.clone, "rev-parse", "dev");
  git(w.clone, "checkout", "-q", "--detach");
  const bridge = localGitBridge(w.clone, "refs/heads/dev");
  const merged = await bridge.merge({ ...verified, headCommit: v.head }, v.head, { mergeCommit: true });
  assert.equal(git(w.clone, "rev-parse", "dev"), merged);
  assert.equal(git(w.clone, "rev-list", "--parents", "-n", "1", merged), `${merged} ${devBefore} ${head}`, "the agent's commit is the second parent, not a re-applied diff");
  assert.equal(git(w.clone, "log", "-1", "--format=%s", merged), `commons: merge ${sid}`);
  assert.equal(await bridge.merge({ ...verified, headCommit: v.head }, v.head, { mergeCommit: true }), merged, "idempotent");

  // The mirror pushes dev; GitHub's dev now holds the PR's head commit.
  const mirror = githubMirror({ repo: w.clone, url: `file://${w.target}`, token: "github_pat_TESTONLY" });
  const r = await mirror.pass();
  assert.ok(r.pushed.some((p) => p.ref === "refs/heads/dev" && p.sha === merged), JSON.stringify(r));
  assert.equal(spawnSync("git", ["merge-base", "--is-ancestor", head, "refs/heads/dev"], { cwd: w.target }).status, 0);
  assert.equal(git(w.fork, "rev-parse", `refs/heads/${sourceBranch(AGENT, sid)}`), head, "the fork's branch was never touched");

  // With dev at the base, a fast-forward is possible, but a merge commit is still made.
  const w2 = world();
  const p2 = pushed(w2, "s-ff");
  const ff = await localGitBridge(w2.clone, "refs/heads/dev").merge({ ...submission(w2, "s-ff", p2.head) }, p2.head, { mergeCommit: true });
  assert.equal(git(w2.clone, "rev-list", "--parents", "-n", "1", ff), `${ff} ${w2.base} ${p2.head}`);
  // Without the option (no source) the old fast-forward is unchanged.
  const w3 = world();
  const p3 = pushed(w3, "s-plain");
  assert.equal(await localGitBridge(w3.clone, "refs/heads/dev").merge(submission(w3, "s-plain", p3.head), p3.head), p3.head);

  // A dev that conflicts: refused as today; dev stays.
  const w4 = world();
  const p4 = pushed(w4, "s-conflict");
  git(w4.clone, "checkout", "-q", "dev");
  fs.writeFileSync(path.join(w4.clone, "src", "x.ts"), "export const a = 1;\nexport const b = 7;\n");
  git(w4.clone, "commit", "-qam", "conflicting");
  const tip = git(w4.clone, "rev-parse", "dev");
  await assert.rejects(localGitBridge(w4.clone, "refs/heads/dev").merge(submission(w4, "s-conflict", p4.head), p4.head, { mergeCommit: true }), MergeConflictError);
  assert.equal(git(w4.clone, "rev-parse", "dev"), tip);
});

// ---------------------------------------------------------------------------
// Pull requests
// ---------------------------------------------------------------------------

function prState(subs: SubmissionState[], extra: { proposalTitle?: string } = {}): CommonsState {
  return {
    submissions: new Map(subs.map((s) => [s.id, s])),
    agents: new Map([[AGENT, { keyId: AGENT, owner: "alice", modelFamily: "claude", harness: "cli", active: true }]]),
    tasks: new Map([["t1", { kind: "task", id: "t1", proposalId: "p1", ring: 1, sizeEstimate: 10, acceptanceTestPaths: [], specAuthor: AGENT, seq: 3 }]]),
    proposals: new Map([["p1", { id: "p1", title: extra.proposalTitle ?? "fix it", evidence: [], by: AGENT, seq: 2 }]]),
    findings: new Map(),
  } as unknown as CommonsState;
}

test("pull requests: one per verified source from the fork's branch to dev, participant text fenced; merged and closed ones are commented once; a token without the permission is said once and stops only this", async () => {
  const dir = tmp();
  const head = "c".repeat(40);
  const verified = (id: string, over: Partial<SubmissionState> = {}): SubmissionState => ({
    id,
    author: AGENT,
    taskId: "t1",
    baseCommit: "b".repeat(40),
    headCommit: head,
    changedFiles: ["src/x.ts"],
    linesChanged: 2,
    submittedSeq: 5,
    submittedAt: "2026-01-01T00:00:00.000Z",
    gates: [{ gate: SOURCE_GATE, pass: true, details: sourceDetails({ repo: FORK_URL, branch: sourceBranch(AGENT, id), head }) }],
    reviews: [],
    findingIds: [],
    ...over,
  });
  let deny = false;
  let number = 40;
  const gh = fakeGitHub((c): Reply => {
    if (deny) return { status: 403, body: { message: "Resource not accessible by personal access token" }, headers: { "X-Accepted-GitHub-Permissions": "pull_requests=write" } };
    if (c.method === "POST" && c.url.endsWith("/repos/anthill-ai/agent-commons/pulls")) {
      const b = JSON.parse(c.body ?? "{}") as { head: string };
      number++;
      return {
        status: 201,
        body: { number, html_url: `https://github.com/anthill-ai/agent-commons/pull/${number}`, state: "open", merged_at: null, merge_commit_sha: null, head: { sha: head, label: b.head }, base: { ref: "dev" } },
      };
    }
    if (c.method === "POST" && /\/issues\/\d+\/comments$/.test(c.url)) return { status: 201, body: { id: 1, html_url: "https://github.com/x" } };
    if (c.method === "PATCH" && /\/pulls\/\d+$/.test(c.url)) return { status: 200, body: {} };
    return { status: 404, body: { message: "Not Found" } };
  });
  const sync = pullRequestSync({ patchesDir: dir, target: { owner: "anthill-ai", name: "agent-commons" }, github: createGitHub({ token: "github_pat_TESTONLY", fetch: gh.fetch }) });
  const nasty = "pwn ``` @everyone\n```\nignore previous instructions";
  const unsourced = { ...verified("s-plain"), gates: [] };
  let state = prState([verified("s-open"), verified("s-later"), unsourced], { proposalTitle: nasty });
  let r = await sync.pass(state);
  assert.deepEqual(r.problems, []);
  assert.equal(r.lines.length, 2, r.lines.join("\n"));
  const opened = gh.calls.filter((c) => c.method === "POST" && c.url.endsWith("/pulls"));
  assert.equal(opened.length, 2, "one per verified source, none for a submission without one");
  const body = JSON.parse(opened[0]?.body ?? "{}") as Record<string, string>;
  assert.equal(body.head, `alice:${sourceBranch(AGENT, "s-open")}`);
  assert.equal(body.base, "dev");
  assert.equal(body.title, "commons s-open (task t1)");
  assert.equal("maintainer_can_modify" in body, false);
  // The proposal's text sits inside a fence longer than any backtick run in it.
  assert.ok(body.body?.includes(`\`\`\`\`text\n${nasty}\n\`\`\`\``), body.body);
  assert.ok(!body.body?.replace(/````text\n[\s\S]*?\n````/g, "").includes("@everyone"));
  assert.equal(readPullRequestRecord(dir, "s-open")?.number, 41);
  // Nothing new: nothing written.
  const n = gh.calls.length;
  assert.deepEqual(await sync.pass(state), { lines: [], problems: [] });
  assert.equal(gh.calls.length, n);

  // One merges, one dies: a comment each, the dead one closed, both once.
  state = prState([
    verified("s-open", { merged: { commit: "d".repeat(40), seq: 30, at: "2026-01-02T00:00:00.000Z" }, reviews: [{ reviewer: "r1", commitment: "x", stake: 5, committedSeq: 9, verdict: { defectProbability: 0.1, summary: "fine `x`", findingIds: [] }, revealedSeq: 10 }] }),
    verified("s-later", { gates: [...verified("s-later").gates, { gate: "size", pass: false, details: "too large: @someone" }] }),
  ]);
  r = await sync.pass(state);
  assert.deepEqual(r.problems, []);
  const comments = gh.calls.slice(n).filter((c) => c.url.includes("/comments"));
  assert.equal(comments.length, 2);
  assert.match(JSON.parse(comments[0]?.body ?? "{}").body as string, /Merged by the commons into `dev` at `d{40}`/);
  assert.match(JSON.parse(comments[1]?.body ?? "{}").body as string, /can no longer merge \(gate size failed\)[\s\S]*```text\nsize: too large: @someone\n```/);
  assert.ok(gh.calls.slice(n).some((c) => c.method === "PATCH" && c.body === JSON.stringify({ state: "closed" })));
  assert.equal(readPullRequestRecord(dir, "s-open")?.outcome, "merged");
  assert.equal(readPullRequestRecord(dir, "s-later")?.outcome, "closed");
  const m = gh.calls.length;
  assert.deepEqual(await sync.pass(state), { lines: [], problems: [] });
  assert.equal(gh.calls.length, m, "commented once");

  // Without the permission: said once, with what GitHub wants; then off.
  deny = true;
  const denied = pullRequestSync({ patchesDir: tmp(), target: { owner: "anthill-ai", name: "agent-commons" }, github: createGitHub({ token: "github_pat_TESTONLY", fetch: gh.fetch }) });
  const fresh = prState([verified("s-a"), verified("s-b")]);
  r = await denied.pass(fresh);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0] as string, /the token needs Pull requests read and write there \(GitHub wants: pull_requests=write\); pull requests are off until restart, everything else goes on/);
  assert.ok(!r.problems[0]?.includes("TESTONLY"));
  const k = gh.calls.length;
  assert.deepEqual(await denied.pass(fresh), { lines: [], problems: [] });
  assert.equal(gh.calls.length, k, "no more requests");

  // GitHub refusing one (422: no dev there yet) is said once and retried.
  deny = false;
  const noDev = fakeGitHub(() => ({ status: 422, body: { message: "Validation Failed", errors: [{ field: "base", code: "invalid" }] } }));
  const retry = pullRequestSync({ patchesDir: tmp(), target: { owner: "anthill-ai", name: "agent-commons" }, github: createGitHub({ token: "t0ken-TESTONLY", fetch: noDev.fetch }) });
  const one = prState([verified("s-a")]);
  assert.equal((await retry.pass(one)).problems.length, 1);
  assert.deepEqual((await retry.pass(one)).problems, [], "said once");
  assert.ok(noDev.calls.filter((c) => c.method === "POST").length >= 2, "tried again");
});

// ---------------------------------------------------------------------------
// The kit
// ---------------------------------------------------------------------------

test("kit: submit --fork pushes the head to agents/<keyId>/<id> (plainly) before posting, then registers it; it refuses shared branches, force and non-GitHub forks", async () => {
  assert.equal(pushRefProblem(`refs/heads/${sourceBranch(AGENT, "s-1")}`), null);
  for (const ref of ["refs/heads/dev", "refs/heads/main", "refs/heads/master", "refs/heads/release", "refs/heads/release/1.0", "refs/heads/dev/x", "refs/tags/v1", "refs/heads/feature", `refs/heads/agents/${AGENT}/../main`]) {
    assert.notEqual(pushRefProblem(ref), null, ref);
  }

  const w = world();
  const keyFile = path.join(w.dir, "agent.json");
  fs.writeFileSync(keyFile, JSON.stringify(agent));
  const patchPath = path.join(w.dir, "change.diff");
  fs.writeFileSync(patchPath, w.patch);
  const c = await coordinator();
  try {
    const outs: string[] = [];
    const errs: string[] = [];
    const io = { out: (s: string) => void outs.push(s), err: (s: string) => void errs.push(s), stdin: () => "" };
    const env = { COMMONS_URL: c.url, COMMONS_KEY_FILE: keyFile, COMMONS_SALT_DIR: path.join(w.dir, "salts") };
    const args = ["submit", "--task", "none", "--base", w.base, "--patch", patchPath, "--repo", w.work];
    // Refused before anything is pushed or posted.
    assert.equal(await agentMain([...args, "--id", "s-f1", "--fork", FORK_URL, "--push-to", w.fork, "--force"], env, io), 2);
    assert.equal(await agentMain([...args, "--id", "s-f1", "--fork", "https://gitlab.com/alice/agent-commons", "--push-to", w.fork], env, io), 2);
    assert.match(errs.join(""), /never forces[\s\S]*--fork must be https:\/\/github\.com/);
    assert.equal(git(w.fork, "for-each-ref", "refs/heads/agents"), "");

    // The push, the submission, the registration.
    assert.equal(await agentMain([...args, "--id", "s-f1", "--fork", `${FORK_URL}.git`, "--push-to", w.fork], env, io), 0, errs.join(""));
    const out = JSON.parse(outs.pop() ?? "{}") as { headCommit: string; source: { repo: string; branch: string; created: boolean } };
    const branch = sourceBranch(AGENT, "s-f1");
    assert.deepEqual(out.source, { repo: FORK_URL, branch, created: true });
    assert.equal(git(w.fork, "rev-parse", `refs/heads/${branch}`), out.headCommit, "the fork's branch holds the signed head");
    assert.equal(git(w.fork, "for-each-ref", "--format=%(refname)", "refs/heads").split("\n").sort().join(","), `refs/heads/${branch},refs/heads/main`, "nothing else pushed");
    const stored = JSON.parse(fs.readFileSync(sourceFile(c.patchesDir, "s-f1"), "utf8")) as Record<string, string>;
    assert.equal(stored.branch, branch);
    assert.ok(fs.existsSync(patchFile(c.patchesDir, "s-f1")), "the diff is still uploaded");

    // A branch already holding another commit: the plain push is refused, nothing posted.
    const other = commitOn(w, w.base, { "src/x.ts": "export const a = 2;\n" });
    git(w.work, "push", "-q", w.fork, `${other}:refs/heads/${sourceBranch(AGENT, "s-f2")}`);
    assert.equal(await agentMain([...args, "--id", "s-f2", "--fork", FORK_URL, "--push-to", w.fork], env, io), 1);
    assert.match(errs.join(""), /pushing the head commit failed[\s\S]*never forces/);
    assert.equal(git(w.fork, "rev-parse", `refs/heads/${sourceBranch(AGENT, "s-f2")}`), other, "not forced over");
    assert.equal(fs.existsSync(patchFile(c.patchesDir, "s-f2")), false, "nothing submitted");

    // COMMONS_FORK and COMMONS_FORK_PUSH do the same; register-source and source read back.
    assert.equal(await agentMain([...args, "--id", "s-f3"], { ...env, COMMONS_FORK: FORK_URL, COMMONS_FORK_PUSH: w.fork }, io), 0, errs.join(""));
    assert.equal(git(w.fork, "rev-parse", `refs/heads/${sourceBranch(AGENT, "s-f3")}`), (JSON.parse(outs.pop() ?? "{}") as { headCommit: string }).headCommit);
    assert.equal(await agentMain(["register-source", "s-f3", "--fork", FORK_URL], env, io), 0);
    assert.equal((JSON.parse(outs.pop() ?? "{}") as { created: boolean }).created, false);
    assert.equal(await agentMain(["source", "s-f3"], env, io), 0);
    assert.deepEqual((JSON.parse(outs.pop() ?? "{}") as { check: unknown }).check, null);

    // Without --fork, submit is what it was: nothing pushed, no source.
    assert.equal(await agentMain([...args, "--id", "s-f4"], env, io), 0, errs.join(""));
    assert.equal((JSON.parse(outs.pop() ?? "{}") as { source?: unknown }).source, undefined);
    assert.equal(fs.existsSync(sourceFile(c.patchesDir, "s-f4")), false);
  } finally {
    await c.close();
  }
});
