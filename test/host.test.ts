import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { ownerMessage, treeMessage, type AnthillTreeSnapshot } from "../src/anthill";
import { normaliseBasePath } from "../src/basePath";
import { main } from "../src/cli";
import { generateKeyPair, keyIdOf, sign } from "../src/crypto";
import { ringOf } from "../src/gates/rings";
import { readHostSettings, targetRepoProblems } from "../src/host";
import { Ledger } from "../src/ledger";
import { commitmentFor } from "../src/review";
import { assignmentBody } from "../src/selection";
import { validateRules } from "../src/rules";
import { startPlayground } from "../src/playground";
import { proxyMatcher } from "../src/server";
import type { Rules } from "../src/types";

// `commons host`: a coordinator that sets itself up on its first start, and
// serving under a base path behind a reverse proxy.

const ROOT = path.resolve(__dirname, "..");
const SIGNER = `0x${"a1".repeat(20)}`;
const SIGNER2 = `0x${"b2".repeat(20)}`;
const SIGNER3 = `0x${"c3".repeat(20)}`;
const FOUNDER = `0x${"0f".repeat(20)}`;
const tmp = () => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "host-"));

test("host settings: defaults, what is missing, and the target URL's strict check", () => {
  const none = readHostSettings({});
  assert.equal(none.settings, undefined);
  assert.deepEqual(none.missing, ["ANTHILL_URL (--anthill-url)", "COMMONS_TARGET_REPO (--target-repo)", "COMMONS_KERNEL_SIGNERS (--kernel-signer)"]);

  const ok = readHostSettings({ anthillUrl: "https://api.anthill.example", targetRepo: "https://github.com/org/repo", kernelSigners: [` ${SIGNER.toUpperCase().replace("0X", "0x")} , ${SIGNER2},`] });
  assert.deepEqual(ok.settings, {
    anthillUrl: "https://api.anthill.example",
    community: "builders",
    project: "builders",
    targetRepo: "https://github.com/org/repo",
    kernelSigners: [SIGNER, SIGNER2],
    preset: "phase1",
  });
  assert.deepEqual(ok.warnings, []);

  const one = readHostSettings({ anthillUrl: "https://a.example", targetRepo: "https://github.com/o/r", kernelSigners: [SIGNER] });
  assert.ok(one.settings);
  assert.match(one.warnings.join("\n"), /only one kernel signer.*main stops moving/);

  for (const [url, why] of [
    ["http://github.com/o/r", /https/],
    ["git@github.com:o/r.git", /not a URL|https/],
    ["ssh://github.com/o/r", /https/],
    ["https://user:token@github.com/o/r", /credentials/],
    ["https://token@github.com/o/r", /credentials/],
    ["https://github.com/o/r?token=x", /query/],
    ["https://github.com/o/r#x", /fragment/],
    ["https://github.com/", /name a repository/],
    ["https://github.com/o/r with space", /spaces/],
    ["https://github.com\\o\\r", /backslashes/],
    ["file:///tmp/r.git", /only for tests/],
  ] as const) {
    assert.match(targetRepoProblems(url).join("; "), why, url);
  }
  assert.deepEqual(targetRepoProblems("https://github.com/kelemeno/agent-commons"), []);
  assert.deepEqual(targetRepoProblems("file:///tmp/r.git", true), []);

  const bad = readHostSettings({ anthillUrl: "ftp://x", targetRepo: "https://github.com/o/r", kernelSigners: ["alice", `${SIGNER},${SIGNER}`], preset: "phase9", community: "a b" });
  assert.equal(bad.settings, undefined);
  assert.equal(bad.missing.length, 0);
  assert.match(bad.problems.join("\n"), /ANTHILL_URL.*http\(s\)/);
  assert.match(bad.problems.join("\n"), /"alice" is not an Anthill user id/);
  assert.match(bad.problems.join("\n"), /names 0xa1.* twice/);
  assert.match(bad.problems.join("\n"), /COMMONS_PRESET.*phase1, solo or none/);
  assert.match(bad.problems.join("\n"), /ANTHILL_COMMUNITY/);
});

test("base paths: one spelling, and only plain segments", () => {
  assert.equal(normaliseBasePath(""), "");
  assert.equal(normaliseBasePath("/"), "");
  assert.equal(normaliseBasePath("/commons/builders/"), "/commons/builders");
  for (const bad of ["commons", "/a//b", "/a/../b", "/a/./b", "/a b", "/a%2Fb", "/a?b"]) assert.throws(() => normaliseBasePath(bad), bad);
});

test("trusted proxies: loopback covers 127.0.0.0/8 and ::1, as IPv4-mapped peers too", () => {
  const loop = proxyMatcher(["loopback"]);
  for (const ip of ["127.0.0.1", "127.1.2.3", "::ffff:127.0.0.1", "::1"]) assert.ok(loop(ip), ip);
  for (const ip of ["10.0.0.1", "::2", "128.0.0.1"]) assert.ok(!loop(ip), ip);
  assert.ok(proxyMatcher(["127.0.0.1"])("::ffff:127.0.0.1"));
});

test("agent-commons' own .commons/rules.json: valid, and its kernel is ring 0", () => {
  const rules = JSON.parse(fs.readFileSync(path.join(ROOT, ".commons", "rules.json"), "utf8")) as Rules;
  assert.deepEqual(validateRules(rules), []);
  for (const f of [
    "src/ledger.ts",
    "src/rules.ts",
    "src/selection.ts",
    "src/review.ts",
    "src/incentives.ts",
    "src/promotion.ts",
    "src/crypto.ts",
    "src/anthill.ts",
    "src/coordinator.ts",
    "src/server.ts",
    "src/cli.ts",
    "src/client.ts",
    "src/gates/rings.ts",
    "agent-kit/commons-agent.ts",
    "agent-kit/bin/commons-agent",
    "scripts/sandbox-docker",
    "scripts/render-start.sh",
    "render.yaml",
    "tsconfig.json",
    ".commons/rules.json",
    "src/mirror.ts",
    // What a coding agent's session loads from a checkout of this repository.
    "CLAUDE.md",
    "AGENTS.md",
    ".claude/settings.json",
    ".mcp.json",
    "agent-kit/.codex/config.toml",
    ".vscode/settings.json",
  ]) {
    assert.equal(ringOf(f, rules), 0, f);
  }
  for (const f of ["README.md", "docs/protocol.md", "src/playground/render.ts", "src/metrics.ts", "test/host.test.ts"]) assert.equal(ringOf(f, rules), 1, f);
  // Every file the globs name exists (a renamed kernel file would drop out of ring 0 silently).
  for (const { glob } of rules.rings.filter((r) => r.ring === 0 && !r.glob.includes("*") && !r.glob.startsWith("."))) {
    if (/^(src|agent-kit|scripts)\//.test(glob) || glob === "render.yaml") assert.ok(fs.existsSync(path.join(ROOT, glob)), glob);
  }
});

// --- the whole thing, in process ---------------------------------------------

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] })
    .toString()
    .trim();

// A bare repository with one commit on main, optionally with rules.
function bareTarget(dir: string, rules?: Rules): string {
  const work = path.join(dir, "work");
  fs.mkdirSync(work);
  git(work, "init", "-q");
  fs.writeFileSync(path.join(work, "README.md"), "target\n");
  if (rules) {
    fs.mkdirSync(path.join(work, ".commons"));
    fs.writeFileSync(path.join(work, ".commons", "rules.json"), JSON.stringify(rules));
  }
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "first");
  const bare = path.join(dir, "target.git");
  git(dir, "clone", "-q", "--bare", work, bare);
  return `file://${bare}`;
}

type FakeAnthill = { url: string; key: { publicKey: string; privateKey: string }; close: () => Promise<void> };

async function fakeAnthill(): Promise<FakeAnthill> {
  const key = generateKeyPair();
  const server = http.createServer((req, res) => {
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.url === "/commons/key") return json(200, { publicKey: key.publicKey });
    if (req.url === "/c/builders/commons/tree") {
      const snapshot: AnthillTreeSnapshot = {
        community: "builders",
        version: 3,
        at: new Date(Date.now() - 60_000).toISOString(),
        parents: { [FOUNDER]: null, [SIGNER]: FOUNDER },
      };
      return json(200, { snapshot, signature: sign(key.privateKey, treeMessage(snapshot)) });
    }
    json(404, { error: "not found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { url: `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`, key, close: () => new Promise((r) => server.close(() => r())) };
}

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });

type Running = { stop: () => Promise<number>; err: () => string; port: number; done: Promise<number> };

async function host(data: string, anthill: string, target: string, extra: string[] = [], env: NodeJS.ProcessEnv = {}): Promise<Running> {
  const port = await freePort();
  let stopNow = () => {};
  const until = new Promise<void>((r) => (stopNow = r));
  let err = "";
  const done = main(
    ["host", "--data", data, "--port", String(port), "--anthill-url", anthill, "--target-repo", target, "--kernel-signer", SIGNER, "--test-allow-file-target", "--base-path", "/commons/builders", "--public-url", "https://backend.example/commons/builders", "--setup-retry-seconds", "1", ...extra],
    { cwd: data, until, env, stdout: () => {}, stderr: (t) => (err += t) },
  );
  return {
    port,
    done,
    err: () => err,
    stop: async () => {
      stopNow();
      return done;
    },
  };
}

async function get(port: number, p: string, timeoutMs = 20_000): Promise<{ status: number; text: string; location: string | null }> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}${p}`, { redirect: "manual" });
      return { status: r.status, text: await r.text(), location: r.headers.get("location") };
    } catch (e) {
      if (Date.now() > until) throw e;
      await new Promise((r) => setTimeout(r, 50));
    }
  }
}

// On a commons host's (Anthill-linked) solo ledger: an owner with a Claude
// and a Codex agent, and s1 by one, reviewed by the other and merged, but in
// no promoted snapshot.
function strandSoloWork(ledgerFile: string, data: string, anthillKey: { privateKey: string }): void {
  const ledger = Ledger.open(ledgerFile);
  const coord = JSON.parse(fs.readFileSync(path.join(data, "keys", "coord.json"), "utf8")) as { publicKey: string; privateKey: string };
  const owner = generateKeyPair();
  const cc = generateKeyPair();
  const cx = generateKeyPair();
  let t = Math.max(Date.now(), Date.parse(ledger.entries().at(-1)?.at ?? "")) + 1000;
  const at = () => new Date((t += 1000)).toISOString();
  const attestation = { community: "builders", user: SIGNER, publicKey: owner.publicKey, at: new Date(t).toISOString() };
  ledger.append({ kind: "anthillOwner", attestation, signature: sign(anthillKey.privateKey, ownerMessage(attestation)) }, coord, at());
  ledger.append({ kind: "agentRegistered", owner: SIGNER, publicKey: cc.publicKey, modelFamily: "claude", harness: "claude-code" }, owner, at());
  ledger.append({ kind: "agentRegistered", owner: SIGNER, publicKey: cx.publicKey, modelFamily: "gpt", harness: "codex" }, owner, at());
  const sha = (c: string) => c.repeat(40);
  ledger.append({ kind: "submission", id: "s1", taskId: null, baseCommit: sha("a"), headCommit: sha("b"), changedFiles: ["docs/x.md"], linesChanged: 3 }, cc, at());
  ledger.append({ kind: "gateResult", submissionId: "s1", gate: "size", pass: true, details: "ok" }, coord, at());
  ledger.append(assignmentBody(ledger.state(), "s1", [keyIdOf(cx.publicKey)], "e"), coord, at());
  const verdict = { defectProbability: 0.05, summary: "looked", findingIds: [] };
  ledger.append({ kind: "reviewCommit", submissionId: "s1", commitment: commitmentFor(verdict, "salt", keyIdOf(cx.publicKey), { submissionId: "s1" }), stake: 5 }, cx, at());
  ledger.append({ kind: "reviewReveal", submissionId: "s1", verdict, salt: "salt" }, cx, at());
  ledger.append({ kind: "merge", submissionId: "s1", commit: sha("c") }, coord, at());
}

async function until200(port: number, p: string, err: () => string, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const r = await get(port, p);
    if (r.status === 200) return r;
    assert.ok(Date.now() < end, `${p}: ${r.status} ${r.text}\n${err()}`);
    await new Promise((res) => setTimeout(res, 100));
  }
}

test("host: sets itself up on the first start, serves under the base path, and reuses everything on a restart", { timeout: 90_000 }, async () => {
  const dir = tmp();
  const anthill = await fakeAnthill();
  try {
    const target = bareTarget(dir, { ...JSON.parse(fs.readFileSync(path.join(ROOT, ".commons", "rules.json"), "utf8")) });
    const data = path.join(dir, "data");
    const first = await host(data, anthill.url, target, ["--loop-seconds", "1"]);
    const head = await until200(first.port, "/commons/builders/api/head", first.err);
    assert.equal(JSON.parse(head.text).seq, 0);
    const log = first.err();
    assert.match(log, /rules: the target's \.commons\/rules\.json/);
    assert.match(log, /only one kernel signer/);
    assert.match(log, /set COMMONS_SITES/);
    assert.ok(log.includes(JSON.stringify({ builders: { coordinator: "https://backend.example/commons/builders", site: "https://backend.example/commons/builders", repo: target } })), log);
    assert.equal(fs.statSync(path.join(data, "keys")).mode & 0o777, 0o700);
    for (const k of ["coord.json", "admin.json"]) assert.equal(fs.statSync(path.join(data, "keys", k)).mode & 0o777, 0o600);
    assert.equal(git(path.join(data, "target"), "rev-parse", "dev"), git(path.join(data, "target"), "rev-parse", "origin/main"));
    assert.ok(!fs.existsSync(path.join(data, "target.partial")) && !fs.existsSync(path.join(data, "commons-ledger.jsonl.setup")));

    // The genesis: linked to the community, the target's kernel, the signer.
    const genesis = JSON.parse(fs.readFileSync(path.join(data, "commons-ledger.jsonl"), "utf8").split("\n")[0] as string).body;
    assert.equal(genesis.anthill.community, "builders");
    assert.deepEqual(genesis.rules.kernelSigners, [SIGNER]);
    assert.equal(genesis.rules.promotion.kernelSignoffs, 1);
    assert.ok(genesis.rules.rings.some((r: { glob: string }) => r.glob === "src/ledger.ts"));

    // The playground under the prefix: every link and asset starts with it.
    const site = await until200(first.port, "/commons/builders/", first.err);
    assert.match(site.text, /href="\/commons\/builders\/"/);
    assert.match(site.text, /src="\/commons\/builders\/static\/refresh\.js"/);
    assert.doesNotMatch(site.text, /(?:href|src|action)="\/(?!commons\/builders\/)/);
    assert.equal((await get(first.port, "/commons/builders/static/refresh.js")).status, 200);
    const bare = await get(first.port, "/commons/builders?x=1");
    assert.equal(bare.status, 308);
    assert.equal(bare.location, "/commons/builders/?x=1");
    assert.equal((await get(first.port, "/api/head")).status, 404);
    assert.equal((await get(first.port, "/")).status, 404);
    // The first passes pin Anthill's tree.
    const end = Date.now() + 20_000;
    while (JSON.parse((await get(first.port, "/commons/builders/api/head")).text).seq < 1) {
      assert.ok(Date.now() < end, first.err());
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.equal(await first.stop(), 0);

    const ledger = fs.readFileSync(path.join(data, "commons-ledger.jsonl"));
    const coord = fs.readFileSync(path.join(data, "keys", "coord.json"));
    const second = await host(data, anthill.url, target);
    await until200(second.port, "/commons/builders/api/head", second.err);
    assert.doesNotMatch(second.err(), /setting up|cloning/);
    assert.equal(await second.stop(), 0);
    assert.deepEqual(fs.readFileSync(path.join(data, "keys", "coord.json")), coord);
    assert.ok(fs.readFileSync(path.join(data, "commons-ledger.jsonl")).subarray(0, ledger.length).equals(ledger));

    // The playground on a port of its own (serve without --one-port) mounts the same way.
    const pg = startPlayground({ ledgerPath: path.join(data, "commons-ledger.jsonl"), port: 0, host: "127.0.0.1", basePath: "/commons/builders" });
    try {
      await new Promise((r) => pg.once("listening", r));
      const port = (pg.address() as net.AddressInfo).port;
      const page = await get(port, "/commons/builders/");
      assert.equal(page.status, 200);
      assert.doesNotMatch(page.text, /(?:href|src)="\/(?!commons\/builders\/)/);
      assert.equal((await get(port, "/commons/builders/api/state")).status, 200);
      assert.equal((await get(port, "/")).status, 404);
    } finally {
      await new Promise((r) => pg.close(r));
    }
  } finally {
    await anthill.close();
  }
});

test("host: recovers from a setup cut off midway, and never reuses a clone of another repository", { timeout: 60_000 }, async () => {
  const dir = tmp();
  const anthill = await fakeAnthill();
  try {
    const target = bareTarget(dir);
    const data = path.join(dir, "data");
    // What a crash leaves: a clone with no dev branch, a partial clone, a key's temporary file, a genesis not linked yet.
    fs.mkdirSync(path.join(data, "keys"), { recursive: true });
    git(data, "clone", "-q", target, "target");
    fs.mkdirSync(path.join(data, "target.partial"));
    fs.writeFileSync(path.join(data, "keys", "admin.json.tmp-999"), "{");
    fs.writeFileSync(path.join(data, "commons-ledger.jsonl.setup"), "{");
    const existing = generateKeyPair();
    fs.writeFileSync(path.join(data, "keys", "coord.json"), JSON.stringify(existing), { mode: 0o644 });
    const run = await host(data, anthill.url, target);
    await until200(run.port, "/commons/builders/api/head", run.err);
    const log = run.err();
    assert.match(log, /cut off midway/);
    assert.match(log, /rules: the generic defaults/);
    assert.match(log, /reusing the coordinator key/);
    assert.equal(await run.stop(), 0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(data, "keys", "coord.json"), "utf8")).publicKey, existing.publicKey);
    assert.equal(fs.statSync(path.join(data, "keys", "coord.json")).mode & 0o777, 0o600);
    assert.ok(!fs.existsSync(path.join(data, "keys", "admin.json.tmp-999")));
    const genesis = JSON.parse(fs.readFileSync(path.join(data, "commons-ledger.jsonl"), "utf8").split("\n")[0] as string).body;
    assert.equal(genesis.coordinator, existing.publicKey);

    // Another repository in the setting than in the clone: setup stops, writes nothing.
    const other = path.join(dir, "other");
    fs.mkdirSync(other);
    fs.cpSync(path.join(data, "target"), path.join(other, "target"), { recursive: true });
    const wrong = await host(other, anthill.url, "https://github.com/someone/else");
    assert.equal(await wrong.done, 2);
    assert.match(wrong.err(), /is a clone of file:.*not COMMONS_TARGET_REPO/);
    assert.ok(!fs.existsSync(path.join(other, "commons-ledger.jsonl")));
  } finally {
    await anthill.close();
  }
});

test("host: without its settings it says which are missing; --hold-on-failure answers 503 instead of exiting", { timeout: 30_000 }, async () => {
  const data = tmp();
  let err = "";
  const io = { cwd: data, env: { ANTHILL_URL: "http://127.0.0.1:9" }, stdout: () => {}, stderr: (t: string) => (err += t) };
  assert.equal(await main(["host", "--data", data, "--check"], io), 1);
  assert.match(err, /setup needs COMMONS_TARGET_REPO \(--target-repo\), COMMONS_KERNEL_SIGNERS \(--kernel-signer\)/);
  assert.doesNotMatch(err, /ANTHILL_URL/);
  err = "";
  assert.equal(await main(["host", "--data", data, "--check"], { ...io, env: { ...io.env, COMMONS_TARGET_REPO: "http://x/y", COMMONS_KERNEL_SIGNERS: SIGNER } }), 2);
  assert.match(err, /must be an https URL/);
  assert.equal(await main(["host", "--data", data, "--check"], { ...io, env: { ...io.env, COMMONS_TARGET_REPO: "https://x.example/y", COMMONS_KERNEL_SIGNERS: SIGNER } }), 0);
  // The GitHub mirror on, with what it cannot use: said, and no reason not to start.
  err = "";
  const settings = { ...io.env, COMMONS_TARGET_REPO: "https://github.com/o/r", COMMONS_KERNEL_SIGNERS: SIGNER, COMMONS_PUSH_UPSTREAM: "1" };
  assert.equal(await main(["host", "--data", data, "--check"], { ...io, env: settings }), 0);
  assert.match(err, /warning: COMMONS_PUSH_UPSTREAM \(--push-upstream\) is on, but COMMONS_GITHUB_TOKEN is not set: the coordinator serves without pushing to GitHub/);
  err = "";
  assert.equal(await main(["host", "--data", data, "--check"], { ...io, env: { ...settings, COMMONS_TARGET_REPO: "https://x.example/y", COMMONS_GITHUB_TOKEN: "t0ken" } }), 0);
  assert.match(err, /is on, but the target "https:\/\/x\.example\/y" is not an https:\/\/github\.com\/<owner>\/<repo> URL/);
  assert.ok(!err.includes("t0ken"));
  err = "";
  assert.equal(await main(["host", "--data", data, "--check"], { ...io, env: { ...settings, COMMONS_GITHUB_TOKEN: "t0ken" } }), 0);
  assert.doesNotMatch(err, /PUSH_UPSTREAM/);

  const port = await freePort();
  let stop = () => {};
  const until = new Promise<void>((r) => (stop = r));
  const done = main(["host", "--data", data, "--port", String(port), "--hold-on-failure"], { ...io, until });
  const held = await get(port, "/");
  assert.equal(held.status, 503);
  assert.match(held.text, /not set up yet/);
  stop();
  assert.equal(await done, 2);
  assert.ok(!fs.existsSync(path.join(data, "commons-ledger.jsonl")));
});

test("host: COMMONS_PUSH_UPSTREAM=1 pushes the clone's dev to the target after a pass, with the token from the environment only", { timeout: 60_000 }, async () => {
  const dir = tmp();
  const anthill = await fakeAnthill();
  try {
    const target = bareTarget(dir);
    const bare = target.replace(/^file:\/\//, "");
    const data = path.join(dir, "data");
    const token = "github_pat_HOSTTEST0123456789";
    const running = await host(data, anthill.url, target, ["--loop-seconds", "1"], { COMMONS_PRESET: "solo", COMMONS_PUSH_UPSTREAM: "1", COMMONS_GITHUB_TOKEN: token });
    try {
      await until200(running.port, "/commons/builders/api/head", running.err);
      assert.match(running.err(), /every pass pushes dev and main to the target on GitHub when they changed \(COMMONS_PUSH_UPSTREAM \(--push-upstream\)\)/);
      const end = Date.now() + 30_000;
      const devOnTarget = () => {
        try {
          return git(bare, "rev-parse", "--verify", "refs/heads/dev");
        } catch {
          return null;
        }
      };
      while (devOnTarget() === null) {
        assert.ok(Date.now() < end, running.err());
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.equal(devOnTarget(), git(path.join(data, "target"), "rev-parse", "dev"));
      assert.ok(!running.err().includes(token));
    } finally {
      assert.equal(await running.stop(), 0);
    }
    // Without the token: said at the start, and it serves on.
    const off = await host(data, anthill.url, target, ["--loop-seconds", "1"], { COMMONS_PUSH_UPSTREAM: "1" });
    try {
      await until200(off.port, "/commons/builders/api/head", off.err);
      assert.match(off.err(), /COMMONS_PUSH_UPSTREAM \(--push-upstream\) is on, but COMMONS_GITHUB_TOKEN is not set: the coordinator serves without pushing/);
      assert.doesNotMatch(off.err(), /every pass pushes/);
    } finally {
      assert.equal(await off.stop(), 0);
    }
  } finally {
    await anthill.close();
  }
});

// --- solo --------------------------------------------------------------------

test("host settings: preset solo needs no kernel signer, and says what it is", () => {
  const solo = readHostSettings({ anthillUrl: "https://a.example", targetRepo: "https://github.com/o/r", preset: "solo" });
  assert.deepEqual(solo.missing, []);
  assert.equal(solo.settings?.preset, "solo");
  assert.deepEqual(solo.settings?.kernelSigners, []);
  assert.match(solo.warnings.join("\n"), /COMMONS_PRESET \(--preset\) solo: solo test: your own agents review each other.*COMMONS_RULES_PRESET \(--rules-preset\) phase1/);
  assert.doesNotMatch(solo.warnings.join("\n"), /only one kernel signer/);
  const one = readHostSettings({ anthillUrl: "https://a.example", targetRepo: "https://github.com/o/r", preset: "solo", kernelSigners: [SIGNER] });
  assert.deepEqual(one.settings?.kernelSigners, [SIGNER]);
  assert.doesNotMatch(one.warnings.join("\n"), /only one kernel signer/, "solo needs no sign-off, so one signer cannot freeze main");
  // Phase 1 still needs one.
  assert.deepEqual(readHostSettings({ anthillUrl: "https://a.example", targetRepo: "https://github.com/o/r" }).missing, ["COMMONS_KERNEL_SIGNERS (--kernel-signer)"]);
});

test("host: preset solo sets up with no kernel signer and snapshots by default; COMMONS_RULES_PRESET phase1 leaves solo once per value, never over stranded work unless forced, never over an admin's later change", { timeout: 90_000 }, async () => {
  const dir = tmp();
  const anthill = await fakeAnthill();
  try {
    const target = bareTarget(dir);
    const data = path.join(dir, "data");
    const ledgerFile = path.join(data, "commons-ledger.jsonl");
    const start = async (env: NodeJS.ProcessEnv, extra: string[] = []) => {
      const port = await freePort();
      let stopNow = () => {};
      const until = new Promise<void>((r) => (stopNow = r));
      let err = "";
      const done = main(["host", "--data", data, "--port", String(port), "--anthill-url", anthill.url, "--target-repo", target, "--test-allow-file-target", "--setup-retry-seconds", "1", ...extra], {
        cwd: data,
        until,
        env,
        stdout: () => {},
        stderr: (t) => (err += t),
      });
      const head = JSON.parse((await until200(port, "/api/head", () => err)).text) as Record<string, unknown>;
      stopNow();
      assert.equal(await done, 0, err);
      return { head, err };
    };
    const lines = () => fs.readFileSync(ledgerFile, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { body: { kind: string; rules?: Rules } });

    // Embedded (Anthill's backend runs it and lists its site): no COMMONS_SITES line to set.
    const first = await start({ COMMONS_PRESET: "solo" }, ["--embedded"]);
    assert.match(first.err, /setup done/);
    assert.doesNotMatch(first.err, /COMMONS_SITES/);
    assert.equal(first.head.mode, "solo");
    assert.equal(first.head.notice, "solo test: your own agents review each other");
    assert.match(first.err, /kernel signers: none; preset solo \(solo test/);
    // Nothing else would snapshot a hosted solo commons, so nothing would be promoted.
    assert.match(first.err, /snapshots: every 1 merged submission; approved tasks: .*approved-tasks\.json \(absent: none\)/);
    const genesis = lines()[0]?.body.rules as Rules;
    assert.equal(genesis.mode, "solo");
    assert.deepEqual(genesis.kernelSigners, []);
    assert.equal(genesis.promotion.kernelSignoffs, 0);

    // COMMONS_PRESET is setup-only: changing it says how to switch, and changes nothing.
    const noted = await start({ COMMONS_PRESET: "phase1" });
    assert.match(noted.err, /COMMONS_PRESET \(--preset\) is read at setup only; this ledger's rules are solo\. To switch them set COMMONS_RULES_PRESET/);
    assert.equal(noted.head.mode, "solo");
    assert.ok(!lines().some((l) => l.body.kind === "rulesChange"));

    // Solo work merged but not on main: leaving solo would strand it, so the
    // switch is refused, the commons serves as it is, and the next start tries again.
    strandSoloWork(ledgerFile, data, anthill.key);
    const leave = { COMMONS_RULES_PRESET: "phase1", COMMONS_KERNEL_SIGNERS: `${SIGNER},${SIGNER2}` };
    const refused = await start(leave);
    assert.equal(refused.head.mode, "solo");
    assert.match(refused.err, /s1: merged, reviewed only by its author's own agents, not on main/);
    assert.match(refused.err, /rules NOT switched to phase1 .* Set COMMONS_RULES_FORCE \(--rules-force\) to 1/);
    assert.ok(!lines().some((l) => l.body.kind === "rulesChange"));
    assert.ok(!fs.existsSync(path.join(data, "rules-preset.json")));

    const switched = await start({ ...leave, COMMONS_RULES_FORCE: "1" });
    assert.equal(switched.head.mode, undefined);
    assert.match(switched.err, /warning: leaving solo with --force strands:/);
    assert.match(switched.err, /rulesChange .* rules v1 -> v2 \(solo -> independent review\)/);
    assert.match(switched.err, /snapshots: never/, "no longer solo: no default snapshots");
    const changes = lines().filter((l) => l.body.kind === "rulesChange");
    assert.equal(changes.length, 1);
    assert.equal(changes[0]?.body.rules?.mode, undefined);
    assert.deepEqual(changes[0]?.body.rules?.kernelSigners, [SIGNER, SIGNER2]);
    assert.equal(changes[0]?.body.rules?.promotion.kernelSignoffs, 1);

    const again = await start(leave);
    assert.match(again.err, /COMMONS_RULES_PRESET \(--rules-preset\) phase1 was applied at entry #\d+; nothing to do\n/);
    assert.equal(lines().filter((l) => l.body.kind === "rulesChange").length, 1);

    // Once per value: an admin's later rulesChange survives restarts with the variable still set.
    let shell = "";
    const io = { cwd: data, stdout: (t: string) => (shell += t), stderr: (t: string) => (shell += t) };
    assert.equal(await main(["rules", "set", "--data", data, "--preset", "phase1", "--kernel-signer", SIGNER, "--kernel-signer", SIGNER2, "--kernel-signer", SIGNER3], io), 0, shell);
    const kept = await start(leave);
    assert.match(kept.err, /The rules changed since \(rulesChange #\d+\), and those changes are kept/);
    assert.equal(lines().filter((l) => l.body.kind === "rulesChange").length, 2);
    assert.deepEqual(lines().filter((l) => l.body.kind === "rulesChange").at(-1)?.body.rules?.kernelSigners, [SIGNER, SIGNER2, SIGNER3]);
    assert.equal(await main(["rules", "set", "--data", data, "--preset", "solo"], io), 0, shell);
    const stillSolo = await start(leave);
    assert.equal(stillSolo.head.mode, "solo", "a restart does not take the ledger out of the solo an admin put it back in");
    assert.equal(lines().filter((l) => l.body.kind === "rulesChange").length, 3);
    assert.match(stillSolo.err, /snapshots: every 1 merged submission;/, "solo: snapshots by default");

    // Without the admin key on the disk the switch cannot be signed: it stops instead of serving as solo.
    const keyFile = path.join(data, "keys", "admin.json");
    fs.renameSync(keyFile, `${keyFile}.away`);
    let err = "";
    const code = await main(["host", "--data", data, "--port", String(await freePort()), "--anthill-url", anthill.url], {
      cwd: data,
      env: { COMMONS_RULES_PRESET: "phase1", COMMONS_KERNEL_SIGNERS: SIGNER, COMMONS_RULES_FORCE: "1" },
      stdout: () => {},
      stderr: (t) => (err += t),
    });
    assert.equal(code, 2);
    assert.match(err, /cannot switch the rules to phase1/);
  } finally {
    await anthill.close();
  }
});

// Async git: the host under test runs in this process.
const agit = (cwd: string, ...args: string[]) =>
  new Promise<{ code: number; out: string; err: string }>((resolve) => {
    execFile("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, timeout: 30_000 }, (e, out, err) =>
      resolve({ code: e ? ((e as { code?: number }).code ?? 1) : 0, out: String(out).trim(), err: String(err) }),
    );
  });

test("host: agents fetch dev from <base>/api/git, and a commit pushed upstream after setup reaches dev, so it is a valid base", { timeout: 90_000 }, async () => {
  const dir = tmp();
  const anthill = await fakeAnthill();
  try {
    const target = bareTarget(dir);
    const data = path.join(dir, "data");
    const running = await host(data, anthill.url, target, ["--loop-seconds", "1"], { COMMONS_PRESET: "solo" });
    try {
      await until200(running.port, "/commons/builders/api/head", running.err);
      assert.match(running.err(), /git: dev and main are served read-only at \/commons\/builders\/api\/git/);
      const url = `http://127.0.0.1:${running.port}/commons/builders/api/git`;
      const devOf = async () => {
        const r = await agit(dir, "ls-remote", url, "refs/heads/dev");
        assert.equal(r.code, 0, r.err + running.err());
        return r.out.split("\t")[0];
      };
      assert.equal(await devOf(), git(path.join(data, "target"), "rev-parse", "dev"));
      // The repository's owner pushes to the public target after setup.
      const work = path.join(dir, "work");
      fs.writeFileSync(path.join(work, "later.md"), "pushed after setup\n");
      git(work, "add", ".");
      git(work, "commit", "-q", "-m", "later");
      git(work, "push", "-q", target.replace(/^file:\/\//, ""), "HEAD:main");
      const later = git(work, "rev-parse", "HEAD");
      const end = Date.now() + 30_000;
      while ((await devOf()) !== later) {
        assert.ok(Date.now() < end, running.err());
        await new Promise((r) => setTimeout(r, 200));
      }
      // An agent fetches it: the base it names is on the coordinator's dev.
      const agent = path.join(dir, "agent");
      assert.equal((await agit(dir, "init", "-q", agent)).code, 0);
      const fetched = await agit(agent, "fetch", "-q", url, "+refs/heads/dev:refs/remotes/commons/dev");
      assert.equal(fetched.code, 0, fetched.err);
      assert.equal((await agit(agent, "rev-parse", "refs/remotes/commons/dev")).out, later);
      // Nothing can be pushed.
      const pushed = await agit(agent, "push", url, "refs/remotes/commons/dev:refs/heads/x");
      assert.notEqual(pushed.code, 0);
    } finally {
      assert.equal(await running.stop(), 0);
    }
    // A solo ledger set up by an older commons (a 24-hour soak): rules are
    // frozen, so the start says how to apply today's preset.
    const ledgerFile = path.join(data, "commons-ledger.jsonl");
    const admin = JSON.parse(fs.readFileSync(path.join(data, "keys", "admin.json"), "utf8")) as { publicKey: string; privateKey: string };
    {
      const ledger = Ledger.open(ledgerFile);
      const r = ledger.state().rules;
      assert.equal(r.promotion.soakFloorHours, 1);
      assert.doesNotMatch(running.err(), /older solo preset/);
      const older = { ...r, version: r.version + 1, promotion: { ...r.promotion, soakFloorHours: 24 } };
      ledger.append({ kind: "rulesChange", rules: older, pollId: "older" }, admin, new Date(Date.parse(ledger.entries().at(-1)?.at ?? "") + 1000).toISOString());
    }
    // COMMONS_FOLLOW_UPSTREAM 0: dev moves only by merges.
    const work = path.join(dir, "work");
    fs.writeFileSync(path.join(work, "again.md"), "x\n");
    git(work, "add", ".");
    git(work, "commit", "-q", "-m", "again");
    git(work, "push", "-q", target.replace(/^file:\/\//, ""), "HEAD:main");
    const still = await host(data, anthill.url, target, ["--loop-seconds", "1"], { COMMONS_FOLLOW_UPSTREAM: "0" });
    try {
      await until200(still.port, "/commons/builders/api/head", still.err);
      assert.match(still.err(), /dev moves only by merges/);
      assert.match(still.err(), /older solo preset \(promotion\.soakFloorHours 24, the preset 1\).*COMMONS_RULES_PRESET/);
      await new Promise((r) => setTimeout(r, 2500));
      assert.notEqual(git(path.join(data, "target"), "rev-parse", "dev"), git(work, "rev-parse", "HEAD"));
    } finally {
      assert.equal(await still.stop(), 0);
    }
    const fixed = await host(data, anthill.url, target, [], { COMMONS_RULES_PRESET: "solo" });
    try {
      await until200(fixed.port, "/commons/builders/api/head", fixed.err);
      assert.equal(Ledger.open(ledgerFile).state().rules.promotion.soakFloorHours, 1, fixed.err());
      assert.doesNotMatch(fixed.err(), /older solo preset/);
    } finally {
      assert.equal(await fixed.stop(), 0);
    }
  } finally {
    await anthill.close();
  }
});
