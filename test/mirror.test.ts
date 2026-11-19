// The GitHub mirror (src/mirror.ts): dev and main pushed after every pass,
// never forced, refusals said once, and following upstream (gitHost.ts) with
// no churn from the mirror's own pushes. A local bare repository stands in
// for GitHub; the token's path to git is checked on the environment built,
// with no network.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { localGitBridge, main } from "../src/cli";
import { followUpstream } from "../src/gitHost";
import { githubMirror, mirrorFailureReason, mirrorGitEnv, mirrorTargetProblems, pushUpstreamProblems } from "../src/mirror";

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "mirror-"));
  dirs.push(d);
  return d;
};
const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", "-c", "commit.gpgSign=false", ...args], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();

const TOKEN = "github_pat_TESTONLY0123456789abcdef";

test("the token reaches git only through the environment, as a header scoped to https://github.com/", () => {
  const env = mirrorGitEnv(TOKEN);
  assert.equal(env.GIT_CONFIG_COUNT, "4");
  assert.equal(env.GIT_CONFIG_KEY_0, "http.https://github.com/.extraheader");
  assert.equal(env.GIT_CONFIG_VALUE_0, `Authorization: Basic ${Buffer.from(`x-access-token:${TOKEN}`).toString("base64")}`);
  assert.equal(env.GIT_CONFIG_KEY_1, "credential.helper");
  assert.equal(env.GIT_CONFIG_VALUE_1, "");
  assert.equal(env.GIT_CONFIG_KEY_2, "http.https://github.com/.followRedirects");
  assert.equal(env.GIT_CONFIG_VALUE_2, "false");
  assert.equal(env.GIT_CONFIG_KEY_3, "http.https://github.com/.sslVerify");
  assert.equal(env.GIT_CONFIG_VALUE_3, "true");
  // Neither the system nor the global config file is read.
  assert.equal(env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(env.GIT_CONFIG_GLOBAL, "/dev/null");
  // Git reads it as config for github.com URLs, and for no other host.
  const urlmatch = (url: string) =>
    spawnSync("git", ["config", "--get-urlmatch", "http.extraheader", url], { encoding: "utf8", env: { ...process.env, ...env } }).stdout.trim();
  assert.equal(urlmatch("https://github.com/org/repo"), env.GIT_CONFIG_VALUE_0);
  for (const other of ["https://github.com.evil.example/org/repo", "https://evil.example/github.com/", "http://github.com/org/repo", "https://api.github.com/x"]) {
    assert.equal(urlmatch(other), "", other);
  }
});

test("the mirror pushes only to https://github.com/<owner>/<repo>, and needs the token", () => {
  for (const ok of ["https://github.com/org/repo", "https://github.com/org/repo.git", "https://github.com/kelemeno/agent-commons/"]) assert.deepEqual(mirrorTargetProblems(ok), [], ok);
  for (const bad of [
    "http://github.com/org/repo",
    "https://gitlab.com/org/repo",
    "https://github.com.evil.example/org/repo",
    "https://github.com/org",
    "https://github.com/org/repo/tree/main",
    "https://github.com/org/..",
    "file:///tmp/x.git",
  ]) {
    assert.match(mirrorTargetProblems(bad).join(""), /not an https:\/\/github\.com\/<owner>\/<repo> URL/, bad);
  }
  assert.deepEqual(mirrorTargetProblems("file:///tmp/x.git", true), []);
  // The problem text is logged: a secret in the URL never shows in it.
  for (const leaky of [
    "https://bot:SECRET1@github.com/o/r",
    "https://SECRET1@github.com/o/r",
    "https://github.com/o/r?access_token=SECRET1",
    "https://github.com/o/r#SECRET1",
    "https://bot:SECRET1@gitlab.example/o/r",
    "file:///tmp/x.git?SECRET1",
  ]) {
    const text = mirrorTargetProblems(leaky, true).join("; ") + pushUpstreamProblems(leaky, { COMMONS_GITHUB_TOKEN: TOKEN }).join("; ");
    assert.match(text, /must not carry credentials, a query or a fragment/, leaky);
    assert.ok(!text.includes("SECRET1") && !text.includes("bot"), text);
  }
  assert.deepEqual(mirrorTargetProblems("not a url SECRET1"), ["the target is not a URL"]);
  assert.deepEqual(mirrorTargetProblems("git@github.com:org/repo.git"), ["the target is not a URL"]);
  assert.deepEqual(mirrorTargetProblems("https://gitlab.com/o/r.git/"), ['the target "https://gitlab.com/o/r.git/" is not an https://github.com/<owner>/<repo> URL']);
  assert.deepEqual(pushUpstreamProblems("https://github.com/o/r", {}), ["COMMONS_GITHUB_TOKEN is not set"]);
  assert.deepEqual(pushUpstreamProblems("https://github.com/o/r", { COMMONS_GITHUB_TOKEN: "  " }), ["COMMONS_GITHUB_TOKEN is not set"]);
  assert.deepEqual(pushUpstreamProblems("https://github.com/o/r", { COMMONS_GITHUB_TOKEN: TOKEN }), []);
  assert.equal(pushUpstreamProblems(undefined, { COMMONS_GITHUB_TOKEN: TOKEN }).length, 1);
});

test("no git the mirror runs carries the token in its argv", { skip: process.platform === "win32" }, async () => {
  const dir = tmp();
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  const log = path.join(dir, "calls.log");
  // A stand-in git that records its argv and the config it was given, and fails.
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\nprintf 'ARGV %s\\n' "$*" >> "${log}"\nprintf 'ENV %s\\n' "$GIT_CONFIG_KEY_0=$GIT_CONFIG_VALUE_0" >> "${log}"\nprintf 'DROP [%s][%s][%s][%s]\\n' "$GIT_SSL_NO_VERIFY" "$GIT_TRACE2_ENV_VARS" "$GIT_TRACE_CURL" "$GIT_CONFIG_PARAMETERS" >> "${log}"\nprintf 'ISO %s %s\\n' "$GIT_CONFIG_NOSYSTEM" "$GIT_CONFIG_GLOBAL" >> "${log}"\nexit 1\n`, { mode: 0o755 });
  const saved = process.env.PATH;
  const risky = { GIT_SSL_NO_VERIFY: "1", GIT_TRACE2_ENV_VARS: "COMMONS_GITHUB_TOKEN", GIT_TRACE_CURL: "1", GIT_CONFIG_PARAMETERS: "'http.sslverify'='false'" };
  process.env.PATH = `${bin}${path.delimiter}${saved ?? ""}`;
  Object.assign(process.env, risky);
  try {
    const r = await githubMirror({ repo: dir, url: "https://github.com/org/repo", token: TOKEN }).pass();
    assert.equal(r.pushed.length, 0);
    assert.ok(r.problems.every((p) => !p.includes(TOKEN)));
  } finally {
    process.env.PATH = saved;
    for (const k of Object.keys(risky)) delete process.env[k];
  }
  const lines = fs.readFileSync(log, "utf8").split("\n");
  // Tracing, unverified TLS and inherited config never reach it; system and global config are not read.
  assert.ok(lines.some((l) => l === "DROP [][][][]"), lines.join("\n"));
  assert.ok(!lines.some((l) => l.startsWith("DROP ") && l !== "DROP [][][][]"), lines.join("\n"));
  assert.ok(lines.some((l) => l === "ISO 1 /dev/null"), lines.join("\n"));
  const basic = Buffer.from(`x-access-token:${TOKEN}`).toString("base64");
  assert.ok(lines.some((l) => l.startsWith("ARGV ") && l.includes("ls-remote")), lines.join("\n"));
  for (const l of lines.filter((x) => x.startsWith("ARGV "))) assert.ok(!l.includes(TOKEN) && !l.includes(basic), l);
  assert.ok(lines.some((l) => l === `ENV http.https://github.com/.extraheader=Authorization: Basic ${basic}`));
});

// "GitHub" (a bare repository), the coordinator's clone as setup makes it,
// and the owner's working copy, which pushes to GitHub's main.
function world() {
  const dir = tmp();
  const owner = path.join(dir, "owner");
  fs.mkdirSync(owner);
  git(owner, "init", "-q");
  fs.writeFileSync(path.join(owner, "a.txt"), "one\n");
  git(owner, "add", ".");
  git(owner, "commit", "-q", "-m", "first");
  const gh = path.join(dir, "github.git");
  git(dir, "clone", "-q", "--bare", owner, gh);
  git(owner, "remote", "add", "gh", gh);
  const url = `file://${gh}`;
  const target = path.join(dir, "target");
  git(dir, "clone", "-q", url, target);
  git(target, "branch", "--no-track", "dev", "origin/main");
  // The owner commits on top of GitHub's main and pushes (a plain push).
  const ownerPush = (file: string) => {
    git(owner, "fetch", "-q", "gh", "main");
    git(owner, "checkout", "-q", "--detach", "FETCH_HEAD");
    fs.writeFileSync(path.join(owner, file), `${file}\n`);
    git(owner, "add", ".");
    git(owner, "commit", "-q", "-m", `owner ${file}`);
    git(owner, "push", "-q", "gh", "HEAD:refs/heads/main");
    return git(owner, "rev-parse", "HEAD");
  };
  // A merge onto dev, as the coordinator's bridge makes one.
  const merge = (file: string) => {
    const dev = git(target, "rev-parse", "dev");
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: target, input: `${file}\n` }).toString().trim();
    const env = { ...process.env, GIT_INDEX_FILE: path.join(dir, `index-${Math.random()}`) };
    execFileSync("git", ["read-tree", dev], { cwd: target, env });
    execFileSync("git", ["update-index", "--add", "--cacheinfo", `100644,${blob},${file}`], { cwd: target, env });
    const tree = execFileSync("git", ["write-tree"], { cwd: target, env }).toString().trim();
    const c = git(target, "commit-tree", tree, "-p", dev, "-m", `merge ${file}`);
    git(target, "update-ref", "refs/heads/dev", c, dev);
    return c;
  };
  const bridge = localGitBridge(target);
  const promote = async () => {
    const dev = git(target, "rev-parse", "dev");
    await bridge.fastForwardMain(dev);
    return dev;
  };
  const on = (ref: string) => {
    const r = spawnSync("git", ["rev-parse", "--verify", "--quiet", ref], { cwd: gh, encoding: "utf8" });
    return r.status === 0 ? r.stdout.trim() : null;
  };
  const mainHolds = (c: string) => spawnSync("git", ["merge-base", "--is-ancestor", c, "refs/heads/main"], { cwd: gh }).status === 0;
  return { dir, gh, target, url, ownerPush, merge, promote, on, mainHolds };
}

test("mirror: dev and main reach GitHub after a pass; following upstream sees its own pushes as nothing new; a main GitHub refuses heals once upstream is followed and promoted", async () => {
  const w = world();
  const m0 = w.on("refs/heads/main") as string;
  const mirror = githubMirror({ repo: w.target, url: w.url, token: TOKEN });

  // First pass: GitHub has main (as the clone's) and no dev: dev is created.
  let r = await mirror.pass();
  assert.deepEqual(r, { pushed: [{ ref: "refs/heads/dev", sha: m0 }], problems: [] });
  assert.equal(w.on("refs/heads/dev"), m0);
  assert.deepEqual(await mirror.pass(), { pushed: [], problems: [] }, "nothing changed: nothing pushed");

  // A merge and a promotion: both go up.
  const d1 = w.merge("d1.txt");
  await w.promote();
  r = await mirror.pass();
  assert.deepEqual(r.pushed, [
    { ref: "refs/heads/dev", sha: d1 },
    { ref: "refs/heads/main", sha: d1 },
  ]);
  assert.equal(w.on("refs/heads/main"), d1);
  // GitHub's main moved because the mirror pushed it: following it changes nothing.
  const up = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(up.kind, "unchanged");
  assert.equal(git(w.target, "rev-parse", "dev"), d1, "no merge commit for our own push");

  // The owner pushes to GitHub's main while the coordinator promotes its own
  // merge: GitHub refuses main (not a fast-forward), takes dev, and keeps
  // the owner's commit. Said once, however many passes retry it.
  const u = w.ownerPush("owner.txt");
  const d2 = w.merge("d2.txt");
  await w.promote();
  r = await mirror.pass();
  assert.deepEqual(r.pushed, [{ ref: "refs/heads/dev", sha: d2 }]);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0] as string, /^main at [0-9a-f]{12} not pushed to file:.*GitHub's main has commits this clone's main lacks \(not a fast-forward; someone pushed there\).*never forced/);
  assert.equal(w.on("refs/heads/main"), u, "never forced over the owner's push");
  assert.deepEqual(await mirror.pass(), { pushed: [], problems: [] }, "retried, not said again");

  // The next pass follows upstream into dev (a merge commit), and the
  // mirror pushes that dev; main is still refused, still not said again.
  const merged = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(merged.kind, "merged");
  const d3 = git(w.target, "rev-parse", "dev");
  r = await mirror.pass();
  assert.deepEqual(r, { pushed: [{ ref: "refs/heads/dev", sha: d3 }], problems: [] });
  // The next promotion holds the owner's commit: GitHub takes it as a fast-forward.
  await w.promote();
  r = await mirror.pass();
  assert.deepEqual(r, { pushed: [{ ref: "refs/heads/main", sha: d3 }], problems: [] });
  assert.ok(w.mainHolds(u) && w.mainHolds(d2));
  assert.equal((await followUpstream(w.target, "refs/heads/dev")).kind, "unchanged", "nothing new upstream after the heal");
  assert.equal(git(w.target, "rev-parse", "dev"), d3);

  // A restart: the mirror reads GitHub first. The owner pushed again on top
  // of the promoted main, and the pass fast-forwarded dev to it; the clone's
  // main is behind GitHub's (an ancestor), which is nothing to push and
  // nothing to say.
  const u2 = w.ownerPush("owner2.txt");
  assert.equal((await followUpstream(w.target, "refs/heads/dev")).kind, "fastForward");
  assert.equal(git(w.target, "rev-parse", "dev"), u2);
  const restarted = githubMirror({ repo: w.target, url: w.url, token: TOKEN });
  assert.deepEqual(await restarted.pass(), { pushed: [{ ref: "refs/heads/dev", sha: u2 }], problems: [] });
  assert.equal(w.on("refs/heads/main"), u2);
  assert.deepEqual(await restarted.pass(), { pushed: [], problems: [] });
});

test("mirror: a refusal by GitHub (branch protection) is said once per commit and never fails the pass; an unreachable GitHub is said once", async () => {
  const w = world();
  // Branch protection on main, as a server-side hook.
  fs.writeFileSync(path.join(w.gh, "hooks", "pre-receive"), "#!/bin/sh\nwhile read old new ref; do [ \"$ref\" = refs/heads/main ] && exit 1; done\nexit 0\n", { mode: 0o755 });
  const mirror = githubMirror({ repo: w.target, url: w.url, token: TOKEN });
  assert.equal((await mirror.pass()).pushed.length, 1, "dev is not protected");
  w.merge("d1.txt");
  const d1 = await w.promote();
  let r = await mirror.pass();
  assert.deepEqual(r.pushed, [{ ref: "refs/heads/dev", sha: d1 }]);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0] as string, /^main at .* refused by GitHub \(pre-receive hook declined\): branch protection on main must let the token's account push/);
  assert.deepEqual(await mirror.pass(), { pushed: [], problems: [] });
  // A new commit refused for the same reason is said again (it is news).
  w.merge("d2.txt");
  const d2 = await w.promote();
  r = await mirror.pass();
  assert.deepEqual(r.pushed, [{ ref: "refs/heads/dev", sha: d2 }]);
  assert.equal(r.problems.length, 1);

  const gone = githubMirror({ repo: w.target, url: `file://${path.join(w.dir, "nowhere.git")}`, token: TOKEN });
  r = await gone.pass();
  assert.equal(r.pushed.length, 0);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0] as string, /^cannot read the branches of file:.*tried again every pass/);
  assert.deepEqual(await gone.pass(), { pushed: [], problems: [] });
});

test("coordinator run-once --push-upstream: pushes the clone to its origin; without the token it says so and the pass goes on", async () => {
  const w = world();
  const dir = w.dir;
  const out = { stdout: "", stderr: "" };
  const run = (args: string[], env: NodeJS.ProcessEnv) =>
    main(args, { cwd: dir, env, stdout: (t) => (out.stdout += t), stderr: (t) => (out.stderr += t) });
  for (const k of ["admin", "coord"]) assert.equal(await run(["keygen", "--out", `${k}.json`], {}), 0);
  assert.equal(await run(["init", "--ledger", "ledger.jsonl", "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json"], {}), 0);
  const once = ["coordinator", "run-once", "--ledger", "ledger.jsonl", "--key", "coord.json", "--repo", w.target, "--push-upstream"];

  assert.equal(await run(once, { COMMONS_TEST_ALLOW_FILE_TARGET: "1" }), 0, out.stderr);
  assert.match(out.stderr, /mirror: --push-upstream is on, but COMMONS_GITHUB_TOKEN is not set: nothing is pushed to GitHub; the coordinator serves on/);
  assert.equal(w.on("refs/heads/dev"), null);

  out.stderr = "";
  assert.equal(await run(once, { COMMONS_GITHUB_TOKEN: TOKEN }), 0, out.stderr);
  assert.match(out.stderr, /is not an https:\/\/github\.com\/<owner>\/<repo> URL/, "a file: origin outside tests");

  out.stdout = "";
  out.stderr = "";
  assert.equal(await run(once, { COMMONS_GITHUB_TOKEN: TOKEN, COMMONS_TEST_ALLOW_FILE_TARGET: "1" }), 0, out.stderr);
  assert.match(out.stdout, /mirror: pushed dev [0-9a-f]{12} to GitHub/);
  assert.equal(w.on("refs/heads/dev"), git(w.target, "rev-parse", "dev"));
  assert.ok(!out.stdout.includes(TOKEN) && !out.stderr.includes(TOKEN));
});

test("mirror: an unreachable GitHub is one stable reason, so an outage is said once, not every pass", async () => {
  const curl = (ms: number, port = 443) => ({ code: 128, out: "", err: `fatal: unable to access 'https://github.com/o/r/': Failed to connect to github.com port ${port} after ${ms} ms: Couldn't connect to server` });
  const reasons = new Set([
    mirrorFailureReason(curl(21034), "refs/heads/dev"),
    mirrorFailureReason(curl(130), "refs/heads/dev"),
    mirrorFailureReason({ code: 128, out: "", err: "fatal: unable to access 'https://github.com/o/r/': Could not resolve host: github.com" }, "refs/heads/dev"),
    mirrorFailureReason({ code: 128, out: "", err: "fatal: unable to access 'https://github.com/o/r/': Recv failure: Connection reset by peer" }, "refs/heads/dev"),
    mirrorFailureReason({ code: 128, out: "", err: "fatal: unable to access 'https://github.com/o/r/': Operation timed out after 300012 milliseconds with 0 bytes received" }, "refs/heads/dev"),
    mirrorFailureReason({ code: 128, out: "", err: "fatal: unable to access 'https://github.com/o/r/': SSL_ERROR_SYSCALL in connection to github.com:443" }, "refs/heads/dev"),
  ]);
  assert.deepEqual([...reasons], ["cannot reach GitHub (network, DNS or TLS)"]);
  // Anything else keeps its words, with numbers that carry units blanked.
  const a = mirrorFailureReason({ code: 1, out: "", err: "error: RPC failed; HTTP 500 curl 22 after 1234 ms, 52.5 KiB sent" }, "refs/heads/dev");
  const b = mirrorFailureReason({ code: 1, out: "", err: "error: RPC failed; HTTP 500 curl 22 after 98 ms, 3 KiB sent" }, "refs/heads/dev");
  assert.equal(a, b);
  assert.match(a, /RPC failed; HTTP 500 curl 22 after N ms, N KiB sent/);
  assert.equal(mirrorFailureReason({ code: null, out: "", err: "fatal: partial output 123 ms" }, "refs/heads/dev"), "git did not finish (it timed out or could not run)");

  // A real refused connection (nothing listens on port 1 here): said once.
  const w = world();
  const down = githubMirror({ repo: w.target, url: "https://127.0.0.1:1/o/r", token: TOKEN, timeoutMs: 20_000 });
  const first = await down.pass();
  assert.equal(first.problems.length, 1);
  assert.match(first.problems[0] as string, /cannot reach GitHub \(network, DNS or TLS\)/);
  assert.deepEqual(await down.pass(), { pushed: [], problems: [] });
});

test("mirror: what was said is bounded: a ref keeps only its latest commit's problems, and forgets them once it pushes", async () => {
  const w = world();
  const hook = path.join(w.gh, "hooks", "pre-receive");
  const protect = () => fs.writeFileSync(hook, "#!/bin/sh\nwhile read old new ref; do [ \"$ref\" = refs/heads/main ] && exit 1; done\nexit 0\n", { mode: 0o755 });
  protect();
  const mirror = githubMirror({ repo: w.target, url: w.url, token: TOKEN });
  await mirror.pass();
  for (const f of ["a1", "a2", "a3", "a4"]) {
    w.merge(`${f}.txt`);
    await w.promote();
    assert.equal((await mirror.pass()).problems.length, 1, f);
    assert.equal(mirror.remembered(), 1, "only main's latest commit");
  }
  fs.rmSync(hook);
  const r = await mirror.pass();
  assert.deepEqual(r.pushed.map((p) => p.ref), ["refs/heads/main"]);
  assert.equal(mirror.remembered(), 0, "forgotten once pushed");
});
