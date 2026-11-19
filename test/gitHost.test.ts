// The coordinator's clone for agents (src/gitHost.ts): upstream main brought
// into dev every pass, and dev and main served read-only over git's smart HTTP.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import type * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { main as agentMain } from "../agent-kit/commons-agent";
import { followUpstream, gitServer } from "../src/gitHost";

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "githost-"));
  dirs.push(d);
  return d;
};
const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", ...args], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();

// An upstream (bare) with one commit, a clone of it as setup makes one (dev
// from origin/main), and a working copy that pushes to upstream.
function world() {
  const dir = tmp();
  const work = path.join(dir, "work");
  fs.mkdirSync(work);
  git(work, "init", "-q");
  fs.writeFileSync(path.join(work, "a.txt"), "one\n");
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "first");
  const bare = path.join(dir, "up.git");
  git(dir, "clone", "-q", "--bare", work, bare);
  git(work, "remote", "add", "up", bare);
  const target = path.join(dir, "target");
  git(dir, "clone", "-q", bare, target);
  git(target, "branch", "--no-track", "dev", "origin/main");
  const push = (file: string, text: string) => {
    fs.writeFileSync(path.join(work, file), text);
    git(work, "add", ".");
    git(work, "commit", "-q", "-m", `edit ${file}`);
    git(work, "push", "-q", "up", "HEAD:main");
    return git(work, "rev-parse", "HEAD");
  };
  // A commit on dev only, as a merge would make.
  const onDev = (file: string, text: string) => {
    const dev = git(target, "rev-parse", "dev");
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: target, input: text }).toString().trim();
    const idx = path.join(dir, `index-${Math.random()}`);
    const env = { ...process.env, GIT_INDEX_FILE: idx };
    execFileSync("git", ["read-tree", dev], { cwd: target, env });
    execFileSync("git", ["update-index", "--add", "--cacheinfo", `100644,${blob},${file}`], { cwd: target, env });
    const tree = execFileSync("git", ["write-tree"], { cwd: target, env }).toString().trim();
    const c = git(target, "commit-tree", tree, "-p", dev, "-m", `dev ${file}`);
    git(target, "update-ref", "refs/heads/dev", c, dev);
    return c;
  };
  return { dir, target, push, onDev };
}

// Async: the server under test runs in this process, so a synchronous git
// client would block the very event loop that must answer it.
const agit = (cwd: string, ...args: string[]) =>
  new Promise<{ code: number; out: string; err: string }>((resolve) => {
    execFile("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, timeout: 30_000 }, (e, out, err) =>
      resolve({ code: e ? ((e as { code?: number }).code ?? 1) : 0, out: String(out).trim(), err: String(err) }),
    );
  });
const ok = async (cwd: string, ...args: string[]) => {
  const r = await agit(cwd, ...args);
  assert.equal(r.code, 0, `git ${args.join(" ")}: ${r.err}`);
  return r.out;
};

const isAncestor = (repo: string, a: string, b: string) => spawnSync("git", ["merge-base", "--is-ancestor", a, b], { cwd: repo }).status === 0;

test("followUpstream: a new upstream commit becomes a valid base on dev; dev's own merges are kept; a conflict leaves dev alone", async () => {
  const w = world();
  assert.equal((await followUpstream(w.target, "refs/heads/dev")).kind, "unchanged");

  // Upstream moves after setup (the owner pushes): dev fast-forwards to it.
  const u1 = w.push("b.txt", "upstream\n");
  const ff = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(ff.kind, "fastForward");
  assert.equal(git(w.target, "rev-parse", "dev"), u1);

  // Dev has a merge of its own and upstream moves too: a merge commit holds both.
  const mine = w.onDev("c.txt", "merged on dev\n");
  const u2 = w.push("d.txt", "more upstream\n");
  const merged = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(merged.kind, "merged");
  const dev = git(w.target, "rev-parse", "dev");
  assert.ok(isAncestor(w.target, mine, dev) && isAncestor(w.target, u2, dev), "both sides are on dev");
  assert.equal(git(w.target, "show", "dev:c.txt"), "merged on dev");
  assert.equal(git(w.target, "show", "dev:d.txt"), "more upstream");
  assert.match(git(w.target, "log", "-1", "--format=%s", "dev"), /^commons: merge upstream origin\/main /);
  assert.equal((await followUpstream(w.target, "refs/heads/dev")).kind, "unchanged", "idempotent");

  // Both change the same file: dev stays where it was.
  w.onDev("a.txt", "dev's\n");
  const before = git(w.target, "rev-parse", "dev");
  w.push("a.txt", "upstream's\n");
  const c = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(c.kind, "conflict");
  assert.equal(git(w.target, "rev-parse", "dev"), before);

  // A remote that cannot be fetched is an error, never a moved dev.
  git(w.target, "remote", "set-url", "origin", path.join(w.dir, "gone.git"));
  const e = await followUpstream(w.target, "refs/heads/dev");
  assert.equal(e.kind, "error");
  assert.equal(git(w.target, "rev-parse", "dev"), before);
});

async function serve(repo: string): Promise<{ url: string; close: () => Promise<void> }> {
  const h = gitServer({ repo, refs: ["refs/heads/dev", "refs/heads/main"] });
  const s = http.createServer((q, r) => h(q, r));
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  return { url: `http://127.0.0.1:${(s.address() as net.AddressInfo).port}/api/git`, close: () => new Promise((r) => s.close(() => r())) };
}

test("gitServer: agents fetch dev (with what merged there) and main; only those refs are listed; nothing can be pushed", { timeout: 60_000 }, async () => {
  const w = world();
  const merged = w.onDev("spec.test.ts", "the acceptance tests a spec writer merged\n");
  git(w.target, "update-ref", "refs/commons/s1", merged);
  const srv = await serve(w.target);
  try {
    const listed = (await ok(w.dir, "ls-remote", srv.url))
      .split("\n")
      .map((l) => l.split("\t")[1])
      .sort();
    assert.deepEqual(listed, ["HEAD", "refs/heads/dev", "refs/heads/main"]);
    for (const v of ["0", "2"]) {
      const listedV = (await ok(w.dir, "-c", `protocol.version=${v}`, "ls-remote", srv.url)).split("\n").map((l) => l.split("\t")[1]);
      assert.ok(!listedV.some((r) => r?.startsWith("refs/commons/") || r?.startsWith("refs/remotes/")), `protocol ${v}: ${listedV.join(", ")}`);
    }
    // An agent's own checkout of the public repository fetches dev from here.
    const agent = path.join(w.dir, "agent");
    git(w.dir, "clone", "-q", path.join(w.dir, "up.git"), agent);
    await ok(agent, "fetch", "-q", srv.url, "+refs/heads/dev:refs/remotes/commons/dev");
    assert.equal(git(agent, "rev-parse", "refs/remotes/commons/dev"), merged);
    assert.equal(git(agent, "show", "refs/remotes/commons/dev:spec.test.ts"), "the acceptance tests a spec writer merged");

    // Read-only: a push is refused before git sees it, and so is the dumb protocol.
    const pushed = await agit(agent, "push", srv.url, "HEAD:refs/heads/dev");
    assert.notEqual(pushed.code, 0);
    assert.match(pushed.err, /read-only/);
    assert.equal(git(w.target, "rev-parse", "dev"), merged);
    assert.equal((await fetch(`${srv.url}/info/refs`)).status, 403);
    assert.equal((await fetch(`${srv.url}/info/refs?service=git-receive-pack`)).status, 403);
    assert.equal((await fetch(`${srv.url}/git-receive-pack`, { method: "POST", body: "x" })).status, 403);
    assert.equal((await fetch(`${srv.url}/HEAD`)).status, 404);
    assert.equal((await fetch(`${srv.url}/objects/info/packs`)).status, 404);
    assert.equal((await fetch(`${srv.url}/../keys/admin.json`)).status, 404);
  } finally {
    await srv.close();
  }
});

test("commons-agent fetch-dev: an agent's checkout gets the commons' dev and main from COMMONS_URL, with no key", { timeout: 60_000 }, async () => {
  const w = world();
  const merged = w.onDev("spec.test.ts", "merged on dev\n");
  const srv = await serve(w.target);
  try {
    const agent = path.join(w.dir, "agent");
    git(w.dir, "clone", "-q", path.join(w.dir, "up.git"), agent);
    const outs: string[] = [];
    const errs: string[] = [];
    const io = { out: (t: string) => void outs.push(t), err: (t: string) => void errs.push(t), stdin: () => "" };
    const code = await agentMain(["fetch-dev", "--repo", agent], { COMMONS_URL: `${srv.url.replace(/\/api\/git$/, "")}/` }, io);
    assert.equal(code, 0, errs.join(""));
    const got = JSON.parse(outs.join("")) as { dev: string; main: string };
    assert.equal(got.dev, merged);
    assert.equal(got.main, git(w.target, "rev-parse", "main"));
    assert.equal(git(agent, "show", "refs/remotes/commons/dev:spec.test.ts"), "merged on dev");
    assert.equal(await agentMain(["fetch-dev", "--repo", agent], {}, io), 2, "COMMONS_URL is required");
  } finally {
    await srv.close();
  }
});
