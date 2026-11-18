import { test } from "node:test";
import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

// scripts/render-start.sh, Render's start command: it must never leave the
// service in a crash loop with no shell, and must not restart into serve
// before the one-time setup (the target clone included) is done.

const ROOT = path.resolve(__dirname, "..");
const tmp = () => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "render-start-"));

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });

type Run = { child: ChildProcess; port: number; stderr: () => string; exited: Promise<number | null> };

async function start(data: string): Promise<Run> {
  const port = await freePort();
  const child = spawn("sh", ["scripts/render-start.sh"], {
    cwd: ROOT,
    env: { ...process.env, COMMONS_DATA: data, PORT: String(port), ANTHILL_URL: "http://127.0.0.1:9", COMMONS_SETUP_POLL_SECONDS: "0.1" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = "";
  child.stderr?.on("data", (d: Buffer) => {
    err += d.toString();
  });
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
  return { child, port, stderr: () => err, exited };
}

async function answer(port: number, timeoutMs = 20_000): Promise<{ status: number; text: string }> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/`);
      return { status: r.status, text: await r.text() };
    } catch (e) {
      if (Date.now() > until) throw e;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

const exitsWithin = (run: Run, ms: number) =>
  Promise.race([run.exited, new Promise<"running">((r) => setTimeout(() => r("running"), ms))]);

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", ...args], { cwd, stdio: "ignore" });

test("render-start: holds the port until the ledger, the key and the target's dev branch all exist", { timeout: 60_000 }, async () => {
  const data = tmp();
  const run = await start(data);
  try {
    const first = await answer(run.port);
    assert.equal(first.status, 503);
    assert.match(first.text, /not set up yet/);
    assert.equal(fs.statSync(path.join(data, "keys")).mode & 0o777, 0o700);
    assert.match(run.stderr(), /missing the ledger .*, the coordinator key .*, the target clone with a dev branch/);
    // init has run, the clone has not: no restart yet.
    fs.writeFileSync(path.join(data, "commons-ledger.jsonl"), "");
    fs.writeFileSync(path.join(data, "keys", "coord.json"), "{}");
    assert.equal(await exitsWithin(run, 1_000), "running");
    const target = path.join(data, "target");
    fs.mkdirSync(target);
    git(target, "init", "-q");
    git(target, "commit", "-q", "--allow-empty", "-m", "x");
    assert.equal(await exitsWithin(run, 1_000), "running", "no dev branch yet");
    git(target, "branch", "dev");
    assert.equal(await exitsWithin(run, 10_000), 1);
    assert.match(run.stderr(), /setup done/);
  } finally {
    run.child.kill("SIGKILL");
  }
});

test("render-start: a serve that fails at startup leaves a holder up, not a crash loop", { timeout: 90_000 }, async () => {
  const data = tmp();
  fs.mkdirSync(path.join(data, "keys"));
  fs.writeFileSync(path.join(data, "commons-ledger.jsonl"), "not a ledger\n");
  fs.writeFileSync(path.join(data, "keys", "coord.json"), "{}");
  const target = path.join(data, "target");
  fs.mkdirSync(target);
  git(target, "init", "-q");
  git(target, "commit", "-q", "--allow-empty", "-m", "x");
  git(target, "branch", "dev");
  const run = await start(data);
  try {
    const until = Date.now() + 60_000;
    while (!/serve failed at startup/.test(run.stderr())) {
      assert.ok(Date.now() < until, run.stderr());
      assert.equal(await exitsWithin(run, 200), "running", run.stderr());
    }
    const held = await answer(run.port);
    assert.equal(held.status, 503);
    assert.match(held.text, /cannot start/);
    assert.match(run.stderr(), /ledger repair --ledger/);
    assert.equal(await exitsWithin(run, 1_000), "running", "it stays up for the shell");
  } finally {
    run.child.kill("SIGKILL");
  }
});
