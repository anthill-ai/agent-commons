// The solo preset from the outside: init --preset solo, the marker on
// GET /api/head and in the playground, and leaving solo (or switching
// presets) with an admin-signed `commons rules set`.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { main } from "../src/cli";
import { generateKeyPair, keyIdOf } from "../src/crypto";
import { hostLayout } from "../src/host";
import { Ledger, signEntry, type Signer } from "../src/ledger";
import { commitmentFor } from "../src/review";
import { assignmentBody } from "../src/selection";
import { startPlayground } from "../src/playground";
import { defaultRules, phase1Rules, SOLO_NOTICE, soloRules } from "../src/rules";
import { createCoordinatorServer } from "../src/server";
import type { EntryBody, Rules } from "../src/types";

const tmp = () => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "solo-cli-"));

async function run(cwd: string, ...args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  const status = await main(args, { cwd, stdout: (t) => (stdout += t), stderr: (t) => (stderr += t) });
  return { status, stdout, stderr };
}

type Json = Record<string, unknown>;
const getJson = async (url: string): Promise<Json> => (await (await fetch(url)).json()) as Json;

async function ok(cwd: string, ...args: string[]): Promise<string> {
  const r = await run(cwd, ...args);
  assert.equal(r.status, 0, `${args.join(" ")}: exit ${r.status}\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}

// A solo ledger as `commons init --preset solo` makes it, with the project's rules.
async function soloLedger(dir: string): Promise<{ ledger: string; project: Rules }> {
  for (const k of ["admin", "coord", "other"]) await ok(dir, "keygen", "--out", `${k}.json`);
  const rules = defaultRules();
  rules.rings = [{ glob: "src/kernel/**", ring: 0 }, ...rules.rings];
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(rules));
  const out = await ok(dir, "init", "--project", "builders", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--rules", "rules.json", "--preset", "solo");
  assert.ok(out.includes(SOLO_NOTICE), out);
  return { ledger: path.join(dir, "commons-ledger.jsonl"), project: rules };
}

test("init --preset solo: the genesis carries the solo rules on top of --rules", async () => {
  const dir = tmp();
  const { ledger, project } = await soloLedger(dir);
  const st = Ledger.open(ledger).state();
  assert.deepEqual(st.rules, soloRules(project));
  assert.equal(st.rules.mode, "solo");
  const bad = await run(dir, "init", "--ledger", "x.jsonl", "--project", "p", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--preset", "duo");
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown --preset duo \(known: phase1, solo\)/);
});

test("GET /api/head and the playground say solo prominently; other ledgers' head is unchanged", async () => {
  const dir = tmp();
  const { ledger } = await soloLedger(dir);
  const coord = JSON.parse(fs.readFileSync(path.join(dir, "coord.json"), "utf8"));
  const api = createCoordinatorServer({ ledgerPath: ledger, coordinatorKey: coord, clock: () => new Date().toISOString(), patchesDir: path.join(dir, "patches") });
  const pg = startPlayground({ ledgerPath: ledger, port: 0, host: "127.0.0.1" });
  try {
    await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
    if (!pg.listening) await new Promise<void>((r) => pg.once("listening", () => r()));
    const head = await getJson(`http://127.0.0.1:${(api.address() as AddressInfo).port}/api/head`);
    assert.deepEqual(Object.keys(head).sort(), ["at", "hash", "mode", "nextSeq", "notice", "seq"]);
    assert.equal(head.mode, "solo");
    assert.equal(head.notice, SOLO_NOTICE);
    const base = `http://127.0.0.1:${(pg.address() as AddressInfo).port}`;
    const page = await (await fetch(`${base}/`)).text();
    assert.match(page, /<div class="solo" role="note">Solo test: your own agents review each other<span>/);
    const state = await getJson(`${base}/api/state`);
    assert.equal(state.mode, "solo");
    assert.equal(state.notice, SOLO_NOTICE);

    // Leaving solo: the marker goes.
    await ok(dir, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json");
    const after = await getJson(`http://127.0.0.1:${(api.address() as AddressInfo).port}/api/head`);
    assert.deepEqual(Object.keys(after).sort(), ["at", "hash", "nextSeq", "seq"]);
    assert.doesNotMatch(await (await fetch(`${base}/`)).text(), /class="solo"/);
    assert.equal((await getJson(`${base}/api/state`)).mode, undefined);
  } finally {
    await new Promise((r) => api.close(r));
    await new Promise((r) => pg.close(r));
  }
});

test("rules set: an admin-signed rulesChange the ledger checks; a no-op when the rules already are the preset", async () => {
  const dir = tmp();
  const { ledger, project } = await soloLedger(dir);
  const entries = () => Ledger.open(ledger).entries();

  // Not an admin key, and nothing asked: refused, nothing appended.
  const other = await run(dir, "rules", "set", "--preset", "phase1", "--admin-key", "other.json");
  assert.equal(other.status, 2);
  assert.match(other.stderr, /not a genesis admin key/);
  assert.equal((await run(dir, "rules", "set", "--admin-key", "admin.json")).status, 2);
  assert.equal((await run(dir, "rules", "set", "--preset", "none", "--admin-key", "admin.json")).status, 2);
  assert.match((await run(dir, "rules", "set", "--preset", "solo", "--admin-key", "admin.json")).stdout, /rules unchanged: v1 already is the solo preset of itself \(solo test/);
  assert.equal(entries().length, 1);

  const out = await ok(dir, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json", "--kernel-signer", "erin", "--kernel-signer", "frank");
  assert.match(out, /#1 rulesChange [0-9a-f]{16} rules v1 -> v2 \(solo -> independent review\)/);
  const st = Ledger.open(ledger).state();
  assert.deepEqual(st.rules, { ...phase1Rules(project), kernelSigners: ["erin", "frank"], version: 2 });
  const last = entries().at(-1);
  assert.equal(last?.body.kind, "rulesChange");
  assert.equal(last?.signer, keyIdOf(JSON.parse(fs.readFileSync(path.join(dir, "admin.json"), "utf8")).publicKey));
  assert.equal(last?.body.kind === "rulesChange" && last.body.pollId, "rules-v2");
  assert.match(await ok(dir, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json"), /rules unchanged/);

  // A whole rules file; the ledger's own check refuses what validateRules refuses.
  const back = { ...soloRules(project), version: 1 };
  fs.writeFileSync(path.join(dir, "solo.json"), JSON.stringify(back));
  assert.match(await ok(dir, "rules", "set", "--rules", "solo.json", "--key", "admin.json"), /rules v2 -> v3 \(independent review -> solo\)/);
  assert.equal(Ledger.open(ledger).state().rules.version, 3);
  fs.writeFileSync(path.join(dir, "bad.json"), JSON.stringify({ ...back, requireOtherModelFamily: false }));
  const bad = await run(dir, "rules", "set", "--rules", "bad.json", "--admin-key", "admin.json");
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /mode solo needs rules\.requireOtherModelFamily true/);
  assert.equal(entries().length, 3);
});

test("rules set --data: a commons host's ledger and keys/admin.json, one command", async () => {
  const dir = tmp();
  const { ledger } = await soloLedger(dir);
  const l = hostLayout(path.join(dir, "data"));
  fs.mkdirSync(l.keys, { recursive: true });
  fs.copyFileSync(ledger, l.ledger);
  fs.copyFileSync(path.join(dir, "admin.json"), l.adminKey);
  assert.match(await ok(dir, "rules", "set", "--data", "data", "--preset", "phase1"), /solo -> independent review/);
  assert.equal(Ledger.open(l.ledger).state().rules.mode, undefined);
  assert.equal(Ledger.open(ledger).state().rules.mode, "solo", "only the host's ledger");
  assert.equal((await run(dir, "rules", "set", "--data", "data", "--ledger", "x", "--preset", "phase1")).status, 2);
});

// Kalman on a solo ledger made by init: a Claude agent (cc) and a Codex agent (cx).
function kalman(dir: string, ledgerPath: string) {
  const ledger = Ledger.open(ledgerPath);
  const keyFile = (k: string) => JSON.parse(fs.readFileSync(path.join(dir, `${k}.json`), "utf8")) as Signer;
  const admin = keyFile("admin");
  const coord = keyFile("coord");
  const owner = generateKeyPair();
  const agents = { cc: generateKeyPair(), cx: generateKeyPair() };
  let t = Date.parse(ledger.entries().at(-1)?.at as string);
  const at = () => new Date((t += 1000)).toISOString();
  const append = (body: EntryBody, signer: Signer) => ledger.append(body, signer, at());
  append({ kind: "ownerKey", owner: "kalman", publicKey: owner.publicKey, inviter: null }, admin);
  append({ kind: "agentRegistered", owner: "kalman", publicKey: agents.cc.publicKey, modelFamily: "claude", harness: "claude-code" }, owner);
  append({ kind: "agentRegistered", owner: "kalman", publicKey: agents.cx.publicKey, modelFamily: "gpt", harness: "codex" }, owner);
  const cx = keyIdOf(agents.cx.publicKey);
  const verdict = { defectProbability: 0.05, summary: "looked", findingIds: [] };
  return {
    ledger,
    agents,
    submit(id: string, by: Signer = agents.cc) {
      append({ kind: "submission", id, taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40), changedFiles: ["src/x.ts"], linesChanged: 3 }, by);
      append({ kind: "gateResult", submissionId: id, gate: "size", pass: true, details: "ok" }, coord);
      append(assignmentBody(ledger.state(), id, [cx], "e"), coord);
    },
    commit(id: string) {
      append({ kind: "reviewCommit", submissionId: id, commitment: commitmentFor(verdict, `salt-${id}`, cx, { submissionId: id }), stake: 5 }, agents.cx);
    },
    reveal(id: string) {
      append({ kind: "reviewReveal", submissionId: id, verdict, salt: `salt-${id}` }, agents.cx);
    },
    merge(id: string) {
      append({ kind: "merge", submissionId: id, commit: "c".repeat(40) }, coord);
    },
    snapshotAndPromote(id: string, sids: string[]) {
      append({ kind: "snapshot", id, commit: "c".repeat(40), previousSnapshotId: null, submissionIds: sids }, coord);
      append({ kind: "promotion", snapshotId: id, commit: "c".repeat(40) }, coord);
    },
  };
}

test("rules set: refuses to leave solo while solo-reviewed work is merged but not on main, or an open submission's seat is the author's own agent; --force leaves anyway", async () => {
  const dir = tmp();
  const { ledger } = await soloLedger(dir);
  const k = kalman(dir, ledger);
  k.submit("s1");
  k.commit("s1");
  k.reveal("s1");
  k.merge("s1");
  k.submit("s2"); // seated cx, not committed
  const length = () => Ledger.open(ledger).entries().length;
  const n = length();

  const r = await run(dir, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json");
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /leaving solo now strands solo-reviewed work:/);
  assert.match(r.stderr, /s1: merged, reviewed only by its author's own agents, not on main \(in no snapshot yet\)/);
  assert.match(r.stderr, /s2: open, its seat [0-9a-f]+ is the author's own agent and has not committed/);
  assert.equal(length(), n, "nothing appended");
  // Switching between solo sets, or to solo, is never refused.
  assert.match(await ok(dir, "rules", "set", "--preset", "solo", "--admin-key", "admin.json"), /rules unchanged/);

  // Once s1 is on main and s2's seat committed, nothing is stranded.
  k.snapshotAndPromote("snap-1", ["s1"]);
  k.commit("s2");
  const clean = await ok(dir, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json", "--kernel-signer", "erin");
  assert.match(clean, /solo -> independent review/);
  assert.doesNotMatch(clean, /strands/);

  // --force: leaves, and says what it strands.
  const dir2 = tmp();
  const second = await soloLedger(dir2);
  const k2 = kalman(dir2, second.ledger);
  k2.submit("s1");
  k2.commit("s1");
  k2.reveal("s1");
  k2.merge("s1");
  const forced = await ok(dir2, "rules", "set", "--preset", "phase1", "--admin-key", "admin.json", "--force");
  assert.match(forced, /warning: leaving solo with --force strands:\n {2}s1: merged/);
  assert.equal(Ledger.open(second.ledger).state().rules.mode, undefined);
});

test("server, solo: both of one person's agents can have a submission open (basePrSlots 2); a third waits", async () => {
  const dir = tmp();
  const { ledger } = await soloLedger(dir);
  const k = kalman(dir, ledger);
  const coord = JSON.parse(fs.readFileSync(path.join(dir, "coord.json"), "utf8"));
  const api = createCoordinatorServer({ ledgerPath: ledger, coordinatorKey: coord, clock: () => new Date().toISOString(), patchesDir: path.join(dir, "patches") });
  try {
    await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
    const post = async (id: string, by: Signer) => {
      const head = await getJson(`${url}/api/head`);
      const at = new Date(Math.max(Date.now(), Date.parse(head.at as string))).toISOString();
      const body: EntryBody = { kind: "submission", id, taskId: null, baseCommit: "a".repeat(40), headCommit: "b".repeat(40), changedFiles: ["src/x.ts"], linesChanged: 3 };
      const entry = signEntry({ seq: head.nextSeq as number, prev: head.hash as string }, body, by, at);
      const r = await fetch(`${url}/api/entries`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(entry) });
      return { status: r.status, body: (await r.json()) as Json };
    };
    assert.equal((await post("s1", k.agents.cc)).status, 201);
    const second = await post("s2", k.agents.cx);
    assert.equal(second.status, 201, JSON.stringify(second.body));
    const third = await post("s3", k.agents.cc);
    assert.equal(third.status, 403);
    assert.equal(third.body.error, "no-pr-slot");
    assert.match(String(third.body.message ?? third.body.detail ?? JSON.stringify(third.body)), /2 open submissions of 2 slots/);
  } finally {
    await new Promise((r) => api.close(r));
  }
});
