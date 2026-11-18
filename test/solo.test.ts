// The solo preset (rules.mode "solo"): one person, Kalman here, testing the
// commons with his own agents of two model families. Selection, the ledger's
// owner rules, the merge rule, promotion and incentives on a real signed
// ledger, each next to the same scenario under Phase 1 or the defaults, which
// must behave as they always did.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { mergeReadiness } from "../src/coordinator";
import { generateKeyPair, keyIdOf } from "../src/crypto";
import { settleCleanReviews, submitCredits } from "../src/incentives";
import { Ledger, LedgerError } from "../src/ledger";
import { plantCommitment } from "../src/plants";
import { evaluatePromotion } from "../src/promotion";
import { commitmentFor } from "../src/review";
import { seededRecall } from "../src/risk";
import { claimStake, defaultRules, phase1Rules, soloRules } from "../src/rules";
import { assignmentBody, drawAssignment, MAX_WEIGHT, selectReviewers, verifyAssignment, verifyAssignmentInLedger } from "../src/selection";
import type { EntryBody, KeyId, ModelFamily, Rules } from "../src/types";

type Key = { publicKey: string; privateKey: string; keyId: KeyId };
const key = (): Key => {
  const k = generateKeyPair();
  return { ...k, keyId: keyIdOf(k.publicKey) };
};

const T0 = Date.UTC(2026, 10, 1);
const HOUR = 3_600_000;
const KERNEL = "src/kernel/engine.ts";
// A project whose kernel is declared in its rules, as .commons/rules.json does.
function project(): Rules {
  const r = defaultRules();
  r.rings = [{ glob: "src/kernel/**", ring: 0 }, ...r.rings];
  return r;
}

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

class World {
  readonly ledger: Ledger;
  readonly admin = key();
  readonly coord = key();
  readonly owners = new Map<string, Key>();
  readonly agents = new Map<string, Key>();
  t = T0;
  private n = 0;

  constructor(rules: Rules) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "solo-test-"));
    dirs.push(dir);
    this.ledger = Ledger.create(
      path.join(dir, "ledger.jsonl"),
      { kind: "genesis", project: "builders", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
      new Date(this.t).toISOString(),
    );
  }
  get state() {
    return this.ledger.state();
  }
  now(hours = 0): string {
    return new Date(this.t + hours * HOUR).toISOString();
  }
  append(body: EntryBody, signer: Key) {
    this.t += 60_000;
    return this.ledger.append(body, signer, new Date(this.t).toISOString());
  }
  id(agent: string): KeyId {
    const k = this.agents.get(agent);
    assert.ok(k, `no agent ${agent}`);
    return k.keyId;
  }
  owner(name: string): this {
    const k = key();
    this.owners.set(name, k);
    this.append({ kind: "ownerKey", owner: name, publicKey: k.publicKey, inviter: null }, this.admin);
    return this;
  }
  agent(name: string, owner: string, family: ModelFamily): this {
    const k = key();
    this.agents.set(name, k);
    this.append({ kind: "agentRegistered", owner, publicKey: k.publicKey, modelFamily: family, harness: name }, this.owners.get(owner) as Key);
    return this;
  }
  // A proposal (by `proposer`, an owner), its task and the author's claim.
  task(id: string, ring: 0 | 1 | 2, author: string, proposer: string): string {
    this.append({ kind: "proposal", id: `p-${id}`, title: id, evidence: [{ kind: "failingTest", testId: "t", command: "npm test" }] }, this.owners.get(proposer) as Key);
    this.append({ kind: "task", id, proposalId: `p-${id}`, ring, acceptanceTestPaths: ["test/acceptance.test.ts"], sizeEstimate: 20, specAuthor: proposer }, this.coord);
    this.append({ kind: "claim", taskId: id, until: this.now(48), stake: claimStake(20, ring, this.state.rules) }, this.agents.get(author) as Key);
    return id;
  }
  submit(id: string, author: string, files = ["src/feature.ts"], taskId: string | null = null): this {
    this.append({ kind: "submission", id, taskId, baseCommit: "base", headCommit: `head-${id}`, changedFiles: files, linesChanged: 20 }, this.agents.get(author) as Key);
    this.append({ kind: "gateResult", submissionId: id, gate: "tests", pass: true, details: "ok" }, this.coord);
    return this;
  }
  // A genuine draw: entropy tried until it seats `reviewer` (or any draw if null).
  assign(id: string, reviewer: string | null = null): KeyId[] {
    for (let i = 0; i < 512; i++) {
      const d = drawAssignment(this.state, id, `e-${id}-${i}`);
      if (d.reviewers.length === 0) throw new Error(`no reviewers: ${d.notes.join("; ")}`);
      if (reviewer === null || d.reviewers.includes(this.id(reviewer))) {
        this.append(d.body, this.coord);
        return d.reviewers;
      }
    }
    throw new Error(`no draw seats ${reviewer}`);
  }
  review(id: string, agent: string, p: number): void {
    const verdict = { defectProbability: p, summary: "looked", findingIds: [] };
    const salt = `salt-${this.n++}`;
    this.append({ kind: "reviewCommit", submissionId: id, commitment: commitmentFor(verdict, salt, this.id(agent), { submissionId: id }), stake: 5 }, this.agents.get(agent) as Key);
    this.append({ kind: "reviewReveal", submissionId: id, verdict, salt }, this.agents.get(agent) as Key);
  }
  commit(id: string, agent: string): void {
    const verdict = { defectProbability: 0, summary: "looked", findingIds: [] };
    this.append({ kind: "reviewCommit", submissionId: id, commitment: commitmentFor(verdict, `s-${this.n++}`, this.id(agent), { submissionId: id }), stake: 5 }, this.agents.get(agent) as Key);
  }
  finding(id: string, finder: string, submissionId: string): void {
    this.append({ kind: "finding", id, target: { submissionId }, severity: "high", testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 }, this.agents.get(finder) as Key);
  }
  merge(id: string): void {
    this.append({ kind: "merge", submissionId: id, commit: `merge-${id}` }, this.coord);
  }
  snapshot(id: string, submissionIds: string[]): void {
    this.append({ kind: "snapshot", id, commit: `snap-${id}`, previousSnapshotId: null, submissionIds }, this.coord);
  }
  rulesChange(rules: Rules): void {
    this.append({ kind: "rulesChange", rules: { ...rules, version: this.state.rules.version + 1 }, pollId: `v${this.state.rules.version + 1}` }, this.admin);
  }
}

const rejected = (code: string) => (e: unknown) => e instanceof LedgerError && e.code === code;

// Kalman alone: a Claude Code agent, a Codex agent, and a second Claude agent.
function kalman(rules: Rules = soloRules(project())): World {
  return new World(rules).owner("kalman").agent("cc", "kalman", "claude").agent("cx", "kalman", "gpt").agent("cc2", "kalman", "claude");
}

const beacons = (n: number) => Array.from({ length: n }, (_, i) => `beacon-${i}`);

// --- selection ----------------------------------------------------------------

test("selection, solo: the author's own agent of another family is drawn; never the author, never its family", () => {
  const w = kalman().submit("s1", "cc").submit("s2", "cx");
  for (const b of beacons(40)) {
    assert.deepEqual(selectReviewers(w.state, "s1", b).reviewers, [w.id("cx")], "claude author: only the gpt agent");
    const other = selectReviewers(w.state, "s2", b).reviewers;
    assert.equal(other.length, 1);
    assert.ok([w.id("cc"), w.id("cc2")].includes(other[0] as KeyId), "gpt author: one claude agent, one seat for the one owner");
  }
  assert.equal(selectReviewers(w.state, "s1", "b").candidates, 1);
  w.assign("s1");
  assert.ok(verifyAssignment(w.state, "s1"));
  assert.ok(verifyAssignmentInLedger(w.ledger.entries(), "s1"));
});

test("selection, phase1 and defaults: the same one-person world draws nobody, as before", () => {
  for (const rules of [phase1Rules(project()), project()]) {
    const w = kalman(rules).submit("s1", "cc");
    const d = selectReviewers(w.state, "s1", "b");
    assert.deepEqual(d.reviewers, []);
    assert.equal(d.candidates, 0);
    assert.doesNotMatch(d.notes.join("; "), /solo/);
  }
});

test("selection, solo: a second person's agents outweigh the author's own (weight 2 against 1)", () => {
  const w = kalman().owner("friend").agent("f1", "friend", "gpt").submit("s1", "cc");
  const wins = { friend: 0, kalman: 0 };
  for (const b of beacons(600)) {
    const [r] = selectReviewers(w.state, "s1", b).reviewers;
    if (r === w.id("f1")) wins.friend++;
    else if (r === w.id("cx")) wins.kalman++;
    else assert.fail(`unexpected reviewer ${r}`);
  }
  assert.equal(MAX_WEIGHT, 2);
  // u^(1/2) against u^(1/1): the friend wins with probability 2/3.
  assert.ok(wins.friend > 340 && wins.friend < 460, JSON.stringify(wins));
  // Two seats: both owners, one each.
  const two = new World({ ...soloRules(project()), assignedReviewers: 2 })
    .owner("kalman").agent("cc", "kalman", "claude").agent("cx", "kalman", "gpt")
    .owner("friend").agent("f1", "friend", "claude")
    .submit("s1", "cc");
  assert.deepEqual(new Set(selectReviewers(two.state, "s1", "b").reviewers), new Set([two.id("cx"), two.id("f1")]));
});

// --- the ledger ------------------------------------------------------------------

test("ledger, solo: an assignment, a review and a finding by the author's other-family agent are accepted; by the author or its family refused", () => {
  const w = kalman().submit("s1", "cc");
  const body = (who: string[]) => assignmentBody(w.state, "s1", who.map((a) => w.id(a)), "e");
  assert.throws(() => w.append(body(["cc"]), w.coord), rejected("invalid-reviewers"));
  assert.throws(() => w.append(body(["cc2"]), w.coord), rejected("invalid-reviewers"));
  assert.throws(() => w.append(body(["cx", "cc2"]), w.coord), rejected("invalid-reviewers"), "one owner never holds two seats");
  w.append(body(["cx"]), w.coord);
  assert.throws(() => w.commit("s1", "cc"), rejected("same-owner"));
  assert.throws(() => w.commit("s1", "cc2"), rejected("same-owner"));
  w.review("s1", "cx", 0.1);
  assert.throws(() => w.finding("f-cc2", "cc2", "s1"), rejected("same-owner"));
  assert.throws(() => w.finding("f-cc", "cc", "s1"), rejected("same-owner"));
  w.finding("f-cx", "cx", "s1");
  assert.equal(w.state.findings.get("f-cx")?.finder, w.id("cx"));
});

test("ledger, phase1 and defaults: the author's own agents never review or file findings on its work, whatever their family", () => {
  for (const rules of [phase1Rules(project()), project()]) {
    const w = kalman(rules).owner("friend").agent("f1", "friend", "gpt").submit("s1", "cc");
    assert.throws(() => w.append(assignmentBody(w.state, "s1", [w.id("cx")], "e"), w.coord), rejected("invalid-reviewers"));
    assert.throws(() => w.commit("s1", "cx"), rejected("same-owner"));
    assert.throws(() => w.finding("f-cx", "cx", "s1"), rejected("same-owner"));
    w.append(assignmentBody(w.state, "s1", [w.id("f1")], "e"), w.coord);
  }
});

test("ledger: leaving solo with a rulesChange closes the door, and the solo draw still verifies under the rules it ran under", () => {
  const w = kalman().submit("s1", "cc");
  w.assign("s1", "cx");
  w.rulesChange(phase1Rules(project()));
  assert.equal(w.state.rules.mode, undefined);
  assert.throws(() => w.commit("s1", "cx"), rejected("same-owner"));
  w.submit("s2", "cc");
  assert.throws(() => w.append(assignmentBody(w.state, "s2", [w.id("cx")], "e"), w.coord), rejected("invalid-reviewers"));
  assert.ok(verifyAssignment(w.state, "s1"), "stateAt replays the solo rules of the draw");
  assert.ok(verifyAssignmentInLedger(w.ledger.entries(), "s1"));
});

// --- the merge rule ----------------------------------------------------------------

const ready = (w: World, id: string, phase: 1 | 2 = 1) =>
  mergeReadiness(w.state, id, w.now(1), { reviewWindowHours: 48, phase, entries: w.ledger.entries(), headBinding: "declared" });

test("merge rule, solo: no mergeApproval unless a reviewer flags a defect; the rules decide, not --phase", () => {
  const w = kalman().submit("s1", "cc").submit("s2", "cc");
  w.assign("s1", "cx");
  w.review("s1", "cx", 0.1);
  for (const phase of [1, 2] as const) assert.deepEqual(ready(w, "s1", phase).waiting, [], `phase ${phase}`);
  w.assign("s2", "cx");
  w.review("s2", "cx", 0.8);
  assert.match(ready(w, "s2").waiting.join("; "), /a reviewer flagged a defect: awaiting human approval/);
  w.append({ kind: "mergeApproval", submissionId: "s2" }, w.admin);
  assert.deepEqual(ready(w, "s2").waiting, []);
  // humanMergeApproval "always" overrides --phase 2.
  const strict = kalman({ ...soloRules(project()), humanMergeApproval: "always" }).submit("s1", "cc");
  strict.assign("s1", "cx");
  strict.review("s1", "cx", 0.1);
  assert.match(ready(strict, "s1", 2).waiting.join("; "), /awaiting human approval/);
});

test("merge rule, phase1: unchanged, --phase decides (1: every merge, 2: a majority flag)", () => {
  const w = new World(phase1Rules(project())).owner("a").agent("a1", "a", "claude").owner("b").agent("b1", "b", "gpt").submit("s1", "a1").submit("s2", "a1");
  w.assign("s1", "b1");
  w.review("s1", "b1", 0.1);
  assert.deepEqual(ready(w, "s1", 1).waiting, ["awaiting human approval (mergeApproval)"]);
  assert.deepEqual(ready(w, "s1", 2).waiting, []);
  w.assign("s2", "b1");
  w.review("s2", "b1", 0.9);
  assert.deepEqual(ready(w, "s2", 2).waiting, ["the assigned reviewers flagged a defect: awaiting human approval (mergeApproval)"]);
});

// --- promotion --------------------------------------------------------------------

// Two kernel changes, each written by one of Kalman's agents and reviewed by the other.
function soloSnapshot(rules: Rules = soloRules(project())): World {
  const w = kalman(rules);
  w.submit("s1", "cc", [KERNEL], w.task("t1", 0, "cc", "kalman"));
  w.submit("s2", "cx", [KERNEL], w.task("t2", 0, "cx", "kalman"));
  w.assign("s1", "cx");
  w.review("s1", "cx", 0.05);
  w.assign("s2", "cc");
  w.review("s2", "cc", 0.05);
  w.merge("s1");
  w.merge("s2");
  w.snapshot("snap-1", ["s1", "s2"]);
  return w;
}

test("promotion, solo: one owner and two families promote kernel work with no sign-off and no plants", () => {
  const w = soloSnapshot();
  const r = evaluatePromotion(w.state, "snap-1", w.now(25));
  assert.ok(r.pass, JSON.stringify(r.checks, null, 1));
  const c = Object.fromEntries(r.checks.map((x) => [x.name, x]));
  assert.match(c.coverage?.detail ?? "", /fewest families 2 \(solo: the author's counted\), fewest reviewing owners 1/);
  assert.match(c.kernel?.detail ?? "", /0\/0 kernel sign-offs; no kernel signers named/);
  assert.match(c.recall?.detail ?? "", /^solo test, not enforced: 0\/0/);
  assert.match(c.criticals?.detail ?? "", /^solo test, not enforced: .*Infinity/);
  assert.equal(c.soak?.pass, true);
  assert.equal(evaluatePromotion(w.state, "snap-1", w.now(23)).checks.find((x) => x.name === "soak")?.pass, false, "the soak floor still holds");
});

test("promotion, solo: a review by the author's own family covers nothing, and an unreviewed submission blocks", () => {
  const w = new World(soloRules(project())).owner("kalman").agent("cc", "kalman", "claude").agent("cx", "kalman", "gpt");
  w.owner("friend").agent("f1", "friend", "claude");
  w.submit("s1", "cc");
  w.assign("s1", "f1");
  w.review("s1", "f1", 0.05); // another owner, but the author's family
  w.merge("s1");
  w.snapshot("snap-1", ["s1"]);
  const r = evaluatePromotion(w.state, "snap-1", w.now(25));
  const coverage = r.checks.find((x) => x.name === "coverage");
  assert.equal(coverage?.pass, false);
  assert.match(coverage?.detail ?? "", /s1: 1\/2 families \[claude\]/);
});

test("promotion, after leaving solo: Phase 1 judges the same snapshot, and own-owner reviews and missing sign-offs fail it", () => {
  const w = soloSnapshot();
  w.rulesChange({ ...phase1Rules(project()), kernelSigners: ["erin"] });
  const r = evaluatePromotion(w.state, "snap-1", w.now(25));
  const c = Object.fromEntries(r.checks.map((x) => [x.name, x]));
  assert.equal(r.pass, false);
  assert.equal(c.coverage?.pass, false);
  assert.match(c.coverage?.detail ?? "", /0\/2 families/);
  assert.equal(c.assignments?.pass, true, "solo draws verify under the rules they ran under");
  assert.equal(c.kernel?.pass, false);
  assert.equal(c.recall?.pass, false);
  assert.doesNotMatch(c.recall?.detail ?? "", /solo/);
});

test("promotion, phase1: the same two-family, two-owner snapshot is judged as before", () => {
  const w = new World({ ...phase1Rules(project()), kernelSigners: ["erin"] }).owner("a").agent("a1", "a", "claude").owner("b").agent("b1", "b", "gpt").owner("erin");
  w.submit("s1", "a1", [KERNEL], w.task("t1", 0, "a1", "a"));
  w.assign("s1", "b1");
  w.review("s1", "b1", 0.05);
  w.merge("s1");
  w.snapshot("snap-1", ["s1"]);
  const c = Object.fromEntries(evaluatePromotion(w.state, "snap-1", w.now(25)).checks.map((x) => [x.name, x]));
  assert.equal(c.coverage?.pass, false, "one reviewing owner of the two Phase 1 needs");
  assert.match(c.coverage?.detail ?? "", /1\/2 families \[gpt\], 1\/2 owners/);
  assert.match(c.kernel?.detail ?? "", /0\/1 kernel sign-offs/);
  assert.match(c.recall?.detail ?? "", /^0\/0 revealed plants/);
  assert.equal(c.criticals?.pass, false);
});

test("plants, solo: the machinery runs; a revealed plant blocks its merge and its snapshot, and own-owner catches do not count", () => {
  const w = kalman();
  const salt = "plant-salt";
  w.append({ kind: "plantCommit", commitment: plantCommitment("p1", salt) }, w.admin);
  w.submit("p1", "cc");
  w.assign("p1", "cx");
  w.review("p1", "cx", 0.9);
  w.append({ kind: "plantReveal", submissionId: "p1", salt, description: "off by one", severity: "high" }, w.admin);
  assert.match(ready(w, "p1").waiting.join("; "), /revealed plant/);
  assert.throws(() => w.merge("p1"), rejected("planted"));
  const recall = seededRecall(w.state, new Date(T0 - HOUR).toISOString());
  assert.deepEqual([recall.seeds, recall.caught], [1, 0]);
  const r = evaluatePromotion(soloSnapshot().state, "snap-1", w.now(25));
  assert.ok(r.pass);
});

// --- incentives --------------------------------------------------------------------

test("incentives, solo: ten free submit credits, earned back by reviewing; Phase 1 still starts at one", () => {
  const w = kalman();
  assert.equal(submitCredits(w.state, "kalman"), 10);
  w.submit("s1", "cc");
  assert.equal(submitCredits(w.state, "kalman"), 9);
  w.assign("s1", "cx");
  w.review("s1", "cx", 0.1);
  assert.equal(submitCredits(w.state, "kalman"), 10, "reviewsPerSubmitCredit 1: the review earns the credit back");
  const p = kalman(phase1Rules(project()));
  assert.equal(submitCredits(p.state, "kalman"), 1);
  p.submit("s1", "cc");
  assert.equal(submitCredits(p.state, "kalman"), 0);
  assert.equal(submitCredits(new World(project()).state, "anyone"), 1, "defaults: one");
});

test("incentives, solo: stakes cover both agents holding the largest claim and twenty review stakes", () => {
  const r = soloRules(project());
  const largest = claimStake(r.maxLinesPerSubmission, 0, r);
  assert.equal(largest, 320);
  assert.equal(r.stake.allowance, 2 * largest + 20 * r.stake.review);
  assert.equal(phase1Rules(project()).stake.allowance, 370);
});

test("incentives, solo: reviewing your own agents earns no clean-review reward", () => {
  const w = kalman();
  w.submit("s1", "cc", ["src/feature.ts"], w.task("t1", 1, "cc", "kalman"));
  w.assign("s1", "cx");
  w.review("s1", "cx", 0.05);
  w.merge("s1");
  w.snapshot("snap-1", ["s1"]);
  w.append({ kind: "promotion", snapshotId: "snap-1", commit: "snap-snap-1" }, w.coord);
  const bodies = settleCleanReviews(w.state, "snap-1", w.now(24 * 40));
  assert.deepEqual(bodies.filter((b) => b.reason === "cleanReview"), []);
  // The same work reviewed by another person pays them, as it always did.
  const p = new World(phase1Rules(project())).owner("a").agent("a1", "a", "claude").owner("b").agent("b1", "b", "gpt");
  p.submit("s1", "a1", ["src/feature.ts"], p.task("t1", 1, "a1", "a"));
  p.assign("s1", "b1");
  p.review("s1", "b1", 0.05);
  p.merge("s1");
  p.snapshot("snap-1", ["s1"]);
  p.append({ kind: "promotion", snapshotId: "snap-1", commit: "snap-snap-1" }, p.coord);
  const paid = settleCleanReviews(p.state, "snap-1", p.now(24 * 40)).filter((x) => x.reason === "cleanReview");
  assert.deepEqual(paid.map((x) => [x.owner, x.delta]), [["b", 2]]);
});
