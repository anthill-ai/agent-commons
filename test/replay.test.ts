// Replay stays identical: ledgers written by the test suite at 07d422f (before
// rules gained the optional mode, humanMergeApproval and freeSubmitCredits
// fields), with the views that code derived from them (test/replay-views.ts),
// in test/fixtures/replay. Each must replay, entry by entry, to the same state
// and the same decisions (selection, merge rule, promotion, credits, metrics,
// the coordinator's plan).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { parseLines } from "../src/ledger";
import { validateRules } from "../src/rules";
import type { Rules } from "../src/types";
import { type ReplayViews, replayViews } from "./replay-views";

const DIR = path.join(__dirname, "fixtures", "replay");
const fixtures = fs
  .readdirSync(DIR)
  .filter((f) => f.endsWith(".jsonl.gz"))
  .map((f) => f.slice(0, -".jsonl.gz".length))
  .sort();

test("replay fixtures are there: default, phase1 and Anthill-linked ledgers", () => {
  assert.ok(fixtures.length >= 15, fixtures.join(", "));
  for (const kind of ["default-", "phase1-", "default-anthill-", "phase1-anthill-"]) assert.ok(fixtures.some((f) => f.startsWith(kind)), kind);
});

for (const name of fixtures) {
  test(`replay of ${name} is identical to 07d422f's`, { timeout: 120_000 }, () => {
    const entries = parseLines(zlib.gunzipSync(fs.readFileSync(path.join(DIR, `${name}.jsonl.gz`))).toString("utf8"));
    const recorded = JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(DIR, `${name}.views.json.gz`))).toString("utf8")) as ReplayViews;
    // Rules written before the optional fields existed validate as they did,
    // and carry none of them.
    for (const e of entries) {
      const rules = e.body.kind === "genesis" || e.body.kind === "rulesChange" ? (e.body.rules as Rules) : null;
      if (rules === null) continue;
      assert.deepEqual(validateRules(rules), [], `${name} #${e.seq}`);
      for (const k of ["mode", "humanMergeApproval", "freeSubmitCredits"]) assert.equal(Object.hasOwn(rules, k), false);
    }
    const now = JSON.parse(JSON.stringify(replayViews(entries))) as ReplayViews;
    assert.equal(now.prefixes.length, recorded.prefixes.length);
    now.prefixes.forEach((p, i) => assert.deepEqual(p, recorded.prefixes[i], `${name}: after entry #${i}`));
    assert.deepEqual(now.final, recorded.final, name);
  });
}
