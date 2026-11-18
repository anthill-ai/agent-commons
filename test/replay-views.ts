// Everything a ledger's replay decides, as plain JSON: the derived state and
// what the kernel modules make of it (selection, merge rule, promotion,
// credits, metrics, the coordinator's plan). Not a test file itself.
// test/replay.test.ts compares these against views recorded by the code
// before rules gained optional fields (test/fixtures/), so a change that
// alters how an existing ledger replays, or what is decided over it, fails.
import { createHash } from "node:crypto";
import { mergeReadiness, planActions } from "../src/coordinator";
import { prSlots, submitCredits } from "../src/incentives";
import { replay } from "../src/ledger";
import { computeMetrics } from "../src/metrics";
import { evaluatePromotion } from "../src/promotion";
import { seededRecall } from "../src/risk";
import { selectReviewers, verifyAssignment } from "../src/selection";
import type { CommonsState, LedgerEntry } from "../src/types";

const HOUR = 3_600_000;

// Maps as sorted [key, value] lists and Sets as sorted lists, keys sorted, so
// equal states give equal text.
export function plain(value: unknown): unknown {
  if (value instanceof Map) return [...value.entries()].map(([k, v]) => [k, plain(v)]).sort((a, b) => (String(a[0]) < String(b[0]) ? -1 : 1));
  if (value instanceof Set) return [...value].map(plain).sort();
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[k];
      if (v !== undefined) out[k] = plain(v);
    }
    return out;
  }
  return value;
}

const digest = (v: unknown) => createHash("sha256").update(JSON.stringify(plain(v))).digest("hex");

const later = (at: string, hours: number) => new Date(Date.parse(at) + hours * HOUR).toISOString();

// What the modules decide over one state, at its head time and later.
export function decisions(state: CommonsState, entries: readonly LedgerEntry[], headAt: string): unknown {
  const subs = [...state.submissions.keys()].sort();
  const snaps = [...state.snapshots.keys()].sort();
  const owners = [...state.owners.keys()].sort();
  const out: Record<string, unknown> = {};
  for (const sid of subs) {
    const s = state.submissions.get(sid);
    out[`merge:${sid}`] = [1, 49, 200].flatMap((h) =>
      ([1, 2] as const).map((phase) => mergeReadiness(state, sid, later(headAt, h), { reviewWindowHours: 48, phase, entries })),
    );
    let draw: unknown;
    try {
      draw = selectReviewers(state, sid, `fixed-beacon:${sid}`);
    } catch (e) {
      draw = { error: (e as Error).message };
    }
    out[`draw:${sid}`] = draw;
    if (s?.assignment) out[`verify:${sid}`] = verifyAssignment(state, sid);
  }
  for (const id of snaps) out[`promote:${id}`] = [1, 100, 2000].map((h) => evaluatePromotion(state, id, later(headAt, h)));
  for (const o of owners) {
    out[`credits:${o}`] = submitCredits(state, o);
    out[`slots:${o}`] = prSlots(Math.max(0, state.owners.get(o)?.reputationDelta ?? 0));
  }
  out.recall = seededRecall(state, later(headAt, -24 * 400));
  return out;
}

export type ReplayViews = {
  // Per prefix of the ledger (1..n entries): digests of the state and of the decisions over it.
  prefixes: { state: string; decisions: string }[];
  // The whole ledger, in full: state, decisions, metrics and the plan.
  final: { state: unknown; decisions: unknown; metrics: unknown; plan: unknown };
};

export function replayViews(entries: readonly LedgerEntry[]): ReplayViews {
  const prefixes: ReplayViews["prefixes"] = [];
  for (let n = 1; n <= entries.length; n++) {
    const part = entries.slice(0, n);
    const st = replay(part);
    const headAt = (part[n - 1] as LedgerEntry).at;
    prefixes.push({ state: digest(st), decisions: digest(decisions(st, part, headAt)) });
  }
  const st = replay(entries);
  const headAt = (entries[entries.length - 1] as LedgerEntry).at;
  const now = later(headAt, 1);
  return {
    prefixes,
    final: {
      state: plain(st),
      decisions: plain(decisions(st, entries, headAt)),
      metrics: plain(computeMetrics(st, now)),
      plan: plain(planActions(st, now, { reviewWindowHours: 48, phase: 1, entries, snapshotEvery: 2 })),
    },
  };
}
