import { test } from "node:test";
import assert from "node:assert/strict";

import {
  type AnthillOwnerAttestation,
  type AnthillTreeSnapshot,
  ownerMessage,
  syncAnthillTree,
  treeMessage,
} from "../src/anthill";
import { generateKeyPair, keyIdOf, sign } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, LedgerError, replay, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { MEMBER_ROOT, memberDigest, memberTree } from "../src/members";
import { defaultRules } from "../src/rules";
import { drawAssignment, selectReviewers, verifyAssignment, verifyAssignmentInLedger } from "../src/selection";
import type { EntryBody, LedgerEntry } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: a ledger linked to the Anthill community "builders", with Anthill
// played by a local key.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();
const user = (n: number) => `0x${n.toString(16).padStart(40, "0")}`;

// root ─┬─ a ─── a1 ─── a2
//       └─ b ─── b1 ─── b2
const ROOT = user(1);
const [A, A1, A2, B, B1, B2] = [user(0xa), user(0xa1), user(0xa2), user(0xb), user(0xb1), user(0xb2)] as const;
const OUTSIDER = user(0xff);
const PARENTS: Record<string, string | null> = { [ROOT]: null, [A]: ROOT, [A1]: A, [A2]: A1, [B]: ROOT, [B1]: B, [B2]: B1 };

class World {
  anthill = generateKeyPair();
  admin = generateKeyPair();
  coord = generateKeyPair();
  ownerKeys = new Map<string, Signer>();
  agentKeys = new Map<string, Signer>();
  minute = 0;
  version = 0;
  entries: LedgerEntry[];
  state: LedgerState;

  constructor(linked = true) {
    const genesis = genesisEntry(
      {
        kind: "genesis",
        project: "builders",
        admins: [this.admin.publicKey],
        coordinator: this.coord.publicKey,
        rules: defaultRules(),
        ...(linked ? { anthill: { community: "builders", publicKey: this.anthill.publicKey } } : {}),
      },
      iso(0),
    );
    this.entries = [genesis];
    this.state = emptyState(genesis);
  }

  append(body: EntryBody, signer: Signer = this.coord): LedgerEntry {
    this.minute += 1;
    const e = signEntry(this.state, body, signer, iso(this.minute));
    applyEntry(this.state, e);
    this.entries.push(e);
    return e;
  }

  signedTree(parents: Record<string, string | null>, over: Partial<AnthillTreeSnapshot> = {}) {
    this.version += 1;
    const snapshot: AnthillTreeSnapshot = { community: "builders", version: this.version, at: iso(this.minute), parents, ...over };
    return { snapshot, signature: sign(this.anthill.privateKey, treeMessage(snapshot)) };
  }

  pin(parents: Record<string, string | null> = PARENTS, over: Partial<AnthillTreeSnapshot> = {}): LedgerEntry {
    return this.append({ kind: "anthillTree", ...this.signedTree(parents, over) });
  }

  signedOwner(id: string, publicKey: string, over: Partial<AnthillOwnerAttestation> = {}) {
    const attestation: AnthillOwnerAttestation = { community: "builders", user: id, publicKey, at: iso(this.minute), ...over };
    return { attestation, signature: sign(this.anthill.privateKey, ownerMessage(attestation)) };
  }

  join(id: string, family = "claude"): this {
    const owner = generateKeyPair();
    this.ownerKeys.set(id, owner);
    this.append({ kind: "anthillOwner", ...this.signedOwner(id, owner.publicKey) });
    const agent = generateKeyPair();
    this.agentKeys.set(id, agent);
    this.append({ kind: "agentRegistered", owner: id, publicKey: agent.publicKey, modelFamily: family, harness: "test" }, owner);
    return this;
  }

  submit(by: string, id = "s1"): void {
    const sha = (c: string) => c.repeat(40);
    this.append(
      { kind: "submission", id, taskId: null, baseCommit: sha("a"), headCommit: sha("b"), changedFiles: ["docs/x.md"], linesChanged: 3 },
      this.agentKeys.get(by) as Signer,
    );
  }
}

function refused(w: World, body: EntryBody, code: string, signer?: Signer) {
  assert.throws(
    () => w.append(body, signer),
    (e: unknown) => e instanceof LedgerError && e.code === code,
  );
}

// ---------------------------------------------------------------------------
// Message format: anthill-backend/src/commonsLink.ts signs these exact bytes.
// ---------------------------------------------------------------------------

test("message format is pinned (anthill-backend/scripts/commonsLinkChecks.ts checks the same strings)", () => {
  assert.equal(
    treeMessage({ community: "builders", version: 7, at: "2026-01-01T00:00:00.000Z", parents: { "0xb": "0xa", "0xa": null } }),
    'anthill-commons/tree/v1\n{"at":"2026-01-01T00:00:00.000Z","community":"builders","parents":{"0xa":null,"0xb":"0xa"},"version":7}',
  );
  assert.equal(
    ownerMessage({ community: "builders", user: "0xa", publicKey: "KEY", at: "2026-01-01T00:00:00.000Z" }),
    'anthill-commons/owner/v1\n{"at":"2026-01-01T00:00:00.000Z","community":"builders","publicKey":"KEY","user":"0xa"}',
  );
});

// ---------------------------------------------------------------------------
// Genesis and the entries
// ---------------------------------------------------------------------------

test("a linked ledger starts with no pinned tree: only the virtual root, so nobody is a member", () => {
  const w = new World();
  assert.deepEqual(w.state.anthill?.link, { community: "builders", publicKey: w.anthill.publicKey });
  assert.equal(w.state.anthill?.tree, undefined);
  assert.deepEqual(memberTree(w.state).members(), [MEMBER_ROOT]);
});

test("genesis refuses an Anthill key that is not an ed25519 key", () => {
  assert.throws(
    () =>
      emptyState({
        kind: "genesis",
        project: "x",
        admins: [generateKeyPair().publicKey],
        coordinator: generateKeyPair().publicKey,
        rules: defaultRules(),
        anthill: { community: "builders", publicKey: "nope" },
      }),
    (e: unknown) => e instanceof LedgerError && e.code === "invalid-key",
  );
});

test("anthillTree: a pinned tree becomes the member tree, rooted at the community's root", () => {
  const w = new World();
  w.pin();
  const t = memberTree(w.state);
  assert.equal(t.root(), ROOT);
  assert.equal(t.distance(A2, B2), 6);
  assert.equal(t.distance(A1, A2), 1);
  assert.equal(w.state.anthill?.tree?.version, 1);
});

test("anthillTree: refused when not signed by Anthill, for another community, not newer, or not a tree", () => {
  const w = new World();
  const forged = w.signedTree(PARENTS);
  forged.signature = sign(generateKeyPair().privateKey, treeMessage(forged.snapshot));
  refused(w, { kind: "anthillTree", ...forged }, "signature");
  refused(w, { kind: "anthillTree", ...w.signedTree(PARENTS, { community: "other" }) }, "invalid-value");
  // Signed over different contents than it carries.
  const swapped = w.signedTree(PARENTS);
  refused(w, { kind: "anthillTree", snapshot: { ...swapped.snapshot, parents: { [ROOT]: null } }, signature: swapped.signature }, "signature");

  w.pin();
  refused(w, { kind: "anthillTree", ...w.signedTree(PARENTS, { version: 1 }) }, "invalid-value");
  refused(w, { kind: "anthillTree", ...w.signedTree({ [A]: B, [B]: A }) }, "invalid-value"); // no root
  refused(w, { kind: "anthillTree", ...w.signedTree({ [ROOT]: null, [A]: user(0x99) }) }, "invalid-value"); // unknown parent
  refused(w, { kind: "anthillTree", ...w.signedTree({ [ROOT]: null, Alice: ROOT }) }, "invalid-value"); // not an Anthill id
  refused(w, { kind: "anthillTree", ...w.signedTree(PARENTS, { at: iso(9_999) }) }, "time"); // signed after the entry
  // Only the coordinator pins.
  refused(w, { kind: "anthillTree", ...w.signedTree(PARENTS) }, "unauthorised", w.admin);
});

test("anthillOwner: admits the Anthill user under their own id, relayed by the coordinator", () => {
  const w = new World();
  const owner = generateKeyPair();
  w.append({ kind: "anthillOwner", ...w.signedOwner(A, owner.publicKey) });
  assert.equal(w.state.owners.get(A)?.keyId, keyIdOf(owner.publicKey));
  assert.equal(w.state.ownerByKey.get(keyIdOf(owner.publicKey)), A);
  // Twice for one user, or a key already in use, is refused.
  refused(w, { kind: "anthillOwner", ...w.signedOwner(A, generateKeyPair().publicKey) }, "duplicate-id");
  refused(w, { kind: "anthillOwner", ...w.signedOwner(B, owner.publicKey) }, "duplicate-key");
});

test("anthillOwner: refused without Anthill's signature or for another community", () => {
  const w = new World();
  const key = generateKeyPair().publicKey;
  const forged = w.signedOwner(A, key);
  forged.signature = sign(w.admin.privateKey, ownerMessage(forged.attestation));
  refused(w, { kind: "anthillOwner", ...forged }, "signature");
  refused(w, { kind: "anthillOwner", ...w.signedOwner(A, key, { community: "other" }) }, "invalid-value");
  refused(w, { kind: "anthillOwner", ...w.signedOwner("alice", key) }, "invalid-value");
  // An agent key may not relay it.
  w.join(B);
  refused(w, { kind: "anthillOwner", ...w.signedOwner(A, key) }, "unauthorised", w.agentKeys.get(B));
});

test("a linked ledger refuses ownerKey; an unlinked one refuses the Anthill entries", () => {
  const linked = new World();
  refused(linked, { kind: "ownerKey", owner: "alice", publicKey: generateKeyPair().publicKey, inviter: null }, "unauthorised", linked.admin);
  const plain = new World(false);
  refused(plain, { kind: "anthillTree", ...plain.signedTree(PARENTS) }, "unauthorised");
  refused(plain, { kind: "anthillOwner", ...plain.signedOwner(A, generateKeyPair().publicKey) }, "unauthorised");
});

test("replay rebuilds the pinned tree and owners", () => {
  const w = new World();
  w.pin();
  w.join(A2).join(B2, "gpt");
  w.pin({ ...PARENTS, [OUTSIDER]: ROOT });
  const again = replay(w.entries);
  assert.equal(memberDigest(again), memberDigest(w.state));
  assert.equal(again.anthill?.tree?.version, 2);
  assert.ok(again.owners.has(B2));
});

// ---------------------------------------------------------------------------
// Reviewer draws over the pinned tree
// ---------------------------------------------------------------------------

test("selection: draws over the pinned tree; close members and owners outside it get no seat", () => {
  const w = new World();
  w.pin();
  w.join(A2).join(A1, "gpt").join(B1, "gpt").join(B2, "gpt").join(OUTSIDER, "gpt");
  w.submit(A2);
  const sel = selectReviewers(w.state, "s1", "f".repeat(64));
  const owners = sel.reviewers.map((k) => w.state.agents.get(k)?.owner);
  assert.ok(!owners.includes(A1), "a1 is 1 from the author: too close");
  assert.ok(!owners.includes(OUTSIDER), "not in the pinned tree: no seat");
  assert.deepEqual([...owners].sort(), [B1, B2].sort());
});

test("selection: an author outside the pinned tree gets no reviewers until a pin includes them", () => {
  const w = new World();
  w.pin();
  w.join(OUTSIDER).join(B2, "gpt");
  w.submit(OUTSIDER);
  assert.deepEqual(selectReviewers(w.state, "s1", "f".repeat(64)).reviewers, []);
  w.pin({ ...PARENTS, [OUTSIDER]: A2 });
  assert.equal(selectReviewers(w.state, "s1", "f".repeat(64)).reviewers.length, 1);
});

test("an assignment records the pinned tree's digest; a later pin does not make it unverifiable", () => {
  const w = new World();
  w.pin();
  w.join(A2).join(B1, "gpt").join(B2, "gpt");
  w.submit(A2);
  const before = memberDigest(w.state);
  const drawn = drawAssignment(w.state, "s1", "round-1");
  assert.equal(drawn.reviewers.length, 2);
  w.append(drawn.body);
  assert.equal(w.state.submissions.get("s1")?.assignment?.treeDigest, before);
  // The tree changes afterwards: b1 moves under a's branch, next to the author.
  w.pin({ ...PARENTS, [B1]: A, [B2]: B1 });
  assert.notEqual(memberDigest(w.state), before);
  assert.ok(verifyAssignment(w.state, "s1"));
  assert.ok(verifyAssignmentInLedger(w.entries, "s1"));
});

// ---------------------------------------------------------------------------
// syncAnthillTree
// ---------------------------------------------------------------------------

test("syncAnthillTree pins a changed tree and skips an unchanged or older one", async () => {
  const w = new World();
  let served = w.signedTree(PARENTS);
  const fetchFn = (async () => new Response(JSON.stringify(served))) as unknown as typeof fetch;
  const append = async (b: EntryBody) => w.append(b);
  assert.equal(await syncAnthillTree(w.state, "http://anthill", append, fetchFn), 1);
  assert.equal(await syncAnthillTree(w.state, "http://anthill", append, fetchFn), null);
  served = w.signedTree(PARENTS); // newer version, same tree
  assert.equal(await syncAnthillTree(w.state, "http://anthill", append, fetchFn), null);
  served = w.signedTree({ ...PARENTS, [OUTSIDER]: ROOT });
  assert.equal(await syncAnthillTree(w.state, "http://anthill", append, fetchFn), 3);
  assert.ok(memberTree(w.state).has(OUTSIDER));
});
