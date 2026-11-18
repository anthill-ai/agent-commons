import { test } from "node:test";
import assert from "node:assert/strict";

import { createHash } from "node:crypto";
import {
  agentMessage,
  agentRevokeMessage,
  type AnthillAgentAttestation,
  type AnthillAgentRevokeAttestation,
  type AnthillOwnerAttestation,
  type AnthillTreeSnapshot,
  keyFingerprint,
  normalisePairingCode,
  ownerMessage,
  pairMessage,
  syncAnthillTree,
  treeMessage,
} from "../src/anthill";
import { generateKeyPair, keyIdOf, sign } from "../src/crypto";
import { computeMetrics } from "../src/metrics";
import { evaluatePromotion } from "../src/promotion";
import { reviewerScores } from "../src/review";
import { route, type Site } from "../src/playground/render";
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

  signedAgent(id: string, agentKey: string, over: Partial<AnthillAgentAttestation> = {}) {
    const attestation: AnthillAgentAttestation = {
      agentKey,
      at: iso(this.minute),
      community: "builders",
      harness: "claude-code",
      modelFamily: "claude",
      user: id,
      ...over,
    };
    return { attestation, signature: sign(this.anthill.privateKey, agentMessage(attestation)) };
  }

  signedRevoke(id: string, agentKey: string, over: Partial<AnthillAgentRevokeAttestation> = {}) {
    const attestation: AnthillAgentRevokeAttestation = { agentKey, at: iso(this.minute), community: "builders", reason: "lost", user: id, ...over };
    return { attestation, signature: sign(this.anthill.privateKey, agentRevokeMessage(attestation)) };
  }

  // A member who connects an agent on the website: no owner key.
  connect(id: string, family = "claude"): Signer {
    const agent = generateKeyPair();
    this.agentKeys.set(id, agent);
    this.append({ kind: "anthillAgent", ...this.signedAgent(id, agent.publicKey, { modelFamily: family }) });
    return agent;
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

test("message format is pinned (anthill-backend/scripts/commonsLinkChecks.ts and agentChecks.ts check the same strings)", () => {
  assert.equal(
    treeMessage({ community: "builders", version: 7, at: "2026-01-01T00:00:00.000Z", parents: { "0xb": "0xa", "0xa": null } }),
    'anthill-commons/tree/v1\n{"at":"2026-01-01T00:00:00.000Z","community":"builders","parents":{"0xa":null,"0xb":"0xa"},"version":7}',
  );
  assert.equal(
    ownerMessage({ community: "builders", user: "0xa", publicKey: "KEY", at: "2026-01-01T00:00:00.000Z" }),
    'anthill-commons/owner/v1\n{"at":"2026-01-01T00:00:00.000Z","community":"builders","publicKey":"KEY","user":"0xa"}',
  );
  const u = `0x${"a".repeat(40)}`;
  assert.equal(
    agentMessage({ agentKey: "KEY", at: "2026-01-01T00:00:00.000Z", community: "builders", harness: "claude-code", modelFamily: "claude", user: u }),
    'anthill-commons/agent/v1\n{"agentKey":"KEY","at":"2026-01-01T00:00:00.000Z","community":"builders","harness":"claude-code","modelFamily":"claude","user":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
  );
  assert.equal(
    agentRevokeMessage({ agentKey: "KEY", at: "2026-01-01T00:00:00.000Z", community: "builders", reason: "lost", user: u }),
    'anthill-commons/agent-revoke/v1\n{"agentKey":"KEY","at":"2026-01-01T00:00:00.000Z","community":"builders","reason":"lost","user":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
  );
  assert.equal(
    pairMessage({ agentKey: "KEY", code: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX", community: "builders", harness: "claude-code", modelFamily: "claude" }),
    'anthill-commons/pair/v1\n{"agentKey":"KEY","code":"ABCD-EFGH-IJKL-MNOP-QRST-UVWX","community":"builders","harness":"claude-code","modelFamily":"claude"}',
  );
});

test("fingerprints and signatures are pinned: ed25519 is deterministic, so the backend can check the same values", () => {
  // The key whose PKCS8 seed is 32 bytes of 0x01.
  const seeded = {
    publicKey: "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    privateKey: "MC4CAQAwBQYDK2VwBCIEIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
  };
  assert.equal(keyFingerprint(seeded.publicKey), "fd11-0d30-1d2f-077d");
  const der = Buffer.from(seeded.publicKey, "base64url");
  assert.equal(keyFingerprint(seeded.publicKey), (createHash("sha256").update(der).digest("hex").slice(0, 16).match(/.{4}/g) as string[]).join("-"));
  assert.equal(keyFingerprint("KEY"), "377b-ec8e-02c8-0365");
  const u = `0x${"a".repeat(40)}`;
  const at = "2026-01-01T00:00:00.000Z";
  assert.equal(
    sign(seeded.privateKey, agentMessage({ agentKey: "KEY", at, community: "builders", harness: "claude-code", modelFamily: "claude", user: u })),
    "syWPwQ3hASgNzNVS-bfO1xPw7k9tFH5tUPwgFzsnadBsF5eI58c8q_9fqQQTLIsNSjF8h9Zbt-Afk5kZ3jDkBg",
  );
  assert.equal(
    sign(seeded.privateKey, agentRevokeMessage({ agentKey: "KEY", at, community: "builders", reason: "lost", user: u })),
    "juzkvF8VrNooaEJZpbbIRUeH0yhgfVu1o8wy_NGEz-5GF0IJzK9pzuzyJlVvqdV0h7T5Mw1eum_Kk2mPUNsQAQ",
  );
  assert.equal(
    sign(seeded.privateKey, pairMessage({ agentKey: "KEY", code: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX", community: "builders", harness: "claude-code", modelFamily: "claude" })),
    "QMejVUwqRgg5LnmMMD40tN3DqF9It4Y59dwRgxSUZLdJlKpjLOIYnJdr1hM9V610ziikotl06DhScxhvKJToBA",
  );
});

test("pairing codes are put in their one spelling before they are signed", () => {
  assert.equal(normalisePairingCode("ABCD-EFGH-IJKL-MNOP-QRST-UVWX"), "ABCD-EFGH-IJKL-MNOP-QRST-UVWX");
  assert.equal(normalisePairingCode(" abcd efgh-ijklmnop qrst uvwx\n"), "ABCD-EFGH-IJKL-MNOP-QRST-UVWX");
  assert.equal(normalisePairingCode("ABCD-EFGH"), null);
  assert.equal(normalisePairingCode("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-Y"), null);
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

// ---------------------------------------------------------------------------
// anthillAgent and anthillAgentRevoked: Anthill vouches for agents directly
// ---------------------------------------------------------------------------

test("anthillAgent: registers the agent and admits its member as an owner without a key", () => {
  const w = new World();
  const agent = w.connect(A);
  const keyId = keyIdOf(agent.publicKey);
  const owner = w.state.owners.get(A);
  assert.deepEqual(owner, { id: A, keyId: null, inviter: null, reputationDelta: 0, lockedStake: 0, registeredSeq: 1 });
  // Exactly what agentRegistered builds.
  assert.deepEqual(w.state.agents.get(keyId), { keyId, owner: A, modelFamily: "claude", harness: "claude-code", active: true, registeredSeq: 1 });
  assert.equal(w.state.publicKeys.get(keyId), agent.publicKey);
  assert.equal([...w.state.ownerByKey.values()].includes(A), false, "a keyless owner has no key to sign with");
  // The agent signs like any other.
  w.append({ kind: "proposal", id: "p1", title: "fix", evidence: [{ kind: "location", file: "a.ts", line: 1, note: "n" }] }, agent);
  assert.equal(w.state.proposals.get("p1")?.by, keyId);
  // A second agent joins the same owner; the admin may relay too.
  const second = generateKeyPair();
  w.append({ kind: "anthillAgent", ...w.signedAgent(A, second.publicKey, { modelFamily: "gpt", harness: "codex" }) }, w.admin);
  assert.equal(w.state.agents.get(keyIdOf(second.publicKey))?.owner, A);
  assert.equal(w.state.owners.size, 1);
});

test("anthillAgent: a member with an owner key gets the agent under that owner", () => {
  const w = new World();
  w.join(A);
  const ownerKey = w.state.owners.get(A)?.keyId;
  const agent = generateKeyPair();
  w.append({ kind: "anthillAgent", ...w.signedAgent(A, agent.publicKey) });
  assert.equal(w.state.agents.get(keyIdOf(agent.publicKey))?.owner, A);
  assert.equal(w.state.owners.get(A)?.keyId, ownerKey);
  // And the owner key may revoke it like its own registrations.
  w.append({ kind: "agentRevoked", agent: keyIdOf(agent.publicKey), reason: "rotated" }, w.ownerKeys.get(A));
  assert.equal(w.state.agents.get(keyIdOf(agent.publicKey))?.revokedBy, "owner");
});

test("anthillAgent: refused for another community, a bad signature, an unknown family, a known key, a late or sloppy attestation", () => {
  const w = new World();
  const key = generateKeyPair().publicKey;
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { community: "other" }) }, "invalid-value");
  const forged = w.signedAgent(A, key);
  forged.signature = sign(w.admin.privateKey, agentMessage(forged.attestation));
  refused(w, { kind: "anthillAgent", ...forged }, "signature");
  // Anthill's signature over the same fields under another domain does not pass.
  const asOwner = w.signedAgent(A, key);
  asOwner.signature = sign(w.anthill.privateKey, `anthill-commons/owner/v1\n${agentMessage(asOwner.attestation).split("\n")[1]}`);
  refused(w, { kind: "anthillAgent", ...asOwner }, "signature");
  // Signed over different contents than it carries.
  const swapped = w.signedAgent(A, key);
  refused(w, { kind: "anthillAgent", attestation: { ...swapped.attestation, user: B }, signature: swapped.signature }, "signature");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { modelFamily: "Claude" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { modelFamily: "anthropic" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { harness: "claude\ncode" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { harness: "x".repeat(65) }) }, "invalid-value");
  // One rule with the kit and Anthill: printable ASCII words, single spaces.
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { harness: "claude  code" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { harness: " claude-code" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { harness: "cl\u00e4ude" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { modelFamily: "-claude" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { at: "2026-01-01T00:00:00Z" }) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent("alice", key) }, "invalid-value");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key, { at: iso(9_999) }) }, "time");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, "not-a-key") }, "invalid-key");
  const extra = w.signedAgent(A, key);
  refused(w, { kind: "anthillAgent", attestation: { ...extra.attestation, publicKey: key } as AnthillAgentAttestation, signature: extra.signature }, "invalid-value");
  // Any key the ledger knows: an agent's, an owner's, the coordinator's.
  w.join(B);
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, (w.agentKeys.get(B) as Signer).publicKey) }, "duplicate-key");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, (w.ownerKeys.get(B) as Signer).publicKey) }, "duplicate-key");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, w.coord.publicKey) }, "duplicate-key");
  // Only the coordinator or an admin relays: not an agent, not an owner.
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key) }, "unauthorised", w.agentKeys.get(B));
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, key) }, "unauthorised", w.ownerKeys.get(B));
  // Nothing above changed the state.
  assert.equal(w.state.owners.has(A), false);
  w.append({ kind: "anthillAgent", ...w.signedAgent(A, key) });
  assert.ok(w.state.owners.has(A));
});

test("an unlinked ledger refuses the agent entries", () => {
  const plain = new World(false);
  const key = generateKeyPair().publicKey;
  refused(plain, { kind: "anthillAgent", ...plain.signedAgent(A, key) }, "unauthorised");
  refused(plain, { kind: "anthillAgentRevoked", ...plain.signedRevoke(A, key) }, "unauthorised");
});

test("anthillAgentRevoked: revokes the member's own active agent, as its owner, for good", () => {
  const w = new World();
  const agent = w.connect(A);
  const keyId = keyIdOf(agent.publicKey);
  const e = w.append({ kind: "anthillAgentRevoked", ...w.signedRevoke(A, agent.publicKey, { reason: "lost the sandbox" }) });
  assert.deepEqual(w.state.agents.get(keyId), {
    keyId,
    owner: A,
    modelFamily: "claude",
    harness: "claude-code",
    active: false,
    registeredSeq: 1,
    revokedReason: "lost the sandbox",
    revokedBy: "owner",
    revokedSeq: e.seq,
  });
  // A revoked agent signs nothing more.
  refused(w, { kind: "proposal", id: "p1", title: "x", evidence: [{ kind: "location", file: "a.ts", line: 1, note: "n" }] }, "signer-revoked", agent);
  // Twice is refused, and so is registering the key again.
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(A, agent.publicKey) }, "inactive-agent");
  refused(w, { kind: "anthillAgent", ...w.signedAgent(A, agent.publicKey) }, "duplicate-key");
  // An empty reason is allowed; an over-long one is not.
  const other = w.connect(B);
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(B, other.publicKey, { reason: "x".repeat(201) }) }, "invalid-value");
  w.append({ kind: "anthillAgentRevoked", ...w.signedRevoke(B, other.publicKey, { reason: "" }) });
  assert.equal(w.state.agents.get(keyIdOf(other.publicKey))?.revokedReason, "");
});

test("anthillAgentRevoked: refused for someone else's agent, an unknown agent, a bad signature or another community", () => {
  const w = new World();
  const agent = w.connect(A);
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(B, agent.publicKey) }, "unauthorised");
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(A, generateKeyPair().publicKey) }, "unknown-ref");
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(A, "nope") }, "invalid-key");
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(A, agent.publicKey, { community: "other" }) }, "invalid-value");
  const forged = w.signedRevoke(A, agent.publicKey);
  forged.signature = sign(w.coord.privateKey, agentRevokeMessage(forged.attestation));
  refused(w, { kind: "anthillAgentRevoked", ...forged }, "signature");
  // A registration signature is not a revocation one.
  const reg = w.signedAgent(A, agent.publicKey);
  refused(w, { kind: "anthillAgentRevoked", attestation: w.signedRevoke(A, agent.publicKey).attestation, signature: reg.signature }, "signature");
  refused(w, { kind: "anthillAgentRevoked", ...w.signedRevoke(A, agent.publicKey) }, "unauthorised", agent);
  assert.equal(w.state.agents.get(keyIdOf(agent.publicKey))?.active, true);
});

test("a keyless owner takes an owner key later with anthillOwner, keeping their agents", () => {
  const w = new World();
  const agent = w.connect(A);
  const ownerKey = generateKeyPair();
  w.append({ kind: "anthillOwner", ...w.signedOwner(A, ownerKey.publicKey) });
  const o = w.state.owners.get(A);
  assert.equal(o?.keyId, keyIdOf(ownerKey.publicKey));
  assert.equal(o?.registeredSeq, 1, "still the owner who joined at seq 1");
  assert.equal(w.state.ownerByKey.get(keyIdOf(ownerKey.publicKey)), A);
  // Now they sign for themselves: revoke the Anthill-vouched agent, register another.
  w.append({ kind: "agentRevoked", agent: keyIdOf(agent.publicKey), reason: "rotated" }, ownerKey);
  w.append({ kind: "agentRegistered", owner: A, publicKey: generateKeyPair().publicKey, modelFamily: "gpt", harness: "cli" }, ownerKey);
  refused(w, { kind: "anthillOwner", ...w.signedOwner(A, generateKeyPair().publicKey) }, "duplicate-id");
  assert.deepEqual(replay(w.entries).owners.get(A), w.state.owners.get(A));
});

test("an owner without a key cannot register agents with agentRegistered: no key of theirs signs", () => {
  const w = new World();
  w.connect(A);
  w.join(B);
  refused(
    w,
    { kind: "agentRegistered", owner: A, publicKey: generateKeyPair().publicKey, modelFamily: "claude", harness: "x" },
    "unauthorised",
    w.ownerKeys.get(B),
  );
});

test("replay rebuilds Anthill-vouched agents and revocations exactly", () => {
  const w = new World();
  w.pin();
  const a = w.connect(A2);
  w.join(B2, "gpt");
  w.append({ kind: "anthillAgent", ...w.signedAgent(B2, generateKeyPair().publicKey, { modelFamily: "gemini" }) });
  w.append({ kind: "anthillAgentRevoked", ...w.signedRevoke(A2, a.publicKey) });
  const again = replay(w.entries);
  assert.deepEqual([...again.owners.entries()], [...w.state.owners.entries()]);
  assert.deepEqual([...again.agents.entries()], [...w.state.agents.entries()]);
  assert.equal(again.headHash, w.state.headHash);
  // Every prefix replays too (what the playground's follower and stateAt rely on).
  for (let n = 1; n <= w.entries.length; n++) replay(w.entries.slice(0, n));
});

test("selection: an attested agent of a keyless owner in the pinned tree reviews; outside it, it does not", () => {
  const w = new World();
  w.pin();
  w.join(A2);
  w.connect(B2, "gpt");
  w.connect(OUTSIDER, "gemini");
  w.submit(A2);
  const sel = selectReviewers(w.state, "s1", "f".repeat(64));
  assert.deepEqual(sel.reviewers.map((k) => w.state.agents.get(k)?.owner), [B2]);
  const drawn = drawAssignment(w.state, "s1", "round-1");
  w.append(drawn.body);
  // The reviewer commits; later its member revokes it. The draw stays verifiable
  // over the pool as it was.
  const reviewer = w.agentKeys.get(B2) as Signer;
  w.append({ kind: "anthillAgentRevoked", ...w.signedRevoke(B2, reviewer.publicKey) });
  assert.ok(verifyAssignment(w.state, "s1"));
  assert.ok(verifyAssignmentInLedger(w.entries, "s1"));
  // An author whose agent was attested gets reviewers like anyone.
  const v = new World();
  v.pin();
  v.connect(A2);
  v.join(B1, "gpt");
  v.submit(A2);
  assert.equal(selectReviewers(v.state, "s1", "f".repeat(64)).reviewers.length, 1);
});

test("an owner without a key goes through metrics and the playground", () => {
  const w = new World();
  w.pin();
  const agent = w.connect(A2);
  w.append({ kind: "proposal", id: "p1", title: "fix", evidence: [{ kind: "location", file: "a.ts", line: 1, note: "n" }] }, agent);
  // Active through its agent: the owner itself never signs.
  const active = computeMetrics(w.state, iso(w.minute + 1)).find((r) => r.metric === "active owners");
  assert.equal(active?.value, 1);
  w.append({ kind: "anthillAgent", ...w.signedAgent(A2, generateKeyPair().publicKey, { harness: "codex", modelFamily: "gpt" }) });
  w.append({ kind: "anthillAgentRevoked", ...w.signedRevoke(A2, agent.publicKey, { reason: "lost" }) });
  const nowIso = iso(w.minute + 1);
  const rows = computeMetrics(w.state, nowIso);
  assert.ok(rows.length > 0);
  const site: Site = {
    state: w.state,
    entries: w.entries,
    nowIso,
    log: () => {},
    derive: { metrics: () => rows, promotion: (id: string) => evaluatePromotion(w.state, id, nowIso), reviewerScores: () => reviewerScores(w.state, nowIso) },
  };
  const owner = route(() => site, "GET", `/owners/${A2}`);
  assert.equal(owner.status, 200);
  assert.match(owner.body, /none: Anthill vouches for their agents/);
  const home = route(() => site, "GET", "/");
  assert.equal(home.status, 200);
  assert.match(home.body, /connected agent/);
  assert.match(home.body, /revoked by its owner through Anthill/);
  const state = route(() => site, "GET", "/api/state");
  assert.equal(state.status, 200);
  assert.equal(route(() => site, "GET", "/api/metrics").status, 200);
});
