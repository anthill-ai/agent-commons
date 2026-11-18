// The link to Anthill, the platform the commons' community lives on.
//
// A ledger whose genesis names an Anthill community (genesis.anthill) takes
// two things from Anthill instead of from its own admin:
//
// - who is close to whom: the coordinator pins Anthill's signed tree of the
//   community in the ledger (an anthillTree entry), and members.memberTree is
//   the latest pinned tree. The snapshot itself is in the ledger, not just its
//   hash, so anyone holding the ledger can still recompute every reviewer
//   draw, which is why the commons once dropped Anthill: a live tree changes
//   (people climb, move, leave) and a draw against it could not be checked
//   later.
// - who an owner is: a member signs in to Anthill and asks it to vouch that a
//   commons key is theirs. Anthill signs that attestation, and an
//   anthillOwner entry carrying it admits the member as an owner whose id is
//   their Anthill user id.
// - which agents a member runs: a member who works from a browser and a
//   disposable sandbox has nowhere good to keep an owner key, so Anthill can
//   vouch for an agent key directly. The member approves the agent on the
//   website (signed in), Anthill signs an agent attestation, and an
//   anthillAgent entry carrying it registers the agent under the member,
//   admitting them as an owner without a key if they were not one yet. This
//   is no new trust: Anthill can already vouch for any member's owner key.
//   An agent-revoke attestation (anthillAgentRevoked) revokes such an agent
//   the same way.
//
// Anthill signs with its own ed25519 key, named in genesis.anthill.publicKey.
// Every message is domain-separated canonical JSON, so a signature over one
// kind can never be replayed as another. anthill-backend/src/commonsLink.ts
// builds the same messages; test/anthill.test.ts pins the format.
//
// Pairing (anthill-backend's pairing routes, and `commons-agent pair`): an
// agent claims a one-time code with a proof that it holds the key it names,
// its own signature over pairMessage. The commons never checks a pairing
// proof (Anthill does), but the message is defined here, next to the others,
// so both sides build it from one definition.

import { canonical, sha256hex, sign, verify } from "./crypto";
import { FAMILY_RE } from "./rules";
import type { CommonsState, EntryBody } from "./types";

export type AnthillLink = { community: string; publicKey: string };

// Anthill's tree of one community as it signs it. `version` is Anthill's count
// of tree actions in the community, so it grows with every change; `parents`
// holds every member the root reaches, the root with parent null.
export type AnthillTreeSnapshot = {
  community: string;
  version: number;
  at: string;
  parents: Record<string, string | null>;
};

// Anthill vouching that `publicKey` is the commons key of its user `user`, a
// member of `community` when it signed.
export type AnthillOwnerAttestation = {
  community: string;
  user: string;
  publicKey: string;
  at: string;
};

// Anthill vouching that `agentKey` is an agent run by its user `user`, a
// member of `community` when it signed, declared as `modelFamily` (one of the
// ledger's rules.modelFamilies; the ledger checks) under `harness`.
export type AnthillAgentAttestation = {
  agentKey: string;
  at: string;
  community: string;
  harness: string;
  modelFamily: string;
  user: string;
};

// Anthill, at its user's request, revoking the agent `agentKey` it vouched for.
export type AnthillAgentRevokeAttestation = {
  agentKey: string;
  at: string;
  community: string;
  reason: string;
  user: string;
};

// What an agent signs with its own key to claim a pairing code.
export type PairClaim = {
  agentKey: string;
  code: string;
  community: string;
  harness: string;
  modelFamily: string;
};

export const TREE_DOMAIN = "anthill-commons/tree/v1";
export const OWNER_DOMAIN = "anthill-commons/owner/v1";
export const AGENT_DOMAIN = "anthill-commons/agent/v1";
export const AGENT_REVOKE_DOMAIN = "anthill-commons/agent-revoke/v1";
export const PAIR_DOMAIN = "anthill-commons/pair/v1";

// What an agent declares when it pairs, and Anthill signs. One rule, checked
// the same way by the kit's `pair` (so a typo fails before the code is spent),
// anthill-backend (src/commonsAgents.ts, when the member asks for a code and
// when the agent claims it), its website's Agents page, and the ledger:
// - modelFamily: a family name as rules.modelFamilies spells them (FAMILY_RE:
//   lowercase letters, digits, ".", "_" and "-", at most 64, starting with a
//   letter or digit). The ledger also requires it to be one of the list in force.
// - harness: 1 to 64 printable ASCII characters, words separated by single
//   spaces (no leading, trailing or double spaces): "claude-code", "codex",
//   "Aider 0.86". It is a name shown on the website and the playground, so it
//   carries nothing to normalise, nothing invisible, no line breaks and no
//   terminal escapes.
// A revoke's reason is a short sentence, at most 200 characters (the backend
// cleans it before signing).
export const MAX_HARNESS = 64;
export const MAX_REVOKE_REASON = 200;
export const HARNESS_RE = /^[!-~]+(?: [!-~]+)*$/;

export const isModelFamilyName = (v: unknown): v is string => typeof v === "string" && FAMILY_RE.test(v);
export const isHarnessName = (v: unknown): v is string => typeof v === "string" && v.length <= MAX_HARNESS && HARNESS_RE.test(v);

// When an agent attestation may be signed, against the entry that carries it
// (the entry's own `at`, so replay decides the same way every time). Anthill
// signs at relay time and relays at once, and a retry signs again, so:
// - an anthillAgent attestation older than ANTHILL_AGENT_MAX_AGE_MS is
//   refused. Nothing in it names one ledger, and every attestation that
//   landed is public (GET /api/entries): without a bound, a ledger re-created
//   for the same community (same Anthill key) would take an old attestation
//   whose revocation stayed behind in the old ledger. A revoke needs no bound:
//   replaying one can only revoke.
// - either kind may be signed up to ANTHILL_AGENT_SKEW_MS after the entry, the
//   coordinator's clock: Anthill's clock may run ahead of it (the API allows
//   agents the same skew). The two older kinds (anthillOwner, anthillTree)
//   keep their strict check, as existing ledgers replay them.
// So Anthill's and the coordinator's clocks must agree within the skew.
export const ANTHILL_AGENT_MAX_AGE_MS = 10 * 60_000;
export const ANTHILL_AGENT_SKEW_MS = 5 * 60_000;

// Most members one snapshot may hold. The ledger keeps every snapshot and
// every node replays them, so a snapshot is bounded like every other field.
export const MAX_SNAPSHOT_MEMBERS = 20_000;

// Anthill user ids: 0x and 40 lowercase hex digits (the off-chain backend's
// newUserId, and the addresses of the seeded demo tree). Lowercase only, so a
// member cannot appear under two spellings in one tree.
export const ANTHILL_USER_RE = /^0x[0-9a-f]{40}$/;

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export function treeMessage(snapshot: AnthillTreeSnapshot): string {
  return `${TREE_DOMAIN}\n${canonical(snapshot)}`;
}

export function ownerMessage(attestation: AnthillOwnerAttestation): string {
  return `${OWNER_DOMAIN}\n${canonical(attestation)}`;
}

export function agentMessage(attestation: AnthillAgentAttestation): string {
  return `${AGENT_DOMAIN}\n${canonical(attestation)}`;
}

export function agentRevokeMessage(attestation: AnthillAgentRevokeAttestation): string {
  return `${AGENT_REVOKE_DOMAIN}\n${canonical(attestation)}`;
}

export function pairMessage(claim: PairClaim): string {
  return `${PAIR_DOMAIN}\n${canonical(claim)}`;
}

// What a person compares on the website with what their agent printed: the
// first 8 bytes of sha256 over the agent key's DER, as 4 groups of 4 hex
// digits (3f2a-91bc-07de-55e1). Short enough to read aloud, long enough that
// nobody can make a key to match a given one.
export function keyFingerprint(publicKey: string): string {
  const hex = sha256hex(Buffer.from(publicKey, "base64url")).slice(0, 16);
  return (hex.match(/.{4}/g) as string[]).join("-");
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));

const exactKeys = (o: Record<string, unknown>, keys: string[]) =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

const isIso = (v: unknown): v is string => typeof v === "string" && ISO_RE.test(v) && !Number.isNaN(Date.parse(v));

// Problems with a snapshot's shape, before any signature or tree check.
// Structural soundness (one root, no cycle, every parent a member) is checked
// by building the tree (members.treeFromParents), which throws.
export function snapshotProblems(s: unknown): string[] {
  if (!isPlainObject(s)) return ["snapshot is not an object"];
  if (!exactKeys(s, ["community", "version", "at", "parents"])) return ["snapshot must have exactly community, version, at, parents"];
  const problems: string[] = [];
  if (typeof s.community !== "string" || s.community === "") problems.push("community must be a non-empty string");
  if (!Number.isSafeInteger(s.version) || (s.version as number) < 0) problems.push("version must be a non-negative integer");
  if (!isIso(s.at)) problems.push("at must be an ISO time in UTC");
  if (!isPlainObject(s.parents)) return [...problems, "parents must be an object"];
  const ids = Object.keys(s.parents);
  if (ids.length === 0) problems.push("parents is empty");
  if (ids.length > MAX_SNAPSHOT_MEMBERS) problems.push(`more than ${MAX_SNAPSHOT_MEMBERS} members`);
  for (const id of ids) {
    const parent = s.parents[id];
    if (!ANTHILL_USER_RE.test(id)) problems.push(`member ${JSON.stringify(id).slice(0, 80)} is not an Anthill user id`);
    else if (parent !== null && (typeof parent !== "string" || !ANTHILL_USER_RE.test(parent))) {
      problems.push(`parent of ${id} is not an Anthill user id or null`);
    }
    if (problems.length > 10) break;
  }
  return problems;
}

export function attestationProblems(a: unknown): string[] {
  if (!isPlainObject(a)) return ["attestation is not an object"];
  if (!exactKeys(a, ["community", "user", "publicKey", "at"])) return ["attestation must have exactly community, user, publicKey, at"];
  const problems: string[] = [];
  if (typeof a.community !== "string" || a.community === "") problems.push("community must be a non-empty string");
  if (typeof a.user !== "string" || !ANTHILL_USER_RE.test(a.user)) problems.push("user is not an Anthill user id");
  if (typeof a.publicKey !== "string") problems.push("publicKey must be a string");
  if (!isIso(a.at)) problems.push("at must be an ISO time in UTC");
  return problems;
}

// The time in the one spelling the agent messages use: toISOString's, with
// milliseconds, in UTC.
const isExactIso = (v: unknown): v is string => typeof v === "string" && isIso(v) && new Date(v).toISOString() === v;

export function agentAttestationProblems(a: unknown): string[] {
  if (!isPlainObject(a)) return ["attestation is not an object"];
  const keys = ["agentKey", "at", "community", "harness", "modelFamily", "user"];
  if (!exactKeys(a, keys)) return [`attestation must have exactly ${keys.join(", ")}`];
  const problems: string[] = [];
  if (typeof a.agentKey !== "string") problems.push("agentKey must be a string");
  if (!isExactIso(a.at)) problems.push("at must be an ISO time in UTC with milliseconds");
  if (typeof a.community !== "string" || a.community === "") problems.push("community must be a non-empty string");
  if (!isHarnessName(a.harness)) {
    problems.push(`harness must be 1 to ${MAX_HARNESS} printable ASCII characters, words separated by single spaces`);
  }
  // Membership of rules.modelFamilies is the ledger's check: it depends on the rules in force.
  if (!isModelFamilyName(a.modelFamily)) problems.push(`modelFamily must be a lowercase family name matching ${FAMILY_RE.source}`);
  if (typeof a.user !== "string" || !ANTHILL_USER_RE.test(a.user)) problems.push("user is not an Anthill user id");
  return problems;
}

export function agentRevokeProblems(a: unknown): string[] {
  if (!isPlainObject(a)) return ["attestation is not an object"];
  const keys = ["agentKey", "at", "community", "reason", "user"];
  if (!exactKeys(a, keys)) return [`attestation must have exactly ${keys.join(", ")}`];
  const problems: string[] = [];
  if (typeof a.agentKey !== "string") problems.push("agentKey must be a string");
  if (!isExactIso(a.at)) problems.push("at must be an ISO time in UTC with milliseconds");
  if (typeof a.community !== "string" || a.community === "") problems.push("community must be a non-empty string");
  if (typeof a.reason !== "string" || a.reason.length > MAX_REVOKE_REASON) problems.push(`reason must be at most ${MAX_REVOKE_REASON} characters`);
  if (typeof a.user !== "string" || !ANTHILL_USER_RE.test(a.user)) problems.push("user is not an Anthill user id");
  return problems;
}

export function verifyTree(link: AnthillLink, snapshot: AnthillTreeSnapshot, signature: string): boolean {
  return verify(link.publicKey, treeMessage(snapshot), signature);
}

export function verifyOwner(link: AnthillLink, attestation: AnthillOwnerAttestation, signature: string): boolean {
  return verify(link.publicKey, ownerMessage(attestation), signature);
}

export function verifyAgent(link: AnthillLink, attestation: AnthillAgentAttestation, signature: string): boolean {
  return verify(link.publicKey, agentMessage(attestation), signature);
}

export function verifyAgentRevoke(link: AnthillLink, attestation: AnthillAgentRevokeAttestation, signature: string): boolean {
  return verify(link.publicKey, agentRevokeMessage(attestation), signature);
}

// ---------------------------------------------------------------------------
// Talking to an Anthill backend (CLI and coordinator side; never in replay).
// ---------------------------------------------------------------------------

export type SignedTree = { snapshot: AnthillTreeSnapshot; signature: string };
export type SignedOwner = { attestation: AnthillOwnerAttestation; signature: string };

type Fetch = typeof globalThis.fetch;

const base = (url: string) => url.replace(/\/+$/, "");

async function getJson(fetchFn: Fetch, url: string, init?: RequestInit): Promise<unknown> {
  const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(15_000) });
  const text = await res.text();
  if (!res.ok) throw new Error(`anthill: ${init?.method ?? "GET"} ${url}: ${res.status} ${text.slice(0, 200)}`);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`anthill: ${url} did not answer JSON`);
  }
}

// Anthill's public signing key: what genesis.anthill.publicKey should hold.
export async function fetchAnthillKey(url: string, fetchFn: Fetch = globalThis.fetch): Promise<string> {
  const body = (await getJson(fetchFn, `${base(url)}/commons/key`)) as { publicKey?: unknown };
  if (typeof body.publicKey !== "string") throw new Error("anthill: /commons/key has no publicKey");
  return body.publicKey;
}

// The community's current signed tree. Not trusted here: the ledger checks the
// signature and the tree when the entry is appended.
export async function fetchAnthillTree(url: string, community: string, fetchFn: Fetch = globalThis.fetch): Promise<SignedTree> {
  return (await getJson(fetchFn, `${base(url)}/c/${encodeURIComponent(community)}/commons/tree`)) as SignedTree;
}

// Asks Anthill, as the signed-in member whose session token this is, to vouch
// for `publicKey`. The token is Anthill's own session token (the frontend keeps
// it in localStorage as anthill.session).
export async function requestOwnerAttestation(
  url: string,
  community: string,
  sessionToken: string,
  publicKey: string,
  fetchFn: Fetch = globalThis.fetch,
): Promise<SignedOwner> {
  return (await getJson(fetchFn, `${base(url)}/c/${encodeURIComponent(community)}/commons/owner`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({ publicKey }),
  })) as SignedOwner;
}

// Hands a signed attestation to a running coordinator, which relays it to the
// ledger (POST /api/anthill/owner).
export async function submitOwnerAttestation(coordinatorUrl: string, signed: SignedOwner, fetchFn: Fetch = globalThis.fetch): Promise<{ seq: number; owner: string }> {
  return (await getJson(fetchFn, `${base(coordinatorUrl)}/api/anthill/owner`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signed),
  })) as { seq: number; owner: string };
}

// Pins Anthill's current tree if it is newer than the pinned one. Returns the
// version pinned, or null when the ledger already has it (or is not linked).
export async function syncAnthillTree(
  state: Pick<CommonsState, "anthill">,
  url: string,
  append: (body: EntryBody) => Promise<unknown>,
  fetchFn: Fetch = globalThis.fetch,
): Promise<number | null> {
  if (state.anthill === undefined) return null;
  const signed = await fetchAnthillTree(url, state.anthill.link.community, fetchFn);
  // Anthill's version counts every action (votes, renames too), so a newer
  // version often has the same tree: pin only a changed one.
  const pinned = state.anthill.tree;
  if (pinned !== undefined && typeof signed.snapshot?.version === "number") {
    if (signed.snapshot.version <= pinned.version) return null;
    if (canonical(signed.snapshot.parents) === canonical(pinned.parents)) return null;
  }
  await append({ kind: "anthillTree", snapshot: signed.snapshot, signature: signed.signature });
  return signed.snapshot.version;
}

// ---------------------------------------------------------------------------
// Pairing an agent through Anthill (the agent side: commons-agent pair).
// ---------------------------------------------------------------------------

// A pairing code as the website shows it: 24 letters and digits in groups of
// four. People paste codes with spaces, lowercase or without dashes, so the
// code is put in this one spelling before it is signed and sent: the proof
// covers exactly the code the backend receives.
export function normalisePairingCode(code: string): string | null {
  const plain = code.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (plain.length !== 24) return null;
  return (plain.match(/.{4}/g) as string[]).join("-");
}

export type PairingAnswer = { httpStatus: number; body: Record<string, unknown> | null; text: string };

async function postPairing(fetchFn: Fetch, url: string, body: unknown): Promise<PairingAnswer> {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await res.text();
  let parsed: Record<string, unknown> | null = null;
  try {
    const v: unknown = JSON.parse(text);
    if (isPlainObject(v)) parsed = v;
  } catch {
    // Not JSON: the caller reports the status and the start of the text.
  }
  return { httpStatus: res.status, body: parsed, text };
}

const pairingsUrl = (url: string, community: string) => `${base(url)}/c/${encodeURIComponent(community)}/commons/pairings`;

// Claims a pairing code for the agent key `key`, with the key's signature over
// pairMessage as proof that the agent holds it. Anthill answers
// { status: "claimed", fingerprint } and shows the claim to the member who
// made the code.
export async function claimPairing(
  url: string,
  claim: PairClaim,
  privateKey: string,
  fetchFn: Fetch = globalThis.fetch,
): Promise<PairingAnswer> {
  const proof = sign(privateKey, pairMessage(claim));
  return postPairing(fetchFn, `${pairingsUrl(url, claim.community)}/claim`, {
    code: claim.code,
    agentKey: claim.agentKey,
    modelFamily: claim.modelFamily,
    harness: claim.harness,
    proof,
  });
}

// Where a claimed pairing stands. POST, so the code stays out of URLs and logs.
export async function pairingStatus(url: string, community: string, code: string, fetchFn: Fetch = globalThis.fetch): Promise<PairingAnswer> {
  return postPairing(fetchFn, `${pairingsUrl(url, community)}/claim-status`, { code });
}
