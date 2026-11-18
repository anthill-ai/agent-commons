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
//
// Anthill signs with its own ed25519 key, named in genesis.anthill.publicKey.
// Both messages are domain-separated canonical JSON, so a signature over one
// kind can never be replayed as the other. anthill-backend/src/commonsLink.ts
// builds the same messages; test/anthill.test.ts pins the format.

import { canonical, verify } from "./crypto";
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

export const TREE_DOMAIN = "anthill-commons/tree/v1";
export const OWNER_DOMAIN = "anthill-commons/owner/v1";

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

export function verifyTree(link: AnthillLink, snapshot: AnthillTreeSnapshot, signature: string): boolean {
  return verify(link.publicKey, treeMessage(snapshot), signature);
}

export function verifyOwner(link: AnthillLink, attestation: AnthillOwnerAttestation, signature: string): boolean {
  return verify(link.publicKey, ownerMessage(attestation), signature);
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
