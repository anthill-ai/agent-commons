import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";

import { main as agentMain } from "../agent-kit/commons-agent";
import {
  agentMessage,
  agentRevokeMessage,
  type AnthillAgentAttestation,
  keyFingerprint,
  normalisePairingCode,
  pairMessage,
} from "../src/anthill";
import { main as cliMain } from "../src/cli";
import { generateKeyPair, keyIdOf, sign, verify } from "../src/crypto";
import { Ledger, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { createCoordinatorServer, proxyMatcher, type CoordinatorServer } from "../src/server";

// Agents vouched for by Anthill, end to end on the commons side: the
// coordinator's relay routes and GET /api/agents, `commons serve --one-port`,
// and `commons-agent pair` against a stand-in for anthill-backend.

const user = (n: number) => `0x${n.toString(16).padStart(40, "0")}`;
const [A, B] = [user(0xa), user(0xb)];
const tmp = (name: string) => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), `agents-test-${name}-`));
const nowIso = () => new Date().toISOString();

type Coordinator = { url: string; server: CoordinatorServer; anthill: Signer; ledgerPath: string; close: () => Promise<void> };

async function coordinator(linked = true): Promise<Coordinator> {
  const dir = tmp("coord");
  const ledgerPath = path.join(dir, "ledger.jsonl");
  const anthill = generateKeyPair();
  const coord = generateKeyPair();
  Ledger.create(
    ledgerPath,
    {
      kind: "genesis",
      project: "builders",
      admins: [generateKeyPair().publicKey],
      coordinator: coord.publicKey,
      rules: defaultRules(),
      ...(linked ? { anthill: { community: "builders", publicKey: anthill.publicKey } } : {}),
    },
    new Date(Date.now() - 60_000).toISOString(),
  );
  const server = createCoordinatorServer({
    ledgerPath,
    coordinatorKey: coord,
    clock: nowIso,
    patchesDir: path.join(dir, "patches"),
    policy: { submitCredits: () => 1, prSlots: () => 1, claimStake: () => 1 },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    server,
    anthill,
    ledgerPath,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

function signedAgent(anthill: Signer, id: string, agentKey: string, over: Partial<AnthillAgentAttestation> = {}) {
  const attestation: AnthillAgentAttestation = { agentKey, at: nowIso(), community: "builders", harness: "claude-code", modelFamily: "claude", user: id, ...over };
  return { attestation, signature: sign(anthill.privateKey, agentMessage(attestation)) };
}

function signedRevoke(anthill: Signer, id: string, agentKey: string, reason = "lost") {
  const attestation = { agentKey, at: nowIso(), community: "builders", reason, user: id };
  return { attestation, signature: sign(anthill.privateKey, agentRevokeMessage(attestation)) };
}

async function postJson(url: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// The coordinator's routes
// ---------------------------------------------------------------------------

test("POST /api/anthill/agent relays Anthill's attestation; a repeat is 409 already-registered", async () => {
  const c = await coordinator();
  try {
    const agent = generateKeyPair();
    const signed = signedAgent(c.anthill, A, agent.publicKey);
    const first = await postJson(`${c.url}/api/anthill/agent`, signed);
    assert.equal(first.status, 201, JSON.stringify(first.body));
    assert.deepEqual({ ...first.body, hash: undefined }, { seq: 1, hash: undefined, agent: keyIdOf(agent.publicKey), owner: A });
    const st = Ledger.open(c.ledgerPath).state();
    assert.equal(st.agents.get(keyIdOf(agent.publicKey))?.owner, A);
    assert.equal(st.owners.get(A)?.keyId, null);
    // Anthill retries after a lost answer: a distinct, harmless 409.
    const again = await postJson(`${c.url}/api/anthill/agent`, signed);
    assert.equal(again.status, 409);
    assert.equal(again.body.error, "already-registered");
    assert.equal(again.body.agent, keyIdOf(agent.publicKey));
    assert.equal(Ledger.open(c.ledgerPath).entries().length, 2, "nothing appended");
    // The ledger's refusals come back as 400 with its code.
    const forged = signedAgent(c.anthill, B, generateKeyPair().publicKey);
    forged.signature = sign(generateKeyPair().privateKey, agentMessage(forged.attestation));
    assert.deepEqual((await postJson(`${c.url}/api/anthill/agent`, forged)).body.error, "signature");
    const family = await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, B, generateKeyPair().publicKey, { modelFamily: "anthropic" }));
    assert.equal(family.status, 400);
    assert.equal(family.body.error, "invalid-value");
    // The same key for another member is the ledger's duplicate-key, not "done".
    const stolen = await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, B, agent.publicKey));
    assert.equal(stolen.status, 400);
    assert.equal(stolen.body.error, "duplicate-key");
    // Shape.
    assert.equal((await postJson(`${c.url}/api/anthill/agent`, "not json")).status, 400);
    assert.equal((await postJson(`${c.url}/api/anthill/agent`, { ...signed, extra: 1 })).body.error, "malformed");
    assert.equal((await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, A, "nope"))).body.error, "invalid-value");
  } finally {
    await c.close();
  }
});

test("POST /api/anthill/agent-revoke revokes; a repeat is 409 already-revoked; the key cannot come back", async () => {
  const c = await coordinator();
  try {
    const agent = generateKeyPair();
    const reg = signedAgent(c.anthill, A, agent.publicKey);
    assert.equal((await postJson(`${c.url}/api/anthill/agent`, reg)).status, 201);
    const notMine = await postJson(`${c.url}/api/anthill/agent-revoke`, signedRevoke(c.anthill, B, agent.publicKey));
    assert.equal(notMine.status, 400);
    assert.equal(notMine.body.error, "unauthorised");
    const revoke = signedRevoke(c.anthill, A, agent.publicKey, "lost the sandbox");
    const done = await postJson(`${c.url}/api/anthill/agent-revoke`, revoke);
    assert.equal(done.status, 201, JSON.stringify(done.body));
    assert.equal(done.body.agent, keyIdOf(agent.publicKey));
    assert.equal(done.body.owner, A);
    const again = await postJson(`${c.url}/api/anthill/agent-revoke`, revoke);
    assert.equal(again.status, 409);
    assert.equal(again.body.error, "already-revoked");
    // Re-registering a revoked key is not "done": the website must say to pair a new key.
    const back = await postJson(`${c.url}/api/anthill/agent`, reg);
    assert.equal(back.status, 400);
    assert.equal(back.body.error, "agent-revoked");
    const unknown = await postJson(`${c.url}/api/anthill/agent-revoke`, signedRevoke(c.anthill, A, generateKeyPair().publicKey));
    assert.equal(unknown.body.error, "unknown-ref");
  } finally {
    await c.close();
  }
});

test("GET /api/agents?owner= lists an owner's agents with their public keys, oldest first, revoked ones included", async () => {
  const c = await coordinator();
  try {
    const first = generateKeyPair();
    const second = generateKeyPair();
    await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, A, first.publicKey));
    await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, A, second.publicKey, { modelFamily: "gpt", harness: "codex" }));
    await postJson(`${c.url}/api/anthill/agent`, signedAgent(c.anthill, B, generateKeyPair().publicKey));
    await postJson(`${c.url}/api/anthill/agent-revoke`, signedRevoke(c.anthill, A, first.publicKey, "lost"));
    const entries = Ledger.open(c.ledgerPath).entries();
    const r = await fetch(`${c.url}/api/agents?owner=${A}`);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), {
      owner: A,
      agents: [
        {
          keyId: keyIdOf(first.publicKey),
          publicKey: first.publicKey,
          modelFamily: "claude",
          harness: "claude-code",
          active: false,
          revokedReason: "lost",
          revokedBy: "owner",
          registeredAt: entries[1]?.at,
        },
        { keyId: keyIdOf(second.publicKey), publicKey: second.publicKey, modelFamily: "gpt", harness: "codex", active: true, registeredAt: entries[2]?.at },
      ],
    });
    assert.deepEqual(await (await fetch(`${c.url}/api/agents?owner=${user(0xc)}`)).json(), { owner: user(0xc), agents: [] });
    assert.equal((await fetch(`${c.url}/api/agents`)).status, 400);
  } finally {
    await c.close();
  }
});

test("the agent routes answer 404 not-linked on a ledger not linked to Anthill", async () => {
  const c = await coordinator(false);
  try {
    for (const route of ["agent", "agent-revoke", "owner"]) {
      const r = await postJson(`${c.url}/api/anthill/${route}`, signedAgent(c.anthill, A, generateKeyPair().publicKey));
      assert.equal(r.status, 404, route);
      assert.equal(r.body.error, "not-linked");
    }
  } finally {
    await c.close();
  }
});

test("trusted proxies: exact addresses and IPv4 ranges, IPv4-mapped peers included; a bad range throws", () => {
  const m = proxyMatcher(["10.0.0.0/8", "192.0.2.7", "::1"]);
  assert.ok(m("10.1.2.3"));
  assert.ok(m("::ffff:10.200.0.1"));
  assert.ok(m("192.0.2.7"));
  assert.ok(m("::ffff:192.0.2.7"));
  assert.ok(m("::1"));
  assert.ok(!m("11.0.0.1"));
  assert.ok(!m("192.0.2.8"));
  assert.ok(!m("2001:db8::1"));
  assert.ok(proxyMatcher(["0.0.0.0/0"])("203.0.113.1"));
  assert.ok(!proxyMatcher([])("127.0.0.1"));
  assert.throws(() => proxyMatcher(["10.0.0.0/33"]));
  assert.throws(() => proxyMatcher(["10.0.0/8"]));
  assert.throws(() => proxyMatcher(["300.0.0.0/8"]));
});

// ---------------------------------------------------------------------------
// commons serve --one-port
// ---------------------------------------------------------------------------

test("serve --one-port: the coordinator API and the playground on one port; two ports still work", async () => {
  const dir = tmp("serve");
  const run = async (...args: string[]) => {
    let out = "";
    const status = await cliMain(args, { cwd: dir, stdout: (t) => (out += t), stderr: (t) => (out += t) });
    return { status, out };
  };
  const anthill = generateKeyPair();
  for (const k of ["admin", "coord"]) assert.equal((await run("keygen", "--out", `${k}.json`)).status, 0);
  const init = await run(
    "init", "--project", "builders", "--admin-key", "admin.json", "--coordinator-key", "coord.json",
    "--preset", "phase1", "--anthill-community", "builders", "--anthill-key", anthill.publicKey,
  );
  assert.equal(init.status, 0, init.out);

  // Usage: one port needs the coordinator, and has no API port of its own.
  assert.equal((await run("serve", "--one-port", "--port", "0")).status, 2);
  assert.equal((await run("serve", "--one-port", "--coordinator", "--key", "coord.json", "--port", "0", "--api-port", "0")).status, 2);
  assert.equal((await run("serve", "--coordinator", "--key", "coord.json", "--port", "0", "--trusted-proxy", "10.0.0.0/40")).status, 2);

  const serve = async (args: string[], check: (out: string) => Promise<void>) => {
    let stop!: () => void;
    const until = new Promise<void>((r) => (stop = r));
    let out = "";
    const serving = cliMain(["serve", ...args], { cwd: dir, until, stdout: (t) => (out += t), stderr: (t) => (out += t) });
    try {
      await check(await (async () => {
        const deadline = Date.now() + 5000;
        const want = args.includes("--one-port") ? 1 : 2;
        while ((out.match(/on http:\/\//g) ?? []).length < want && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
        return out;
      })());
    } finally {
      stop();
    }
    assert.equal(await serving, 0, out);
  };

  await serve(["--coordinator", "--one-port", "--key", "coord.json", "--port", "0", "--trusted-proxy", "10.0.0.0/8"], async (out) => {
    const url = /coordinator API and playground on (http:\/\/\S+)/.exec(out)?.[1];
    assert.ok(url, out);
    assert.equal(((await (await fetch(`${url}/api/head`)).json()) as { nextSeq: number }).nextSeq, 1);
    const agent = generateKeyPair();
    const posted = await postJson(`${url}/api/anthill/agent`, signedAgent(anthill, A, agent.publicKey));
    assert.equal(posted.status, 201, JSON.stringify(posted.body));
    const agents = (await (await fetch(`${url}/api/agents?owner=${A}`)).json()) as { agents: { keyId: string }[] };
    assert.deepEqual(agents.agents.map((a) => a.keyId), [keyIdOf(agent.publicKey)]);
    // The playground answers what the API does not, and sees the new entry.
    const home = await fetch(`${url}/`);
    assert.equal(home.status, 200);
    assert.match(home.headers.get("content-type") ?? "", /text\/html/);
    assert.match(await home.text(), /connected agent/);
    const ownerPage = await fetch(`${url}/owners/${A}`);
    assert.equal(ownerPage.status, 200);
    assert.match(await ownerPage.text(), /none: Anthill vouches for their agents/);
    const state = (await (await fetch(`${url}/api/state`)).json()) as Record<string, unknown>;
    assert.ok(state !== null && typeof state === "object");
    assert.equal((await fetch(`${url}/no-such-page`)).status, 404);
    assert.equal((await fetch(`${url}/`, { method: "HEAD" })).status, 200);
  });

  await serve(["--coordinator", "--key", "coord.json", "--port", "0"], async (out) => {
    const api = /coordinator API on (http:\/\/\S+)/.exec(out)?.[1];
    const pg = /playground on (http:\/\/\S+)/.exec(out)?.[1];
    assert.ok(api && pg && api !== pg, out);
    assert.equal((await fetch(`${api}/api/head`)).status, 200);
    assert.equal((await fetch(`${api}/`)).status, 404, "two ports: the API has no playground behind it");
    assert.equal((await fetch(`${pg}/`)).status, 200);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// commons-agent pair, against a stand-in for anthill-backend's pairing routes
// ---------------------------------------------------------------------------

type Pairing = { code: string; agentKey?: string; modelFamily?: string; harness?: string; status: "open" | "claimed" | "approved" | "rejected"; polls: number };

// Checks the claim the way the backend must (proof over pairMessage under the
// agent key it names), relays the agent attestation to a real coordinator
// once "approved" (after `approveAfter` status polls), and keeps a log.
async function fakeAnthill(c: Coordinator, opts: { approveAfter?: number; reject?: boolean; fingerprint?: string } = {}) {
  const pairings = new Map<string, Pairing>();
  const log: string[] = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (d: Buffer) => (raw += d.toString()));
    req.on("end", () => {
      const send = (status: number, body: unknown) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
      const body = JSON.parse(raw || "{}") as Record<string, string>;
      log.push(`${req.method} ${req.url} ${Object.keys(body).sort().join(",")}`);
      const p = pairings.get(body.code ?? "");
      if (req.url === "/c/builders/commons/pairings/claim") {
        if (!p) return send(404, { error: "no-pairing", message: "no such code" });
        if (p.status !== "open") return send(409, { error: "claimed", message: "already claimed" });
        const claim = { agentKey: body.agentKey ?? "", code: body.code ?? "", community: "builders", harness: body.harness ?? "", modelFamily: body.modelFamily ?? "" };
        if (!verify(claim.agentKey, pairMessage(claim), body.proof ?? "")) return send(400, { error: "proof", message: "bad proof" });
        Object.assign(p, { status: "claimed", agentKey: claim.agentKey, modelFamily: claim.modelFamily, harness: claim.harness });
        return send(200, { status: "claimed", fingerprint: opts.fingerprint ?? keyFingerprint(claim.agentKey) });
      }
      if (req.url === "/c/builders/commons/pairings/claim-status") {
        if (!p) return send(404, { error: "no-pairing", message: "no such code" });
        p.polls++;
        if (p.status === "claimed" && p.polls > (opts.approveAfter ?? 1)) {
          if (opts.reject) {
            p.status = "rejected";
          } else {
            const signed = signedAgent(c.anthill, A, p.agentKey ?? "", { modelFamily: p.modelFamily, harness: p.harness });
            void postJson(`${c.url}/api/anthill/agent`, signed).then((r) => {
              p.status = r.status === 201 ? "approved" : "rejected";
            });
            return send(200, { status: "claimed" });
          }
        }
        return send(200, { status: p.status, ...(p.status === "approved" ? { agent: { keyId: keyIdOf(p.agentKey ?? "") } } : {}) });
      }
      send(404, { error: "not-found" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    open: (code: string) => pairings.set(code, { code, status: "open", polls: 0 }),
    pairings,
    log,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

test("commons-agent pair: claims with a proof, prints the fingerprint, waits for approval, and the agent is in the ledger", async () => {
  const c = await coordinator();
  const anthill = await fakeAnthill(c, { approveAfter: 2 });
  const dir = tmp("pair");
  try {
    const code = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ";
    anthill.open(code);
    const outs: string[] = [];
    const errs: string[] = [];
    const io = { out: (s: string) => void outs.push(s), err: (s: string) => void errs.push(s), stdin: () => "" };
    const keyFile = path.join(dir, "agent-key.json");
    assert.equal(await agentMain(["keygen", "--out", keyFile], {}, io), 0);
    const key = JSON.parse(fs.readFileSync(keyFile, "utf8")) as Signer;
    outs.length = 0;
    const args = ["pair", "--anthill", anthill.url, "--community", "builders", "--model-family", "claude", "--harness", "claude-code", "--key", keyFile, "--poll-seconds", "0.05"];
    // Typed the way people paste it: lowercase, spaces.
    assert.equal(await agentMain([...args, "--code", " abcd efgh jklm npqr stuv wxyz "], {}, io), 0, errs.join(""));
    assert.deepEqual(JSON.parse(outs.pop() ?? "{}"), { status: "approved", fingerprint: keyFingerprint(key.publicKey), agent: { keyId: keyIdOf(key.publicKey) } });
    assert.match(errs.join(""), new RegExp(`fingerprint ${keyFingerprint(key.publicKey)}`));
    assert.equal(anthill.pairings.get(code)?.agentKey, key.publicKey, "the normalised code was claimed");
    // The code never travels in a URL.
    assert.ok(anthill.log.every((l) => !l.includes("ABCD")), anthill.log.join("\n"));
    assert.ok(anthill.log.some((l) => l === "POST /c/builders/commons/pairings/claim agentKey,code,harness,modelFamily,proof"), anthill.log.join("\n"));
    const st = Ledger.open(c.ledgerPath).state();
    assert.equal(st.agents.get(keyIdOf(key.publicKey))?.owner, A);
    assert.equal(st.agents.get(keyIdOf(key.publicKey))?.harness, "claude-code");

    // A used code is refused; a wrong one too; neither is retried as if waiting.
    assert.equal(await agentMain([...args, "--code", code], {}, io), 1);
    assert.match(errs.join(""), /claiming the code failed: 409 claimed/);
    assert.equal(await agentMain([...args, "--code", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"], {}, io), 1);
    assert.match(errs.join(""), /does not know this code/);
    // Usage errors spend nothing.
    assert.equal(await agentMain([...args, "--code", "ABCD-EFGH"], {}, io), 2);
    assert.equal(await agentMain(["pair", "--anthill", "ftp://x", "--community", "builders", "--code", code, "--model-family", "claude", "--harness", "h", "--key", keyFile], {}, io), 2);
    errs.length = 0;
    const family = ["pair", "--anthill", anthill.url, "--community", "builders", "--code", code, "--harness", "h", "--key", keyFile, "--model-family", "Claude Opus"];
    assert.equal(await agentMain(family, {}, io), 2);
    assert.match(errs.join(""), /--model-family must be one lowercase word/);
    assert.equal(anthill.pairings.size, 1);
  } finally {
    await anthill.close();
    await c.close();
  }
});

test("commons-agent pair: a rejection, a timeout (exit 3, then pair-status), a fingerprint mismatch and an expired pairing", async () => {
  const c = await coordinator();
  const dir = tmp("pair2");
  const key = generateKeyPair();
  const env = { COMMONS_AGENT_KEY: JSON.stringify(key) };
  const outs: string[] = [];
  const errs: string[] = [];
  const io = { out: (s: string) => void outs.push(s), err: (s: string) => void errs.push(s), stdin: () => "" };
  const code = normalisePairingCode("abcdefghjkmnpqrstuvwxyz2") as string;
  const pair = (url: string, ...extra: string[]) =>
    agentMain(["pair", "--anthill", url, "--community", "builders", "--code", code, "--model-family", "gpt", "--harness", "codex", "--poll-seconds", "0.02", ...extra], env, io);
  try {
    const rejecting = await fakeAnthill(c, { reject: true });
    rejecting.open(code);
    assert.equal(await pair(rejecting.url), 1);
    assert.equal(JSON.parse(outs.pop() ?? "{}").status, "rejected");
    await rejecting.close();

    const slow = await fakeAnthill(c, { approveAfter: 1_000_000 });
    slow.open(code);
    assert.equal(await pair(slow.url, "--wait-seconds", "0.1"), 3);
    assert.deepEqual(JSON.parse(outs.pop() ?? "{}"), { status: "claimed", fingerprint: keyFingerprint(key.publicKey) });
    assert.match(errs.join(""), /commons-agent pair-status --anthill/);
    // Keep waiting without claiming again; then the pairing disappears.
    assert.equal(await agentMain(["pair-status", "--anthill", slow.url, "--community", "builders", "--code", code, "--wait-seconds", "0.1", "--poll-seconds", "0.02"], env, io), 3);
    slow.pairings.clear();
    assert.equal(await agentMain(["pair-status", "--anthill", slow.url, "--community", "builders", "--code", code, "--poll-seconds", "0.02"], env, io), 1);
    assert.equal(JSON.parse(outs.pop() ?? "{}").status, "expired");
    await slow.close();

    const lying = await fakeAnthill(c, { fingerprint: "0000-0000-0000-0000" });
    lying.open(code);
    assert.equal(await pair(lying.url), 1);
    assert.match(errs.join(""), /tell your owner not to approve/);
    await lying.close();
  } finally {
    await c.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
