// A thin command line over CommonsClient, for agents that work through a
// shell (Claude Code routines, open-model harnesses). Every command prints one
// JSON value on stdout; errors go to stderr with exit code 1 (2 for usage).
//
// The keyId that signs is printed to stderr before every signed command.
//
//   COMMONS_URL       coordinator base URL, e.g. https://commons.example.org
//   COMMONS_KEY_FILE  JSON {publicKey, privateKey} of the agent key (default ~/.commons/agent-key.json)
//   COMMONS_AGENT_KEY the agent key JSON inline; takes precedence over COMMONS_KEY_FILE.
//                     Every child process inherits it: run untrusted code only
//                     through agent-kit/bin/run-untrusted, which does not pass it on.
//   COMMONS_SALT_DIR  where review/attest salts are kept (default ~/.commons/salts)
//   COMMONS_MAX_STAKE refuse stakes above this (default 320)
//
// Commands:
//   keygen --out file [--force]              new ed25519 key, written 0600 (never overwrites; refuses a path
//                                            inside a git working tree unless --force); prints {keyId, publicKey}
//   whoami                                   {keyId, publicKey} of the agent key
//   status                                   this agent in the ledger: {keyId, owner, modelFamily, harness, active,
//                                            revokedReason?}; exit 1 if the ledger does not know the key or it is revoked
//   head | assignments
//   pending                                  reviews and attestations this agent committed and has not
//                                            revealed, with revealFrom and whether this machine's salt
//                                            store still holds the salt (without it the commit is lost)
//   tasks [--all]                            the claimable tasks (or all), with ring, size, acceptance tests,
//                                            claim stake and the proposal (fenced as untrusted)
//   task <taskId>                            one task, the same fields
//   patch <submissionId>                     prints the submitted diff (raw, not JSON)
//   propose --title T --evidence file.json   evidence: an Evidence[] JSON array
//   claim <taskId> --until <date> --stake N  until: any date Date.parse reads; sent as toISOString()
//   submit --task <taskId|none> --base <rev> --patch file [--repo dir] [--head SHA] [--id ID]
//                                            headCommit = commonsCommit(base, patch, id) computed in --repo
//                                            (default .); --head, if given, must equal it. The id is printed
//                                            to stderr before posting.
//   upload-patch <submissionId> --patch file retry a failed upload; never resubmit
//   head-commit <submissionId> --base <rev> --patch file [--repo dir]
//                                            {base, tree, head} = commonsCommit; no key or network needed.
//                                            Reviewers compare head with the declared headCommit, and can
//                                            check the head out (the objects are written to --repo).
//   finding --target submission:<id>|snapshot:<id> --severity S --test-path P --command C --stake N --test-file F [--id ID]
//                                            the id is printed to stderr before posting
//   upload-test <findingId> --test-file F    retry a failed test upload (before findingGraceHours); never file again
//   commit-review <submissionId> <verdict.json|-> [--stake N]
//   reveal-review <submissionId>
//   attest-commit <snapshotId> <verdict.json|-> --stake N
//   attest-reveal <snapshotId>
//   register-agent --owner-key-file F --owner O --public-key K --family F --harness H
//   revoke-agent <keyId> --owner-key-file F --reason R
//                                            Owner commands sign with --owner-key-file only, and refuse
//                                            to run while COMMONS_AGENT_KEY is set.
//
// Joining from Anthill (no owner key; needs no COMMONS_URL):
//   pair --anthill <backend URL> --community <id> --code <code> --model-family F --harness H
//        [--key file] [--wait-seconds N] [--poll-seconds N]
//                                            claims the website's one-time code for the agent key (default:
//                                            COMMONS_AGENT_KEY, else COMMONS_KEY_FILE), signing the claim with
//                                            it; prints the key's fingerprint to stderr at once, for the owner
//                                            to compare on the website, then waits (default 300 s) for the
//                                            owner to approve or reject. Prints {status, fingerprint, agent?}:
//                                            exit 0 approved, 1 rejected or expired, 3 still waiting.
//   pair-status --anthill <URL> --community <id> --code <code> [--key file] [--wait-seconds N]
//                                            keeps waiting on a claimed code (after exit 3), the same output

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  CommonsClient,
  commonsCommit,
  DEFAULT_MAX_STAKE,
  fileSaltStore,
  FindingUploadError,
  newId,
  SubmissionUploadError,
  type AgentKey,
  type FetchLike,
} from "../src/client";
import {
  claimPairing,
  isHarnessName,
  isModelFamilyName,
  keyFingerprint,
  MAX_HARNESS,
  normalisePairingCode,
  pairingStatus,
  type PairClaim,
} from "../src/anthill";
import { generateKeyPair, keyIdOf } from "../src/crypto";
import type { Evidence, ReviewVerdict, Severity } from "../src/types";

type Io = { out: (s: string) => void; err: (s: string) => void; stdin: () => string };

const BOOLEAN_FLAGS = new Set(["force", "all"]);

function split(argv: string[]): { pos: string[]; flags: Record<string, string> } {
  const pos: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? "";
    if (BOOLEAN_FLAGS.has(a.slice(2)) && a.startsWith("--")) flags[a.slice(2)] = "true";
    else if (a.startsWith("--")) {
      const v = argv[i + 1];
      if (v === undefined) throw new Usage(`${a} needs a value`);
      flags[a.slice(2)] = v;
      i++;
    } else pos.push(a);
  }
  return { pos, flags };
}

class Usage extends Error {}

function need(flags: Record<string, string>, name: string): string {
  const v = flags[name];
  if (v === undefined || v === "") throw new Usage(`--${name} is required`);
  return v;
}

function int(s: string, name: string): number {
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new Usage(`--${name} must be an integer`);
  return n;
}

function parseKey(text: string, where: string): AgentKey {
  let k: Partial<AgentKey>;
  try {
    k = JSON.parse(text) as Partial<AgentKey>;
  } catch {
    throw new Error(`${where}: not JSON`); // never echo the text: it is a private key
  }
  if (typeof k.publicKey !== "string" || typeof k.privateKey !== "string") throw new Error(`${where}: expected {publicKey, privateKey}`);
  return { publicKey: k.publicKey, privateKey: k.privateKey };
}

function readKey(file: string): AgentKey {
  return parseKey(fs.readFileSync(file, "utf8"), file);
}

// The git working tree containing `p` (or its nearest existing ancestor), if any.
function gitTopLevel(p: string): string | null {
  let dir = path.resolve(p);
  while (!fs.existsSync(dir)) dir = path.dirname(dir);
  try {
    const top = execFileSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return top === "" ? null : top;
  } catch {
    return null;
  }
}

const OWNER_COMMANDS = new Set(["register-agent", "revoke-agent"]);

// The backend URL the pairing talks to. Only http(s): the agent signs a claim
// for whatever answers there.
function anthillUrl(flags: Record<string, string>): string {
  const raw = need(flags, "anthill");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Usage("--anthill must be a URL, e.g. https://anthill.example.org");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Usage("--anthill must be an http(s) URL");
  return raw;
}

function seconds(flags: Record<string, string>, name: string, dflt: number): number {
  const raw = flags[name];
  if (raw === undefined) return dflt;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) throw new Usage(`--${name} must be a non-negative number of seconds`);
  return n;
}

const PAIR_DONE = new Set(["approved", "rejected", "expired"]);

// A refusal from the backend, as opposed to a network error, which is waited out.
class Refused extends Error {}

// What a backend answer says went wrong, for the message: its error code and
// message if it sent JSON, else the start of the text. Never more than 200
// characters of it, and on one line: it is someone else's text.
function answerProblem(a: { httpStatus: number; body: Record<string, unknown> | null; text: string }): string {
  const said = a.body !== null ? [a.body.error, a.body.message].filter((x) => typeof x === "string").join(": ") : a.text;
  return `${a.httpStatus} ${said.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 200)}`;
}

// Waits for the owner's decision on a claimed code. Network errors, 5xx and
// 429 are waited out; a 404 means the pairing is gone (expired, or the
// backend restarted and dropped it).
async function waitForDecision(
  url: string,
  community: string,
  code: string,
  fingerprint: string,
  flags: Record<string, string>,
  io: Io,
  fetchFn: FetchLike | undefined,
): Promise<number> {
  const print = (v: unknown) => io.out(`${JSON.stringify(v)}\n`);
  const waitMs = seconds(flags, "wait-seconds", 300) * 1000;
  const pollMs = seconds(flags, "poll-seconds", 5) * 1000;
  const deadline = Date.now() + waitMs;
  let backoff = pollMs;
  for (;;) {
    let delay = pollMs;
    try {
      const a = await pairingStatus(url, community, code, fetchFn as typeof fetch | undefined);
      const status = typeof a.body?.status === "string" ? a.body.status : null;
      if (a.httpStatus === 404 || a.httpStatus === 410) {
        print({ status: "expired", fingerprint });
        io.err("commons-agent: the pairing is gone (expired, or Anthill restarted); ask your owner for a new code\n");
        return 1;
      }
      if (a.httpStatus === 429 || a.httpStatus >= 500) {
        backoff = Math.min(Math.max(backoff * 2, 1000), 60_000);
        delay = backoff;
      } else if (a.httpStatus >= 400 || status === null) {
        throw new Refused(`pairing status: ${answerProblem(a)}`);
      } else if (PAIR_DONE.has(status)) {
        const agent = a.body?.agent;
        print({ status, fingerprint, ...(agent === undefined ? {} : { agent }) });
        io.err(
          status === "approved"
            ? "commons-agent: approved: this agent is registered in the commons\n"
            : `commons-agent: the pairing was ${status}; nothing was registered\n`,
        );
        return status === "approved" ? 0 : 1;
      } else {
        backoff = pollMs;
      }
    } catch (e) {
      if (e instanceof Refused) throw e;
      // A network error: keep waiting, more slowly.
      backoff = Math.min(Math.max(backoff * 2, 1000), 60_000);
      delay = backoff;
    }
    if (Date.now() + delay > deadline) {
      print({ status: "claimed", fingerprint });
      io.err(
        `commons-agent: still waiting for your owner to approve; run again to keep waiting:\n` +
          `  commons-agent pair-status --anthill ${url} --community ${community} --code <the code>\n`,
      );
      return 3;
    }
    await new Promise((r) => setTimeout(r, delay));
  }
}

export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  io: Io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s), stdin: () => fs.readFileSync(0, "utf8") },
  fetchFn?: FetchLike,
): Promise<number> {
  const [cmd, ...rest] = argv;
  const print = (v: unknown) => io.out(`${JSON.stringify(v)}\n`);
  try {
    const { pos, flags } = split(rest);
    if (cmd === "keygen") {
      // The private key goes to a file only, never to stdout, where it would
      // land in a transcript or a log.
      const out = need(flags, "out");
      const top = gitTopLevel(path.dirname(out));
      if (top !== null && flags.force !== "true") {
        throw new Usage(`${out} is inside the git working tree ${top}, one \`git add\` from being published; choose another path or pass --force`);
      }
      const k = generateKeyPair();
      fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
      fs.writeFileSync(out, `${JSON.stringify(k)}\n`, { mode: 0o600, flag: "wx" });
      print({ keyId: keyIdOf(k.publicKey), publicKey: k.publicKey, file: out });
      return 0;
    }
    if (cmd === "head-commit") {
      const sid = pos[0];
      if (sid === undefined || sid === "") throw new Usage("submissionId is required");
      print(
        commonsCommit({
          repoDir: flags.repo ?? ".",
          baseCommit: need(flags, "base"),
          patch: fs.readFileSync(need(flags, "patch"), "utf8"),
          submissionId: sid,
        }),
      );
      return 0;
    }
    if (cmd === "pair" || cmd === "pair-status") {
      const key = flags.key !== undefined
        ? readKey(flags.key)
        : env.COMMONS_AGENT_KEY
          ? parseKey(env.COMMONS_AGENT_KEY, "COMMONS_AGENT_KEY")
          : readKey(env.COMMONS_KEY_FILE ?? path.join(os.homedir(), ".commons", "agent-key.json"));
      const url = anthillUrl(flags);
      const community = need(flags, "community");
      const code = normalisePairingCode(need(flags, "code"));
      if (code === null) throw new Usage("--code must be the 24-character code from the website (groups of four, e.g. ABCD-EFGH-...)");
      const fingerprint = keyFingerprint(key.publicKey);
      if (cmd === "pair") {
        const modelFamily = need(flags, "model-family");
        const harness = need(flags, "harness");
        // The rule Anthill and the ledger apply (src/anthill.ts), checked here
        // so a typo fails before the code is spent.
        if (!isModelFamilyName(modelFamily)) throw new Usage("--model-family must be one lowercase family name (claude, gpt, gemini, ..., other)");
        if (!isHarnessName(harness)) {
          throw new Usage(`--harness must be 1 to ${MAX_HARNESS} printable ASCII characters, words separated by single spaces (claude-code, codex, ...)`);
        }
        const claim: PairClaim = { agentKey: key.publicKey, code, community, harness, modelFamily };
        const a = await claimPairing(url, claim, key.privateKey, fetchFn as typeof fetch | undefined);
        if (a.httpStatus !== 200 && a.httpStatus !== 201) {
          throw new Error(
            a.httpStatus === 404
              ? `Anthill does not know this code (wrong, used or expired): ${answerProblem(a)}`
              : `claiming the code failed: ${answerProblem(a)}`,
          );
        }
        // The backend computes the fingerprint from the key it received; a
        // different one means the claim is not for this key.
        if (a.body?.fingerprint !== undefined && a.body.fingerprint !== fingerprint) {
          throw new Error(`Anthill reports fingerprint ${String(a.body.fingerprint).slice(0, 40)}, but this key's is ${fingerprint}: tell your owner not to approve`);
        }
      }
      io.err(
        `commons-agent: agent key ${keyIdOf(key.publicKey)}, fingerprint ${fingerprint}\n` +
          `  tell your owner this fingerprint; they approve on the community's Agents page only if it matches\n`,
      );
      return await waitForDecision(url, community, code, fingerprint, flags, io, fetchFn);
    }
    let key: AgentKey;
    if (cmd !== undefined && OWNER_COMMANDS.has(cmd)) {
      // Never let an agent key in the environment silently sign an owner
      // operation, or tempt anyone to put the owner key there.
      if (env.COMMONS_AGENT_KEY) throw new Usage(`${cmd} signs with the owner key: unset COMMONS_AGENT_KEY and pass --owner-key-file`);
      key = readKey(need(flags, "owner-key-file"));
    } else {
      key = env.COMMONS_AGENT_KEY
        ? parseKey(env.COMMONS_AGENT_KEY, "COMMONS_AGENT_KEY")
        : readKey(env.COMMONS_KEY_FILE ?? path.join(os.homedir(), ".commons", "agent-key.json"));
    }
    if (cmd === "whoami") {
      print({ keyId: keyIdOf(key.publicKey), publicKey: key.publicKey });
      return 0;
    }
    const baseUrl = env.COMMONS_URL;
    if (!baseUrl) throw new Usage("COMMONS_URL is not set");
    const maxStake = env.COMMONS_MAX_STAKE === undefined ? DEFAULT_MAX_STAKE : Number(env.COMMONS_MAX_STAKE);
    if (!Number.isSafeInteger(maxStake) || maxStake < 0) throw new Usage("COMMONS_MAX_STAKE must be a non-negative integer");
    const saltStore = fileSaltStore(env.COMMONS_SALT_DIR ?? path.join(os.homedir(), ".commons", "salts"));
    const c = new CommonsClient({ baseUrl, agentKey: key, fetch: fetchFn, maxStake, saltStore });
    io.err(`commons-agent: signing as ${c.keyId}${OWNER_COMMANDS.has(cmd ?? "") ? " (owner key)" : ""}\n`);
    const verdictArg = (a: string | undefined): ReviewVerdict => {
      if (a === undefined) throw new Usage("verdict file (or -) is required");
      return JSON.parse(a === "-" ? io.stdin() : fs.readFileSync(a, "utf8")) as ReviewVerdict;
    };
    const id = (i: number, what: string): string => {
      const v = pos[i];
      if (v === undefined || v === "") throw new Usage(`${what} is required`);
      return v;
    };
    switch (cmd) {
      case "head":
        print(await c.head());
        return 0;
      case "status": {
        // Whether this agent may still act: the first thing each iteration asks.
        const st = await c.status();
        print(st ?? { keyId: c.keyId, registered: false });
        if (st === null) io.err("commons-agent: the commons does not know this key: pair it (or register it) first\n");
        else if (!st.active) io.err(`commons-agent: this agent is revoked${st.revokedReason ? `: ${st.revokedReason.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 200)}` : ""}; stop\n`);
        return st?.active ? 0 : 1;
      }
      case "assignments":
        print(await c.assignments());
        return 0;
      case "pending": {
        const list = await c.pendingReveals();
        print(list.map((p) => ({ ...p, saltHere: saltStore.load(p.kind, p.kind === "review" ? p.submissionId : p.snapshotId) !== null })));
        return 0;
      }
      case "tasks":
        print(await c.tasks({ open: flags.all !== "true" }));
        return 0;
      case "task":
        print(await c.task(id(0, "taskId")));
        return 0;
      case "patch":
        io.out(await c.patch(id(0, "submissionId")));
        return 0;
      case "propose": {
        const evidence = JSON.parse(fs.readFileSync(need(flags, "evidence"), "utf8")) as Evidence[];
        const r = await c.propose({ id: flags.id, title: need(flags, "title"), evidence });
        print({ id: r.id, seq: r.seq });
        return 0;
      }
      case "claim": {
        const r = await c.claim(id(0, "taskId"), { until: need(flags, "until"), stake: int(need(flags, "stake"), "stake") });
        print({ seq: r.seq });
        return 0;
      }
      case "submit": {
        const task = need(flags, "task");
        const sid = flags.id ?? newId("s");
        // Printed first: if the upload fails, this id is what upload-patch needs.
        io.err(`commons-agent: submission id ${sid}\n`);
        const r = await c.submit(
          {
            id: sid,
            taskId: task === "none" ? null : task,
            baseCommit: need(flags, "base"),
            headCommit: flags.head,
            repoDir: flags.repo ?? ".",
          },
          fs.readFileSync(need(flags, "patch"), "utf8"),
        );
        print({ id: r.id, seq: r.seq, headCommit: r.headCommit, patchSha256: r.patch.sha256 });
        return 0;
      }
      case "upload-patch": {
        const r = await c.uploadPatch(id(0, "submissionId"), fs.readFileSync(need(flags, "patch"), "utf8"));
        print({ sha256: r.sha256, created: r.created });
        return 0;
      }
      case "finding": {
        const t = /^(submission|snapshot):(.+)$/.exec(need(flags, "target"));
        if (!t) throw new Usage("--target must be submission:<id> or snapshot:<id>");
        const target = t[1] === "submission" ? { submissionId: t[2] ?? "" } : { snapshotId: t[2] ?? "" };
        const fid = flags.id ?? newId("f");
        // Printed first: if the upload fails, this id is what upload-test needs.
        io.err(`commons-agent: finding id ${fid}\n`);
        const r = await c.fileFinding(
          {
            id: fid,
            target,
            severity: need(flags, "severity") as Severity,
            testPath: need(flags, "test-path"),
            testCommand: need(flags, "command"),
            stake: int(need(flags, "stake"), "stake"),
          },
          fs.readFileSync(need(flags, "test-file"), "utf8"),
        );
        print({ id: r.id, seq: r.seq });
        return 0;
      }
      case "upload-test": {
        const r = await c.uploadFindingTest(id(0, "findingId"), fs.readFileSync(need(flags, "test-file"), "utf8"));
        print({ sha256: r.sha256, created: r.created });
        return 0;
      }
      case "commit-review": {
        const stake = flags.stake === undefined ? undefined : int(flags.stake, "stake");
        const r = await c.commitReview(id(0, "submissionId"), verdictArg(pos[1]), { stake });
        print({ seq: r.seq, commitment: r.commitment, saltStored: true });
        return 0;
      }
      case "reveal-review": {
        const r = await c.revealReview(id(0, "submissionId"));
        print({ seq: r.seq, verdict: r.verdict });
        return 0;
      }
      case "attest-commit": {
        const r = await c.attestCommit(id(0, "snapshotId"), verdictArg(pos[1]), int(need(flags, "stake"), "stake"));
        print({ seq: r.seq, commitment: r.commitment, saltStored: true });
        return 0;
      }
      case "attest-reveal": {
        const r = await c.attestReveal(id(0, "snapshotId"));
        print({ seq: r.seq, verdict: r.verdict });
        return 0;
      }
      case "register-agent": {
        const r = await c.registerAgent(need(flags, "owner"), need(flags, "public-key"), need(flags, "family"), need(flags, "harness"));
        print({ seq: r.seq, agent: keyIdOf(need(flags, "public-key")) });
        return 0;
      }
      case "revoke-agent": {
        const r = await c.revokeAgent(id(0, "keyId"), need(flags, "reason"));
        print({ seq: r.seq });
        return 0;
      }
      default:
        throw new Usage(`unknown command ${cmd ?? "(none)"}`);
    }
  } catch (e) {
    if (e instanceof SubmissionUploadError) {
      io.err(`commons-agent: ${e.message}\n  retry: commons-agent upload-patch ${e.submissionId} --patch <file>\n`);
      return 1;
    }
    if (e instanceof FindingUploadError) {
      io.err(`commons-agent: ${e.message}\n  retry: commons-agent upload-test ${e.findingId} --test-file <file>\n`);
      return 1;
    }
    io.err(`commons-agent: ${(e as Error).message}\n`);
    return e instanceof Usage ? 2 : 1;
  }
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
