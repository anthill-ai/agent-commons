// A coordinator for an Anthill community that sets itself up on its first
// start (`commons host`; README, "Hosting a coordinator for an Anthill
// community"). Everything lives in one data directory:
//
//   <data>/commons-ledger.jsonl   the ledger
//   <data>/keys/coord.json        the coordinator key (0600, in a 0700 dir)
//   <data>/keys/admin.json        the admin key (on the disk by default; README)
//   <data>/target                 the coordinator's clone, with a dev branch (served
//                                 read-only at <base path>/api/git; every pass brings
//                                 origin's main into dev: gitHost.ts)
//   <data>/patches                patches and finding tests
//   <data>/agent-state            agents' encrypted state blobs (server.ts
//                                 /api/agent-state; not part of the ledger)
//
// Setup runs only while there is no ledger, and every step is safe to repeat
// after a crash at any point: nothing that exists is overwritten, and what a
// crash can leave half-done is detected and redone.
// - The clone is made in target.partial and renamed to target only once its
//   dev branch exists, so a target without a dev branch (or a leftover
//   target.partial) is a clone cut off midway, cloned again. No ledger
//   exists yet, so nothing has been merged into it.
// - A key is written to a temporary file, synced, and hard-linked to its
//   name, which fails if the name exists: a key file is whole or absent, and
//   an existing one is reused, never replaced.
// - init writes the genesis to commons-ledger.jsonl.setup, which is synced
//   and linked to the ledger's name the same way. The ledger's existence is
//   what says setup is done.
//
// Before anything is written, Anthill is asked for its signing key and the
// community's tree, and the tree's signature is checked against the key: the
// genesis is permanent, so a mistyped community or backend fails here, not
// in the first pass. One process per data directory (a single instance).

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { ANTHILL_USER_RE, fetchAnthillKey, fetchAnthillTree, treeMessage } from "./anthill";
import { generateKeyPair, keyIdOf, sign, verify } from "./crypto";
import { SOLO_NOTICE } from "./rules";

export type HostLayout = {
  data: string;
  ledger: string;
  keys: string;
  coordKey: string;
  adminKey: string;
  target: string;
  patches: string;
  // What COMMONS_RULES_PRESET last did here (written by commons host), so the
  // preset is applied once per value, not at every start.
  rulesPresetMarker: string;
  // Task bodies the operator approved (serve --approved-tasks); absent = none.
  approvedTasks: string;
};

export function hostLayout(data: string): HostLayout {
  const keys = path.join(data, "keys");
  return {
    data,
    ledger: path.join(data, "commons-ledger.jsonl"),
    keys,
    coordKey: path.join(keys, "coord.json"),
    adminKey: path.join(keys, "admin.json"),
    target: path.join(data, "target"),
    patches: path.join(data, "patches"),
    rulesPresetMarker: path.join(data, "rules-preset.json"),
    approvedTasks: path.join(data, "approved-tasks.json"),
  };
}

export type HostSettings = {
  anthillUrl: string;
  community: string;
  project: string;
  targetRepo: string;
  kernelSigners: string[];
  preset: HostPreset;
};

// The setup presets: the rules presets (rules.ts PRESETS) or none, the
// generic defaults. Solo is one person testing with their own agents: no
// kernel signer is needed (kernelSignoffs 0).
export const HOST_PRESETS = ["phase1", "solo", "none"] as const;
export type HostPreset = (typeof HOST_PRESETS)[number];

// Each setting as a flag and as an environment variable (a flag wins).
export const HOST_SETTINGS = {
  anthillUrl: { flag: "anthill-url", env: "ANTHILL_URL" },
  community: { flag: "community", env: "ANTHILL_COMMUNITY" },
  project: { flag: "project", env: "COMMONS_PROJECT" },
  targetRepo: { flag: "target-repo", env: "COMMONS_TARGET_REPO" },
  kernelSigners: { flag: "kernel-signer", env: "COMMONS_KERNEL_SIGNERS" },
  preset: { flag: "preset", env: "COMMONS_PRESET" },
  // Not a setup setting: once per value (with its kernel signers), on the
  // first start over an existing ledger that sees it, its rules are switched
  // to this preset (an admin-signed rulesChange with keys/admin.json, through
  // `commons rules set`) unless they already are it. <data>/rules-preset.json
  // records that, so a later start never re-applies it over a rulesChange an
  // admin made since.
  rulesPreset: { flag: "rules-preset", env: "COMMONS_RULES_PRESET" },
  // "1": pass --force to that `rules set` (leave solo although solo work
  // would be stranded).
  rulesForce: { flag: "rules-force", env: "COMMONS_RULES_FORCE" },
  // Merged submissions that trigger a snapshot (serve --snapshot-every); 0 =
  // never. Unset: 1 on a solo ledger (nothing else would ever snapshot it,
  // so nothing would be promoted), never otherwise.
  snapshotEvery: { flag: "snapshot-every", env: "COMMONS_SNAPSHOT_EVERY" },
  // "1" (default): every coordinator pass fetches the target's main from its
  // origin and brings it into dev (serve --follow-upstream), so commits the
  // repository's owner pushes after setup are valid bases. "0": dev moves
  // only by merges.
  followUpstream: { flag: "follow-upstream", env: "COMMONS_FOLLOW_UPSTREAM" },
  // "1": after every pass, push the clone's dev and main to the target on
  // GitHub (serve --push-upstream; mirror.ts), with the token from
  // COMMONS_GITHUB_TOKEN, which is never a flag. Unset or "0": nothing leaves
  // the clone.
  pushUpstream: { flag: "push-upstream", env: "COMMONS_PUSH_UPSTREAM" },
} as const;

export const settingName = (k: keyof typeof HOST_SETTINGS) => `${HOST_SETTINGS[k].env} (--${HOST_SETTINGS[k].flag})`;

export type RawHostSettings = {
  anthillUrl?: string;
  community?: string;
  project?: string;
  targetRepo?: string;
  // Signer ids as given: each may itself be a comma-separated list.
  kernelSigners?: string[];
  preset?: string;
};

export type ReadSettings = { settings?: HostSettings; missing: string[]; problems: string[]; warnings: string[] };

const COMMUNITY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// What the single-signer warning says (logged at every setup, and in the README).
export const ONE_SIGNER_WARNING =
  "only one kernel signer is named. A kernel signer may not sign off a snapshot that holds their own ring-0 work, " +
  "so once a ring-0 change of theirs (or of an agent of theirs) merges to dev, no snapshot holding it can be signed off: " +
  "main stops moving until an admin-signed rulesChange (commons rules set --kernel-signer) or a new ledger adds a second signer. " +
  "Until then that signer should keep their own work out of ring 0. Signing off also takes an owner key (anthill join): " +
  "a member admitted only through the Agents page has none.";

// The target must be a public repository the coordinator can clone with no
// credentials: https only, nothing secret in the URL (it is logged, and goes
// into COMMONS_SITES, which Anthill shows every agent). file: URLs only for
// tests, when allowed.
export function targetRepoProblems(raw: string, allowFile = false): string[] {
  if (/[\s\\\x00-\x1f\x7f]/.test(raw)) return ["must not contain spaces, backslashes or control characters"];
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return ["is not a URL"];
  }
  if (u.protocol === "file:") return allowFile ? [] : ["file: URLs are only for tests (--test-allow-file-target); use the repository's public https URL"];
  if (u.protocol !== "https:") return [`must be an https URL (got ${u.protocol}); the coordinator clones it with no credentials`];
  const problems: string[] = [];
  if (u.username !== "" || u.password !== "" || raw.includes("@")) {
    problems.push("must not carry credentials (user:token@...): the repository must be public, and this URL is logged and shown to every agent");
  }
  if (u.search !== "" || u.hash !== "" || raw.includes("?") || raw.includes("#")) problems.push("must not have a query or a fragment");
  if (u.pathname === "/" || u.pathname === "") problems.push("must name a repository, e.g. https://github.com/org/repo");
  return problems;
}

function anthillUrlProblems(raw: string): string[] {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return ["is not a URL"];
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return ["must be an http(s) URL"];
  if (u.username !== "" || u.password !== "") return ["must not carry credentials"];
  return [];
}

export function readHostSettings(raw: RawHostSettings, opts: { allowFileTarget?: boolean } = {}): ReadSettings {
  const missing: string[] = [];
  const problems: string[] = [];
  const warnings: string[] = [];
  const val = (v: string | undefined) => (v === undefined || v.trim() === "" ? undefined : v.trim());

  const anthillUrl = val(raw.anthillUrl);
  if (anthillUrl === undefined) missing.push(settingName("anthillUrl"));
  else for (const p of anthillUrlProblems(anthillUrl)) problems.push(`${settingName("anthillUrl")} ${p}`);

  const community = val(raw.community) ?? "builders";
  if (!COMMUNITY_RE.test(community)) problems.push(`${settingName("community")} must be an Anthill community id (letters, digits, . _ -; at most 64)`);

  const project = val(raw.project) ?? community;
  if (project.length > 128 || !/^[\x20-\x7e]+$/.test(project)) problems.push(`${settingName("project")} must be at most 128 printable ASCII characters`);

  const targetRepo = val(raw.targetRepo);
  if (targetRepo === undefined) missing.push(settingName("targetRepo"));
  else for (const p of targetRepoProblems(targetRepo, opts.allowFileTarget)) problems.push(`${settingName("targetRepo")} ${p}`);

  const signers: string[] = [];
  for (const item of (raw.kernelSigners ?? []).flatMap((s) => s.split(","))) {
    const t = item.trim();
    if (t === "") continue;
    if (!/^0x[0-9a-fA-F]{40}$/.test(t)) {
      problems.push(`${settingName("kernelSigners")}: ${JSON.stringify(t.slice(0, 50))} is not an Anthill user id (0x and 40 hex digits)`);
      continue;
    }
    // Anthill spells ids in lowercase (ANTHILL_USER_RE); a pasted checksummed address is the same id.
    const id = t.toLowerCase();
    if (!ANTHILL_USER_RE.test(id)) continue;
    if (signers.includes(id)) problems.push(`${settingName("kernelSigners")} names ${id} twice`);
    else signers.push(id);
  }
  const preset = val(raw.preset) ?? "phase1";
  const knownPreset = (HOST_PRESETS as readonly string[]).includes(preset);
  if (!knownPreset) problems.push(`${settingName("preset")} must be phase1, solo or none`);
  // Solo requires no kernel sign-off, so it needs no signer, and one cannot freeze main.
  const solo = preset === "solo";
  if (!solo && signers.length === 0 && !problems.some((p) => p.startsWith(HOST_SETTINGS.kernelSigners.env))) missing.push(settingName("kernelSigners"));
  if (!solo && signers.length === 1) warnings.push(`${settingName("kernelSigners")}: ${ONE_SIGNER_WARNING}`);
  if (solo) warnings.push(`${settingName("preset")} solo: ${SOLO_NOTICE}. Reviews are by the author's own agents of another model family; leave solo with ${settingName("rulesPreset")} phase1, or commons rules set --data <data> --preset phase1`);

  if (missing.length > 0 || problems.length > 0) return { missing, problems, warnings };
  return {
    settings: {
      anthillUrl: anthillUrl as string,
      community,
      project,
      targetRepo: targetRepo as string,
      kernelSigners: signers,
      preset: preset as HostPreset,
    },
    missing,
    problems,
    warnings,
  };
}

// A setup step that failed. `retry`: worth trying again unchanged (the
// network, Anthill or the git host); otherwise the operator must act.
export class SetupError extends Error {
  constructor(
    message: string,
    readonly retry: boolean,
  ) {
    super(message);
  }
}

// What setUp needs from its caller: init is the CLI's own `commons init`
// (argv after "commons"), so the genesis is made by the one code path.
export type SetupDeps = {
  log: (line: string) => void;
  init: (argv: string[]) => Promise<number>;
  fetch?: typeof globalThis.fetch;
  // The coordinator's public URL, for the COMMONS_SITES line (unknown: a placeholder).
  publicUrl?: string;
  // Run by a parent that proxies it and lists its site itself (Anthill's
  // backend, commons host --embedded): no COMMONS_SITES line to set.
  embedded?: boolean;
  // Clone and git timeouts (tests shorten nothing; a huge repository may need more).
  cloneTimeoutMs?: number;
};

// As cli.ts runs git: no hooks, no fsmonitor, no LFS filters; and never a prompt.
const GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.lfs.process=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false"];
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "", SSH_ASKPASS: "" };

function git(cwd: string, args: string[], timeoutMs = 120_000): { ok: boolean; out: string; err: string } {
  const r = spawnSync("git", [...GIT_SAFE, ...args], { cwd, encoding: "utf8", env: GIT_ENV, timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
  return { ok: r.status === 0, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() || (r.error ? r.error.message : `exit ${r.status}`) };
}

// The clone, which can take minutes, runs without blocking: the caller's 503
// holder must keep answering meanwhile. Every other git call here is quick.
function gitAsync(cwd: string, args: string[], timeoutMs: number): Promise<{ ok: boolean; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn("git", [...GIT_SAFE, ...args], { cwd, env: GIT_ENV, stdio: ["ignore", "pipe", "pipe"], timeout: timeoutMs });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out = (out + d.toString()).slice(-64 * 1024)));
    child.stderr.on("data", (d: Buffer) => (err = (err + d.toString()).slice(-64 * 1024)));
    child.on("error", (e) => resolve({ ok: false, out, err: e.message }));
    child.on("close", (code, signal) => resolve({ ok: code === 0, out: out.trim(), err: err.trim() || (signal ? `killed by ${signal}` : `exit ${code}`) }));
  });
}

const exists = (p: string) => fs.existsSync(p);

function syncFile(p: string): void {
  const fd = fs.openSync(p, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function syncDir(dir: string): void {
  try {
    syncFile(dir);
  } catch {
    // Some filesystems cannot fsync a directory; the rename or link stands.
  }
}

// Creates `file` with `content` only if it does not exist: written whole to
// a temporary file, synced, then hard-linked to its name. Returns false if
// the name already existed.
function createExclusive(file: string, content: string, mode: number): boolean {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.rmSync(tmp, { force: true });
  fs.writeFileSync(tmp, content, { flag: "wx", mode });
  fs.chmodSync(tmp, mode);
  syncFile(tmp);
  try {
    fs.linkSync(tmp, file);
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw e;
  } finally {
    fs.rmSync(tmp, { force: true });
    syncDir(path.dirname(file));
  }
}

// --- the steps -------------------------------------------------------------

async function checkAnthill(s: HostSettings, deps: SetupDeps): Promise<string> {
  let key: string;
  try {
    key = await fetchAnthillKey(s.anthillUrl, deps.fetch);
  } catch (e) {
    throw new SetupError(`cannot get Anthill's signing key from ${s.anthillUrl}/commons/key: ${(e as Error).message}`, true);
  }
  let tree: Awaited<ReturnType<typeof fetchAnthillTree>>;
  try {
    tree = await fetchAnthillTree(s.anthillUrl, s.community, deps.fetch);
  } catch (e) {
    throw new SetupError(`cannot get the tree of Anthill community "${s.community}" (is ${settingName("community")} right?): ${(e as Error).message}`, true);
  }
  let signed = false;
  try {
    signed = tree?.snapshot?.community === s.community && verify(key, treeMessage(tree.snapshot), tree.signature);
  } catch {
    signed = false;
  }
  if (!signed) throw new SetupError(`the tree Anthill served for "${s.community}" is not signed by the key it serves at /commons/key`, false);
  const members = new Set(Object.keys(tree.snapshot.parents));
  deps.log(`Anthill at ${s.anthillUrl}: signing key ${keyIdOf(key)}, community "${s.community}" with ${members.size} members (tree version ${tree.snapshot.version})`);
  for (const id of s.kernelSigners) {
    if (!members.has(id)) deps.log(`warning: kernel signer ${id} is not a member of "${s.community}" yet; they must join before they can sign off`);
  }
  return key;
}

// A finished clone: target is its own repository (not a directory inside
// some other one) with a dev branch.
function cloneComplete(target: string): boolean {
  if (!exists(path.join(target, ".git"))) return false;
  const top = git(target, ["rev-parse", "--absolute-git-dir"]);
  if (!top.ok || fs.realpathSync(top.out) !== fs.realpathSync(path.join(target, ".git"))) return false;
  return git(target, ["rev-parse", "--verify", "--quiet", "refs/heads/dev^{commit}"]).ok;
}

async function ensureTarget(l: HostLayout, s: HostSettings, deps: SetupDeps): Promise<void> {
  const partial = `${l.target}.partial`;
  if (exists(l.target)) {
    if (cloneComplete(l.target)) {
      const origin = git(l.target, ["config", "--get", "remote.origin.url"]).out;
      if (origin !== s.targetRepo) {
        throw new SetupError(
          `${l.target} is a clone of ${origin || "(no origin)"}, not ${settingName("targetRepo")} ${s.targetRepo}: ` +
            `set it back, or delete ${l.target} (no ledger exists yet, so nothing was merged there) and restart`,
          false,
        );
      }
      deps.log(`target: reusing the clone in ${l.target} (dev at ${git(l.target, ["rev-parse", "refs/heads/dev"]).out.slice(0, 12)})`);
      return;
    }
    deps.log(`target: ${l.target} is a clone cut off midway (no dev branch); cloning again`);
    fs.rmSync(l.target, { recursive: true, force: true });
  }
  if (exists(partial)) {
    deps.log(`target: removing ${partial}, left by an interrupted clone`);
    fs.rmSync(partial, { recursive: true, force: true });
  }
  deps.log(`target: cloning ${s.targetRepo}`);
  const clone = await gitAsync(l.data, ["clone", "--quiet", "--no-recurse-submodules", "--origin", "origin", "--", s.targetRepo, partial], deps.cloneTimeoutMs ?? 60 * 60_000);
  if (!clone.ok) {
    fs.rmSync(partial, { recursive: true, force: true });
    throw new SetupError(`cannot clone ${s.targetRepo} (it must be public): ${clone.err.split("\n").slice(-3).join(" / ")}`, true);
  }
  let start = "refs/remotes/origin/main";
  if (!git(partial, ["rev-parse", "--verify", "--quiet", `${start}^{commit}`]).ok) {
    const head = git(partial, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"]);
    if (!head.ok || !git(partial, ["rev-parse", "--verify", "--quiet", `${head.out}^{commit}`]).ok) {
      fs.rmSync(partial, { recursive: true, force: true });
      throw new SetupError(`${s.targetRepo} has no main branch and no default branch (is it empty?)`, false);
    }
    start = head.out;
  }
  const branch = git(partial, ["branch", "--no-track", "dev", start]);
  if (!branch.ok) throw new SetupError(`cannot make the dev branch: ${branch.err}`, true);
  fs.renameSync(partial, l.target);
  syncDir(l.data);
  deps.log(`target: cloned into ${l.target}, dev from ${start.replace("refs/remotes/", "")} at ${git(l.target, ["rev-parse", "refs/heads/dev"]).out.slice(0, 12)}`);
}

function readKey(file: string): { publicKey: string; privateKey: string } | null {
  try {
    const k = JSON.parse(fs.readFileSync(file, "utf8")) as { publicKey?: unknown; privateKey?: unknown };
    if (typeof k.publicKey !== "string" || typeof k.privateKey !== "string") return null;
    if (!verify(k.publicKey, "commons host: key check", sign(k.privateKey, "commons host: key check"))) return null;
    return { publicKey: k.publicKey, privateKey: k.privateKey };
  } catch {
    return null;
  }
}

function ensureKey(file: string, what: string, deps: SetupDeps): string {
  if (!exists(file)) {
    const pair = generateKeyPair();
    if (createExclusive(file, `${JSON.stringify(pair, null, 2)}\n`, 0o600)) {
      deps.log(`keys: made the ${what} key ${file} (key id ${keyIdOf(pair.publicKey)})`);
      return pair.publicKey;
    }
  }
  const k = readKey(file);
  if (k === null) {
    throw new SetupError(`${file} exists but is not a key pair; it is never overwritten: move it away and restart if it is not a key you need`, false);
  }
  fs.chmodSync(file, 0o600);
  deps.log(`keys: reusing the ${what} key ${file} (key id ${keyIdOf(k.publicKey)})`);
  return k.publicKey;
}

function ensureKeys(l: HostLayout, deps: SetupDeps): { coord: string; admin: string } {
  fs.mkdirSync(l.keys, { recursive: true, mode: 0o700 });
  fs.chmodSync(l.keys, 0o700);
  // Temporary files of a key write a crash cut off: never linked, never used.
  for (const f of fs.readdirSync(l.keys)) if (/\.tmp-\d+$/.test(f)) fs.rmSync(path.join(l.keys, f), { force: true });
  return { coord: ensureKey(l.coordKey, "coordinator", deps), admin: ensureKey(l.adminKey, "admin", deps) };
}

// The genesis rules: the target's own .commons/rules.json on dev, written
// out for init, or null for the generic defaults.
function targetRules(l: HostLayout, deps: SetupDeps): string | null {
  const blob = "refs/heads/dev:.commons/rules.json";
  if (!git(l.target, ["cat-file", "-e", blob]).ok) {
    deps.log(
      "rules: the generic defaults (the target has no .commons/rules.json, so its own kernel is ring 1, judged like any other code; " +
        "commit one to the target before setup to name it: README, Hosting)",
    );
    return null;
  }
  const text = git(l.target, ["show", blob]);
  if (!text.ok) throw new SetupError(`cannot read the target's .commons/rules.json: ${text.err}`, true);
  const file = path.join(l.data, "setup-rules.json");
  fs.writeFileSync(file, `${text.out}\n`);
  deps.log("rules: the target's .commons/rules.json (as on dev)");
  return file;
}

export async function setUp(l: HostLayout, s: HostSettings, deps: SetupDeps): Promise<void> {
  if (exists(l.ledger)) throw new SetupError(`${l.ledger} exists; setup never touches a ledger`, false);
  fs.mkdirSync(l.data, { recursive: true });
  deps.log(`setting up a coordinator for Anthill community "${s.community}" (project ${s.project}) in ${l.data}`);
  const anthillKey = await checkAnthill(s, deps);
  await ensureTarget(l, s, deps);
  const keys = ensureKeys(l, deps);
  const rules = targetRules(l, deps);
  const tmp = `${l.ledger}.setup`;
  fs.rmSync(tmp, { force: true });
  const code = await deps.init([
    "init",
    "--ledger",
    tmp,
    "--project",
    s.project,
    "--admin-key",
    l.adminKey,
    "--coordinator-key",
    l.coordKey,
    ...(rules === null ? [] : ["--rules", rules]),
    ...(s.preset === "none" ? [] : ["--preset", s.preset]),
    ...s.kernelSigners.flatMap((id) => ["--kernel-signer", id]),
    "--anthill-community",
    s.community,
    "--anthill-key",
    anthillKey,
  ]);
  if (rules !== null) fs.rmSync(rules, { force: true });
  if (code !== 0) {
    fs.rmSync(tmp, { force: true });
    throw new SetupError(`commons init failed (exit ${code}; its error is above)`, false);
  }
  syncFile(tmp);
  try {
    fs.linkSync(tmp, l.ledger);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new SetupError(`a ledger appeared at ${l.ledger} during setup; it is left alone`, false);
    throw e;
  } finally {
    fs.rmSync(tmp, { force: true });
    syncDir(l.data);
  }
  const url = deps.publicUrl ?? "https://<this coordinator's public URL>";
  deps.log(`setup done: ledger ${l.ledger}, coordinator key ${keyIdOf(keys.coord)}, admin key ${keyIdOf(keys.admin)} (${l.adminKey}; README, Hosting: moving it off the disk)`);
  deps.log(`kernel signers: ${s.kernelSigners.length === 0 ? "none" : s.kernelSigners.join(", ")}; preset ${s.preset}${s.preset === "solo" ? ` (${SOLO_NOTICE})` : ""}`);
  deps.log(`public URL: ${url}${deps.publicUrl === undefined ? " (not known here: set --public-url or COMMONS_PUBLIC_URL)" : ""}`);
  if (deps.embedded === true) return;
  deps.log(`set COMMONS_SITES on the anthill-backend service to (or add this community's key to the object it holds):`);
  deps.log(sitesValue(s, url));
}

export function sitesValue(s: Pick<HostSettings, "community" | "targetRepo">, url: string): string {
  return JSON.stringify({ [s.community]: { coordinator: url, site: url, repo: s.targetRepo } });
}

// The clone's origin URL (what the mirror pushes to), or undefined without a clone.
export function cloneOrigin(target: string): string | undefined {
  if (!exists(path.join(target, ".git"))) return undefined;
  const r = git(target, ["config", "--get", "remote.origin.url"]);
  return r.ok && r.out !== "" ? r.out : undefined;
}

// What a ledger made earlier still needs before it can be served.
export function missingForServe(l: HostLayout): string[] {
  const missing: string[] = [];
  if (!exists(l.coordKey)) missing.push(`the coordinator key (${l.coordKey})`);
  if (!cloneComplete(l.target)) missing.push(`the target clone with a dev branch (${l.target})`);
  return missing;
}
