// The GitHub mirror (serve --push-upstream; commons host COMMONS_PUSH_UPSTREAM=1):
// at the end of every coordinator pass, the clone's dev and main go to the
// target's GitHub repository, so merged and promoted work is on GitHub, not
// only in <data>/target.
//
// - Opt-in, and the only write credential the coordinator holds: the token
//   comes from COMMONS_GITHUB_TOKEN alone. It reaches git through the
//   environment (GIT_CONFIG_COUNT/KEY/VALUE: an Authorization header for
//   https://github.com/ only), never argv, a URL or a log line.
// - A ref is pushed when it differs from what GitHub was last seen to hold
//   (git ls-remote on the first pass, then every successful push), with a
//   plain push: never forced. A ref that is an ancestor of what GitHub holds
//   is left alone (main here lags an upstream main that followUpstream
//   already brought into dev).
// - A refusal (GitHub's branch moved, branch protection, the token) is said
//   once per (ref, commit, reason) and tried again every pass; it never fails
//   the pass. A main refused because someone pushed to GitHub's main heals by
//   itself: the next pass brings that main into dev (gitHost.ts
//   followUpstream), and the next promotion moves main to a commit that
//   descends from it.
// - Following upstream sees no churn from the mirror's own pushes: a pushed
//   main is a promoted snapshot, already on dev, so followUpstream finds it
//   there and changes nothing.

import { spawn } from "node:child_process";

export const GITHUB_TOKEN_ENV = "COMMONS_GITHUB_TOKEN";
export const MIRROR_REFS = ["refs/heads/dev", "refs/heads/main"] as const;

// As the rest of the code runs git: no hooks, no fsmonitor, no LFS filters.
// Pushing writes nothing in the clone but objects; these keep a push from
// carrying more than the two refs.
const GIT_SAFE = [
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "filter.lfs.process=",
  "-c",
  "filter.lfs.smudge=",
  "-c",
  "filter.lfs.required=false",
  "-c",
  "push.followTags=false",
  "-c",
  "push.gpgSign=false",
];

// Tracing would print the request headers (redacted by default, but not
// worth relying on): none of it reaches a git that carries the token.
const TRACE_ENV = ["GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE_CURL_NO_DATA", "GIT_CURL_VERBOSE", "GIT_TRACE_PACKET", "GIT_TRACE_REDACT", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF"];

// The mirror pushes only to a GitHub repository over https, the one place the
// header is scoped to. file: only for tests.
export function mirrorTargetProblems(url: string, allowFile = false): string[] {
  if (allowFile && url.startsWith("file://")) return [];
  const m = /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(url);
  if (m === null || /^\.+$/.test(m[2] as string)) {
    return [`the target ${JSON.stringify(url.slice(0, 200))} is not an https://github.com/<owner>/<repo> URL`];
  }
  return [];
}

// Why the mirror cannot run (empty: it can): the token is missing, or the
// target (the clone's origin) is not a GitHub repository.
export function pushUpstreamProblems(url: string | undefined, env: NodeJS.ProcessEnv, allowFile = false): string[] {
  const problems: string[] = [];
  if ((env[GITHUB_TOKEN_ENV] ?? "").trim() === "") problems.push(`${GITHUB_TOKEN_ENV} is not set`);
  if (url === undefined || url === "") problems.push("the clone has no origin URL");
  else problems.push(...mirrorTargetProblems(url, allowFile));
  return problems;
}

// The environment that gives git the token: git reads GIT_CONFIG_COUNT,
// GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n> (git 2.31+) as command-line
// config, so nothing secret is in any process's argv. The header is scoped by
// http.<url>.extraHeader to https://github.com/ (git matches the scheme, the
// host exactly and the path by segments), so a remote anywhere else never
// sees it. GitHub takes a token as the password of Basic auth; the name is
// not checked. An empty credential.helper drops any helper the machine
// configures, so nothing is read from or stored to a keychain.
export function mirrorGitEnv(token: string): Record<string, string> {
  const basic = Buffer.from(`x-access-token:${token}`, "utf8").toString("base64");
  return {
    GIT_CONFIG_COUNT: "2",
    GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
    GIT_CONFIG_KEY_1: "credential.helper",
    GIT_CONFIG_VALUE_1: "",
  };
}

type GitResult = { code: number | null; out: string; err: string };

function run(repo: string, args: string[], env: Record<string, string>, timeoutMs: number): Promise<GitResult> {
  const base: NodeJS.ProcessEnv = { ...process.env };
  for (const k of TRACE_ENV) delete base[k];
  return new Promise((resolve) => {
    const child = spawn("git", [...GIT_SAFE, ...args], {
      cwd: repo,
      env: { ...base, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "", SSH_ASKPASS: "", GIT_OPTIONAL_LOCKS: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out = (out + d.toString()).slice(-64 * 1024)));
    child.stderr.on("data", (d: Buffer) => (err = (err + d.toString()).slice(-16 * 1024)));
    child.on("error", (e) => resolve({ code: null, out, err: e.message }));
    child.on("close", (code, signal) => resolve({ code, out: out.trim(), err: err.trim() || (signal ? `killed by ${signal}` : `exit ${code}`) }));
  });
}

export type MirrorOptions = {
  repo: string; // the coordinator's clone
  url: string; // where to push (the clone's origin, checked by mirrorTargetProblems)
  token: string;
  refs?: readonly string[]; // default MIRROR_REFS
  timeoutMs?: number; // per git call; default 120 s
};

// What one pass did: refs pushed, and problems not said before (each distinct
// one is reported once; the caller logs them).
export type MirrorReport = { pushed: { ref: string; sha: string }[]; problems: string[] };

export type Mirror = { pass: () => Promise<MirrorReport> };

export function githubMirror(opts: MirrorOptions): Mirror {
  const env = mirrorGitEnv(opts.token);
  const refs = opts.refs ?? MIRROR_REFS;
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const secrets = [opts.token, env.GIT_CONFIG_VALUE_0 as string, (env.GIT_CONFIG_VALUE_0 as string).replace(/^Authorization: Basic /, "")].filter((s) => s.length >= 4);
  // Git never prints the header, but a line we log must not carry it whatever git says.
  const scrub = (s: string) => secrets.reduce((acc, x) => acc.split(x).join("***"), s);
  const git = (args: string[]) => run(opts.repo, args, env, timeoutMs);
  // What GitHub holds, as last read or pushed; null until read.
  let remote: Map<string, string | null> | null = null;
  const said = new Set<string>();
  return {
    pass: async () => {
      const report: MirrorReport = { pushed: [], problems: [] };
      const once = (key: string, line: string) => {
        if (said.has(key)) return;
        said.add(key);
        report.problems.push(scrub(line));
      };
      try {
        if (remote === null) {
          const ls = await git(["ls-remote", "--", opts.url, ...refs]);
          if (ls.code !== 0) {
            const reason = failureReason(ls, "");
            once(`ls-remote\0${reason}`, `cannot read the branches of ${opts.url}: ${reason}; tried again every pass`);
            return report;
          }
          const seen = new Map<string, string | null>(refs.map((r) => [r, null]));
          for (const line of ls.out.split("\n")) {
            const [sha, ref] = line.split("\t");
            if (sha !== undefined && ref !== undefined && seen.has(ref)) seen.set(ref, sha);
          }
          remote = seen;
        }
        for (const ref of refs) {
          const local = (await git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`])).out;
          if (!/^[0-9a-f]{40,64}$/.test(local)) continue;
          const known = remote.get(ref) ?? null;
          if (known === local) continue;
          // GitHub already holds it (the object is here, and local is in its history).
          if (known !== null && (await git(["merge-base", "--is-ancestor", local, known])).code === 0) continue;
          // Plain push, never --force: a branch GitHub moved is refused, not overwritten.
          const pushed = await git(["push", "--porcelain", "--no-verify", "--recurse-submodules=no", "--", opts.url, `${ref}:${ref}`]);
          if (pushed.code === 0) {
            remote.set(ref, local);
            report.pushed.push({ ref, sha: local });
            continue;
          }
          const reason = failureReason(pushed, ref);
          once(`${ref}\0${local}\0${reason}`, `${ref.replace("refs/heads/", "")} at ${local.slice(0, 12)} not pushed to ${opts.url}: ${reason}; tried again every pass, never forced`);
        }
      } catch (e) {
        const detail = (e as Error).message;
        once(`error\0${detail}`, `mirror: ${detail}`);
      }
      return report;
    },
  };
}

// A stable reason for a failed ls-remote or push, so the same refusal is said
// once however many passes retry it.
function failureReason(r: GitResult, ref: string): string {
  const status = r.out.split("\n").find((l) => l.startsWith("!\t"));
  const why = status === undefined ? null : (/\[(?:remote )?rejected\] \((.*)\)\s*$/.exec(status)?.[1] ?? status.split("\t")[2] ?? "");
  const branch = ref.replace("refs/heads/", "");
  if (why !== null) {
    if (/non-fast-forward|fetch first|stale info/.test(why)) {
      return `GitHub's ${branch} has commits this clone's ${branch} lacks (not a fast-forward; someone pushed there)`;
    }
    if (/protected branch|GH006|declined/i.test(why) || /protected branch|GH006/i.test(r.err)) {
      return `refused by GitHub (${why}): branch protection on ${branch} must let the token's account push`;
    }
    return `refused (${why})`;
  }
  if (r.code === null) return r.err;
  if (/Authentication failed|could not read Username|terminal prompts disabled|returned error: 40[13]|Permission to .* denied|Write access to repository not granted/i.test(r.err)) {
    return `authentication or permission refused (${GITHUB_TOKEN_ENV} must be valid, with Contents read and write on this repository)`;
  }
  if (/Repository not found|returned error: 404/i.test(r.err)) {
    return `repository not found (or ${GITHUB_TOKEN_ENV} cannot see it)`;
  }
  const lines = r.err
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("hint:") && !l.startsWith("To "));
  return (lines.slice(-2).join(" / ") || `exit ${r.code}`).slice(0, 300);
}
