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

// Dropped from the environment of every git that carries the token: tracing
// (GIT_TRACE*, GIT_TRACE2* and GIT_CURL_VERBOSE would print requests,
// config and environment; redaction is a default, not worth relying on),
// GIT_SSL_NO_VERIFY (a header sent over unverified TLS is a header given
// away), and config a parent git passed down (GIT_CONFIG_PARAMETERS).
const dropEnv = (k: string) => k.startsWith("GIT_TRACE") || k === "GIT_CURL_VERBOSE" || k === "GIT_SSL_NO_VERIFY" || k === "GIT_CONFIG_PARAMETERS";

// The mirror pushes only to a GitHub repository over https, the one place the
// header is scoped to. file: only for tests. The problem text is logged, so
// it never echoes the raw URL: one that carries credentials or a query is
// named only as such, and any other only by scheme, host and path.
export function mirrorTargetProblems(url: string, allowFile = false): string[] {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return ["the target is not a URL"];
  }
  if (u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "" || /[@?#]/.test(url)) {
    return ["the target must not carry credentials, a query or a fragment"];
  }
  if (allowFile && u.protocol === "file:") return [];
  const m = /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(url);
  if (m === null || /^\.+$/.test(m[2] as string)) {
    return [`the target ${JSON.stringify(`${u.protocol}//${u.host}${u.pathname}`.slice(0, 200))} is not an https://github.com/<owner>/<repo> URL`];
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
// host exactly and the path by segments), so git adds it only to requests for
// that URL; followRedirects=false keeps a redirect from github.com from
// carrying such a request elsewhere, and sslVerify stays on there whatever
// the clone's config says. GitHub takes a token as the password of Basic
// auth; the name is not checked. An empty credential.helper drops any helper
// the machine configures, so nothing is read from or stored to a keychain.
// The system and global config files are not read (a helper, a proxy or an
// insteadOf rewrite there would apply to these requests); the clone's own
// config still is.
export function mirrorGitEnv(token: string): Record<string, string> {
  const basic = Buffer.from(`x-access-token:${token}`, "utf8").toString("base64");
  return {
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_COUNT: "4",
    GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
    GIT_CONFIG_KEY_1: "credential.helper",
    GIT_CONFIG_VALUE_1: "",
    GIT_CONFIG_KEY_2: "http.https://github.com/.followRedirects",
    GIT_CONFIG_VALUE_2: "false",
    GIT_CONFIG_KEY_3: "http.https://github.com/.sslVerify",
    GIT_CONFIG_VALUE_3: "true",
  };
}

export type GitResult = { code: number | null; out: string; err: string };

function run(repo: string, args: string[], env: Record<string, string>, timeoutMs: number): Promise<GitResult> {
  const base: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!dropEnv(k)) base[k] = v;
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

// remembered: how many problems it keeps as said (diagnostics and tests; bounded).
export type Mirror = { pass: () => Promise<MirrorReport>; remembered: () => number };

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
  // Problems said, as `${what}\0...` keys. Bounded: a ref keeps only those
  // about its latest commit, and forgets them once it pushes.
  const said = new Set<string>();
  const forget = (prefix: string, keep?: string) => {
    for (const k of said) if (k.startsWith(prefix) && (keep === undefined || !k.startsWith(keep))) said.delete(k);
  };
  return {
    remembered: () => said.size,
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
            const reason = mirrorFailureReason(ls, "");
            once(`ls-remote\0${reason}`, `cannot read the branches of ${opts.url}: ${reason}; tried again every pass`);
            return report;
          }
          forget("ls-remote\0");
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
            forget(`${ref}\0`);
            continue;
          }
          const reason = mirrorFailureReason(pushed, ref);
          forget(`${ref}\0`, `${ref}\0${local}\0`);
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
// once however many passes retry it: curl's messages carry timings, ports
// and addresses that change every attempt, so a GitHub that cannot be
// reached is one reason, and what is left has its numbers with units
// blanked.
export function mirrorFailureReason(r: GitResult, ref: string): string {
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
  if (r.code === null) return "git did not finish (it timed out or could not run)";
  if (
    /Failed to connect|Could not resolve (host|proxy)|Couldn't resolve|Couldn't connect|Connection (reset|refused|timed out)|timed out|Operation timed out|SSL|TLS|certificate|gnutls|schannel|Empty reply from server|(Recv|Send) failure|Network is unreachable|No route to host/i.test(
      r.err,
    )
  ) {
    return "cannot reach GitHub (network, DNS or TLS)";
  }
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
  return (lines.slice(-2).join(" / ") || `exit ${r.code}`)
    .replace(/\d+(?:\.\d+)?\s*(ms|milliseconds?|s|sec|seconds?|bytes?|[KMG]i?B|%)(?![A-Za-z])/g, "N $1")
    .slice(0, 300);
}
