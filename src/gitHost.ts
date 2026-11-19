// The coordinator's clone as agents need it, for a hosted coordinator
// (`commons host`) whose operator has no shell:
//
// - followUpstream: every pass fetches the target's main from its origin and
//   brings it into dev (a fast-forward, else a merge commit), so commits the
//   repository's owner pushes after setup are valid bases. Without it the
//   clone is fixed at setup: every agent that bases on the current upstream
//   main is refused at binding ("not on dev").
// - serveGit: dev and main, read-only, over git's smart HTTP protocol (git
//   http-backend), at <base path>/api/git. Merges land on dev in this clone
//   only, so an agent that works on a spec writer's merged acceptance tests,
//   or reviews on top of them, fetches dev from here:
//     git fetch <coordinator>/api/git dev
//   Only refs/heads/dev and refs/heads/main are advertised; nothing can be
//   pushed (receive-pack is refused before git sees the request). Hiding the
//   other refs (refs/commons/<id> bound heads, origin's) keeps the list
//   clear; it is not secrecy: git may still hand out an unadvertised object
//   asked for by id, and everything in the clone is public anyway (a public
//   target, patches served at /api/patches).

import { spawn } from "node:child_process";
import type * as http from "node:http";
import * as path from "node:path";
import { COMMONS_COMMIT_IDENTITY } from "./client";

// As cli.ts runs git: no hooks, no fsmonitor, no LFS filters; never a prompt.
const GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.lfs.process=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false"];

type GitResult = { code: number | null; out: string; err: string };

function run(repo: string, args: string[], opts: { env?: Record<string, string>; input?: string; timeoutMs?: number } = {}): Promise<GitResult> {
  return new Promise((resolve) => {
    const child = spawn("git", [...GIT_SAFE, ...args], {
      cwd: repo,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "", SSH_ASKPASS: "", GIT_OPTIONAL_LOCKS: "0", ...opts.env },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: opts.timeoutMs ?? 120_000,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out = (out + d.toString()).slice(-256 * 1024)));
    child.stderr.on("data", (d: Buffer) => (err = (err + d.toString()).slice(-16 * 1024)));
    child.on("error", (e) => resolve({ code: null, out, err: e.message }));
    child.on("close", (code, signal) => resolve({ code, out: out.trim(), err: err.trim() || (signal ? `killed by ${signal}` : `exit ${code}`) }));
    child.stdin.end(opts.input ?? "");
  });
}

export type UpstreamResult =
  | { kind: "unchanged"; upstream: string; dev: string }
  | { kind: "fastForward" | "merged"; upstream: string; dev: string; before: string }
  | { kind: "conflict"; upstream: string; dev: string; detail: string }
  | { kind: "error"; detail: string };

// Fetches origin's `branch` (default: main, else origin's default branch, as
// setup chose) and brings it into `devRef`: nothing when dev already holds
// it, a fast-forward when dev has nothing of its own, else a merge commit of
// dev and upstream (no rename detection, the commons identity, so the same
// inputs make the same commit). A conflict leaves dev alone. Dev moves with
// compare-and-swap, so a concurrent merge makes this fail, not lose it.
export async function followUpstream(repo: string, devRef: string, opts: { remote?: string; branch?: string; timeoutMs?: number } = {}): Promise<UpstreamResult> {
  const remote = opts.remote ?? "origin";
  let branch = opts.branch;
  if (branch === undefined) {
    const head = await run(repo, ["symbolic-ref", "--quiet", `refs/remotes/${remote}/HEAD`]);
    const hasMain = (await run(repo, ["rev-parse", "--verify", "--quiet", `refs/remotes/${remote}/main^{commit}`])).code === 0;
    branch = hasMain || head.code !== 0 ? "main" : head.out.replace(`refs/remotes/${remote}/`, "");
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(branch) || branch.startsWith("-")) return { kind: "error", detail: `bad upstream branch ${JSON.stringify(branch)}` };
  const tracking = `refs/remotes/${remote}/${branch}`;
  const fetched = await run(repo, ["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--", remote, `+refs/heads/${branch}:${tracking}`], {
    timeoutMs: opts.timeoutMs ?? 120_000,
  });
  if (fetched.code !== 0) return { kind: "error", detail: `git fetch ${remote} ${branch} failed: ${fetched.err.split("\n").slice(-3).join(" / ")}` };
  const upstream = (await run(repo, ["rev-parse", "--verify", "--quiet", `${tracking}^{commit}`])).out;
  const devRead = await run(repo, ["rev-parse", "--verify", "--quiet", `${devRef}^{commit}`]);
  if (upstream === "" || devRead.code !== 0) return { kind: "error", detail: `cannot read ${tracking} or ${devRef}` };
  const dev = devRead.out;
  const isAncestor = async (a: string, b: string) => {
    const r = await run(repo, ["merge-base", "--is-ancestor", a, b]);
    if (r.code !== 0 && r.code !== 1) throw new Error(`git merge-base failed: ${r.err}`);
    return r.code === 0;
  };
  try {
    if (await isAncestor(upstream, dev)) return { kind: "unchanged", upstream, dev };
    let next = upstream;
    let kind: "fastForward" | "merged" = "fastForward";
    if (!(await isAncestor(dev, upstream))) {
      const tree = await run(repo, ["merge-tree", "--write-tree", "--no-messages", "-X", "no-renames", dev, upstream]);
      if (tree.code === 1) return { kind: "conflict", upstream, dev, detail: `${remote}/${branch} at ${upstream.slice(0, 12)} does not merge cleanly into dev at ${dev.slice(0, 12)}` };
      if (tree.code !== 0) return { kind: "error", detail: `git merge-tree failed: ${tree.err}` };
      const who = COMMONS_COMMIT_IDENTITY;
      const commit = await run(repo, ["-c", "commit.gpgSign=false", "commit-tree", "--no-gpg-sign", tree.out.split("\n")[0]?.trim() ?? "", "-p", dev, "-p", upstream], {
        env: {
          GIT_AUTHOR_NAME: who.name,
          GIT_AUTHOR_EMAIL: who.email,
          GIT_AUTHOR_DATE: who.date,
          GIT_COMMITTER_NAME: who.name,
          GIT_COMMITTER_EMAIL: who.email,
          GIT_COMMITTER_DATE: who.date,
        },
        input: `commons: merge upstream ${remote}/${branch} ${upstream.slice(0, 12)}\n`,
      });
      if (commit.code !== 0) return { kind: "error", detail: `git commit-tree failed: ${commit.err}` };
      next = commit.out;
      kind = "merged";
    }
    const moved = await run(repo, ["update-ref", devRef, next, dev]);
    if (moved.code !== 0) return { kind: "error", detail: `dev moved meanwhile (${moved.err}); the next pass tries again` };
    return { kind, upstream, dev: next, before: dev };
  } catch (e) {
    return { kind: "error", detail: (e as Error).message };
  }
}

// --- read-only smart HTTP ----------------------------------------------------

export type GitServeOptions = {
  repo: string; // the clone (its working tree's root, or a bare repository)
  refs: readonly string[]; // the only refs advertised, e.g. refs/heads/dev, refs/heads/main
  maxConcurrent?: number; // default 2: each fetch packs objects
  maxRequestBytes?: number; // the negotiation a POST carries; default 1 MiB
};

export const GIT_PATH_PREFIX = "/api/git";

// Requests under GIT_PATH_PREFIX (after the base path). Answers every one:
// the two smart-HTTP upload-pack endpoints go to `git http-backend`; anything
// else (a push, the dumb protocol) is refused here.
export function gitServer(opts: GitServeOptions): (req: http.IncomingMessage, res: http.ServerResponse) => void {
  let running = 0;
  const max = opts.maxConcurrent ?? 2;
  const maxBytes = opts.maxRequestBytes ?? 1024 * 1024;
  const repo = path.resolve(opts.repo);
  const plain = (res: http.ServerResponse, status: number, text: string, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers });
    res.end(`${text}\n`);
  };
  return (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const sub = url.pathname.slice(GIT_PATH_PREFIX.length);
    const method = req.method ?? "GET";
    const advert = sub === "/info/refs" && method === "GET";
    const pack = sub === "/git-upload-pack" && method === "POST";
    if (sub === "/git-receive-pack" || url.searchParams.get("service") === "git-receive-pack") {
      req.resume();
      return plain(res, 403, "this repository is read-only: agents submit patches, never push");
    }
    if (!advert && !pack) {
      req.resume();
      return plain(res, 404, `not found: fetch dev or main with git, e.g. git fetch <this coordinator>${GIT_PATH_PREFIX} dev`);
    }
    if (advert && url.searchParams.get("service") !== "git-upload-pack") {
      req.resume();
      return plain(res, 403, "only git's smart HTTP protocol is served (git fetch does that)");
    }
    const declared = Number(req.headers["content-length"] ?? "0");
    if (pack && !(declared <= maxBytes)) {
      req.resume();
      return plain(res, 413, `request exceeds ${maxBytes} bytes`, { Connection: "close" });
    }
    if (running >= max) {
      req.resume();
      return plain(res, 503, "busy: too many fetches at once; try again shortly", { "Retry-After": "5" });
    }
    running++;
    let released = false;
    const release = () => {
      if (!released) running--;
      released = true;
    };
    res.on("close", release);
    // Every ref hidden but the advertised ones (later hideRefs entries win).
    const hide = ["-c", "uploadpack.hideRefs=refs/", ...opts.refs.flatMap((r) => ["-c", `uploadpack.hideRefs=!${r}`])];
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: process.env.HOME ?? "/",
      GIT_TERMINAL_PROMPT: "0",
      GIT_PROJECT_ROOT: path.dirname(repo),
      GIT_HTTP_EXPORT_ALL: "1",
      // The path is ours, never the client's: only this repository is served.
      PATH_INFO: `/${path.basename(repo)}${sub}`,
      REQUEST_METHOD: method,
      QUERY_STRING: advert ? "service=git-upload-pack" : "",
      CONTENT_TYPE: String(req.headers["content-type"] ?? ""),
      REMOTE_ADDR: req.socket.remoteAddress ?? "",
      ...(req.headers["content-length"] === undefined ? {} : { CONTENT_LENGTH: String(declared) }),
      ...(typeof req.headers["content-encoding"] === "string" ? { HTTP_CONTENT_ENCODING: req.headers["content-encoding"] } : {}),
      ...(typeof req.headers["git-protocol"] === "string" ? { GIT_PROTOCOL: req.headers["git-protocol"], HTTP_GIT_PROTOCOL: req.headers["git-protocol"] } : {}),
    };
    const child = spawn("git", [...GIT_SAFE, "-c", "http.receivepack=false", "-c", "uploadpack.allowFilter=false", ...hide, "http-backend"], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10 * 60_000,
    });
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        child.kill("SIGKILL");
        req.destroy();
      }
    });
    req.pipe(child.stdin);
    child.stdin.on("error", () => {});
    child.stderr.resume();
    res.on("close", () => {
      if (child.exitCode === null) child.kill("SIGKILL");
    });
    // The CGI response: headers, a blank line, the body.
    let head = Buffer.alloc(0);
    let started = false;
    child.stdout.on("data", (chunk: Buffer) => {
      if (started) {
        res.write(chunk);
        return;
      }
      head = Buffer.concat([head, chunk]);
      const crlf = head.indexOf("\r\n\r\n");
      const lf = head.indexOf("\n\n");
      const end = crlf >= 0 && (lf < 0 || crlf < lf) ? crlf : lf;
      if (end < 0) {
        if (head.length > 64 * 1024) child.kill("SIGKILL");
        return;
      }
      const sep = end === crlf ? 4 : 2;
      let status = 200;
      const headers: Record<string, string> = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
      for (const line of head.subarray(0, end).toString("latin1").split(/\r?\n/)) {
        const i = line.indexOf(":");
        if (i <= 0) continue;
        const name = line.slice(0, i).trim();
        const value = line.slice(i + 1).trim();
        if (name.toLowerCase() === "status") status = Number.parseInt(value, 10) || 500;
        else if (/^(content-type|content-length|expires|pragma|cache-control)$/i.test(name)) headers[name] = value;
      }
      started = true;
      res.writeHead(status, headers);
      const rest = head.subarray(end + sep);
      if (rest.length > 0) res.write(rest);
    });
    child.on("error", () => {
      if (!res.headersSent) plain(res, 500, "git is not available on this coordinator");
      else res.destroy();
    });
    child.on("close", (code) => {
      if (!started) {
        if (!res.headersSent) plain(res, 500, `git http-backend failed (exit ${code})`);
        return;
      }
      if (code === 0) res.end();
      else res.destroy();
    });
  };
}
