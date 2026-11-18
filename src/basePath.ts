// Serving under a path prefix behind a reverse proxy: an Anthill backend that
// forwards https://<backend>/commons/builders/... to a coordinator it runs
// (commons serve --base-path /commons/builders). The proxy forwards the full
// path, prefix included; the API then answers at <prefix>/api/..., the
// playground at <prefix>/, and every link and asset the playground renders
// starts with the prefix (playground/render.ts).

import type * as http from "node:http";

const SEGMENT_RE = /^[A-Za-z0-9._~-]+$/;

// The one spelling of a base path: "" for the root, else "/a/b" with no
// trailing slash, made only of unreserved URL characters (so it is the same
// encoded and decoded, and needs no escaping in HTML). Throws on anything else.
export function normaliseBasePath(raw: string): string {
  if (raw === "" || raw === "/") return "";
  if (!raw.startsWith("/")) throw new Error(`base path ${JSON.stringify(raw)} must start with /`);
  const trimmed = raw.endsWith("/") ? raw.slice(0, -1) : raw;
  const segs = trimmed.slice(1).split("/");
  if (segs.some((s) => !SEGMENT_RE.test(s) || s === "." || s === "..")) {
    throw new Error(`base path ${JSON.stringify(raw)} must be /-separated names of letters, digits and . _ ~ - (no empty, . or .. segment)`);
  }
  return `/${segs.join("/")}`;
}

// Mounts a request at `base`: rewrites req.url to the path below it and
// returns false, or answers the request itself and returns true. The bare
// prefix redirects (308) to the prefix with a slash, where the site's root
// is; anything outside the prefix is a 404. With base "" nothing changes.
export function answeredOutsideBase(base: string, req: http.IncomingMessage, res: http.ServerResponse): boolean {
  if (base === "") return false;
  const raw = req.url ?? "/";
  const q = raw.indexOf("?");
  const pathPart = q < 0 ? raw : raw.slice(0, q);
  const query = q < 0 ? "" : raw.slice(q);
  if (pathPart.startsWith(`${base}/`)) {
    req.url = pathPart.slice(base.length) + query;
    return false;
  }
  req.resume();
  if (pathPart === base) {
    const keep = /^[\x21-\x7e]*$/.test(query) ? query : "";
    res.writeHead(308, { Location: `${base}/${keep}`, "Content-Type": "text/plain; charset=utf-8", "Content-Length": "0" });
    res.end();
    return true;
  }
  const body = `not found: this site is under ${base}/\n`;
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff", "Content-Length": String(Buffer.byteLength(body)) });
  res.end(req.method === "HEAD" ? undefined : body);
  return true;
}
