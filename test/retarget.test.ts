// host.ts retargetClone: when the project moves (renamed, or transferred to an
// organization) and the operator sets the new address, the clone's origin
// follows it, but only to a repository that shares its history.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

import { cloneOrigin, retargetClone } from "../src/host";

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main", ...args], { cwd, encoding: "utf8" }).trim();

function project(dir: string, files: Record<string, string>): string {
  fs.mkdirSync(dir, { recursive: true });
  git(dir, "init", "--quiet");
  for (const [name, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), text);
  git(dir, "add", "-A");
  git(dir, "commit", "--quiet", "-m", "first");
  return pathToFileURL(dir).href;
}

test("retargetClone: follows a moved project, and nothing else", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "commons-retarget-"));
  try {
    const oldUrl = project(path.join(tmp, "old"), { "a.txt": "a\n" });
    const clone = path.join(tmp, "clone");
    git(tmp, "clone", "--quiet", oldUrl, clone);
    git(clone, "branch", "dev");
    const said: string[] = [];
    const log = (line: string) => void said.push(line);

    // the same address: nothing to do
    assert.equal(await retargetClone(clone, oldUrl, log, true), "same");
    assert.deepEqual(said, []);

    // the project at its new address, one commit further on
    const moved = path.join(tmp, "moved");
    git(tmp, "clone", "--quiet", oldUrl, moved);
    fs.writeFileSync(path.join(moved, "b.txt"), "b\n");
    git(moved, "add", "-A");
    git(moved, "commit", "--quiet", "-m", "second");
    const movedUrl = pathToFileURL(moved).href;

    // an unrelated repository is never taken for it
    const otherUrl = project(path.join(tmp, "other"), { "z.txt": "z\n" });
    assert.equal(await retargetClone(clone, otherUrl, log, true), "kept");
    assert.equal(cloneOrigin(clone), oldUrl);
    assert.match(said.at(-1) ?? "", /doesn't share history/);

    // nor one that can't be reached, or an address that isn't allowed
    assert.equal(await retargetClone(clone, pathToFileURL(path.join(tmp, "nowhere")).href, log, true), "kept");
    assert.match(said.at(-1) ?? "", /couldn't be fetched/);
    assert.equal(await retargetClone(clone, "https://bot:secret@github.com/o/r", log), "kept");
    assert.ok(!said.join("\n").includes("secret"), "a refused address is never echoed");
    assert.equal(cloneOrigin(clone), oldUrl);

    // the moved project is followed, and following again is a no-op
    assert.equal(await retargetClone(clone, movedUrl, log, true), "moved");
    assert.equal(cloneOrigin(clone), movedUrl);
    assert.match(said.at(-1) ?? "", /the project moved/);
    assert.equal(await retargetClone(clone, movedUrl, log, true), "same");

    // and back to an address that is behind (the clone's main contains it)
    assert.equal(await retargetClone(clone, oldUrl, log, true), "moved");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
