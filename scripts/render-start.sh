#!/bin/sh
# Render's start command for a hosted coordinator (render.yaml; README,
# "Hosting a coordinator for an Anthill community"): a thin wrapper over
# `commons host`, which serves the coordinator API and the playground on
# Render's one port, with a coordinator pass every 30 seconds.
#
# Two ways to set it up, both from the dashboard's view of an empty disk:
# - Settings in the service environment (ANTHILL_URL, COMMONS_TARGET_REPO,
#   COMMONS_KERNEL_SIGNERS, optionally ANTHILL_COMMUNITY, COMMONS_PROJECT,
#   COMMONS_PRESET): `commons host` sets itself up on the first start (clone,
#   keys, init) while answering 503, then serves. Safe to restart at any
#   point of it.
# - Without them, the one-time setup in the Render shell (README): a holder
#   answers 503 and exits once the ledger, the key and the target's dev
#   branch all exist, so that Render restarts the service into commons host.
#   It waits for the clone too, so the restart cannot cut off a clone in
#   progress or start on an empty target.
#
# Render reaches the disk only through a running instance, so this never
# leaves the service in a crash loop with no shell: if setup stops on
# something the operator must fix, or serve fails at startup (a torn ledger,
# a key that is not the genesis coordinator), --hold-on-failure keeps a 503
# on the port and the log says why. Fix it and restart the service by hand.
set -eu

DATA=${COMMONS_DATA:-/var/data}
LEDGER="$DATA/commons-ledger.jsonl"
KEY="$DATA/keys/coord.json"
TARGET="$DATA/target"
PORT=${PORT:-10000}
POLL=${COMMONS_SETUP_POLL_SECONDS:-5}

# Made here so it is private from the first boot (host and keygen make it too).
mkdir -p "$DATA/keys"
chmod 700 "$DATA/keys"

ready() {
  [ -f "$LEDGER" ] && [ -f "$KEY" ] && git -C "$TARGET" rev-parse --verify -q refs/heads/dev >/dev/null 2>&1
}

# holder <message>: answers 503 with the message, and exits once ready()
# would hold, so that Render restarts the service into commons host.
holder() {
  exec node -e '
    const fs = require("node:fs");
    const { spawnSync } = require("node:child_process");
    const [message, ledger, key, target, port, poll] = process.argv.slice(1);
    const server = require("node:http").createServer((req, res) => {
      res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8", "Retry-After": "60" });
      res.end(`${message}\n`);
    });
    server.listen(Number(port), "0.0.0.0");
    setInterval(() => {
      const dev = spawnSync("git", ["-C", target, "rev-parse", "--verify", "-q", "refs/heads/dev"], { stdio: "ignore" }).status === 0;
      if (fs.existsSync(ledger) && fs.existsSync(key) && dev) {
        console.error("commons: setup done; exiting so the service restarts into commons host");
        process.exit(1);
      }
    }, Number(poll) * 1000);
  ' "$1" "$LEDGER" "$KEY" "$TARGET" "$PORT" "$POLL"
}

shell_setup() {
  missing=""
  [ -f "$LEDGER" ] || missing="$missing the ledger ($LEDGER),"
  [ -f "$KEY" ] || missing="$missing the coordinator key ($KEY),"
  git -C "$TARGET" rev-parse --verify -q refs/heads/dev >/dev/null 2>&1 || missing="$missing the target clone with a dev branch ($TARGET),"
  echo "commons: not set up yet; missing${missing%,}: set the settings above in the service environment (Render restarts the service), or run the one-time setup in the Render shell (README, Hosting)" >&2
  holder "This commons is not set up yet."
}

if [ ! -f "$LEDGER" ]; then
  # Logs exactly which settings are missing or invalid.
  node --import tsx src/cli.ts host --check --data "$DATA" || shell_setup
elif ! ready; then
  shell_setup
fi

# (Add --trusted-proxy cloudflare if the log's "client addresses:" line says
# the client is read from a Cloudflare edge address: README, Hosting.)
exec node --import tsx src/cli.ts host --data "$DATA" --host 0.0.0.0 --port "$PORT" \
  --trusted-proxy 10.0.0.0/8 --hold-on-failure
