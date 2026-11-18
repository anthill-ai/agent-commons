#!/bin/sh
# Render's start command for a hosted coordinator (render.yaml; README,
# "Hosting a coordinator for an Anthill community"): the coordinator API and
# the playground on Render's one port, a coordinator pass every 30 seconds,
# pinning the Anthill tree whenever it changed.
#
# Render reaches the disk only through a running instance, so this never
# leaves the service in a crash loop with no shell to fix it from:
# - until the one-time setup in the Render shell is done (the target clone
#   with its dev branch, the keys, init), a holder answers 503 on the port and
#   exits once all of it exists, so that Render restarts the service into
#   commons serve. It waits for the clone too, so the restart cannot cut off
#   a clone in progress or start serve on an empty target.
# - if serve fails at startup (a torn ledger, a key that is not the genesis
#   coordinator), the same holder answers 503 and stays up until the operator
#   has fixed it and restarted the service by hand. A serve that stops later
#   exits, and Render restarts it.
set -eu

DATA=${COMMONS_DATA:-/var/data}
LEDGER="$DATA/commons-ledger.jsonl"
KEY="$DATA/keys/coord.json"
TARGET="$DATA/target"
PORT=${PORT:-10000}
POLL=${COMMONS_SETUP_POLL_SECONDS:-5}
: "${ANTHILL_URL:?set ANTHILL_URL to the Anthill backend URL in the service environment}"

# keygen makes it too; made here so it is private from the first boot.
mkdir -p "$DATA/keys"
chmod 700 "$DATA/keys"

ready() {
  [ -f "$LEDGER" ] && [ -f "$KEY" ] && git -C "$TARGET" rev-parse --verify -q refs/heads/dev >/dev/null 2>&1
}

# holder <setup|failed> <message>: answers 503 with the message. In setup mode
# it exits once ready() would hold; in failed mode it never exits by itself.
holder() {
  exec node -e '
    const fs = require("node:fs");
    const { spawnSync } = require("node:child_process");
    const [mode, message, ledger, key, target, port, poll] = process.argv.slice(1);
    const server = require("node:http").createServer((req, res) => {
      res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8", "Retry-After": "60" });
      res.end(`${message}\n`);
    });
    server.listen(Number(port), "0.0.0.0");
    if (mode === "setup") {
      setInterval(() => {
        const dev = spawnSync("git", ["-C", target, "rev-parse", "--verify", "-q", "refs/heads/dev"], { stdio: "ignore" }).status === 0;
        if (fs.existsSync(ledger) && fs.existsSync(key) && dev) {
          console.error("commons: setup done; exiting so the service restarts into commons serve");
          process.exit(1);
        }
      }, Number(poll) * 1000);
    }
  ' "$1" "$2" "$LEDGER" "$KEY" "$TARGET" "$PORT" "$POLL"
}

if ! ready; then
  missing=""
  [ -f "$LEDGER" ] || missing="$missing the ledger ($LEDGER),"
  [ -f "$KEY" ] || missing="$missing the coordinator key ($KEY),"
  git -C "$TARGET" rev-parse --verify -q refs/heads/dev >/dev/null 2>&1 || missing="$missing the target clone with a dev branch ($TARGET),"
  echo "commons: not set up yet; missing${missing%,}: run the one-time setup in the Render shell (README, Hosting)" >&2
  holder setup "This commons is not set up yet."
fi

npx tsx src/cli.ts serve \
  --ledger "$LEDGER" --key "$KEY" \
  --coordinator --one-port --host 0.0.0.0 --port "$PORT" \
  --loop-seconds 30 --anthill-url "$ANTHILL_URL" \
  --repo "$TARGET" --patches "$DATA/patches" \
  --trusted-proxy 10.0.0.0/8 &
# (Add --trusted-proxy cloudflare if the log's "client addresses:" line says
# the client is read from a Cloudflare edge address: README, Hosting.)
pid=$!
started=$(date +%s)
stopping=0
# Render stops the service with SIGTERM: pass it on, and exit with serve.
trap 'stopping=1; kill -TERM "$pid" 2>/dev/null || :' TERM INT
while :; do
  status=0
  wait "$pid" || status=$?
  # A trapped signal interrupts wait while serve is still running.
  kill -0 "$pid" 2>/dev/null || break
done
trap - TERM INT

if [ "$stopping" = 1 ] || [ "$status" = 0 ] || [ $(($(date +%s) - started)) -gt 120 ]; then
  exit "$status"
fi
echo "commons: serve failed at startup (exit $status; its error is above). The service stays up for the Render shell:" >&2
echo "  a torn ledger (an interrupted write): npx tsx src/cli.ts ledger repair --ledger $LEDGER" >&2
echo "  a key mismatch: $KEY must be the coordinator key init was given" >&2
echo "then restart the service by hand." >&2
holder failed "This commons cannot start; the operator has the details in the service logs."
