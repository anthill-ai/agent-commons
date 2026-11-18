#!/bin/sh
# Render's start command for a hosted coordinator (render.yaml; README,
# "Hosting a coordinator for an Anthill community"): the coordinator API and
# the playground on Render's one port, a coordinator pass every 30 seconds,
# pinning the Anthill tree whenever it changed.
#
# Until the operator has run the one-time setup in the Render shell (keys,
# init, the target clone), there is no ledger to serve. Exiting would leave
# the service in a crash loop with no shell to set it up from, so a
# placeholder holds the port, answers 503, and exits once the ledger and the
# coordinator key exist, so that Render restarts the service into the real
# one (or restart it by hand).
set -eu

DATA=${COMMONS_DATA:-/var/data}
LEDGER="$DATA/commons-ledger.jsonl"
KEY="$DATA/keys/coord.json"
PORT=${PORT:-10000}
: "${ANTHILL_URL:?set ANTHILL_URL to the Anthill backend URL in the service environment}"

if [ ! -f "$LEDGER" ] || [ ! -f "$KEY" ]; then
  echo "commons: no ledger at $LEDGER yet: run the one-time setup in the Render shell (README, Hosting)" >&2
  exec node -e '
    const fs = require("node:fs");
    const [ledger, key, port] = process.argv.slice(1);
    const server = require("node:http").createServer((req, res) => {
      res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8", "Retry-After": "60" });
      res.end("This commons is not set up yet.\n");
    });
    server.listen(Number(port), "0.0.0.0");
    setInterval(() => {
      if (fs.existsSync(ledger) && fs.existsSync(key)) {
        console.error("commons: ledger found; exiting so the service restarts into commons serve");
        process.exit(1);
      }
    }, 5000);
  ' "$LEDGER" "$KEY" "$PORT"
fi

mkdir -p "$DATA/target"
exec npx tsx src/cli.ts serve \
  --ledger "$LEDGER" --key "$KEY" \
  --coordinator --one-port --host 0.0.0.0 --port "$PORT" \
  --loop-seconds 30 --anthill-url "$ANTHILL_URL" \
  --repo "$DATA/target" --patches "$DATA/patches" \
  --trusted-proxy 10.0.0.0/8
