#!/bin/bash
# =============================================================================
# WP1 Ingest Proxy — launcher
#
# Starts mitmdump as a reverse proxy in front of Juice Shop
# (localhost:8080 -> localhost:3000), running ingest_addon.py to log every
# request/response body keyed by cid into
# <this dir>/data/logs/ingest_log.jsonl (plus the enriched and body-field logs).
#
# Plain nohup + PID file, matching how attacks.sh/benign_traffic.sh are run
# on this VM (no systemd unit, no tmux/Docker convention exists for these
# scripts to match).
#
# Usage:
#   bash start_ingest_proxy.sh          # start (no-op if already running)
#   bash start_ingest_proxy.sh stop     # stop
#   bash start_ingest_proxy.sh status   # check
# =============================================================================

# Data lives next to this script (juice-shop/data/), wherever it is deployed
# (~/cjp-vm since Plan P2.2); CJP_DATA_DIR overrides it. Exported so
# ingest_addon.py writes to the same place.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CJP_DATA_DIR="${CJP_DATA_DIR:-$SCRIPT_DIR/data}"
DATA_DIR="$CJP_DATA_DIR"
PID_FILE="$DATA_DIR/ingest_proxy.pid"
OUT_LOG="$DATA_DIR/logs/ingest_proxy.out"
MITMDUMP="$SCRIPT_DIR/.venv/bin/mitmdump"
LISTEN_PORT=8080
UPSTREAM="http://localhost:3000"

mkdir -p "$DATA_DIR/logs"

is_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

case "${1:-start}" in
  start)
    if is_running; then
      echo "ingest proxy already running (pid $(cat "$PID_FILE"))"
      exit 0
    fi
    if [ ! -x "$MITMDUMP" ]; then
      echo "mitmdump not found at $MITMDUMP — install with:"
      echo "  python3 -m venv $SCRIPT_DIR/.venv && $SCRIPT_DIR/.venv/bin/pip install -r $SCRIPT_DIR/requirements-proxy.txt"
      echo "  (cjp vm deploy does this for you)"
      exit 1
    fi
    nohup "$MITMDUMP" -s "$SCRIPT_DIR/ingest_addon.py" \
      --mode "reverse:$UPSTREAM" --listen-port "$LISTEN_PORT" \
      >> "$OUT_LOG" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    if is_running; then
      echo "ingest proxy started (pid $(cat "$PID_FILE"), port $LISTEN_PORT -> $UPSTREAM)"
      echo "  ingest log: $DATA_DIR/logs/ingest_log.jsonl"
      echo "  proxy log:  $OUT_LOG"
    else
      echo "ingest proxy failed to start — check $OUT_LOG"
      rm -f "$PID_FILE"
      exit 1
    fi
    ;;
  stop)
    if is_running; then
      kill "$(cat "$PID_FILE")"
      rm -f "$PID_FILE"
      echo "ingest proxy stopped"
    else
      echo "ingest proxy not running"
    fi
    ;;
  status)
    if is_running; then
      echo "ingest proxy running (pid $(cat "$PID_FILE"))"
    else
      echo "ingest proxy not running"
    fi
    ;;
  *)
    echo "usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
