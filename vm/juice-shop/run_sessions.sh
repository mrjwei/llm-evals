#!/bin/bash
# =============================================================================
# WP1 Session Runner — OWASP Juice Shop
#
# Runs attacks.sh and/or benign_traffic.sh for one or more sessions with a
# single command. When both are run for a session, benign_traffic.sh is
# invoked immediately after attacks.sh so it joins the same session
# directory via its own last-session logic (see benign_traffic.sh), instead
# of minting an unrelated session id.
#
# Sessions run through the ingest proxy (JUICE_URL=http://localhost:8080)
# unless JUICE_URL is set, because only a proxied session fills all three
# SIEM evidence arms (Plan P2.3). Set JUICE_URL=http://localhost:3000 for a
# direct, S1-only session.
#
# Before the first session, runs warm_ingest_proxy.sh — a no-op unless
# JUICE_URL points at the ingest proxy and today's enriched_access.log
# doesn't exist yet, in which case it sends a throwaway request and waits
# ~1 minute so Wazuh discovers the new daily log file before any real
# session's early alerts would otherwise be missed (see that script and
# wazuh-and-vm-notes §7).
#
# Usage: bash run_sessions.sh [-n N] [-m both|attacks|benign] [-s SEED]
#   -n, --sessions N   Number of sessions to run (default: 1)
#   -m, --mode MODE    Which script(s) to run: both, attacks, or benign
#                       (default: both)
#   -s, --seed SEED    Seed of the first session; session i gets SEED+i-1,
#                       passed to both scripts as SEED (default: unseeded)
#   -h, --help         Show this help message
#
# Examples:
#   bash run_sessions.sh -s 1                   # 1 session, both scripts, seed 1
#   bash run_sessions.sh -n 3 -s 1               # 3 sessions, seeds 1, 2, 3
#   bash run_sessions.sh -n 3 -m attacks          # 3 attack-only sessions
#   bash run_sessions.sh --mode benign            # 1 benign-only session
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SESSIONS=1
MODE="both"
SEED_START=""
export JUICE_URL="${JUICE_URL:-http://localhost:8080}"

usage() {
  sed -n '2,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--sessions)
      SESSIONS="${2:-}"
      shift 2
      ;;
    -m|--mode)
      MODE="${2:-}"
      shift 2
      ;;
    -s|--seed)
      SEED_START="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "$SESSIONS" =~ ^[0-9]+$ ]] || [ "$SESSIONS" -lt 1 ]; then
  echo "Error: --sessions must be a positive integer (got: $SESSIONS)" >&2
  exit 1
fi

if [ -n "$SEED_START" ] && ! [[ "$SEED_START" =~ ^[0-9]+$ ]]; then
  echo "Error: --seed must be a non-negative integer (got: $SEED_START)" >&2
  exit 1
fi

case "$MODE" in
  both|attacks|benign) ;;
  *)
    echo "Error: --mode must be one of: both, attacks, benign (got: $MODE)" >&2
    exit 1
    ;;
esac

echo "============================================="
echo "  WP1 Session Runner"
echo "  Sessions: $SESSIONS"
echo "  Mode: $MODE"
echo "  Target: $JUICE_URL"
echo "  Seed: ${SEED_START:-none}"
echo "============================================="

bash "$SCRIPT_DIR/warm_ingest_proxy.sh" || true

for i in $(seq 1 "$SESSIONS"); do
  if [ -n "$SEED_START" ]; then export SEED=$((SEED_START + i - 1)); fi
  echo ""
  echo ">>> Session run $i/$SESSIONS (mode: $MODE, seed: ${SEED:-none})"

  case "$MODE" in
    both)
      bash "$SCRIPT_DIR/attacks.sh"
      bash "$SCRIPT_DIR/benign_traffic.sh"
      ;;
    attacks)
      bash "$SCRIPT_DIR/attacks.sh"
      ;;
    benign)
      bash "$SCRIPT_DIR/benign_traffic.sh"
      ;;
  esac
done

echo ""
echo "============================================="
echo "  All $SESSIONS session run(s) complete"
echo "============================================="
