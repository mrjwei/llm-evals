#!/bin/bash
# =============================================================================
# WP1 Ingest Proxy — daily warm-up
#
# Mitigates a real, diagnosed Wazuh file-discovery cold start: the agent
# doesn't tail enriched_access.log.<date>/body_field_access.log.<date> until
# it notices the newly-created file, and that discovery isn't instant — a
# ~46-second gap was measured directly (session_20260916_075013, see
# docs/STATUS.md's 2026-09-16 entries), during which real attack techniques
# in that day's first proxied session went completely unalerted in the
# enriched/body_field arms. access.log doesn't have this problem because
# Wazuh has typically already been tailing it since much earlier in the day.
#
# This sends one throwaway request through the ingest proxy — which is what
# actually creates that day's dated log file, since ingest_addon.py computes
# the path fresh per-request rather than pre-creating it — then waits long
# enough for Wazuh to discover it, before any real session's alerts would be
# missed. A no-op once that day's file already exists, so it's safe to run
# before every session without needlessly re-waiting.
#
# Usage: bash warm_ingest_proxy.sh
#   Requires JUICE_URL to point at the ingest proxy (same convention as
#   attacks.sh/benign_traffic.sh) — a no-op otherwise, since warming up a
#   direct (non-proxied) session's access.log doesn't apply here.
# =============================================================================

# Data lives next to this script (juice-shop/data/), wherever it is deployed
# (~/cjp-vm since Plan P2.2); CJP_DATA_DIR overrides it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${CJP_DATA_DIR:-$SCRIPT_DIR/data}"
LOG_DIR="$DATA_DIR/logs"
WAIT_SECONDS=60

if [ -z "${JUICE_URL:-}" ]; then
  echo "warm_ingest_proxy: JUICE_URL not set, skipping (not a proxied session)"
  exit 0
fi

DATE_SUFFIX=$(date -u +%Y-%m-%d)
ENRICHED_LOG="$LOG_DIR/enriched_access.log.$DATE_SUFFIX"

if [ -f "$ENRICHED_LOG" ]; then
  echo "warm_ingest_proxy: $ENRICHED_LOG already exists, skipping (not the first proxied session today)"
  exit 0
fi

echo "warm_ingest_proxy: no enriched_access.log.$DATE_SUFFIX yet — sending a throwaway request through $JUICE_URL"
curl -s -o /dev/null "$JUICE_URL/"

if [ ! -f "$ENRICHED_LOG" ]; then
  echo "warm_ingest_proxy: warning — $ENRICHED_LOG still doesn't exist after the throwaway request; is the ingest proxy running? (start_ingest_proxy.sh status)"
  exit 1
fi

echo "warm_ingest_proxy: $ENRICHED_LOG created, waiting ${WAIT_SECONDS}s for Wazuh to discover it"
sleep "$WAIT_SECONDS"
echo "warm_ingest_proxy: done"
