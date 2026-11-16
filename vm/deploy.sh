#!/bin/bash
# =============================================================================
# cjp VM deploy: runs ON the VM, called by `cjp vm deploy` after it has
# rsynced the repo's vm/ to this directory (~/cjp-vm). Plan P2.2.
#
# Idempotent: every step checks the current state and changes only what
# differs, so re-running it on an up-to-date VM changes nothing.
#
#   1. data dirs     juice-shop/data/{logs,sessions}. logs/ is world-writable
#                    because the Juice Shop container writes as uid 65532.
#   2. proxy venv    juice-shop/.venv with the mitmproxy pinned in
#                    juice-shop/requirements-proxy.txt.
#   3. Wazuh rules   copy wazuh/{decoders,rules} into the manager if they
#                    differ, run every case in wazuh/logtest_cases.tsv, and
#                    only then restart the manager. A failing case restores the
#                    previous files and nothing is restarted. (wazuh-logtest
#                    loads the rule files from disk per session, so it tests
#                    the new files before the restart; checked 30 Sep.)
#   4. Juice Shop    (re)create the container from this directory, so its
#                    access log lands in juice-shop/data/logs.
#   5. ingest proxy  restart it if it isn't running or its code changed, stop
#                    any proxy running from another checkout, and create
#                    today's log files with one throwaway request.
#   6. DEPLOYED_SHA  removed first, written last: it exists only after a
#                    complete deploy. DEPLOYED.json holds the details.
#
# Never uses sudo. The agent's <localfile> paths live in the root-owned
# ossec.conf; `cjp vm deploy` checks them through the manager API and prints
# the one sudo command if they need changing.
#
# Usage: bash deploy.sh <git-sha> [git-describe]
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHA="${1:?usage: deploy.sh <git-sha> [git-describe]}"
DESCRIBE="${2:-$SHA}"
MANAGER="${CJP_WAZUH_MANAGER:-single-node-wazuh.manager-1}"
JS="$ROOT/juice-shop"
DATA="$JS/data"
MITMPROXY_VERSION="$(sed -n 's/^mitmproxy==//p' "$JS/requirements-proxy.txt")"
RULE_FILES=(decoders/body_field_decoders.xml rules/body_field_rules.xml)

log() { echo "[deploy] $*"; }
die() { echo "[deploy] FAILED: $*" >&2; exit 1; }

rm -f "$ROOT/DEPLOYED_SHA" "$ROOT/DEPLOYED.json"
log "deploying $DESCRIBE ($SHA) to $ROOT"

# ── 1. data dirs ─────────────────────────────────────────────────────────────
mkdir -p "$DATA/logs" "$DATA/sessions"
chmod 0777 "$DATA/logs"
log "1/6 data dirs ready: $DATA"

# ── 2. proxy runtime ─────────────────────────────────────────────────────────
have_mitm="$("$JS/.venv/bin/mitmdump" --version 2>/dev/null | sed -n 's/^Mitmproxy: //p' || true)"
if [ "$have_mitm" != "$MITMPROXY_VERSION" ]; then
  log "2/6 building proxy runtime: mitmproxy ${have_mitm:-none} -> $MITMPROXY_VERSION"
  rm -rf "$JS/.venv"
  python3 -m venv "$JS/.venv"
  "$JS/.venv/bin/pip" install --quiet --disable-pip-version-check -r "$JS/requirements-proxy.txt"
else
  log "2/6 proxy runtime up to date (mitmproxy $MITMPROXY_VERSION)"
fi

# ── 3. Wazuh custom decoder and rules ────────────────────────────────────────
docker inspect "$MANAGER" >/dev/null 2>&1 || die "manager container $MANAGER not found (docker ps)"
changed=()
for f in "${RULE_FILES[@]}"; do
  want="$(sha256sum < "$ROOT/wazuh/$f" | cut -d' ' -f1)"
  have="$( { docker exec "$MANAGER" cat "/var/ossec/etc/$f" 2>/dev/null || true; } | sha256sum | cut -d' ' -f1)"
  [ "$want" = "$have" ] || changed+=("$f")
done

backup=""
if [ ${#changed[@]} -gt 0 ]; then
  backup="$ROOT/.deploy-backup/$(date -u +%Y%m%dT%H%M%SZ)"
  for f in "${changed[@]}"; do
    mkdir -p "$backup/$(dirname "$f")"
    docker cp "$MANAGER:/var/ossec/etc/$f" "$backup/$f" 2>/dev/null || true   # a new file has no previous version
    docker cp "$ROOT/wazuh/$f" "$MANAGER:/var/ossec/etc/$f"
    docker exec "$MANAGER" chown wazuh:wazuh "/var/ossec/etc/$f"
    docker exec "$MANAGER" chmod 660 "/var/ossec/etc/$f"
  done
  log "3/6 installed ${changed[*]} (previous versions in $backup)"
else
  log "3/6 manager rules already match the repo"
fi

restore_rules() {
  for f in "${changed[@]}"; do
    if [ -f "$backup/$f" ]; then
      docker cp "$backup/$f" "$MANAGER:/var/ossec/etc/$f"
    else
      docker exec "$MANAGER" rm -f "/var/ossec/etc/$f"
    fi
  done
}

n=0; fails=0
while IFS=$'\t' read -r expect line; do
  case "$expect" in ''|'#'*) continue ;; esac
  n=$((n + 1))
  if ! printf '%s\n' "$line" | docker exec -i "$MANAGER" /var/ossec/bin/wazuh-logtest -q -U "$expect" >/dev/null 2>&1; then
    fails=$((fails + 1))
    log "    logtest FAIL: expected $expect for: ${line:0:90}"
  fi
done < "$ROOT/wazuh/logtest_cases.tsv"
if [ "$fails" -gt 0 ]; then
  if [ ${#changed[@]} -gt 0 ]; then
    restore_rules
    die "$fails of $n logtest cases failed; previous rule files restored, manager not restarted"
  fi
  die "$fails of $n logtest cases failed against the rules already installed"
fi
log "    logtest: $n/$n cases pass"

if [ ${#changed[@]} -gt 0 ]; then
  log "    restarting the manager to load the new rules"
  docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart >/dev/null
  for _ in $(seq 1 30); do
    docker exec "$MANAGER" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running' && break
    sleep 2
  done
  docker exec "$MANAGER" /var/ossec/bin/wazuh-control status | grep -q 'wazuh-analysisd is running' \
    || die "wazuh-analysisd is not running after the restart; see docker exec $MANAGER tail /var/ossec/logs/ossec.log"
  log "    manager restarted, analysisd running"
fi

# ── 4. Juice Shop container ──────────────────────────────────────────────────
mount_src="$(docker inspect juice-shop --format '{{range .Mounts}}{{if eq .Destination "/juice-shop/logs"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
if [ "$mount_src" != "$DATA/logs" ]; then
  log "4/6 juice-shop logs to '${mount_src:-no container}'; recreating it from $JS"
else
  log "4/6 juice-shop container already logs to $DATA/logs"
fi
docker compose -f "$JS/docker-compose.yml" up -d 2>&1 | sed 's/^/    /'
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 || true)" = "200" ] && break
  sleep 2
done
[ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 || true)" = "200" ] \
  || die "Juice Shop is not answering 200 on :3000 (docker logs juice-shop)"
log "    Juice Shop answers 200 on :3000"

# ── 5. ingest proxy ──────────────────────────────────────────────────────────
for pid in $(pgrep -f 'mitmdump.*ingest_addon.py' || true); do
  if ! tr '\0' ' ' < "/proc/$pid/cmdline" | grep -qF "$JS/ingest_addon.py"; then
    log "5/6 stopping an ingest proxy from another checkout (pid $pid)"
    kill "$pid"
  fi
done
code_sha="$(cat "$JS/ingest_addon.py" "$JS/start_ingest_proxy.sh" | sha256sum | cut -d' ' -f1)"
stamp="$DATA/ingest_proxy.code.sha256"
if bash "$JS/start_ingest_proxy.sh" status | grep -q 'proxy running' && [ "$(cat "$stamp" 2>/dev/null || true)" = "$code_sha" ]; then
  log "5/6 ingest proxy running, code unchanged"
else
  bash "$JS/start_ingest_proxy.sh" stop >/dev/null
  bash "$JS/start_ingest_proxy.sh" start | sed 's/^/    /'
  echo "$code_sha" > "$stamp"
  log "5/6 ingest proxy (re)started from $JS"
fi
# One throwaway request writes a line to all three of today's logs, creating
# them if needed, so the agent can find them before a session starts (cold
# start, notes §7). A plain product search answers 200 and raises no alert in
# any arm. (GET / would not do: Juice Shop serves it before its access log.)
# mitmdump can take a few seconds to bind :8080 after start, hence the retries.
warm=""
for _ in $(seq 1 15); do
  warm="$(curl -s -o /dev/null -w '%{http_code}' -H 'Referer: cjp-deploy-warmup' \
          'http://localhost:8080/rest/products/search?q=apple' || true)"
  [ "$warm" = "200" ] && break
  sleep 2
done
[ "$warm" = "200" ] || die "no 200 from the ingest proxy on :8080 (got '${warm}'); see $DATA/logs/ingest_proxy.out"
today="$(date -u +%Y-%m-%d)"
for f in "access.log.$today" "enriched_access.log.$today" "body_field_access.log.$today"; do
  [ -f "$DATA/logs/$f" ] || die "expected $DATA/logs/$f after the warm-up request"
done
log "    today's three log files exist in $DATA/logs"

# ── 6. record what is deployed ───────────────────────────────────────────────
cat > "$ROOT/DEPLOYED.json" <<EOF
{
  "sha": "$SHA",
  "describe": "$DESCRIBE",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "juice_shop_image_id": "$(docker inspect juice-shop --format '{{.Image}}')",
  "wazuh_manager_image": "$(docker inspect "$MANAGER" --format '{{.Config.Image}}')",
  "mitmproxy": "$MITMPROXY_VERSION",
  "logtest_cases_passed": $n
}
EOF
echo "$SHA" > "$ROOT/DEPLOYED_SHA"
log "6/6 DEPLOYED_SHA = $SHA"
