#!/bin/bash
# =============================================================================
# WP1 Benign Traffic Generator — OWASP Juice Shop
#
# Fires realistic, non-malicious user journeys against Juice Shop so that
# sessions have true negatives to measure against. Without this, precision
# and false-positive rate are undefined (Plan M6) — every alert looks like a
# true positive because nothing else was ever sent.
#
# Every route below was checked against the running Juice Shop (19.2.1) to
# return its expected status (Plan P3.1, P3.2, 1 Oct). Logged-in requests send
# the user's own token and basket id, as the Juice Shop web app does.
#
# Journeys 1-5 are ordinary use and should raise no alert. Journeys 6-11 are
# hard negatives (Plan P3.2): legitimate behaviour that looks like an attack
# to a signature or status-code rule (typos at login, a password change,
# page refreshes, informal feedback, stale links, searches with apostrophes or
# SQL-ish words). They supply the alerting benign requests that precision and
# the false-positive rate are measured on.
#
# Mirrors attacks.sh's conventions exactly, so the cjp mapper and the
# triage leakage sanitiser handle both with the same code path:
#   - every request goes through fire(), tagged with a correlation ID sent
#     via the Referer header (-e), of the form
#     wp1-benign-<session>-<seq>-<req_seq> — the "benign-" infix is the only
#     difference from attacks.sh's cid scheme, and is what lets a downstream
#     mapper tell "this alert came from benign traffic" from "this alert
#     came from an attack technique" using the same join key shape.
#   - one "kind":"attack"-equivalent record per journey (here "kind":"attack"
#     too, category "BENIGN", so the mapper's existing attack-log parser
#     needs no separate code path) plus one "kind":"request" record per HTTP
#     call, exactly like attacks.sh.
#
# Pacing is deliberately slower and more irregular than attacks.sh's tight
# loops — real users don't fire 5 identical requests 0.4s apart. Delays here
# are randomised within a human-plausible range instead of fixed.
#
# Session handling (matches attacks.sh's per-session fix): writes into
# data/sessions/<SESSION_ID>/benign_log.jsonl instead of one shared,
# never-rotated file. If attacks.sh was run within the last
# LAST_SESSION_MAX_AGE seconds (the documented "run attacks.sh then
# benign_traffic.sh" workflow, RUNBOOK), this script joins that same session
# directory rather than minting an unrelated id — so one collection session
# ends up as one directory with both attack_log.jsonl and benign_log.jsonl.
# An explicit session id can also be passed as $1 to force this.
#
# Usage: bash benign_traffic.sh [session_id]
# Output: <this dir>/data/sessions/<SESSION_ID>/
#           benign_log.jsonl, access.log, ingest_log.jsonl (only populated
#           when JUICE_URL points at the ingest proxy)
# =============================================================================

JUICE="${JUICE_URL:-http://localhost:3000}"
# Data lives next to this script (juice-shop/data/), wherever it is deployed
# (~/cjp-vm since Plan P2.2); CJP_DATA_DIR overrides it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${CJP_DATA_DIR:-$SCRIPT_DIR/data}"
LAST_SESSION_FILE="$DATA_DIR/.last_session"
# seconds; join an attacks.sh session started within this window. Measured
# from attacks.sh's start (its SESSION_ID timestamp), not its finish — a
# full attacks.sh run can itself take 30+ minutes, so this needs enough
# headroom past that runtime for benign_traffic.sh to still join even when
# started immediately after attacks.sh completes.
LAST_SESSION_MAX_AGE=3600

# The benign set: the journeys below and their requests. Bump it whenever
# they change, so a session's benign alerts can be compared only with
# sessions from the same set. The script's own hash is recorded too, so a
# forgotten bump still shows. 1: the legacy set; 2: real routes and the
# user's own token and basket (Plan P3.1); 3: hard-negative journeys 6-11
# (Plan P3.2).
BENIGN_SET_VERSION=3

# Provenance for the session_manifest marker, as in attacks.sh (Plan P2.3).
# SEED also seeds $RANDOM, the only randomness here (random_delay), so a
# seeded session repeats the same pacing.
SEED="${SEED:-}"
if [ -n "$SEED" ] && ! [[ "$SEED" =~ ^[0-9]+$ ]]; then
  echo "Error: SEED must be a non-negative integer (got: $SEED)" >&2
  exit 1
fi
if [ -n "$SEED" ]; then RANDOM=$SEED; fi
DEPLOYED_SHA=$(cat "$SCRIPT_DIR/../DEPLOYED_SHA" 2>/dev/null || true)
SCRIPT_SHA256=$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)

mkdir -p "$DATA_DIR"

# session_epoch <SESSION_ID> — parse the YYYYMMDD_HHMMSS session id back into
# epoch seconds so its age can be checked; empty/unparseable on failure.
session_epoch() {
  local sid=$1
  date -d "${sid:0:4}-${sid:4:2}-${sid:6:2} ${sid:9:2}:${sid:11:2}:${sid:13:2}" +%s 2>/dev/null
}

SESSION_ID=${1:-}
if [ -z "$SESSION_ID" ] && [ -f "$LAST_SESSION_FILE" ]; then
  candidate=$(cat "$LAST_SESSION_FILE" 2>/dev/null)
  candidate_epoch=$(session_epoch "$candidate")
  if [ -n "$candidate_epoch" ]; then
    age=$(( $(date +%s) - candidate_epoch ))
    if [ "$age" -ge 0 ] && [ "$age" -le "$LAST_SESSION_MAX_AGE" ]; then
      SESSION_ID=$candidate
      echo "[*] Joining existing session $SESSION_ID (attacks.sh started ${age}s ago)"
    fi
  fi
fi
if [ -z "$SESSION_ID" ]; then
  SESSION_ID=$(date +%Y%m%d_%H%M%S)
  echo "[*] Starting standalone benign session $SESSION_ID"
fi

SESSION_DIR="$DATA_DIR/sessions/$SESSION_ID"
LOG_FILE="$SESSION_DIR/benign_log.jsonl"
mkdir -p "$SESSION_DIR"

# =============================================================================
# Helpers
# =============================================================================

ATTACK_SEQ=0
REQ_SEQ=0
CUR_CAT=""
CUR_LABEL=""
# Set by the login journey. While set, fire() sends it the way the Juice Shop
# web app does: as a Bearer header and as the `token` cookie (some routes,
# e.g. /rest/user/whoami, read only the cookie). No log arm records either
# header (ingest_addon.py keeps only Content-Type, User-Agent and Referer),
# so the JWT, which names the user, never reaches the prompt.
AUTH_TOKEN=""

# random_delay <min> <max> — sleep a human-plausible, non-uniform interval
# rather than attacks.sh's fixed short/between delays.
random_delay() {
  local min=$1 max=$2
  # Draw $RANDOM here, in the script's own shell: bash reseeds it inside
  # $(...) (checked on the VM's bash 5.2), so a draw there would ignore SEED.
  local r=$RANDOM
  local range=$(echo "$max - $min" | bc)
  local frac=$(awk -v seed=$r 'BEGIN{srand(seed); print rand()}')
  local delay=$(echo "$min + $frac * $range" | bc -l)
  sleep "$delay"
}

log_journey() {
  local label=$1 description=$2 url=$3
  ATTACK_SEQ=$((ATTACK_SEQ+1))
  REQ_SEQ=0
  CUR_CAT="BENIGN"
  CUR_LABEL=$label
  echo "{\"kind\":\"attack\",\"session\":\"$SESSION_ID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"attack_seq\":$ATTACK_SEQ,\"category\":\"BENIGN\",\"label\":\"$label\",\"description\":\"$description\",\"url\":\"$url\"}" >> $LOG_FILE
}

section() {
  echo ""
  echo "──────────────────────────────────────────"
  echo "[*] $1"
  echo "──────────────────────────────────────────"
}

# fire <method> <url> [body] [outfile] — issue one correlation-ID-tagged HTTP
# request and log a "kind":"request" record, exactly like attacks.sh's fire().
# The response body is discarded unless <outfile> is given (the login token,
# the captcha answer). It is written to a file, not returned through $(...):
# a command substitution runs the function in a subshell, so its REQ_SEQ
# increment would be lost and the next request would reuse the same CID.
fire() {
  local method=$1 url=$2 body=${3:-} outfile=${4:-/dev/null}
  REQ_SEQ=$((REQ_SEQ+1))
  local cid="wp1-benign-${SESSION_ID}-${ATTACK_SEQ}-${REQ_SEQ}"
  local t_start=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)

  local args=(-s -o "$outfile" -w '%{http_code}' -e "$cid")
  if [ -n "$AUTH_TOKEN" ]; then
    args+=(-H "Authorization: Bearer $AUTH_TOKEN" -b "token=$AUTH_TOKEN")
  fi
  local status
  if [ -z "$body" ]; then
    status=$(curl "${args[@]}" "$JUICE$url")
  else
    status=$(curl "${args[@]}" -X "$method" "$JUICE$url" \
             -H 'Content-Type: application/json' -d "$body")
  fi

  local t_end=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  printf '{"kind":"request","cid":"%s","session":"%s","attack_seq":%d,"req_seq":%d,"category":"%s","label":"%s","method":"%s","url":"%s","status":"%s","t_start":"%s","t_end":"%s"}\n' \
    "$cid" "$SESSION_ID" "$ATTACK_SEQ" "$REQ_SEQ" "$CUR_CAT" "$CUR_LABEL" \
    "$method" "$url" "$status" "$t_start" "$t_end" >> "$LOG_FILE"
}

# log_in <password> — submit the login form for $BENIGN_EMAIL. The response
# carries the user's token and own basket id ("bid"): on success they are set
# in LOGIN_TOKEN and LOGIN_BASKET, on a failed login (401) both are empty.
# The legacy script asked for /rest/basket/1 (another user's basket) with no
# token: a 401, and with a token it would have been the basket-IDOR attack.
log_in() {
  local response_file
  response_file=$(mktemp)
  fire POST "/rest/user/login" \
    "{\"email\":\"$BENIGN_EMAIL\",\"password\":\"$1\"}" "$response_file"
  LOGIN_TOKEN=$(grep -o '"token":"[^"]*"' "$response_file" | cut -d'"' -f4)
  LOGIN_BASKET=$(grep -o '"bid":[0-9]*' "$response_file" | cut -d: -f2)
  rm -f "$response_file"
}

# leave_feedback <rating> <comment> — the Customer Feedback form: load a
# captcha, then post the feedback anonymously. A person solves the captcha;
# Juice Shop also returns its answer, which is read here. <comment> must not
# contain a double quote or backslash (it goes into the JSON body as is).
leave_feedback() {
  local rating=$1 comment=$2 captcha_file captcha_id answer
  captcha_file=$(mktemp)
  fire GET "/rest/captcha" "" "$captcha_file"
  captcha_id=$(grep -o '"captchaId":[0-9]*' "$captcha_file" | cut -d: -f2)
  answer=$(grep -o '"answer":"[^"]*"' "$captcha_file" | cut -d'"' -f4)
  rm -f "$captcha_file"
  random_delay 10 25          # reading the form and typing the comment
  fire POST "/api/Feedbacks/" \
    "{\"captchaId\":${captcha_id:-0},\"captcha\":\"$answer\",\"comment\":\"$comment\",\"rating\":$rating}"
}

# search <term> — the search box: spaces become %20, as in the web app's URL.
# Apostrophes stay as typed (browsers don't percent-encode them in a query).
search() {
  fire GET "/rest/products/search?q=$(echo "$1" | sed 's/ /%20/g')"
}

# =============================================================================
# Session start
# =============================================================================

echo "============================================="
echo "  WP1 Benign Traffic Session: $SESSION_ID"
echo "  Target: $JUICE"
echo "  Log: $LOG_FILE"
echo "============================================="
echo "{\"session\":\"$SESSION_ID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"session_start\"}" >> $LOG_FILE

# =============================================================================
# Journey 1 — browse the product catalogue
# =============================================================================

section "Browse product catalogue"
log_journey "browse_catalogue" "Anonymous user browses the product listing and views item details and reviews" "/api/Products"
fire GET "/api/Products"
random_delay 1 3
# Ids that exist in Juice Shop 19.2.1 (12 and 40 return 404).
for id in 1 3 7 19 24; do
  fire GET "/api/Products/$id"
  random_delay 1 2
  fire GET "/rest/products/$id/reviews"
  random_delay 1 4
done

random_delay 2 5

# =============================================================================
# Journey 2 — search for real products
# =============================================================================

section "Search products (legitimate terms)"
log_journey "search_products" "Search the catalogue using ordinary, non-malicious search terms" "/rest/products/search"
for term in apple juice banana orange "fruit press"; do
  search "$term"
  random_delay 1 3
done

random_delay 2 5

# =============================================================================
# Journey 3 — browse static/info pages
# =============================================================================

section "Browse informational pages"
log_journey "browse_info_pages" "View About Us, contact form, and public assets" "/"
fire GET "/"
random_delay 1 2
fire GET "/rest/admin/application-version"
random_delay 1 2
fire GET "/rest/languages"
random_delay 1 2
fire GET "/rest/products/search?q="
random_delay 2 5

# =============================================================================
# Journey 4 — register a new (legitimate) account
# =============================================================================

section "Register a new account"
log_journey "register_account" "Register a new account with valid, well-formed credentials" "/api/Users/"
# Unique per session (Juice Shop emails are unique), but nothing in it says
# "benign" or matches the session-id pattern the CID redaction looks for:
# the register and login bodies reach the prompt in the L1 conditions.
BENIGN_EMAIL="alex.morgan+${SESSION_ID//_/}@example.com"
BENIGN_PASS="CorrectHorseBattery9!"
fire POST "/api/Users/" \
  "{\"email\":\"$BENIGN_EMAIL\",\"password\":\"$BENIGN_PASS\",\"passwordRepeat\":\"$BENIGN_PASS\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"none\"}"

random_delay 2 4

# =============================================================================
# Journey 5 — log in with the account just created, browse basket, checkout
# =============================================================================

section "Login and shopping flow"
log_journey "login_and_shop" "Legitimate login, view own profile and basket, add an item" "/rest/user/login"
log_in "$BENIGN_PASS"
BASKET_ID=$LOGIN_BASKET

random_delay 1 3

if [ -n "$LOGIN_TOKEN" ] && [ -n "$BASKET_ID" ]; then
  AUTH_TOKEN=$LOGIN_TOKEN
  fire GET "/rest/user/whoami"
  random_delay 1 2
  fire GET "/rest/basket/$BASKET_ID"
  random_delay 1 3
  fire POST "/api/BasketItems/" "{\"ProductId\":1,\"BasketId\":\"$BASKET_ID\",\"quantity\":1}"
  random_delay 1 2
  fire GET "/rest/basket/$BASKET_ID"
  AUTH_TOKEN=""
else
  echo "[!] Login returned no token or basket id — skipping the logged-in requests" >&2
fi

random_delay 2 4

# =============================================================================
# Hard negatives (Plan P3.2). Each status below was checked on Juice Shop
# 19.2.1 (1 Oct), with the stock rule it raises in S1, the plain access log.
# 4xx statuses are spread over journeys 6, 7 and 10, with quiet journeys in
# between, so they stay well below stock rule 31151 (14 within 90 s from one
# IP, and every request here comes from the same Docker gateway).
# =============================================================================

# =============================================================================
# Journey 6 — mistyped password, then a successful login
# =============================================================================

section "Mistyped password, then login"
log_journey "mistyped_login" "Returning user tries to sign up again, mistypes the password twice, then logs in" "/rest/user/login"
# Forgot they already have an account: 400 "email must be unique" (31101).
fire POST "/api/Users/" \
  "{\"email\":\"$BENIGN_EMAIL\",\"password\":\"$BENIGN_PASS\",\"passwordRepeat\":\"$BENIGN_PASS\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"none\"}"
random_delay 3 6
log_in "CorrectHorseBatery9!"         # a dropped letter: 401 (31101)
random_delay 3 6
log_in "cORRECThORSEbATTERY9!"        # caps lock on: 401 (31101)
random_delay 4 8
log_in "$BENIGN_PASS"
if [ -n "$LOGIN_TOKEN" ]; then
  AUTH_TOKEN=$LOGIN_TOKEN
  random_delay 1 2
  fire GET "/rest/user/whoami"
fi

random_delay 2 5

# =============================================================================
# Journey 7 — change the password, then log in again
# =============================================================================

section "Change password"
log_journey "change_password" "Changes the password (mistypes the repeat once), logs out, logs in with the old one by habit, then the new one" "/rest/user/change-password"
# Juice Shop's change-password form is a GET with the passwords in the query
# string, so they appear in every arm's log, as they would in production.
NEW_PASS="OrchardWalk-2026!"
if [ -n "$AUTH_TOKEN" ]; then
  # Repeat field mistyped: 401 "New and repeated password do not match" (31101).
  fire GET "/rest/user/change-password?current=$BENIGN_PASS&new=$NEW_PASS&repeat=OrchardWalk-2026"
  random_delay 3 6
  fire GET "/rest/user/change-password?current=$BENIGN_PASS&new=$NEW_PASS&repeat=$NEW_PASS"
  AUTH_TOKEN=""                       # logging out only drops the token client-side
  random_delay 5 10
  log_in "$BENIGN_PASS"               # the old password by habit: 401 (31101)
  random_delay 3 6
  log_in "$NEW_PASS"
else
  echo "[!] Not logged in — skipping the password change" >&2
fi

random_delay 2 5

# =============================================================================
# Journey 8 — refresh a product page several times
# =============================================================================

section "Refresh a product page"
log_journey "product_refresh" "Reloads the same product page several times, as on a slow connection" "/api/Products/24"
for i in 1 2 3 4; do
  fire GET "/api/Products/24"
  random_delay 0.3 1
  fire GET "/rest/products/24/reviews"
  random_delay 1 3
done

random_delay 2 5

# =============================================================================
# Journey 9 — long, informal customer feedback
# =============================================================================

section "Leave customer feedback"
log_journey "leave_feedback" "Leaves long, informal feedback with apostrophes, dashes and everyday words such as from, where and select" "/api/Feedbacks/"
# No alert in S1 (the body isn't logged there). The body-carrying arms see
# " from " and " where " (stock 31103 in S2, 100011 in S3), plus "--" and a
# quoted 'select all'. Kept well under stock 31115's 7900-byte URL limit in S2.
leave_feedback 5 "Honestly the best juice I've had since moving here. I ordered the apple juice and the lemon juice for my partner's birthday and both arrived cold, which I didn't expect from an online shop. Two small things: the search didn't find O'Reilly's cider (maybe you don't stock it?), and it took me a while to work out where the delivery options were. I'd also love a mixed box where you can select juice flavours yourself, e.g. 3 apple + 3 banana. Anyway, 10/10 would order again, and I've already told my neighbours about you!"
random_delay 3 8
leave_feedback 2 "Juice was fine but delivery took 3 weeks -- not great. Also: please add a 'select all' button to the basket; removing items one by one from a big order is tedious."

random_delay 2 5

# =============================================================================
# Journey 10 — stale links to products no longer in the catalogue
# =============================================================================

section "Follow stale product links"
log_journey "stale_links" "Opens old bookmarks and shared links to products that are no longer in the catalogue" "/api/Products/12"
# Gaps in the catalogue's ids (10, 11, 12, 27, 28, 31, 39, 40, 44 on 1 Oct).
# The product page loads the product (404, 31101) and its reviews (200, []).
for id in 12 40 10 28 44; do
  fire GET "/api/Products/$id"
  random_delay 0.3 1
  fire GET "/rest/products/$id/reviews"
  random_delay 3 8
done

random_delay 2 5

# =============================================================================
# Journey 11 — searches with apostrophes and SQL-ish words
# =============================================================================

section "Search with apostrophes and SQL-ish words"
log_journey "search_tricky_terms" "Searches for names with apostrophes and phrases containing select, from and union" "/rest/products/search"
# An apostrophe breaks Juice Shop's own (injectable) search query: 500, stock
# 31122. The others return 200 but match stock 31103's keywords: 31106.
for term in "O'Reilly" "kid's t-shirt" "granny's apple" "select juice" "juice from concentrate" "union jack sticker"; do
  search "$term"
  random_delay 2 6
done

random_delay 2 4

# =============================================================================
# Session end
# =============================================================================

echo ""
echo "============================================="
echo "  Benign session complete: $SESSION_ID"
echo "  Log written to: $LOG_FILE"
echo "============================================="
echo "{\"session\":\"$SESSION_ID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"session_end\"}" >> $LOG_FILE

# Snapshot this session's own benign access-log lines, same approach as
# attacks.sh: grep by CID prefix, not by date, so this session's lines are
# correctly isolated even when other sessions ran the same day. Appended
# (not overwritten) since attacks.sh may already have written access.log
# into this same session directory.
sleep 1
grep -Fh "wp1-benign-${SESSION_ID}-" "$DATA_DIR"/logs/access.log.* 2>/dev/null >> "$SESSION_DIR/access.log"
ACCESS_LOG_COUNT=$(grep -Fc "wp1-benign-${SESSION_ID}-" "$SESSION_DIR/access.log" 2>/dev/null)
echo "  Access-log lines matched to this session: ${ACCESS_LOG_COUNT:-0}"

# Same pattern, against the ingest-proxy's flat body-level log (see
# ingest_addon.py). Appended, not overwritten, since attacks.sh may already
# have written ingest_log.jsonl into this same session directory. Empty when
# the session didn't run through the proxy (JUICE_URL unset) — expected, not
# an error.
grep -Fh "wp1-benign-${SESSION_ID}-" "$DATA_DIR/logs/ingest_log.jsonl" 2>/dev/null >> "$SESSION_DIR/ingest_log.jsonl"
INGEST_LOG_COUNT=$(grep -Fc "wp1-benign-${SESSION_ID}-" "$SESSION_DIR/ingest_log.jsonl" 2>/dev/null)
INGEST_LOG_COUNT=${INGEST_LOG_COUNT:-0}
echo "  Ingest-log lines matched to this session: $INGEST_LOG_COUNT"

# Same pattern again, against the ingest-proxy's apache-format enriched
# access log (see ingest_addon.py / attacks.sh). Appended, not overwritten,
# for the same reason as above.
grep -Fh "wp1-benign-${SESSION_ID}-" "$DATA_DIR"/logs/enriched_access.log.* 2>/dev/null >> "$SESSION_DIR/enriched_access.log"
ENRICHED_LOG_COUNT=$(grep -Fc "wp1-benign-${SESSION_ID}-" "$SESSION_DIR/enriched_access.log" 2>/dev/null)
echo "  Enriched access-log lines matched to this session: ${ENRICHED_LOG_COUNT:-0}"

# Same pattern again, against the ingest-proxy's body-field access log (see
# ingest_addon.py / attacks.sh) — arm 3. Appended, not overwritten, for the
# same reason as above.
grep -Fh "wp1-benign-${SESSION_ID}-" "$DATA_DIR"/logs/body_field_access.log.* 2>/dev/null >> "$SESSION_DIR/body_field_access.log"
BODY_FIELD_LOG_COUNT=$(grep -Fc "wp1-benign-${SESSION_ID}-" "$SESSION_DIR/body_field_access.log" 2>/dev/null)
echo "  Body-field access-log lines matched to this session: ${BODY_FIELD_LOG_COUNT:-0}"

# VM-side facts about the benign leg of this session, same rationale as
# attacks.sh; `cjp collect` copies them into manifest.json.
if [ "$INGEST_LOG_COUNT" -gt 0 ]; then APPLICATION_LOGGING=true; else APPLICATION_LOGGING=false; fi
if [ -n "$DEPLOYED_SHA" ]; then DEPLOYED_SHA_JSON="\"$DEPLOYED_SHA\""; else DEPLOYED_SHA_JSON=null; fi
echo "{\"session\":\"$SESSION_ID\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"session_manifest\",\"application_logging\":$APPLICATION_LOGGING,\"vm_deployed_sha\":$DEPLOYED_SHA_JSON,\"seed\":${SEED:-null},\"script_sha256\":\"$SCRIPT_SHA256\",\"benign_set_version\":$BENIGN_SET_VERSION}" >> $LOG_FILE
echo "  Session directory: $SESSION_DIR"
