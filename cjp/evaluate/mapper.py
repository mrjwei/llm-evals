"""
WP4 — map Wazuh alerts back to the WP1 attack technique that produced them.
Moved from wp4_mapper.py in Plan P2.1; run it as `cjp map`. Output goes to
data/outputs/wp4/<session>/<arm>_v<N>/output.jsonl.

Three tiers (ARCHITECTURE §4):
  Tier 1 — exact match via the correlation ID (CID) carried in the Referer
           header and surviving verbatim into full_log (attacks.sh v4+).
  Tier 2 — interval fallback for sessions collected before CID instrumentation:
           match on the request time parsed out of full_log against explicit,
           closed attack time windows (with a declared tolerance), never on
           [t_n, t_{n+1}) half-open guessing.
  Tier 3 — an independent URL/method signature cross-check, reported alongside
           (not instead of) the CID/interval result. Plan M9 reuses
           SIGNATURES as the URL-regex baseline.

Every alert gets an explicit match_method and match_confidence — nothing is
silently assigned.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

from cjp.config import OUTPUTS_DIR
from cjp.runs import git_sha, resolve_run_dir, write_meta

# Matches both attacks.sh's wp1-<session>-<seq>-<req> and
# benign_traffic.sh's wp1-benign-<session>-<seq>-<req> — the "benign-" infix
# is how a benign request's CID is told apart from an attack's. Two
# alternatives: quoted (apache-combined's Referer field, arms 1/2 —
# access.log/enriched_access.log) or cid=<cid> unquoted (arm 3's bespoke
# body_probe line format, body_field_access.log — see
# vm/wazuh/decoders/body_field_decoders.xml).
CID_RE = re.compile(r'"(wp1-(?:benign-)?\d{8}_\d{6}-\d+-\d+)"|cid=(wp1-(?:benign-)?\d{8}_\d{6}-\d+-\d+)')
CID_SESSION_RE = re.compile(r"^wp1-(?:benign-)?(\d{8}_\d{6})-")


def alert_cid(alert: dict) -> str | None:
    """The correlation ID in an alert's full_log, or None."""
    m = CID_RE.search(alert.get("full_log", ""))
    return (m.group(1) or m.group(2)) if m else None


def cid_session(cid: str) -> str | None:
    """The session id inside a CID: wp1-[benign-]<session>-<seq>-<req>."""
    m = CID_SESSION_RE.match(cid)
    return m.group(1) if m else None

# request time inside full_log, e.g. [03/Aug/2026:08:59:37 +0000]
LOG_TIME_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Correlation rules whose alert spans multiple attack techniques by design —
# assigning them to a single technique would be a category error.
AGGREGATE_RULE_IDS = {"31151"}

# Tier 3 — independent signature cross-check. Order matters: first
# match wins. Some labels share an identical (method, URL) shape and are
# genuinely inseparable by signature alone — grouped explicitly rather than
# guessed at, per the doc's own known-limitation note.
LOGIN_AMBIGUOUS = {"sql_injection", "brute_force", "weak_credentials", "account_enumeration"}
FEEDBACK_AMBIGUOUS = {"improper_input_validation", "forged_feedback"}

SIGNATURES = [
    ("idor", "GET", r"^/rest/basket/\d+$"),
    ("path_traversal", "GET", r"^/ftp/(\.\.|%2e|%2E)"),
    ("sensitive_data_exposure", "GET", r"^/ftp/[\w.\-]+$"),
    ("login_endpoint_probe", "POST", r"^/rest/user/login"),  # sql_injection | brute_force | weak_credentials | account_enumeration
    ("sql_injection_union", "GET", r"^/rest/products/search\?q=.*union", ),
    ("xss", "GET", r"^/rest/products/search\?q=.*(script|iframe|onerror)"),
    ("security_misconfiguration", "GET",
     r"^/(score-board|api-docs|administration|metrics|swagger\.json|api/Challenges)"),
    ("feedback_endpoint_probe", "POST", r"^/api/Feedbacks/"),  # improper_input_validation | forged_feedback
    ("error_probing", "GET",
     r"^/(admin|config|backup|hidden|secret|\.git|wp-admin|phpmyadmin|robots\.txt|\.env|web\.config|server-status)$"),
    ("ssrf", "POST", r"^/profile/image/url$"),
]
# signature labels that are structurally ambiguous between two-or-more ground-truth
# labels (identical request shape, only distinguishable by body content the access
# log doesn't carry) — mapped to the set of labels they should be considered to agree with
AMBIGUOUS_GROUPS = {
    "login_endpoint_probe": LOGIN_AMBIGUOUS,
    "feedback_endpoint_probe": FEEDBACK_AMBIGUOUS,
}
_COMPILED_SIGNATURES = [(label, method, re.compile(pattern, re.IGNORECASE))
                         for label, method, pattern in SIGNATURES]


def signature_match(method: str, url: str) -> str | None:
    for label, sig_method, pattern in _COMPILED_SIGNATURES:
        if sig_method and method and sig_method.upper() != method.upper():
            continue
        if pattern.search(url or ""):
            return label
    return None


def labels_agree(mapped_label: str | None, sig_label: str | None) -> bool | None:
    if mapped_label is None or sig_label is None:
        return None
    group = AMBIGUOUS_GROUPS.get(sig_label)
    if group is not None:
        return mapped_label in group
    return mapped_label == sig_label


def parse_log_time(full_log: str):
    """Parse the [dd/Mon/yyyy:HH:MM:SS +ZZZZ] request time out of full_log."""
    m = LOG_TIME_RE.search(full_log or "")
    if not m:
        return None
    ts_str, tz_str = m.groups()
    day, mon, rest = ts_str.split("/", 2)
    year, hh, mm, ss = rest.split(":")
    dt = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                   tzinfo=timezone.utc)
    sign = 1 if tz_str[0] == "+" else -1
    offset = timedelta(hours=int(tz_str[1:3]), minutes=int(tz_str[3:5])) * sign
    return dt - offset


def parse_iso(ts: str):
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_jsonl(path: str) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"WARNING: skipping unparseable line in {path}: {line[:80]!r}")
    return records


def build_ground_truth(attack_log_path: str):
    """
    Returns (cid_to_request, attack_windows):
      cid_to_request: cid -> request record (attack_seq, category, label, method, url, status)
      attack_windows: list of dicts with attack_seq, category, label, skipped,
                      window_start, window_end (both tz-aware datetimes)
    Handles both the v4 schema (kind: attack/request, explicit t_start/t_end)
    and the pre-v4 schema (bare category/label/timestamp markers, no kind field).
    """
    records = load_jsonl(attack_log_path)

    cid_to_request: dict[str, dict] = {}
    attacks: dict[int, dict] = {}  # attack_seq -> {category,label,description,skipped,t_start,t_end}
    has_kind_field = any("kind" in r for r in records)

    if has_kind_field:
        for r in records:
            kind = r.get("kind")
            if kind == "attack":
                seq = r["attack_seq"]
                attacks[seq] = {
                    "attack_seq": seq,
                    "category": r.get("category"),
                    "label": r.get("label"),
                    "skipped": r.get("label") == "skipped",
                    "t_start": parse_iso(r.get("timestamp")),
                    "t_end": parse_iso(r.get("timestamp")),
                }
            elif kind == "request":
                seq = r["attack_seq"]
                cid_to_request[r["cid"]] = {
                    "attack_seq": seq,
                    "category": r.get("category"),
                    "label": r.get("label"),
                    "method": r.get("method"),
                    "url": r.get("url"),
                    "status": r.get("status"),
                }
                t_start = parse_iso(r.get("t_start"))
                t_end = parse_iso(r.get("t_end"))
                a = attacks.get(seq)
                if a is not None and t_start and t_end:
                    if a["t_start"] is None or t_start < a["t_start"]:
                        a["t_start"] = t_start
                    if a["t_end"] is None or t_end > a["t_end"]:
                        a["t_end"] = t_end
    else:
        # pre-v4: one bare record per technique (category/label/timestamp), no
        # per-request timestamps. Approximate each technique's window as
        # [its own timestamp, the next technique's timestamp).
        seq = 0
        ordered = [r for r in records if "category" in r]
        for i, r in enumerate(ordered):
            seq += 1
            t_start = parse_iso(r.get("timestamp"))
            t_end = parse_iso(ordered[i + 1]["timestamp"]) if i + 1 < len(ordered) else t_start
            attacks[seq] = {
                "attack_seq": seq,
                "category": r.get("category"),
                "label": r.get("label"),
                "skipped": r.get("label") == "skipped",
                "t_start": t_start,
                "t_end": t_end,
            }

    attack_windows = [a for a in attacks.values() if not a["skipped"]
                       and a["t_start"] is not None and a["t_end"] is not None]
    return cid_to_request, attacks, attack_windows


def interval_lookup(request_time, attack_windows, tolerance_seconds: float):
    """Return list of attack_seqs whose [t_start-tol, t_end+tol] contains request_time."""
    tol = timedelta(seconds=tolerance_seconds)
    hits = []
    for a in attack_windows:
        if a["t_start"] - tol <= request_time <= a["t_end"] + tol:
            hits.append(a)
    return hits


def load_wp3(path: str | None) -> dict:
    if not path:
        return {}
    by_id = {}
    for rec in load_jsonl(path):
        alert_id = rec.get("wazuh_alert_id")
        if alert_id is not None:
            by_id[alert_id] = rec
    return by_id


def load_benign_ground_truth(session_dir: str) -> dict:
    """
    cid -> benign request record (category, label, method, url, status),
    read from benign_traffic.sh's optional benign_log.jsonl.
    Empty dict if the session has no benign traffic collected — benign
    traffic is opt-in per session, not every session has it.
    """
    path = os.path.join(session_dir, "benign_log.jsonl")
    if not os.path.exists(path):
        return {}
    cid_to_benign: dict[str, dict] = {}
    for r in load_jsonl(path):
        if r.get("kind") == "request":
            cid_to_benign[r["cid"]] = {
                "category": r.get("category"),
                "label": r.get("label"),
                "method": r.get("method"),
                "url": r.get("url"),
                "status": r.get("status"),
            }
    return cid_to_benign


def map_alerts(session_dir: str, wp3_path: str | None, tolerance_seconds: float,
                alerts_file: str = "wazuh_alerts.jsonl"):
    attack_log_path = os.path.join(session_dir, "attack_log.jsonl")
    alerts_path = os.path.join(session_dir, alerts_file)

    cid_to_request, attacks, attack_windows = build_ground_truth(attack_log_path)
    cid_to_benign = load_benign_ground_truth(session_dir)
    # The session ids this session's own traffic carries in its CIDs. A CID
    # naming any other session is a back-to-back neighbour's request caught
    # at the window edge (wazuh-and-vm-notes §9): never attributed here, by
    # time or signature, because the neighbour session scores it.
    benign_log_path = os.path.join(session_dir, "benign_log.jsonl")
    own_sessions = {r["session"] for path in (attack_log_path, benign_log_path)
                    if os.path.exists(path) for r in load_jsonl(path) if r.get("session")}
    alerts = load_jsonl(alerts_path)
    wp3_by_id = load_wp3(wp3_path)

    results = []
    for alert in alerts:
        rule_id = alert.get("rule", {}).get("id")
        full_log = alert.get("full_log", "")
        data = alert.get("data", {})

        row = {
            "wazuh_alert_id": alert.get("id"),
            "wazuh_timestamp": alert.get("timestamp"),
            "wazuh_rule_id": rule_id,
            "wazuh_rule_description": alert.get("rule", {}).get("description"),
            "git_sha": git_sha(),
            "match_method": None,
            "match_confidence": None,
            "matched_attack_seq": None,
            "matched_category": None,
            "matched_label": None,
            "matched_cid": None,
            "is_attack": None,  # True: matched an attack technique. False: matched benign
                                # traffic — a candidate false positive, since
                                # Wazuh fired on a request that was never an attack. None:
                                # aggregate or unattributed, no ground truth to compare to.
            "signature_label": None,
            "signature_agrees": None,
        }

        method = data.get("protocol")
        url = data.get("url")
        row["signature_label"] = signature_match(method, url)

        if rule_id in AGGREGATE_RULE_IDS:
            row["match_method"] = "aggregate"
            row["match_confidence"] = "none"

        else:
            cid_str = alert_cid(alert)
            request = cid_to_request.get(cid_str) if cid_str else None
            benign_request = cid_to_benign.get(cid_str) if cid_str and request is None else None

            if request is not None:
                row["match_method"] = "cid"
                row["match_confidence"] = "exact"
                row["matched_cid"] = cid_str
                row["matched_attack_seq"] = request["attack_seq"]
                row["matched_category"] = request["category"]
                row["matched_label"] = request["label"]
                row["is_attack"] = True

            elif benign_request is not None:
                row["match_method"] = "cid"
                row["match_confidence"] = "exact"
                row["matched_cid"] = cid_str
                row["matched_category"] = benign_request["category"]
                row["matched_label"] = benign_request["label"]
                row["is_attack"] = False

            elif cid_str and own_sessions and cid_session(cid_str) not in own_sessions:
                row["match_method"] = "other_session"
                row["match_confidence"] = "none"
                row["matched_cid"] = cid_str

            else:
                request_time = parse_log_time(full_log)
                if request_time is None:
                    row["match_method"] = "unattributed"
                    row["match_confidence"] = "none"
                else:
                    hits = interval_lookup(request_time, attack_windows, tolerance_seconds)
                    if len(hits) == 1:
                        a = hits[0]
                        row["match_method"] = "interval_unique"
                        row["match_confidence"] = "medium"
                        row["matched_attack_seq"] = a["attack_seq"]
                        row["matched_category"] = a["category"]
                        row["matched_label"] = a["label"]
                        row["is_attack"] = True
                    elif len(hits) > 1:
                        a = hits[0]
                        row["match_method"] = "interval_ambiguous"
                        row["match_confidence"] = "low"
                        row["matched_attack_seq"] = a["attack_seq"]
                        row["matched_category"] = a["category"]
                        row["matched_label"] = a["label"]
                        row["is_attack"] = True
                    elif row["signature_label"] and row["signature_label"] not in AMBIGUOUS_GROUPS:
                        row["match_method"] = "signature"
                        row["match_confidence"] = "low"
                        row["matched_label"] = row["signature_label"]
                        row["is_attack"] = True
                    else:
                        row["match_method"] = "unattributed"
                        row["match_confidence"] = "none"

        row["signature_agrees"] = labels_agree(row["matched_label"], row["signature_label"])

        wp3_rec = wp3_by_id.get(row["wazuh_alert_id"])
        if wp3_rec is not None:
            llm_output = wp3_rec.get("llm_output", {})
            row["llm_event_type"] = llm_output.get("event_type")
            row["llm_severity"] = llm_output.get("severity")
            row["llm_confidence"] = llm_output.get("confidence")
            row["llm_parse_ok"] = wp3_rec.get("parse_ok")
            # Prompt v2 fields (P2.6), None on legacy rows: the closed-set
            # label, its candidates when uncertain, the disposition, the
            # output format and whether the answer passed the local check.
            row["llm_technique_label"] = llm_output.get("technique_label")
            row["llm_candidate_labels"] = llm_output.get("candidate_labels")
            row["llm_disposition"] = llm_output.get("disposition")
            row["llm_format"] = wp3_rec.get("format")
            row["llm_schema_ok"] = wp3_rec.get("schema_ok")
            # For scoring (P2.7): the model that answered, which prices the
            # row, and the repeat number (Plan M7). Both None on legacy rows.
            row["llm_model"] = wp3_rec.get("model")
            row["llm_repeat"] = wp3_rec.get("repeat")
            # Which prompt wording produced this row, and its token
            # cost — carried through (not just re-exposed) so downstream
            # scoring can group alerts by prompt iteration without
            # re-joining the triage output by hand.
            row["llm_prompt_version"] = wp3_rec.get("prompt_version")
            row["llm_token_usage"] = wp3_rec.get("token_usage")
            # The call failed and no answer exists (P2.10): scoring skips
            # the row, because an outage is not the model's mistake.
            row["llm_api_error"] = bool(wp3_rec.get("api_error")) or str(
                llm_output.get("error", "")).startswith("exception: ")

        results.append(row)

    return results, attacks


def summarise(results: list[dict], attacks: dict[int, dict]) -> str:
    from collections import Counter
    method_counts = Counter(r["match_method"] for r in results)

    detected_seqs = {r["matched_attack_seq"] for r in results if r["matched_attack_seq"] is not None}
    real_techniques = {seq: a for seq, a in attacks.items() if not a["skipped"]}
    missed = [a for seq, a in real_techniques.items() if seq not in detected_seqs]

    lines = ["", "match_method distribution:"]
    for method, count in method_counts.most_common():
        lines.append(f"  {method:20s} {count}")

    lines.append("")
    lines.append(f"Techniques detected : {len(detected_seqs)}/{len(real_techniques)}")
    if missed:
        lines.append("Missed techniques:")
        for a in missed:
            lines.append(f"  attack_seq={a['attack_seq']} {a['category']}/{a['label']}")

    benign_hits = [r for r in results if r["is_attack"] is False]
    if benign_hits:
        lines.append("")
        lines.append(f"Alerts fired on benign traffic (candidate false positives): {len(benign_hits)}")
        by_label = Counter(r["matched_label"] for r in benign_hits)
        for label, count in by_label.most_common():
            lines.append(f"  {count}× {label}")

    return "\n".join(lines)


def run_tag_for(alerts_file: str) -> str:
    """Run-directory tag for an arm's alert file: wazuh_alerts.jsonl ->
    primary, enriched_wazuh_alerts.jsonl -> enriched, and so on."""
    alerts_stem = os.path.splitext(alerts_file)[0]
    if alerts_stem == "wazuh_alerts":
        return "primary"
    if alerts_stem.endswith("_wazuh_alerts"):
        return alerts_stem[:-len("_wazuh_alerts")]
    return alerts_stem


def map_session(session: str, wp3: str | None = None, alerts_file: str = "wazuh_alerts.jsonl",
                out: str | None = None, tolerance: float = 1.5) -> str:
    """Map one arm of one session, write output.jsonl + its _meta.json sidecar,
    print the summary, and return the output path."""
    session_tag = os.path.basename(os.path.normpath(session))

    if out:
        out_path = out
    else:
        run_dir = resolve_run_dir(str(OUTPUTS_DIR / "wp4"), session_tag, run_tag_for(alerts_file))
        out_path = os.path.join(run_dir, "output.jsonl")

    results, attacks = map_alerts(session, wp3, tolerance, alerts_file)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        for row in results:
            f.write(json.dumps(row) + "\n")

    meta_path = write_meta(out_path, {
        "script": "cjp map",
        "cli_args": {"session": session, "wp3": wp3,
                     "alerts_file": alerts_file, "tolerance": tolerance,
                     "out": out},
        "git_sha": git_sha(),
        "alert_rows": len(results),
    })

    print(f"Wrote {len(results)} mapped alert(s) to {out_path}")
    print(f"Wrote run metadata to {meta_path}")
    print(summarise(results, attacks))
    return out_path
