"""
WP2 — collect a session's Wazuh alerts, one file per SIEM evidence arm, plus
manifest.json. Moved from wp2_collector.py in Plan P2.1; run it as
`cjp collect [--offline]`.

Two modes. Offline (recommended): traffic has already run on the VM; pull
each finished VM session directory and query the indexer for its window.
Online: block while the operator runs traffic, then query. `cjp session new`
(Plan P2.3, new_session below) runs the traffic too, then collects offline.

manifest.json records what the VM wrote into each run's session_manifest
marker at traffic time (deployed SHA, seed, benign-set version, script
hashes), plus per-arm log lines and alerts and any warnings about them.

Sessions are written to data/sessions/session_<id>/ (the legacy scripts used
./sessions). An existing session directory is never overwritten.
"""

import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from cjp import vm
from cjp.config import (BODY_FIELD_JUICE_LOG_PATH, ENRICHED_JUICE_LOG_PATH, JUICE_LOG_PATH,
                        JUICE_SHOP_IMAGE, SESSIONS_DIR, VM_ATTACKS_SH_PATH, VM_HOST,
                        VM_SESSIONS_DIR, VM_USER, WAZUH_VERSION)
from cjp.evaluate.mapper import alert_cid, cid_session
from cjp.indexer import get_alerts_since
from cjp.runs import git_sha

SESSION_DIR = str(SESSIONS_DIR)

# Applied on top of the measured VM/host clock offset when adjusting a
# session's query window (both start and end) — absorbs residual jitter
# between the VM shell clock and the indexer's own clock so alerts right at
# the boundary aren't dropped. Kept small and symmetric: sessions have been
# observed running back-to-back less than a minute apart (wazuh-and-vm-notes
# §9), so a large buffer on the end side would reopen the same alert-leaking
# bug it's meant to guard against.
CLOCK_SKEW_SAFETY_BUFFER = timedelta(seconds=2)


def start_session() -> tuple[str, str, str, str]:
    """Create a session directory, record start time, and block until the
    operator confirms attacks are complete — recording that moment as the
    session's end time too. Both bounds are needed to scope the alert query
    to just this session's own window: without an end bound, a session
    started shortly after this one (as sessions run back-to-back are) leaks
    its alerts into this one's collection (wazuh-and-vm-notes §9)."""
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_path = os.path.join(SESSION_DIR, f"session_{session_id}")
    os.makedirs(session_path, exist_ok=True)

    start_time = datetime.now(timezone.utc).isoformat()

    print(f"[*] Session started: {session_id}")
    print(f"[*] Session path: {session_path}")
    print(f"[*] Now run your attack script in the VM")
    print(f"[*] Press Enter when attacks are complete...")
    input()

    end_time = datetime.now(timezone.utc).isoformat()

    print(f"[*] Waiting 30 seconds for Wazuh to process and index logs...")
    for i in range(30, 0, -5):
        print(f"    {i}s remaining...")
        time.sleep(5)
    print(f"[*] Collecting alerts now...\n")

    return session_id, session_path, start_time, end_time


def drop_foreign_alerts(alerts: list[dict], session_id: str) -> tuple[list[dict], Counter]:
    """Split off alerts whose correlation ID names another session. Back-to-
    back sessions (run_sessions.sh starts the next one at once) let the 2 s
    end-of-window buffer catch the next session's first request; that alert
    belongs to the other session, which collects it too. Alerts with no CID
    (rule 11 log volume, 31151 frequency) can't be attributed this way and
    are kept. Returns (kept, Counter of dropped alerts per foreign session)."""
    kept, dropped = [], Counter()
    for alert in alerts:
        cid = alert_cid(alert)
        other = cid_session(cid) if cid else None
        if other and other != session_id:
            dropped[other] += 1
        else:
            kept.append(alert)
    return kept, dropped


def collect_alerts(session_path: str, start_time: str, end_time: str | None = None,
                   session_id: str | None = None):
    """Pull Juice Shop alerts generated in (start_time, end_time]. Callers
    should always pass end_time when it's known — see get_alerts_since().

    Queries the plain access log (JUICE_LOG_PATH), the payload-enriched log
    (ENRICHED_JUICE_LOG_PATH, arm 2 — body-in-url, stock rules), and the
    body-field log (BODY_FIELD_JUICE_LOG_PATH, arm 3 — body in its own
    field, via the custom decoder/rules in vm/wazuh/) separately
    and write them to separate files — wazuh_alerts.jsonl,
    enriched_wazuh_alerts.jsonl, body_field_wazuh_alerts.jsonl — rather than
    merging them, since the closing-the-loop plan's before/after comparisons
    need each rule-firing arm kept apart, not just distinguishable via the
    per-alert `location` field. Each file is always written, even when empty
    (pre-toggle sessions, or before the relevant wazuh-agent <localfile>
    block existed, produce zero matches) — same convention throughout.

    With session_id (the VM's id, which the CIDs carry), alerts whose CID
    names another session are dropped (drop_foreign_alerts). Online mode
    passes none: its directory is named from the Mac's clock, not the VM's
    session id. Returns the three arms' alerts plus one warning per arm that
    lost any, for the manifest."""
    alerts = get_alerts_since(after_timestamp=start_time, before_timestamp=end_time,
                               limit=200, location_pattern=JUICE_LOG_PATH)
    enriched_alerts = get_alerts_since(after_timestamp=start_time, before_timestamp=end_time,
                                        limit=200, location_pattern=ENRICHED_JUICE_LOG_PATH)
    body_field_alerts = get_alerts_since(after_timestamp=start_time, before_timestamp=end_time,
                                          limit=200, location_pattern=BODY_FIELD_JUICE_LOG_PATH)

    warnings = []
    arm_alerts = {"S1-plain": alerts, "S2-body-in-url": enriched_alerts,
                  "S3-body-field": body_field_alerts}
    for arm, arm_list in arm_alerts.items():
        if session_id is None:
            continue
        kept, dropped = drop_foreign_alerts(arm_list, session_id)
        arm_alerts[arm] = kept
        if dropped:
            others = ", ".join(f"{n} from {sid}" for sid, n in sorted(dropped.items()))
            warnings.append(f"{arm}: dropped {sum(dropped.values())} alert(s) whose CID names "
                            f"another session ({others}); window overlap, wazuh-and-vm-notes §9")
            print(f"[!] {warnings[-1]}")
    alerts, enriched_alerts, body_field_alerts = arm_alerts.values()

    output_file = os.path.join(session_path, "wazuh_alerts.jsonl")
    with open(output_file, "w") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[*] Collected {len(alerts)} alerts → {output_file}")

    enriched_output_file = os.path.join(session_path, "enriched_wazuh_alerts.jsonl")
    with open(enriched_output_file, "w") as f:
        for alert in enriched_alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[*] Collected {len(enriched_alerts)} enriched-log alerts → {enriched_output_file}")

    body_field_output_file = os.path.join(session_path, "body_field_wazuh_alerts.jsonl")
    with open(body_field_output_file, "w") as f:
        for alert in body_field_alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[*] Collected {len(body_field_alerts)} body-field-log alerts → {body_field_output_file}")

    return alerts, enriched_alerts, body_field_alerts, warnings


# Each SIEM evidence arm's access-log snapshot (written into the session by
# attacks.sh / benign_traffic.sh) and alerts file (written by collect_alerts).
ARM_FILES = {
    "S1-plain": ("access.log", "wazuh_alerts.jsonl"),
    "S2-body-in-url": ("enriched_access.log", "enriched_wazuh_alerts.jsonl"),
    "S3-body-field": ("body_field_access.log", "body_field_wazuh_alerts.jsonl"),
}


def _count_lines(path: str) -> int | None:
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return sum(1 for line in f if line.strip())


def summarise_arms(session_path: str, alert_counts: dict[str, int | None],
                   proxied: bool | None) -> tuple[dict, list[str], list[str]]:
    """Per arm: the log lines the session wrote and the alerts Wazuh raised on
    them. Returns (arms, arms_populated, warnings). An arm is populated when it
    has at least one alert, because alerts are what the pipeline consumes.

    The warnings catch the two ways a proxied session has lost alerts before
    (legacy-evidence §2): log lines with no alerts at all (the agent isn't
    tailing that file), and S2 below S1. S2 logs every request S1 does, plus
    the ones Juice Shop never logs, with the body on the URL; in the legacy
    sessions it fell below S1 only on a first-of-day cold start (notes §7)."""
    arms = {arm: {"log_lines": _count_lines(os.path.join(session_path, log_name)),
                  "alerts": alert_counts.get(arm)}
            for arm, (log_name, _) in ARM_FILES.items()}
    populated = [arm for arm, a in arms.items() if a["alerts"]]
    warnings = []
    for arm, a in arms.items():
        if a["log_lines"] and a["alerts"] == 0:
            warnings.append(f"{arm}: {a['log_lines']} log lines but no alerts "
                            f"(is the agent tailing its log? cold start?)")
    if proxied and len(populated) < len(arms):
        warnings.append(f"proxied session, but only {len(populated)} of {len(arms)} arms have alerts")
    s1, s2 = arms["S1-plain"]["alerts"], arms["S2-body-in-url"]["alerts"]
    if proxied and s1 and s2 is not None and s2 < s1:
        warnings.append(f"S2 has fewer alerts than S1 ({s2} < {s1}); in the legacy sessions "
                        f"that meant a cold start (notes §7)")
    return arms, populated, warnings


def build_manifest(session_id: str, session_path: str, start_time: str,
                    alerts: list[dict], enriched_alerts: list[dict] | None = None,
                    benign_traffic: bool = False,
                    application_logging: bool | None = None,
                    body_field_alerts: list[dict] | None = None,
                    session_meta: dict | None = None,
                    warnings: list[str] | None = None) -> dict:
    """
    Assemble and write data/sessions/session_<id>/manifest.json.

    session_meta holds what the VM recorded at traffic time (Plan P2.3; see
    _session_meta): vm_deployed_sha, seed, benign_set_version and each
    script's sha256. Its fields are null for sessions whose scripts predate
    P2.3, and in online mode. attacks_sh_sha256 falls back to hashing the
    VM's current attacks.sh over SSH, as before P2.3, which is only right if
    nothing was deployed since the session ran.

    vm_clock_offset_seconds is best-effort over SSH and null if VM_HOST isn't
    configured — see vm.measure_clock_offset(). application_logging is null
    if the run predates the ingest-proxy toggle (see _read_session_log); in
    online mode it isn't detected at all and defaults to False unless
    --application-logging is passed, same as benign_traffic.
    enriched_alerts/body_field_alerts are None (not 0) for callers who never
    queried that arm at all, vs. a real empty list from a session that did
    query but got zero matches — kept distinct in the per-arm counts below.
    """
    end_time = datetime.now(timezone.utc).isoformat()
    meta = session_meta or {}

    vm_clock_offset = vm.measure_clock_offset()
    attacks_sh_sha256 = meta.get("attacks_sh_sha256") or \
        vm.ssh_run(f"sha256sum {VM_ATTACKS_SH_PATH} 2>/dev/null | cut -d' ' -f1")

    def count(a):
        return len(a) if a is not None else None
    arms, arms_populated, arm_warnings = summarise_arms(
        session_path, {"S1-plain": count(alerts), "S2-body-in-url": count(enriched_alerts),
                       "S3-body-field": count(body_field_alerts)}, application_logging)
    warnings = [*(warnings or []), *arm_warnings]
    if not meta.get("vm_deployed_sha"):
        warnings.append("no vm_deployed_sha: the traffic scripts predate Plan P2.3, "
                        "or did not run from a `cjp vm deploy` (~/cjp-vm)")

    manifest = {
        "manifest_version": 2,
        "session_id": session_id,
        "vm_deployed_sha": meta.get("vm_deployed_sha"),
        "seed": meta.get("seed"),
        "benign_set_version": meta.get("benign_set_version"),
        "attacks_sh_sha256": attacks_sh_sha256,
        "benign_sh_sha256": meta.get("benign_sh_sha256"),
        "juice_shop_image": JUICE_SHOP_IMAGE,
        "wazuh_version": WAZUH_VERSION,
        "benign_traffic": benign_traffic,
        "application_logging": application_logging,
        "host_start_utc": start_time,
        "host_end_utc": end_time,
        "vm_clock_offset_seconds": vm_clock_offset,
        "arms": arms,
        "arms_populated": arms_populated,
        "warnings": warnings,
        # The per-arm alert counts again, under their pre-P2.3 names, so old
        # and new manifests compare field for field.
        "alert_count": len(alerts),
        "enriched_alert_count": count(enriched_alerts),
        "body_field_alert_count": count(body_field_alerts),
        "git_sha": git_sha(),
    }

    manifest_path = os.path.join(session_path, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"[*] Manifest written → {manifest_path}")
    print(f"    VM deployed SHA: {manifest['vm_deployed_sha']}, seed: {manifest['seed']}, "
          f"benign set: {manifest['benign_set_version']}")
    for arm, a in arms.items():
        print(f"    {arm}: {a['alerts']} alerts from {a['log_lines']} log lines")
    for w in warnings:
        print(f"    [!] {w}")
    if vm_clock_offset is None:
        print(f"    [!] vm_clock_offset_seconds is null — set VM_HOST in .env "
              f"to measure it (see wazuh-and-vm-notes §9)")
    else:
        print(f"    VM clock offset: {vm_clock_offset:+.3f}s")

    return manifest


def _rule_label(alert: dict) -> str:
    """A rule's description, or its id when it has none — Wazuh's built-in
    rule 11 (the hourly log-volume "stats" alert) ships without one and fires
    when seeded runs push traffic well above the hourly average."""
    rule = alert.get("rule", {})
    return rule.get("description") or f"rule {rule.get('id', '?')} (no description)"


def _print_alert_summary(alerts: list[dict], enriched_alerts: list[dict] | None = None,
                          body_field_alerts: list[dict] | None = None) -> None:
    rules = Counter(_rule_label(a) for a in alerts)
    print(f"\n[*] Alert summary:")
    for desc, count in rules.most_common():
        print(f"    {count}× {desc}")
    if enriched_alerts:
        enriched_rules = Counter(_rule_label(a) for a in enriched_alerts)
        print(f"\n[*] Enriched-log alert summary:")
        for desc, count in enriched_rules.most_common():
            print(f"    {count}× {desc}")
    if body_field_alerts:
        body_field_rules = Counter(_rule_label(a) for a in body_field_alerts)
        print(f"\n[*] Body-field-log alert summary:")
        for desc, count in body_field_rules.most_common():
            print(f"    {count}× {desc}")


def _read_session_log(log_path: str) -> dict:
    """Read the marker records out of an attack_log.jsonl or benign_log.jsonl:
    the ground-truth session id and the VM clock's own timestamps for when
    the run began and finished (session_start / session_end), rather than
    whatever the local wall clock happens to read when this is invoked, plus
    the run's session_manifest record.

    Returns {"session_id", "start", "end", "marker"}. end is None if the run
    didn't finish (or predates the session_end marker), in which case the
    alert query is left open-ended. marker is {} if the log predates the
    session_manifest record (before the ingest-proxy toggle, 2026-08-31);
    fields it lacks are "unknown", not "false". From Plan P2.3 the marker
    also carries vm_deployed_sha, seed and script_sha256 (and, for benign
    traffic, benign_set_version)."""
    session_id = None
    start_time = None
    end_time = None
    marker: dict = {}
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event") == "session_start":
                session_id, start_time = rec["session"], rec["timestamp"]
            elif rec.get("event") == "session_end":
                end_time = rec["timestamp"]
            elif rec.get("event") == "session_manifest":
                marker = rec
    if start_time is None:
        raise ValueError(f"No session_start record found in {log_path}")
    return {"session_id": session_id, "start": start_time, "end": end_time, "marker": marker}


def _session_meta(attack_marker: dict, benign_marker: dict) -> tuple[dict, list[str]]:
    """The manifest's provenance fields, from the attack and benign runs'
    session_manifest markers. Both runs record the deployed SHA and seed;
    they should agree, and a mismatch (a redeploy between the two halves of
    one session) is returned as a warning. The attack run's value wins."""
    meta = {"attacks_sh_sha256": attack_marker.get("script_sha256"),
            "benign_sh_sha256": benign_marker.get("script_sha256"),
            "benign_set_version": benign_marker.get("benign_set_version")}
    warnings = []
    for key in ("vm_deployed_sha", "seed"):
        a, b = attack_marker.get(key), benign_marker.get(key)
        meta[key] = a if a is not None else b
        if a is not None and b is not None and a != b:
            warnings.append(f"attack and benign runs disagree on {key} ({a!r} vs {b!r})")
    return meta, warnings


def _list_local_sessions() -> set[str]:
    """Session ids already present under SESSION_DIR (session_<id> subdirs)."""
    if not os.path.isdir(SESSION_DIR):
        return set()
    prefix = "session_"
    return {
        name[len(prefix):]
        for name in os.listdir(SESSION_DIR)
        if name.startswith(prefix)
    }


def _collect_one_offline_session(session_id: str) -> dict:
    """
    Pull and process a single already-finished VM session by id.

    VM-side layout (attacks.sh v5+, 2026-08-05): each run writes its own
    data/sessions/<SESSION_ID>/, already containing attack_log.jsonl, an
    optional benign_log.jsonl, and a session-scoped access.log snapshot
    (isolated by CID, so two sessions run the same day never mix) — so this
    pulls that one directory in a single `scp -r` rather than three separate
    pulls against date-based paths. Returns the manifest.
    """
    session_path = os.path.join(SESSION_DIR, f"session_{session_id}")
    if os.path.exists(session_path):
        raise SystemExit(
            f"{session_path} already exists — refusing to overwrite an existing "
            f"session. Remove it yourself first if you really want to re-pull."
        )

    remote_session_dir = f"{VM_SESSIONS_DIR}/{session_id}"
    os.makedirs(SESSION_DIR, exist_ok=True)
    if not vm.scp_dir_from_vm(remote_session_dir, session_path):
        raise SystemExit(
            f"Failed to scp -r {VM_USER}@{VM_HOST}:{remote_session_dir} — "
            f"check the session id, VM_HOST/VM_USER, and SSH access"
        )
    print(f"[*] Pulled session directory → {session_path}")

    attack_log_path = os.path.join(session_path, "attack_log.jsonl")
    attack = _read_session_log(attack_log_path)
    logged_session_id, start_time, end_time = attack["session_id"], attack["start"], attack["end"]
    application_logging = attack["marker"].get("application_logging")
    benign_marker: dict = {}
    if logged_session_id != session_id:
        print(f"[!] attack_log.jsonl's own session field ({logged_session_id!r}) "
              f"doesn't match the directory it was pulled from ({session_id!r}) — "
              f"proceeding, but this is worth investigating")

    benign_log_path = os.path.join(session_path, "benign_log.jsonl")
    benign_traffic = os.path.exists(benign_log_path)
    if benign_traffic:
        # benign_traffic.sh joins the same session and runs *after*
        # attacks.sh finishes (§4.2) — its own session_end is later than
        # attack_log.jsonl's, and is the true end of this session's window.
        # Bounding on attack_log's session_end alone would clip the
        # session's own benign-traffic alerts.
        benign = _read_session_log(benign_log_path)
        benign_end_time, benign_marker = benign["end"], benign["marker"]
        benign_application_logging = benign_marker.get("application_logging")
        if benign_end_time is not None and (end_time is None or benign_end_time > end_time):
            end_time = benign_end_time
        if benign_application_logging != application_logging:
            print(f"[!] attack_log.jsonl's application_logging ({application_logging!r}) "
                  f"doesn't match benign_log.jsonl's ({benign_application_logging!r}) — "
                  f"the JUICE_URL toggle should be the same for both halves of a "
                  f"session; proceeding with the attack_log.jsonl value")

    print(f"[*] Session {session_id} started {start_time} "
          f"(benign traffic: {'yes' if benign_traffic else 'no'})")

    # The indexer's timestamp field is in the manager's own clock, not the
    # VM shell's — correct for measured VM/host clock skew (notes §9) plus a
    # small safety buffer. The start bound is pulled *earlier* and the end
    # bound pushed *later* by the buffer, so a VM clock running ahead or
    # behind this host doesn't silently drop alerts right at either edge of
    # the window. Without the end bound at all, a session started shortly
    # after this one (attacks.sh runs have been observed under a minute
    # apart) leaks its alerts into this collection — see wazuh-and-vm-notes §9.
    query_start_time = start_time
    query_end_time = end_time
    offset = vm.measure_clock_offset()
    if offset is not None:
        adjusted_start = datetime.fromisoformat(start_time.replace("Z", "+00:00")) \
            - timedelta(seconds=offset) - CLOCK_SKEW_SAFETY_BUFFER
        query_start_time = adjusted_start.isoformat()
        print(f"[*] Adjusting query window for {offset:+.3f}s VM clock offset "
              f"(+2s safety buffer): querying from {query_start_time}")
        if end_time is not None:
            adjusted_end = datetime.fromisoformat(end_time.replace("Z", "+00:00")) \
                - timedelta(seconds=offset) + CLOCK_SKEW_SAFETY_BUFFER
            query_end_time = adjusted_end.isoformat()
            print(f"    querying up to {query_end_time}")
    else:
        print(f"[!] vm_clock_offset_seconds unavailable — querying from the VM's "
              f"raw timestamp unadjusted; alerts near the window boundary may be missed")

    if query_end_time is None:
        print(f"[!] No session_end record in {attack_log_path} — query has no "
              f"upper bound and may pick up alerts from a later session")

    alerts, enriched_alerts, body_field_alerts, collect_warnings = \
        collect_alerts(session_path, query_start_time, query_end_time, session_id=session_id)
    session_meta, meta_warnings = _session_meta(attack["marker"], benign_marker)
    _print_alert_summary(alerts, enriched_alerts, body_field_alerts)
    return build_manifest(session_id, session_path, start_time, alerts, enriched_alerts,
                          benign_traffic=benign_traffic, application_logging=application_logging,
                          body_field_alerts=body_field_alerts, session_meta=session_meta,
                          warnings=[*meta_warnings, *collect_warnings])


def collect_offline(session_id: str | None = None) -> None:
    """
    Collect session(s)' alerts *after* attacks.sh (and optionally
    benign_traffic.sh) have already run and finished on the VM — no need to
    start this before the attack, block on Enter, or guess a wait time.

    With session_id given, pulls just that one VM session
    (data/sessions/<session_id>), even if it's already been superseded by
    newer ones. With no session_id, lists every session under
    VM_SESSIONS_DIR and pulls each one not already present locally under
    SESSION_DIR — i.e. "everything the VM has that we don't yet" — rather
    than just the single latest session (data/.last_session).
    """
    if not VM_HOST:
        raise SystemExit(
            "Offline collection requires VM_HOST (and VM_USER) set in .env "
            "so session artefacts can be pulled via scp (wazuh-and-vm-notes §8)."
        )

    if session_id is not None:
        _collect_one_offline_session(session_id)
        return

    remote_sessions = vm.list_remote_sessions()
    if not remote_sessions:
        raise SystemExit(
            f"No sessions found under {VM_USER}@{VM_HOST}:{VM_SESSIONS_DIR} — "
            f"has attacks.sh been run on the VM? Or pass --session-id explicitly."
        )

    local_sessions = _list_local_sessions()
    uncollected = [sid for sid in remote_sessions if sid not in local_sessions]

    if not uncollected:
        print(f"[*] All {len(remote_sessions)} remote session(s) already "
              f"collected locally — nothing to do")
        return

    print(f"[*] {len(uncollected)} of {len(remote_sessions)} remote session(s) "
          f"not yet collected: {', '.join(uncollected)}")

    failed = []
    for i, sid in enumerate(uncollected, 1):
        print(f"\n[*] --- Collecting session {i}/{len(uncollected)}: {sid} ---")
        try:
            _collect_one_offline_session(sid)
        except SystemExit as e:
            print(f"[!] Failed to collect session {sid}: {e}")
            failed.append(sid)

    collected = len(uncollected) - len(failed)
    print(f"\n[*] Collected {collected}/{len(uncollected)} session(s)")
    if failed:
        raise SystemExit(f"Failed to collect {len(failed)} session(s): {', '.join(failed)}")


def collect_online(benign_traffic: bool = False, application_logging: bool = False):
    session_id, session_path, start_time, end_time = start_session()
    alerts, enriched_alerts, body_field_alerts, warnings = \
        collect_alerts(session_path, start_time, end_time)
    build_manifest(session_id, session_path, start_time, alerts, enriched_alerts,
                    benign_traffic=benign_traffic, application_logging=application_logging,
                    body_field_alerts=body_field_alerts, warnings=warnings)
    _print_alert_summary(alerts, enriched_alerts, body_field_alerts)


def new_session(seed: int, settle: float = 60.0) -> int:
    """
    `cjp session new` (Plan P2.3): warm-up, traffic, settle, collect, in one
    command. Returns a process exit code: 0 when every SIEM evidence arm has
    alerts, 1 when a step failed, 3 when the session was collected but not
    every arm has alerts (see the manifest's warnings).

    The traffic runs from what `cjp vm deploy` put in VM_ROOT, through the
    ingest proxy, with both the attack and benign scripts; the manifest
    records the deployed SHA and seed the VM reports, not what this command
    was asked for. Settling waits for Wazuh to index the last requests;
    the alert query is bounded by the session's own end marker, so waiting
    longer never pulls in another session's alerts.
    """
    if seed < 0:
        print("[session] --seed must be a non-negative integer")
        return 1
    if not VM_HOST:
        print("[session] VM_HOST is not set in .env")
        return 1
    sha = vm.deployed_sha()
    if sha is None:
        print(f"[session] no {vm.VM_ROOT}/DEPLOYED_SHA on {VM_USER}@{VM_HOST}: "
              f"is the VM reachable, and has `cjp vm deploy` completed?")
        return 1
    differs = vm.deployed_vm_differs(sha)
    print(f"[session] VM runs vm/ from {sha[:12]}{sha[40:]}")
    if differs:
        print("[session] [!] this checkout's vm/ differs from the deployed one; "
              "run `cjp vm deploy` first if the session should use it")
    elif differs is None:
        print("[session] [!] cannot compare the deployed vm/ with this checkout "
              "(an --allow-dirty deploy, or a commit this clone lacks)")
    sys.stdout.flush()   # before the VM's output, which streams straight to the terminal

    session_id = vm.run_session_traffic(seed)
    if session_id is None:
        return 1
    print(f"\n[session] traffic done: VM session {session_id}; "
          f"waiting {settle:.0f}s for Wazuh to index it")
    time.sleep(settle)
    try:
        manifest = _collect_one_offline_session(session_id)
    except SystemExit as e:
        print(f"[session] collection failed: {e}")
        return 1

    populated, n_arms = manifest["arms_populated"], len(ARM_FILES)
    print(f"\n[session] session_{session_id}: {len(populated)} of {n_arms} arms populated "
          f"({', '.join(populated) or 'none'})")
    return 0 if len(populated) == n_arms else 3
