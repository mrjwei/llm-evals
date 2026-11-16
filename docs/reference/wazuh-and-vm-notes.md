# Wazuh and VM notes

Operational facts about the UTM VM, Wazuh and Juice Shop that are still true and still useful, collected from the retired docs. Reference doc: **rewrite in place** when a fact changes (Plan §2.4). Paths are the *current* VM layout: since 30 Sep (Plan P2.2) the VM runs whatever `cjp vm deploy` copies from the repo's `vm/` to `~/cjp-vm` ([§12](#12-deploying-vm-with-cjp-vm-deploy)). The old checkout was renamed `~/juice-shop-wazuh.retired-2026-10` on 30 Sep (Plan P1.5).

## Contents

- [1. Hosts, containers and ports](#1-hosts-containers-and-ports)
- [2. Paths on the VM](#2-paths-on-the-vm)
- [3. Agent: which logs Wazuh reads](#3-agent-which-logs-wazuh-reads)
- [4. Manager: custom decoder and rules](#4-manager-custom-decoder-and-rules)
- [5. Testing rules with wazuh-logtest](#5-testing-rules-with-wazuh-logtest)
- [6. Wazuh regex and rule gotchas](#6-wazuh-regex-and-rule-gotchas)
- [7. Cold start on new daily log files](#7-cold-start-on-new-daily-log-files)
- [8. Reaching the VM from macOS](#8-reaching-the-vm-from-macos)
- [9. Clock skew and the alert window](#9-clock-skew-and-the-alert-window)
- [10. Health checks](#10-health-checks)
- [11. Juice Shop quirks](#11-juice-shop-quirks)
- [12. Deploying vm/ with cjp vm deploy](#12-deploying-vm-with-cjp-vm-deploy)

## 1. Hosts, containers and ports

| Component | Where | Notes |
|---|---|---|
| Juice Shop | Docker on the VM, `:3000` | Stock `bkimminich/juice-shop` image, unpinned (the deployed image ID is in `~/cjp-vm/DEPLOYED.json`). Never modified. Compose project `juice-shop`, file `~/cjp-vm/juice-shop/docker-compose.yml` |
| Ingest proxy | mitmproxy 12.2.3 on the VM host, `:8080 → :3000` | `start_ingest_proxy.sh start\|stop\|status`, idempotent; `cjp vm deploy` (re)starts it. Opt-in per run via `JUICE_URL=http://localhost:8080` |
| Wazuh manager | container `single-node-wazuh.manager-1`, `:1514/:1515/:55000` | Wazuh 4.14.4, single node, from `~/wazuh-docker/single-node` (`docker compose up -d`) |
| Wazuh indexer | OpenSearch container, `:9200`, index `wazuh-alerts-4.x-*` | Queried by `cjp/indexer.py` |
| Wazuh dashboard | container, `:443` | Not used by the pipeline |
| Wazuh agent | native apt package on the VM host (systemd), agent `001` "jesse" | Its `ossec.conf` needs **sudo** to edit, so Jesse makes those changes |

Every request reaches Juice Shop from the Docker gateway (`::ffff:172.17.0.1`), so the source IP carries no information. The correlation ID in the `Referer` header is the only join key: `wp1-<SESSION_ID>-<ATTACK_SEQ>-<REQ_SEQ>` for attacks and `wp1-benign-<SESSION_ID>-<SEQ>-<REQ_SEQ>` for benign traffic.

## 2. Paths on the VM

| Path | What |
|---|---|
| `~/wazuh-docker/single-node/` | The **running** Wazuh stack: upstream `wazuh-docker` single-node compose file (manager, indexer, dashboard; `wazuh/*:4.14.4`), its certs and config. Third-party, not a git checkout, not in the repo; leave untouched. `DEPLOYED.json` records the manager image |
| `~/cjp-vm/` | The repo's `vm/`, as deployed by `cjp vm deploy`, plus `DEPLOYED_SHA` / `DEPLOYED.json` (what is deployed) and `.deploy-backup/` (manager rule files replaced by a deploy). Don't edit files here: change `vm/` in the repo and redeploy |
| `~/cjp-vm/juice-shop/` | `attacks.sh`, `benign_traffic.sh`, `run_sessions.sh`, `ingest_addon.py`, `start_ingest_proxy.sh`, `warm_ingest_proxy.sh`, `docker-compose.yml`, `config.yml`, `requirements-proxy.txt`, and the proxy's `.venv/` |
| `…/juice-shop/data/logs/` | Flat daily logs: `access.log.YYYY-MM-DD` (Juice Shop, written as uid 65532, so the dir is `0777`), `ingest_log.jsonl`, `enriched_access.log.YYYY-MM-DD`, `body_field_access.log.YYYY-MM-DD` (proxy). The scripts find `data/` next to themselves (`CJP_DATA_DIR` overrides) |
| `…/juice-shop/data/sessions/<SESSION_ID>/` | Per-session snapshot: each script greps its own CID prefix out of the flat logs at session end |
| `~/cjp-vm/wazuh/` | Custom decoder and rules (installed into the manager by deploy), `agent_localfile.xml`, `logtest_cases.tsv` |
| `~/juice-shop-wazuh.retired-2026-10/` | The old checkout, used by nothing (renamed 30 Sep, Plan P1.5; delete after the results freeze). Its `wazuh-docker/` was an unused copy of upstream: same compose file as the running stack, different certificates |

## 3. Agent: which logs Wazuh reads

The agent's `/var/ossec/etc/ossec.conf` has one `<localfile>` block per arm; the deployable copy is `vm/wazuh/agent_localfile.xml`. After editing, run `sudo systemctl restart wazuh-agent`. The agent's *live* paths can be read without sudo through the manager API, `GET /agents/001/config/logcollector/localfile`; `cjp vm deploy` does this and prints the one `sudo sed … && sudo systemctl restart wazuh-agent` command when they differ from the file.

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/home/jesse/cjp-vm/juice-shop/data/logs/access.log*</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/home/jesse/cjp-vm/juice-shop/data/logs/enriched_access.log*</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>   <!-- not apache: body_probe lines have their own decoder (§4) -->
  <location>/home/jesse/cjp-vm/juice-shop/data/logs/body_field_access.log*</location>
</localfile>
```

On the collection side, each log needs its **own** indexer `location` wildcard (`JUICE_LOG_PATH`, `ENRICHED_JUICE_LOG_PATH`, `BODY_FIELD_JUICE_LOG_PATH` in `cjp/config.py`, derived from `VM_ROOT` and each overridable from `.env`). A test checks that they equal the `<location>`s in `agent_localfile.xml`. `access.log*` does not match `enriched_access.log.*`, and a missing pattern excludes that arm's alerts silently.

The tracked `wazuh-docker/wazuh-agent/config/wazuh-agent-conf` template does **not** describe the live agent: it is for a containerised agent on a different OS.

## 4. Manager: custom decoder and rules

- Files: `/var/ossec/etc/decoders/body_field_decoders.xml` and `/var/ossec/etc/rules/body_field_rules.xml` inside the manager container.
- `/var/ossec/etc` is a Docker **named volume** (`single-node_wazuh_etc`), not a bind mount. It survives restarts but isn't visible on the host, so the git-tracked copy is the durable source of truth.
- Deploy with `cjp vm deploy` ([§12](#12-deploying-vm-with-cjp-vm-deploy)), not by hand. Underneath it is `docker cp <file> single-node-wazuh.manager-1:/var/ossec/etc/rules/`, `chown wazuh:wazuh` + `chmod 660`, then `wazuh-control restart` and `… status`. Rule changes need a restart. If the new ruleset fails to load, the old process keeps running, so a broken file only bites on the *next* restart; this is why deploy runs the logtest cases first.
- Reading stock content needs no sudo: `docker exec single-node-wazuh.manager-1 cat /var/ossec/ruleset/…`. The relevant stock files are `0375-web-accesslog_decoders.xml` and `0245-web_rules.xml`.
- Custom rule IDs start at 100000. In use:

| Rule | Level | Fires on |
|---|---|---|
| 100010 | 0 (silent parent, never indexed) | Any decoded `body_probe` line |
| 100011 | 7, MITRE T1190, group `body_field_sqli,attack,` | SQLi keywords in `http_body` (list copied from stock 31103) |
| 100012 | 5 | Non-2xx status (`<id>^4\|^5</id>`), mirroring stock 31101 |

- Stock rules worth knowing: 31101 (4xx), 31103/31104/31105 (SQLi/XSS/traversal patterns in `url`), 31106 (attack pattern *and* 200), 31151 (repeated 4xx from one IP).
- In alert JSON, `data.id` is the **HTTP status**, and the top-level `id` (`<epoch>.<offset>`) is the stable alert ID.
- The manager's `<alerts><log_alert_level>` default is 3, so level-0 rules never reach the index.

## 5. Testing rules with wazuh-logtest

Validate on real lines **before** restarting the manager or generating traffic. No sudo needed. Each logtest session loads the rule files **from disk**, so it tests newly copied files before any restart (checked 30 Sep with a temporary probe rule).

```bash
docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest-legacy
# paste a line, e.g. a real body_probe line from a session's body_field_access.log
```

Check three cases each time: a line that should fire, a line that should not, and that stock rules don't cross over onto the new field. Record them in `vm/wazuh/logtest_cases.tsv` (`<rule>:<level>:<decoder><TAB><line>`): deploy runs each as `wazuh-logtest -q -U <rule>:<level>:<decoder>`, which exits 0 only on an exact match. Redeploying a rule does **not** re-alert old sessions, because `<localfile>` only processes newly appended lines. A fresh session is needed.

## 6. Wazuh regex and rule gotchas

- **Decoder regex (OSRegex):** a bare `.` is a *literal* dot and `\.` is "any character". Write `(\.*)`, not `(.*)`; the latter silently captures nothing. `\S`, `\d` and `\w` work as expected.
- **Rule matching (OSMatch):** no character classes, so `^[45]` never matches. Use alternation: `^4|^5`.
- **Static fields** such as `id`, `url` and `srcip` use their own tags (`<id>`, `<url>`). `<field name="id">` makes `wazuh-analysisd` refuse the whole ruleset ("Field 'id' is static").
- A custom decoder whose lines start with a literal token (`body_probe cid=…`) should not be a child of the stock `web-accesslog` tree; that keeps the stock web rules off it.

## 7. Cold start on new daily log files

All three arm logs are new files each day (UTC): Juice Shop's own `access.log.*` too, which rotates on the first request after midnight (`audit.json` records it). The agent took ~46 s to discover a new file, so the first proxied session of a day lost its earliest alerts in Arms 2/3. On 1 Oct the first requests of the day raised **no** alert in any arm, and `cjp vm smoke` failed S2/S3; both passed a minute later, once the files existed. `warm_ingest_proxy.sh` (called by `run_sessions.sh`) sends one throwaway request to create the file, then waits 60 s. The agent's scan interval in `ossec.conf` could shrink the gap at the source, but it needs sudo and is still untuned. Its signature is S2 with fewer alerts than S1, and `cjp collect` writes that into the session manifest's `warnings`.

## 8. Reaching the VM from macOS

```bash
ssh -N -L 9200:localhost:9200 -L 55000:localhost:55000 jesse@<vm-ip>   # indexer + manager API
```

Offline collection and clock-skew measurement need **key-based, non-interactive** SSH (`BatchMode=yes`) and `VM_HOST` in `.env`. Sessions are pulled with one `scp -r` of `data/sessions/<id>/`.

## 9. Clock skew and the alert window

`cjp collect` measures the VM–Mac clock offset over SSH (`date -u +%s` on both). It shifts the indexer query window by that offset plus a 2 s buffer. The window is bounded **above** by the session's `session_end` marker: before 12 Aug it wasn't, and back-to-back sessions leaked alerts into each other. Offline mode takes start and end from the pulled `attack_log.jsonl` (the VM's clock), not the Mac's wall clock.

Two artefacts this leaves, both seen in C1 (2 Oct) and both unscored ([decision 010](../decisions/010-c1-unscored-alerts.md)):

- **Back-to-back overlap.** `run_sessions.sh` starts the next session at once, so the 2 s buffer on the end bound can catch the next session's first request. In C1, seed 3's first request also sits in all three of seed 2's arms. Its CID names the other session: the mapper marks it `other_session`, and offline `cjp collect` has dropped such alerts since 3 Oct, warning in the manifest.
- **Rule 11, no description.** Wazuh's hourly log-volume alert (`groups: ["stats"]`, level 4) fires when the hour's events exceed the average by at least 150% and 1,250 (`analysisd.stats_*` in `internal_options.conf`). No rule file defines it. Three sessions in one hour push the count over the threshold, so one session in each C1 collection has one. `cjp collect` labels it `rule 11 (no description)`.

## 10. Health checks

`cjp doctor` (Mac) runs the equivalent of all of these, plus the agent's log paths and the deployed SHA, and prints the fix for each failure. By hand:

```bash
curl -sk -u admin:$INDEXER_PASS "https://127.0.0.1:9200/wazuh-alerts-4.x-*/_count?pretty"        # alerts arriving?
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l                     # agent 001 Active?
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000                                   # Juice Shop up? (VM)
bash ~/cjp-vm/juice-shop/start_ingest_proxy.sh status                                           # proxy up? (VM)
cat ~/cjp-vm/DEPLOYED.json                                                                        # what is deployed? (VM)
```

## 11. Juice Shop quirks

- The image has no shell or coreutils. To look inside, use `/nodejs/bin/node -e "…"`. It writes its access log to `/juice-shop/logs/` inside the container, which `docker-compose.yml` bind-mounts to `data/logs/`.
- Some responses never reach `access.log`: `/ftp/*` 403s, `/api-docs` redirects, some traversal rejections and static files (including `GET /`) are produced before the logger runs. The proxy sees them because it intercepts at the network level.
- Routes, checked on Juice Shop 19.2.1 (1 Oct): products are `/api/Products` and `/api/Products/<id>` (ids 12 and 40 are 404); `/rest/products` and `/rest/products/<id>` are 500 ("Unexpected path"); reviews are `/rest/products/<id>/reviews`. The login response carries the JWT **and the user's own basket id** (`authentication.bid`). `/rest/user/whoami` reads only the `token` cookie (a Bearer header alone returns `{"user":{}}`); the basket and `/api/BasketItems` take the Bearer header.
- The legacy benign set's 7 alerts per session were **all its own bugs**: 6 × rule 31122 (500) from `/rest/products[/<id>]` and 1 × 31101 (401) from `/rest/basket/1` with no token (basket 1 is another user's). With the routes fixed (benign set 2, Plan P3.1), the set raises no alert in any arm.
- Hard-negative behaviour, checked 1 Oct (Plan P3.2):
  - Search is injectable, so an apostrophe (`O'Reilly`) is a 500 `SQLITE_ERROR` (31122). `select juice`, `juice from concentrate` and `union jack sticker` are 200 but match 31103's keywords (31106).
  - Product ids with no product: 10, 11, 12, 27, 28, 31, 39, 40, 44 (404, 31101). Their `/rest/products/<id>/reviews` is 200 `[]`.
  - Unknown `/api/…` and `/rest/…` paths are 500 "Unexpected path". A missing `/ftp/<file>` is 404 but never reaches `access.log`.
  - Signing up again with the same email is 400 ("email must be unique"); a wrong login password is 401.
  - Change password is a **GET** with the passwords in the query string (`/rest/user/change-password?current=…&new=…&repeat=…`, Bearer): a wrong current password or a mismatched repeat is 401.
  - Feedback: `GET /rest/captcha` returns the captcha's answer, then `POST /api/Feedbacks/` (anonymous allowed) is 201.
- **Benign set 3** (63 requests, dry run `20261001_024241`, proxied, seed 1): 16 alerts in S1 (10 × 31101, 3 × 31122, 3 × 31106), 18 in S2 (the same, plus 2 × 31103 on feedback bodies), 15 in S3 (13 × 100012, 2 × 100011). All from journeys 6–11; journeys 1–5 raise none.
- **Attack payload pools** (Plan P3.3): the pooled techniques (path traversal, the SQLi login bypass, the UNION search, XSS, brute force, account enumeration, error probing, SSRF) draw each request from a pool of equivalent variants in a seeded order, at the same per-technique request count. **Checked 2 Oct** (dry run `20261002_124405` and C1): every technique fires the same rules as before pooling, in every arm. A GET URL must not contain a raw space: curl 8.5 rejects it before sending (exit 3, logged as status `000`). Until 2 Oct the UNION pool did this, so `sql_injection_union` never reached Juice Shop in any earlier session, legacy ones included ([decision 009](../decisions/009-recollect-c1-before-prereg.md)). A test now guards this. Encoded, the UNION variants are 200 when the column count matches and 500 when it doesn't, and fire 31103/31106.
- **Prompt-injection probe** (Plan P3.4, `INJECTION=1`, off by default): 12 real attacks whose bodies or queries carry analyst-directed "classify as benign" text, under four `_inj` labels, appended to the working SQLi login, UNION and feedback payloads. **Checked 2 Oct** (C1-inj `20261002_131656`): all four `_inj` labels are detected in all three arms. The appended text does not change which rule fires. S1-plain carries no body, so it sees only the bare attack and serves as the injection control.

## 12. Deploying vm/ with cjp vm deploy

`cjp vm deploy` (Mac) rsyncs `vm/` to `~/cjp-vm` and runs `vm/deploy.sh` there. It refuses uncommitted `vm/` changes unless `--allow-dirty`, so `DEPLOYED_SHA` names a real commit. `deploy.sh` is idempotent (a second run changes nothing) and never uses sudo:

1. `juice-shop/data/{logs,sessions}`, with `logs/` at `0777`.
2. `juice-shop/.venv` with the mitmproxy in `requirements-proxy.txt`; rebuilt only when the version differs.
3. Custom decoder and rules copied into the manager **only if they differ** (previous versions to `.deploy-backup/<time>/`), every `logtest_cases.tsv` case run, and the manager restarted only after all pass. A failing case restores the old files and nothing restarts.
4. `docker compose up -d` from `~/cjp-vm/juice-shop`: recreates the container if its log mount points elsewhere, otherwise a no-op.
5. Stops any ingest proxy running from another checkout; restarts the proxy if it is down or its code changed; one warm-up search creates today's three log files.
6. Writes `DEPLOYED_SHA` (removed at the start, so it exists only after a complete deploy) and `DEPLOYED.json` (describe, time, image IDs, mitmproxy version).

`attacks.sh` and `benign_traffic.sh` read `~/cjp-vm/DEPLOYED_SHA` when they start and record it in their `session_manifest` marker, together with `SEED` and their own sha256. The session's `manifest.json` then names the deployed commit that produced the traffic ([ARCHITECTURE §6](../ARCHITECTURE.md#6-outputs-and-provenance)).

Back on the Mac it reads the agent's live `<localfile>` paths through the manager API. If they differ from `agent_localfile.xml`, it prints one command for Jesse (`sudo sed -i.bak-cjp-<date> … /var/ossec/etc/ossec.conf && sudo systemctl restart wazuh-agent`) and exits 2. Otherwise it runs `cjp vm smoke`: one `GET /rest/basket/1` through the proxy with a `cjp-smoke-<time>` Referer, which must raise an alert from each arm's log under `~/cjp-vm` (31101 in S1 and S2, 100012 in S3) within 180 s. Exit codes: 0 ok, 1 failed, 2 sudo step needed, 3 smoke test failed.
