# ThreatLens: Algorithm and Pseudocode

The design as it was worked out before the code was written. Each section names the module that implements it.

## 1. Problem statement

Given **one host** the operator is authorised to test, discover which TCP ports accept connections, work out what is
listening, and turn that into a **single 0-100 risk score** plus a **prioritised list of fixes**.

Design constraints:

| Constraint | Consequence |
|---|---|
| No root access assumed | Use full TCP connect scans, not raw SYN packets |
| Scans must be fast | Thread pool, short timeouts, one socket per port |
| Port numbers lie (SSH on 2222) | Identify services from what they say, not from the number |
| Score must be explainable | Every point comes from a named finding with a weight |
| Tool is dual-use | Scope limits, authorisation gate, no CIDR sweeps, harmless probes only |

## 2. High-level flow

```
 user input ─► validate target ─► parse ports ─► create job
                                                     │
                     ┌───────────────────────────────┘
                     ▼
              thread pool: probe each port ──► open-port records
                     │                                 │
                     ▼                                 ▼
               progress counter                  risk analysis
                                                       │
                                  findings + score + grade
                                                       │
                                diff vs previous scan ─► save ─► UI / export
```

## 3. Algorithms

### 3.1 Target validation (`app.resolve_target`)

```
FUNCTION resolve_target(raw):
    IF raw is empty OR too long OR contains any of "/ space \ ? # @" OR contains "://":
        REJECT "single hostname or IP only"            # blocks URLs, CIDR, lists
    addr ← first result of DNS/IP resolution of raw    # fail → REJECT "could not resolve"
    IF addr is unspecified OR multicast OR reserved:
        REJECT
    IF addr is loopback:               scope ← "loopback"
    ELSE IF addr is private OR link-local: scope ← "private"
    ELSE:                              scope ← "public"
    IF scope = "public" AND NOT ALLOW_PUBLIC:
        REJECT "public targets disabled"
    RETURN (addr, address family, scope)
```

The scan runs against the **resolved IP**, not the name, so what was checked is what gets scanned.

### 3.2 Port parsing (`scanner.parse_ports`)

```
FUNCTION parse_ports(spec, max_ports):
    IF spec is "" or "common":  RETURN COMMON_PORTS          # ~65 risky ports
    IF spec is "top1024":        RETURN 1..1024
    ports ← empty set
    FOR EACH token IN spec split by ",":
        IF token matches "a-b":  add every port from min(a,b) to max(a,b)
        ELSE IF token is digits: add it
        ELSE:                    REJECT "invalid port expression"
        IF size(ports) > max_ports: REJECT "too many ports"
    IF any port outside 1..65535 OR ports is empty: REJECT
    RETURN sorted(ports)
```

### 3.3 Single-port probe (`scanner.probe_port`)

```
FUNCTION probe_port(host, port, timeout):
    open socket s with timeout
    TRY connect(s, host, port)
        ON timeout:               RETURN {port, state: "filtered"}   # silently dropped
        ON connection refused:    RETURN {port, state: "closed"}     # host answered RST
        ON host/net unreachable:  RETURN {port, state: "filtered"}
        ON other error:           RETURN {port, state: "closed"}
    record ← {port, state: "open", rtt_ms}

    # ---- fingerprinting (only for open ports) ----
    IF port ∈ TLS_PORTS:
        TRY wrap s in TLS (certificate verification off, since we are inspecting)
            tls ← {version, cipher, subject, issuer, expiry, days_left, self_signed, expired}
            add flags: tls_legacy (≤ TLS 1.1), tls_expired, tls_expiring (≤ 30 days), tls_self_signed
        ON failure: mark tls_error, skip banner grab
    probe ← SPECIAL_PROBES[port]  OR  HEAD request if port ∈ HTTP_PORTS  OR  none
    IF probe is none:   raw ← read what the server sends first   # SSH, FTP, SMTP, MySQL
    ELSE:               send probe; raw ← read reply (bounded size and time)

    record.banner  ← sanitised text (control chars removed, max 400 chars)
                     HTTP → "HTTP <status> | Server: … | X-Powered-By: …"
                     MySQL handshake → "MySQL <version>"
    record.service ← identify(port, raw)                       # §3.4
    add misconfiguration flags from the reply:
        "+PONG" to PING                    → redis_unauthenticated
        "VERSION" on 11211                 → memcached_open
        '"ApiVersion"' in body on 2375     → docker_api_unauth
        200 + "cluster_name" on 9200       → es_unauth
    close s; RETURN record
```

Only read-only probes are sent: `HEAD /`, `GET /`, `GET /version`, `PING`, `version`. Nothing writes, authenticates or exploits.

### 3.4 Service identification (`scanner.identify`)

First match on the received text wins:

```
"SSH-"                 → ssh              "RFB "            → vnc
"+PONG" / "-NOAUTH"    → redis            "VERSION " (11211)→ memcached
MySQL handshake bytes  → mysql            "+OK"             → pop3
"220 … FTP/vsFTPd/…"   → ftp              "* OK"            → imap
"220 … SMTP/Postfix/…" → smtp             "HTTP/" on 2375 / 9200 → docker / elasticsearch
otherwise              → none  (fall back to the port-number table)
```

### 3.5 Concurrent scan (`scanner.run_scan`)

```
FUNCTION run_scan(host, ports, timeout, workers, cancel_event):
    open_list ← [];  closed ← 0;  filtered ← 0;  done ← 0
    pool ← thread pool of min(workers, 500) threads
    FOR EACH port: submit task:
        IF cancel_event is set: RETURN nothing          # cooperative cancel
        RETURN probe_port(host, port, timeout)
    FOR EACH task AS IT COMPLETES:
        done ← done + 1
        update counters / append to open_list by state
        report progress(done, total)
    RETURN {open: open_list sorted by port, closed, filtered, cancelled}
```

Complexity: about `ports × timeout / workers` seconds worst case (all filtered). With 1,024 ports, 100 threads and a 0.8 s timeout that is roughly 8 s.

### 3.6 Risk scoring (`risk.analyze`)

**Inputs:** open-port records and the scope. **Outputs:** score, grade, findings, category totals.

```
FUNCTION analyze(open_ports, scope):
    findings ← []
    FOR EACH p IN open_ports:
        key ← p.service  IF known  ELSE  service for p.port  ELSE "unknown"
        add finding "service exposed"          weight = SERVICES[key].weight   (0-9)
        IF SERVICES[key].cleartext_penalty > 0 AND p has no TLS:
            add finding "cleartext protocol"   weight = cleartext_penalty
        FOR EACH signature IN BANNER_SIGNATURES:
            IF regex matches p.banner:  add finding (weight 4-11), once per port per signature
        IF banner reveals a version number AND no signature fired:
            add finding "version disclosure"   weight = 1
        FOR EACH flag IN p.flags:
            add finding FLAG_FINDINGS[flag]    weight = 1.5 to 10
    IF count(open_ports) > 10:
        add finding "large attack surface"     weight = min(5, 0.5 × (count − 10))

    raw      ← sum of all finding weights
    adjusted ← raw × SCOPE_MULTIPLIER[scope]     # loopback 0.6, private 0.85, public 1.0
    score    ← 0 IF no open ports ELSE 100 × (1 − e^(−adjusted / 30))
    grade    ← Minimal (nothing open) | Low (<20) | Moderate (<45) | High (<70) | Critical
    severity of each finding ← critical ≥9, high ≥7, medium ≥4, low ≥2, else info
    sort findings by weight, highest first
    RETURN {score, grade, findings, category totals, top 3 findings as "fix first"}
```

Why a saturating curve: a plain sum would exceed 100 on busy hosts and hide the difference between "bad" and "catastrophic".
`1 − e^(−x/30)` rises steeply at first, so a single critical issue is clearly visible, and flattens near 100.

Worked example (scope = loopback): unauthenticated Redis = 8 (exposed) + 10 (flag) = 18; × 0.6 = 10.8;
score = 100 × (1 − e^(−0.36)) ≈ **30 (Moderate)**. The same host on a public address: 100 × (1 − e^(−0.6)) ≈ **45 (High)**.

### 3.7 Job lifecycle and diff (`app.Job`, `app.build_diff`)

```
FUNCTION run_job(job):
    status ← running
    result ← run_scan(...);  analysis ← analyze(result.open, job.scope)
    final ← "cancelled" IF cancelled ELSE "done"
    IF final = "done":
        prev ← latest finished scan of the same IP started before this one
        IF prev exists:
            diff.newly_open  ← ports open now but not before
            diff.newly_closed← ports open before but not now
            diff.score_delta ← score now − score before
    status ← final           # set AFTER diff and save, so a poller never sees "done" without the diff
    persist job to SQLite
```

The client polls the job every 400 ms until the status is no longer `queued` or `running`.

## 4. Data structures

```
OpenPort  { port, state, rtt_ms, banner, service, label, flags[], tls{…}, http{…} }
Finding   { id, port, severity, title, weight, detail, remediation, category }
Analysis  { score, grade, raw_weight, scope, scope_multiplier, findings[], categories{}, severity_counts{}, top_actions[] }
Job       { id, target, ip, scope, status, progress{done,total}, results[], analysis, diff, counts, options }
```

## 5. Security design decisions

| Risk | Mitigation |
|---|---|
| Tool used against third parties | Loopback and private only by default; mandatory authorisation checkbox; single host per scan |
| Resource abuse | Port cap (5,000), thread cap (300), timeout cap (5 s), max 3 concurrent scans |
| Cross-site request forgery | Scan requests must be JSON, which forces a browser CORS preflight that is never granted |
| Malicious banners attacking the operator (XSS) | UI inserts all remote text with `textContent`; strict Content-Security-Policy |
| CSV formula injection | Cells starting with `= + - @` are prefixed with `'` |
| Misleading results | Probes are read-only; "filtered" and "closed" are kept distinct |

## 6. Known limitations

- IPv4/IPv6 connect scan only; no UDP.
- Version-based findings rely on banner text, which can be hidden or spoofed; treat them as leads, not proof.
- Legacy TLS detection reports only the negotiated version, not every version the server would accept.
- Weights are expert-judgement defaults, not CVSS values; tune them in `risk.py` for your environment.
