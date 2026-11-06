# ThreatLens User Guide

ThreatLens checks which network services a machine is exposing, explains the risk of each one, and gives you a score
and a short list of what to fix first.

> **Only scan systems you own or have written permission to test.** Unauthorised scanning may be illegal.

## 1. Install and start

Requires Python 3.10+.

```bash
cd threatlens
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl+C`.

### Optional settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `THREATLENS_HOST` | `127.0.0.1` | Address the web app listens on. Leave as is unless you understand the exposure. |
| `THREATLENS_PORT` | `5000` | Web app port |
| `THREATLENS_DB` | `threatlens.db` | Where scan history is stored |
| `THREATLENS_MAX_PORTS` | `5000` | Maximum ports in one scan |
| `THREATLENS_ALLOW_PUBLIC` | off | Set to `1` to allow scanning public IP addresses (your own servers only) |

Example: `THREATLENS_PORT=8080 python app.py`

## 2. Try it safely first

```bash
python demo_services.py        # in a second terminal
```

This starts fake weak services on your own machine. In ThreatLens choose **Custom…** ports and enter
`2121,2222,6379,8080,8443,4444` with target `127.0.0.1`. You should see a Critical result with an old FTP server,
an unauthenticated Redis, an old Apache and an expired self-signed certificate.

## 3. Run a scan

1. **Target host**: one hostname or IP address, for example `127.0.0.1`, `192.168.1.10` or `server.lan`.
   URLs, ranges and CIDR blocks (like `10.0.0.0/24`) are refused.
2. **Ports**:
   - *Common risky ports*: about 65 ports for the services attackers target most (fast, recommended first scan).
   - *Well-known 1-1024*: every privileged port.
   - *Custom*: your own list, such as `22,80,443` or `8000-8100` or `22,80,8000-8100`. Limit 5,000 ports.
3. **Timeout**: how long to wait for each port. 0.8 s suits a local network. Raise it (1.5-3 s) for slow or distant hosts.
4. **Threads**: how many ports are tried at once (default 100). Lower it for fragile devices such as routers or printers.
5. Tick **"I own this system or have written permission to scan it"**. Scans will not start without it.
6. Click **Start scan**. A progress bar shows how far along it is. Use **Cancel scan** to stop early.

## 4. Reading the results

### Score and grade
The gauge shows a 0-100 score. Higher means more risk.

| Grade | Score | What it means |
|---|---|---|
| Minimal | no open ports | Nothing is listening on the ports scanned |
| Low | under 20 | Small, expected exposure |
| Moderate | 20-44 | Some services need attention |
| High | 45-69 | Serious exposure; act soon |
| Critical | 70+ | Dangerous services or known-vulnerable software; act now |

Next to the host you see a **scope** tag (loopback, private or public). Public hosts score higher than the same
services on a private network, because more attackers can reach them.

### Fix first
The three highest-weight findings with the recommended action for each. Start here.

### Open ports table
- **Service**: what ThreatLens decided the service is, from its reply rather than only from the port number.
- **Risk**: severity of everything found on that port.
- **Banner / TLS**: what the service announced, plus TLS version, certificate name and days until expiry.
- **ms**: connection time.

### Findings
Each finding shows a severity, a plain explanation, a **Fix** line and its weight (`+8` etc.). The weights add up to the score.

| Severity | Typical examples |
|---|---|
| Critical | Redis with no password, backdoored FTP release, open Docker API |
| High | Databases, remote desktop, SMB, suspicious listeners |
| Medium | Outdated software, expired certificate, FTP |
| Low / Info | Common services, cleartext web, self-signed certificate |

### Risk by category
Shows which kinds of problem (database, remote access, vulnerable software…) contribute most.

### Closed vs filtered
- **Closed**: the host answered "nothing here".
- **Filtered**: no answer, usually a firewall dropping the traffic. A host that is mostly filtered is well protected.

## 5. History and comparing scans

- Every finished scan appears under **History** with its score. Click one to reopen it.
- Scan the same host again later and a **"Since last scan"** banner lists ports that are newly open (red), ports that closed
  (green) and the score change. A new open port you did not expect is worth investigating immediately.
- Click **✕** on a history row to delete it.

## 6. Exporting

After a scan finishes, use **JSON** (the full record, including raw port data) or **CSV** (findings only, for spreadsheets
and tickets). The columns are severity, port, title, weight, category, detail and remediation.

## 7. Scanning your own public server

By default, public addresses are blocked. If you own the server:

```bash
THREATLENS_ALLOW_PUBLIC=1 python app.py
```

Make sure your hosting provider allows port scanning of your own instances. Keep the web app on `127.0.0.1`.

## 8. Troubleshooting

| Message or symptom | Cause and fix |
|---|---|
| "You must confirm you are authorised…" | Tick the authorisation checkbox |
| "Public addresses are disabled…" | Target is not loopback or private; see section 7 |
| "Could not resolve …" | Typo or DNS problem; try the IP address |
| "Enter a single hostname or IP address" | Remove `http://`, paths, spaces or `/24` |
| "Too many ports" | Reduce the range, or raise `THREATLENS_MAX_PORTS` |
| "Too many scans running" | Wait for a running scan to finish (limit 3 at once) |
| Everything shows as filtered | Firewall in the way, or timeout too short |
| Scan is slow | Lower the number of ports, or lower the timeout on a fast local network |
| No TLS details shown | Install `cryptography` (`pip install cryptography`) |

## 8a. Limits worth knowing

- TCP only; UDP services (DNS, SNMP, NTP over UDP) are not covered.
- Version warnings come from banners. A hidden or fake banner can hide an old version, so treat the score as a
  starting point rather than a guarantee that a host is safe.
- The scoring weights are judgement-based defaults. Adjust them in `risk.py` to match your environment.

## 9. Command-line use (API)

The web page uses a small JSON API you can also call directly:

```bash
# start a scan
curl -X POST http://127.0.0.1:5000/api/scans -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","ports":"common","authorized":true}'

# check progress and results
curl http://127.0.0.1:5000/api/scans/<id>

# list history, export, cancel, delete
curl http://127.0.0.1:5000/api/scans
curl -O http://127.0.0.1:5000/api/scans/<id>/export.csv
curl -X POST   http://127.0.0.1:5000/api/scans/<id>/cancel
curl -X DELETE http://127.0.0.1:5000/api/scans/<id>
```

Optional JSON fields: `timeout` (0.1-5 seconds), `workers` (1-300), and `ports` as `"common"`, `"top1024"` or a custom
list such as `"22,80,8000-8100"`.

## 10. Project layout

```
app.py             web server, API, jobs, history
scanner.py         port probing, banner and TLS grabbing, service identification
risk.py            weights, signatures, scoring and grades
static/            web interface (HTML, CSS, JavaScript)
demo_services.py   fake weak services for safe practice
tests/             automated tests (python -m pytest tests)
docs/              this guide and ALGORITHM.md
```
