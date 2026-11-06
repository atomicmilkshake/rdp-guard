# ARCHITECTURE.md

## 1. Context

A home/office Windows 11 server (`WINDOWS-SERVER`, LAN `192.168.1.100`, public `203.0.113.10`) is
reachable from the internet for four reasons the operator wants: RDP, SSH, Jellyfin, Sunshine.
Everything else on it is private (or LAN/Tailscale-gated via TLS on `:443`). It is scanned
continuously — roughly **5,400+ failed logons per day** arrive on port 3389 alone.

Two small components were built in response: one to **stop** the traffic, one to **see** it.

```
                       internet
                          │  (router forwards: 3389, 22, 8096, 8920, 47984-48010)
                          ▼
                 ┌──────────────────┐
                 │  Windows Firewall│◄──────────────┐
                 └────────┬─────────┘               │ one canonical rule: AUTO-BAN-SPRAY
                          │                         │ Name={5be24e42-4d23-451d-98b4-4b0e27195a5e}
        ┌─────────────────┼───────────────┐         │ (Block, Inbound, Any profile/protocol,
        ▼                 ▼               ▼         │  RemoteAddress = banned addresses)
   TermService        sshd           Jellyfin     rdp-guard.ps1
   (3389)             (22, pwd/key)  (8096/8920)      ▲ every 60 s, as SYSTEM
        │                 │               │          │
        └─────────┬───────┴───────────────┘          │
                  ▼                                  │
        Security.log / OpenSSH log ──────────────────┘
                  │
                  ▼
        sec-dash/collect.ps1 ──► commit-manifest.json + data.json ──► server.py :8099 ──► index.html
                  │                                                   (LAN/Tailscale)
                  └──► stats.json · hourly.json · recent.json · shame.json · geo.json (.bak shadow copies)
```

## 2. rdp-guard — the enforcement engine

**File:** `rdp-guard/rdp-guard.ps1` · **Schedule:** scheduled task `\RDP-Guard (anti-spray)`, every
60 s, as `NT AUTHORITY\SYSTEM` · **Concurrency:** `Global\RdpGuardEnforcement` mutex · **Surface:**
exactly one canonical firewall rule (`Name = '{5be24e42-4d23-451d-98b4-4b0e27195a5e}'`,
`DisplayName = 'AUTO-BAN-SPRAY'`).

### Decision policy

| Trigger | Action |
|---|---|
| Failed logon for a username that **cannot log in here** (nonexistent, blank, **or disabled**) | **permanent ban** |
| `Invalid user` over SSH (an account that does not exist, or preauth close for invalid user) | **permanent ban** |
| ≥8 failures for a **real, enabled** account within 15 min, or ≥12 within 60 min | temporary ban, doubling per repeat |
| ≥5 SSH authentication failures within 15 min | temporary ban |
| 4th offence by the same address | permanent ban |

### Guards that must never regress

| Invariant | Why it exists |
|---|---|
| **Fail closed on state or log error** — if `bans.json` (and `bans.json.bak`) cannot be validated or if `Get-WinEvent -ErrorAction Stop` fails on `Security`, quarantine corrupt files, log CRITICAL, exit non-zero, and **do not touch the firewall** | an earlier implementation treated an unreadable list or failed event query as empty and *deleted or shrank the rule* |
| **Preserve & union enforced firewall set** — any valid public IP currently on `AUTO-BAN-SPRAY` is imported into `bans.json` unless explicitly allowlisted, forgiven, or expired (`$nowUtc -gt $b.until`) | prevents silent shrinkage when manual bans or prior rules exist |
| **Single canonical rule + read-after-write verification** — `Set-NetFirewallRule` is followed by `Get-NetFirewallRule` + `Get-NetFirewallAddressFilter` set-equality verification; duplicate `AUTO-BAN-SPRAY` rules and superseded `RDP-BruteForce-Block` rules are removed only after primary rule verification succeeds | two duplicate `AUTO-BAN-SPRAY` rules (`876` vs `986` IPs) previously existed in production |
| **Private ranges are never banned** (RFC1918, loopback, CGNAT `100.64.0.0/10`, link-local, multicast, ULA); **public IPv6 is bannable**; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is normalized to IPv4 | prevents self-ban over LAN or Tailscale while blocking public IPv4 and IPv6 attackers |
| **Allowlist and forgive list are absolute** | the operator must never be locked out by their own tool |
| **An address with a successful real logon in the last hour is skipped** | typos must not permaban a legitimate client |
| **Atomic state writes** (`.tmp` + `[System.IO.File]::Replace` with `.bak`) | a crash mid-write must not truncate live state |
| **Evidence-bound terminal-peer parsing** (`Parse-SshFailureLine`) — anchored on the terminal `from <ip> port <port>(?: ssh2)?(?: [preauth])?$` and validated via `[System.Net.IPAddress]::TryParse` | an attacker-chosen SSH *username* containing `from 1.2.3.4 port 22` could otherwise frame a third party |

### Windows are real windows

Decisions are evaluated from **rolling-window queries against the event logs every run** (24 h for
the "cannot log in" rule, 15/60 min for thresholds). The checkpoint file (`guard-state.json`) is
observability only and gates nothing.

## 3. sec-dash — the observation layer

**Files:** `collect.ps1` (collector) · `server.py` (HTTP on `:8099`, LAN/Tailscale only) · `index.html` (UI).

### Transactional multi-store persistence & watermarks

- **Single writer mutex:** `Global\SecDashCollector` prevents overlapping runs between `server.py`'s background thread, scheduled tasks, and manual CLI invocations.
- **Shadow-copy transaction manifest (`commit-manifest.json`):** Before mutating any store, `collect.ps1` snapshots `stats.json`, `hourly.json`, and `recent.json` to `.bak`, writes `commit-manifest.json` with `status: "committing"` and `generationId`, atomically replaces each store, writes `data.json`, and marks `commit-manifest.json` `status: "ok"`. If a previous run crashed mid-commit (`status != "ok"`), the next run automatically restores all three `.bak` stores to their identical pre-commit generation before ingesting.
- **Event `RecordId` watermarks:** `stats.json` tracks `lastRecordIdSec`, `lastRecordIdSsh`, `lastRecordIdRdp261`, and `lastRecordIdLock` (detecting event log clears when `maxRecordId < lastRecordId`), eliminating equal-second boundary drops and duplicates.
- **Canonical SSH attempt identity:** `stats.json` persists `pendingPreauth` across collector runs and hour boundaries so `Invalid user` + `Failed password` / `[preauth]` close pairs count as 1 attempt while N password retries on one connection count as N attempts.

### Data tiers

| Tier | Coverage | Detail | Source |
|---|---|---|---|
| **Exact events** | last 24 h (or from `ceil(recentMeta.oldest / 1h)` if capped at 25,000) | every attempt, to the second | `recentCompact` + `recentMeta` in `data.json` |
| **Hourly** | rolling 14 days aligned to local calendar midnight (`America/Chicago`) | UTC keys (`YYYY-MM-DDTHH:00:00Z`), top-400 per-IP detail in `data.json` (5,000 in `hourly.json`), plus uncapped `hourlyTotals: [rdp, ssh, uniqueIps]` | `hourly.json` |
| **Daily** | forever | authoritative protocol totals (`fails`, `ssh`, `rdpConn`, `lockouts`), uncapped `totalIps`, and top-400 `ips` | `stats.json` |
| **Hall of Shame** | retained-log window at seed time + live 30 s ingest | per-IP attempts naming a username that **cannot log in here** (blank/nonexistent/disabled) | `shame.json` |

**Ownership rule (`normalize()` in `sec-dash/index.html`):**
Tier boundaries are anchored to `parseHost(data.generated)` in `America/Chicago` and every selection
is half-open `[from, to)`. `exactStart` is `ceil((anchor - 24h) / 1h) * 1h` (or advanced to
`ceil(parseHost(recentMeta.oldest) / 1h) * 1h` if `recentMeta.truncated` is true so hours evicted
by the 25,000-event cap are seamlessly served from `hourly`). Hourly buckets use authoritative
`hourlyTotals[key]` protocol counts alongside capped per-IP detail, and `hourly.json` is pruned at
local calendar midnight (`America/Chicago`) so `hourlyStart` aligns cleanly with `daily` without
partial-day gaps.

### Exposure rules for the dashboard (`sec-dash/server.py`)

- Binds `:8099` (`BoundedHTTPServer`, max 16 concurrent worker threads, 10 s per-socket timeout); WAN is blocked at the host firewall.
- Enforces source-IP validation (`127.0.0.1`, `::1`, `192.168.4.0/24`, `100.64.0.0/10`) and `Host` header validation inside `server.py`.
- Both `do_GET` and `do_HEAD` route through `_authorize_and_resolve()`, which URL-decodes and normalizes (`posixpath.normpath`) the path *before* checking the strict route allowlist (`/`, `/index.html`, `/data.json`, `/health`, `/healthz`, `/vendor/leaflet.js`, `/vendor/leaflet.css`). Any traversal (`/vendor/..%2fserver.py`) returns `404`.
- Sends `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Frame-Options: DENY` (the referer value is required so OpenStreetMap serves the dashboard map tiles; do not revert to `no-referrer`).
- `/healthz` and `/health` validate `commit-manifest.json` (`status == "ok"`), `data.json` freshness (`< 180s`), and `health.firewallEffectiveOk == true` (`200 OK` when healthy, `503` when degraded).

## 4. Invariants (the whole system)

1. **Enforcement never fails open.** Any doubt about state or event logs means *leave the firewall alone*.
2. **The operator can never be banned** (allowlist, forgive list, recent-success grace, private/Tailscale range exclusion).
3. **The tiers never double-count and never gap** (single ownership rule + calendar-midnight hourly pruning + `recentMeta` truncation handoff).
4. **What the dashboard shows must be measured**, and where detail is capped at top-400 IPs, authoritative uncapped totals (`hourlyTotals`, `daily.totalIps`) are preserved alongside it.
5. **No credential reaches the browser-visible path**, `C:\srv` ACLs restrict write access to `SYSTEM` and `Administrators`, and no documentation lives in the served directory.
6. **Every claim of "fixed" is reproduced by an independent harness or model.**
