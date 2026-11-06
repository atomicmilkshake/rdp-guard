# RUNBOOK.md — operating the security stack

Every command here has been executed on this machine. Anything marked **VERIFY** must be confirmed
from the live artifact, not assumed.

---

## 1. Is it actually working? (five checks, in order)

```powershell
# 1. the guard is scheduled and has run recently (LastTaskResult = 0)
Get-ScheduledTaskInfo -TaskName 'RDP-Guard (anti-spray)' | Select-Object LastRunTime, LastTaskResult, NextRunTime

# 2. the canonical firewall rule exists (exactly 1 instance), is enabled, and holds the expected addresses
$rules = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY')
$rules | Select-Object Name, DisplayName, Enabled, Action, Direction, Profile
@(($rules[0] | Get-NetFirewallAddressFilter).RemoteAddress).Count   # must match bans.json

# 3. state is readable (stateVersion 2) and count-consistent
(Get-Content C:\srv\rdp-guard\bans.json -Raw | ConvertFrom-Json).data.bans.PSObject.Properties.Count

# 4. the dashboard and collector transaction manifest are healthy (HTTP 200, firewall_effective_ok = true)
Invoke-RestMethod http://127.0.0.1:8099/healthz

# 5. OpenSSH is running and accepting auth (PasswordAuthentication yes, PubkeyAuthentication yes)
& (Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName.Trim('"') -T | Select-String '^(passwordauthentication|pubkeyauthentication|authorizedkeysfile)\b'
```

**A ban logged is not a ban enforced.** `guard.log` records intent; only check 2 and `/healthz`
(`firewall_effective_ok: true`) prove the firewall agrees.

## 2. Un-ban an address

Two mechanisms, and the difference matters:

| Goal | Action |
|---|---|
| **Temporary** — a guest mistyped a username | add the IP to `C:\srv\rdp-guard\forgive.txt` |
| **Permanent** — a trusted client | add the IP to `C:\srv\rdp-guard\allowlist.txt` |

Both files: one address per line, `#` comments allowed. They take effect within 60 seconds.
`rdp-guard.ps1` preserves all currently enforced firewall IPs across runs *unless* an IP appears in
`allowlist.txt` or `forgive.txt` (or its temporary `until` timestamp expires), so always use
`forgive.txt` or `allowlist.txt` to un-ban an address cleanly across both `bans.json` and the live
firewall rule.

## 3. Stop or start the stack (`stop-stack.ps1` / `start-stack.ps1`)

```powershell
# Stop scheduled tasks and HTTP listener while keeping AUTO-BAN-SPRAY active in Windows Firewall:
pwsh -NoProfile -File C:\srv\agent-ops\bin\stop-stack.ps1

# (Optional) Stop AND remove the AUTO-BAN-SPRAY firewall rule:
pwsh -NoProfile -File C:\srv\agent-ops\bin\stop-stack.ps1 -ReleaseFirewallBans

# Start and verify the stack:
pwsh -NoProfile -File C:\srv\agent-ops\bin\start-stack.ps1
```

Both scripts target Windows PowerShell 5.1 and PowerShell 7 (PS 5.1 execution is NOT CONFIRMED on
this host — `System32\powershell.exe` is shimmed to pwsh 7). `stop-stack.ps1` quiesces writers with
poll-create-hold on `Global\RdpGuardEnforcement` + `Global\SecDashCollector` (a SYSTEM-held mutex
denies a direct admin open; the script retries within a bounded budget — `ADR-0015`), kills only
writer processes observed after both locks are held, rolls back (re-enables both tasks, restarts the
HTTP server if it was killed) on any abort with a non-zero exit, and verifies `/healthz` closure.
The `AUTO-BAN-SPRAY` firewall rule is never touched unless `-ReleaseFirewallBans` is passed.

## 4. Restart the dashboard HTTP server

```powershell
Get-CimInstance Win32_Process -Filter "(Name='python.exe' OR Name='pythonw.exe') AND CommandLine LIKE '%sec-dash%server.py%'" |
  Where-Object { $_.ProcessId -ne $PID } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-ScheduledTask -TaskName 'sec-dash (security dashboard)'   # also runs at boot + every 15 min (self-heal)
Invoke-RestMethod http://127.0.0.1:8099/healthz
```

`server.py` binds `:8099` before spawning its collector loop and exits `0` cleanly on `EADDRINUSE`
(`winerror == 10048`) if an existing healthy `sec-dash` instance is already serving `:8099`.

## 5. Recover from a corrupt or missing `bans.json` or `sec-dash` store

- **`rdp-guard/bans.json`:** `rdp-guard.ps1` automatically falls back to `bans.json.bak` if
  `bans.json` is corrupt. If both are unreadable, it quarantines the corrupt file to
  `bans.json.corrupt-<timestamp>`, logs `CRITICAL`, exits `2`, and **leaves the `AUTO-BAN-SPRAY`
  firewall rule untouched**. Because `rdp-guard.ps1` unions the live `AUTO-BAN-SPRAY` `RemoteAddress`
  set into state on every valid run, seeding `{"stateVersion":2,"data":{"bans":{},"strikes":{}}}`
  into `bans.json` and running `rdp-guard.ps1` will automatically re-import all currently enforced
  firewall IPs.
- **`sec-dash` stores (`stats.json`, `hourly.json`, `recent.json`):** `collect.ps1` maintains
  `commit-manifest.json` (`status: "committing" -> "ok"`) and pre-commit `.bak` shadow copies. If a
  collector run crashes mid-commit, the next run automatically restores all three `.bak` stores to
  their consistent pre-commit generation.

## 6. Run the master verification suite

```powershell
pwsh -NoProfile -File C:\srv\agent-ops\verification\run-all.ps1
```

`run-all.ps1` executes Phase 0 (ACL + HTTP allowlist/traversal/HEAD/CSP), Phase 1 (`rdp-guard` on
PS7 and PS5.1), Phase 2 (`collect.ps1 -SelfTest` + multi-store synthetic verification on PS7 and
PS5.1), Phase 3 (headless Chromium oracle + XSS verification), and a negative mutated-fixture
self-test proving the verifier exits non-zero on a mismatch.

## 7. Exposed services — what should be reachable from outside

| Port | Service | Expected |
|---|---|---|
| 3389 | RDP | open (guarded by `AUTO-BAN-SPRAY`) |
| 22 | SSH | open (password & key auth; guarded by `AUTO-BAN-SPRAY`) |
| 8096 / 8920 | Jellyfin HTTP / HTTPS | open; **prefer 8920 remotely** |
| 47984-48010 | Sunshine / Apollo | open |
| 443 | qBittorrent WebUI TLS proxy | LAN + Tailscale only (`WAN-BLOCK 443`) |
| 8099 | `sec-dash` dashboard | LAN + Tailscale only (`WAN-BLOCK` + in-process IP filter) |
| everything else | — | WAN-blocked by `WAN-BLOCK <port> …` rules |

## 8. Re-seed the Hall of Shame store (after the Security log rolls)

```powershell
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File C:\srv\sec-dash\collect.ps1 -ShameBackfill
```
