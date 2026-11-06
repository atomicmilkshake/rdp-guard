# SECURITY.md — threat model, exposure, and what is actually protected

Written from **measured** state, not intent. Where a claim was verified, the verification is named.
Where something is *not* protected, it says so.

---

## 1. Threat model

| Threat | Reality here |
|---|---|
| **Opportunistic scanning / credential spraying** | Continuous. ~5,400+ failed logons/day on RDP; SSH sees crypto-bot username dictionaries (`sol`, `validator`, `ethereum`, `avalanche`), and RDP sees `admin` / `ADMINISTRATOR` / harvested names from other victims |
| **Targeted attacks** | None observed. The username of the real account has never been attempted (verified over the retained logs) — the campaign is generic |
| **Local privilege escalation / HTTP traversal** | Hardened in Phase 0 (`ADR-0011` / `PERMIT-0013`): `C:\srv` ACL inheritance removed (`SYSTEM:F`, `Administrators:F`, `Users:RX` only) and `sec-dash/server.py` enforces URL-decoded normalized allowlist checks across `GET` and `HEAD` |
| **Data exposure by misconfiguration** | All exposed services are inventoried and probed; Jellyfin passwordless accounts and `:8080` workspace dump were closed and verified |
| **Silent failure of the defence** | Guarded by fail-closed `rdp-guard.ps1` (`Get-WinEvent -ErrorAction Stop`, `.bak` state recovery, set-union preservation) and deep `/healthz` (`firewallEffectiveOk`, `commit-manifest.json`) |
| **Physical/social** | Out of scope |

## 2. What is exposed, and what holds it

| Port | Service | Protection | Verified |
|---|---|---|---|
| 3389 | RDP | NLA required, TLS, only **one** enabled account (`operator`), RDP right limited to Administrators, 10-attempt lockout, plus `rdp-guard.ps1` (`AUTO-BAN-SPRAY`) | live config read + `phase1_verify.ps1` |
| 22 | SSH | Password and Key authentication (`PasswordAuthentication yes`, `PubkeyAuthentication yes`), plus `rdp-guard.ps1` | `sshd.exe -T` output (`passwordauthentication yes`, `pubkeyauthentication yes`) |
| 8096 | Jellyfin (HTTP) | account passwords (all four accounts require one) | passwordless login attempted from public address → 401 |
| 8920 | Jellyfin (HTTPS) | TLS with a self-signed cert; **use this remotely** | encrypted login confirmed from public address |
| 47984-48010 | Sunshine / Apollo | web UI over HTTPS requiring login; factory defaults rejected (HTTP 401) | default-credential test |
| 443 | qBittorrent WebUI TLS proxy (`qbit-webui-proxy`) | LAN + Tailscale (`100.64.0.0/10`) only via `WAN-BLOCK 443` rule; forwards to loopback `127.0.0.1:8082` withPBKDF2 auth | live listener + firewall verification |
| 8099 | this dashboard (`sec-dash`) | LAN + Tailscale only (`WAN-BLOCK` + in-process source IP & `Host` validation) + normalized HTTP allowlist (`GET` & `HEAD`) + CSP | `phase0_verify.py` (21/21 HTTP/traversal/HEAD/ACL checks) |
| others | — | `WAN-BLOCK` firewall rules per port | external probes |

## 3. The failures that were actually found and fixed

| Finding | Severity | State |
|---|---|---|
| **`Authenticated Users:(OI)(CI)(M)` on `C:\srv` allowed local modify of `SYSTEM`-scheduled scripts** | critical | **fixed + verified (2026-10-17, PERMIT-0013)**: inheritance disabled across `C:\srv` and 2,430 child items; only `SYSTEM` and `Administrators` hold write/modify rights (`phase0-verify.json`) |
| **`server.py` `do_HEAD` bypassed `do_GET` allowlist and `/vendor/..%2f` URL-encoded traversal exposed files in `C:\srv\sec-dash`** | critical | **fixed + verified (2026-10-17, PERMIT-0013)**: unified `_authorize_and_resolve()` URL-decodes and `posixpath.normpath`s before checking the strict 7-path allowlist (`phase0-verify.json`) |
| **SSH `PasswordAuthentication` was still commented out (`#PasswordAuthentication yes` = enabled) in `C:\ProgramData\ssh\sshd_config`** | high | **restored (2026-10-20, ADR-0016 / PERMIT-0020)**: `PasswordAuthentication yes` explicitly restored per operator requirement for remote client password access; brute-force attacks mitigated by `rdp-guard` and Windows lockout policy |
| **Duplicate `AUTO-BAN-SPRAY` firewall rules (`876` vs `986` IPs) and silent state-shrinkage risk in `rdp-guard.ps1`** | high | **fixed + verified (2026-10-17, PERMIT-0014)**: single canonical rule `{5be24e42-4d23-451d-98b4-4b0e27195a5e}`, union of enforced firewall IPs into `bans.json`, `Get-WinEvent -ErrorAction Stop` fail-closed, `.bak` recovery, and automatic duplicate removal (`phase1-verify.json`) |
| **SSH username injection (`Invalid user bait from 1.2.3.4 port 9 from <real_ip> port <p>`) and IPv6 regex gaps** | high | **fixed + verified (2026-10-17, PERMIT-0014/0015)**: anchored terminal-peer regex + `[System.Net.IPAddress]::TryParse` canonicalization in both `rdp-guard.ps1` and `collect.ps1` |
| **Multi-store non-transactional writes, hourly 400-IP cap loss across restarts, Fall-Back DST key collision, and partial-day hourly pruning gap** | high | **fixed + verified (2026-10-17, PERMIT-0015/0016)**: shadow-copy `commit-manifest.json` recovery, UTC `YYYY-MM-DDTHH:00:00Z` keys, local-midnight pruning, uncapped `hourlyTotals` & `daily.totalIps`, and `recentMeta` truncation handoff (`phase2-verify.json`, `candidate-20261017-results.json`) |
| **Passwordless Jellyfin accounts reachable from the internet** (`Dad`, `Mommy`, `Kiddos`) | critical | **fixed + verified**: empty password now 401, new passwords login 200 |
| **Jellyfin served plain HTTP** with `RequireHttps=false` and nothing on 8920 | high | **fixed**: TLS enabled on 8920, `EnableHttps=true`, cert issued |
| **Jellyfin's UPnP enabled** (self-opening router ports) | medium | **fixed**: `EnableUPnP=false` |
| **A work artefact served unauthenticated on :8080** | critical | **fixed**: WAN-blocked at the host firewall; WorkspaceViewer retired |
| **Firewall log was disabled** | medium | **fixed**: packet logging on (32 MB cap) |
| **Security log capped at 20 MB** (~8.7 h retention) | high | **fixed**: raised to 1 GB |
| **A corrupt `bans.json` deleted the firewall rule**, releasing every banned attacker | critical | **fixed**: fail-closed + atomic writes + `.bak` fallback |
| **Public IPv6 attackers were invisible** (any `:` treated as private) | medium | **fixed** |

## 4. Not protected / accepted risks

1. **RDP remains reachable from the internet** — by operator choice. Its protection is NLA plus one
   password. There is no second factor, no IP restriction and no VPN in front of it.
2. **`AUTO-BAN-SPRAY` is a single canonical firewall rule.** It is verified on every `rdp-guard.ps1`
   run and monitored via `/healthz` (`firewall_effective_ok`).
3. **No mutual TLS / certificate auth on RDP.**
4. **Jellyfin's self-signed certificate** is not a publicly trusted cert.
5. **UPnP remains enabled on the router** and in **Sunshine** / **Moonlight** services.
6. **Geolocation is third-party and unauthenticated** (`ip-api.com` over plain HTTP), escaped before rendering.
7. **The operator's work/client IP is not in `allowlist.txt`** — only the operator can populate their
   external client IPs in `C:\srv\rdp-guard\allowlist.txt`.

## 5. Standing rules

- Enforcement state is the source of truth for *enforcement*; the dashboard is the source of truth
   for *observation*. `/healthz` continuously cross-checks `firewall_effective_ok` against live
   Windows Firewall state.
- No new internet-facing service without: a strong unique credential, a note in this file, and a
   probe from outside the host.
- No credential, token, or key file may be committed to a repository in this tree.
- Every security-relevant change gets a `docs/CHANGELOG.md` entry **and** a journal entry, in the same
   turn.
