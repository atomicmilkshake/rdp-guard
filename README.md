# RDP-Guard & Security Dashboard

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-blue.svg)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-Zero%20(Pure%20Stdlib)-brightgreen.svg)](#)

A lightweight, zero-dependency Windows anti-brute-force defense engine and real-time security dashboard designed for internet-exposed Remote Desktop (RDP) and OpenSSH servers.

RDP-Guard intercepts brute-force attacks from Windows Event Logs and enforces kernel-level drops via the Windows Filtering Platform (WFP), reducing CPU and memory overhead by preventing attackers from reaching user-mode authentication services (lsass.exe and 	ermsrv.dll).

> [!IMPORTANT]
> **Disclaimer:** This is a personal project created for my own edification and experimentation. The author makes no warranty, express or implied, as to its functionality, reliability, or performance. It's just a silly weekend curiosity project enhanced by access to the ability to vibe-code.

---

## Architecture Overview

```
                       Internet
                          │  (Attacker traffic on port 3389 / 22)
                          ▼
                 ┌──────────────────┐
                 │  Windows Firewall│◄──────────────┐
                 └────────┬─────────┘               │ One canonical rule: AUTO-BAN-SPRAY
                          │ (Dropped in Kernel)     │ (Block, Inbound, Any Profile/Protocol)
        ┌─────────────────┴───────────────┐         │
        ▼                                 ▼         │
   TermService (RDP 3389)             sshd (SSH 22) │
        │                                 │         │
        └─────────┬───────────────────────┘         │
                  ▼                                 │
     Windows Security & OpenSSH Logs                │
                  │                                 │
                  ▼                                 │
       rdp-guard/rdp-guard.ps1 ─────────────────────┘
       (Runs every 60s as SYSTEM; enforces bans.json)
                  │
                  ▼
       sec-dash/collect.ps1 ──► data.json ──► server.py :8099 ──► index.html
       (Telemetry aggregator)                 (Threaded Python)   (Live Dark-Mode UI)
```

---

## Key Features

### 🛡️ RDP-Guard (`rdp-guard/`)
* **Kernel-Level Packet Dropping:** Blocks banned addresses via a single canonical Windows Firewall rule (`AUTO-BAN-SPRAY`). Inbound packets are dropped in the kernel before reaching user-mode sockets, protecting CPU and disk I/O.
* **Intelligent Threat Heuristics:**
  * **Invalid / Non-Existent Usernames:** Any IP attempting to authenticate as a user that cannot log in (non-existent name, blank username, or disabled account such as built-in `Administrator`) is permanently banned on first offense.
  * **Real Account Protection:** Failed attempts against existing enabled accounts trigger temporary bans (24h default, doubling with each subsequent offense) after reaching configurable thresholds (e.g. 8 attempts in 15 minutes, or 12 attempts over 60 minutes).
  * **SSH Hardening:** Direct terminal peer extraction supports IPv4 and IPv6 to defend against framed/crafted username injections.
* **Fail-Closed & Set-Preservation Invariants:**
  * Strict atomic writes with shadow backups (`.bak`).
  * Enforcement state never shrinks on transient read/WMI errors.
  * Mutex-guarded execution (`Global\RdpGuardEnforcement`) ensures strict single-writer access.
* **Operator Lockout Defenses:**
  * Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, CGNAT `100.64.0.0/10`) are never banned.
  * Static exemption via `allowlist.txt`.
  * Auto-allow grace window: IPs that have successfully authenticated within the last hour are exempt from automated bans.

### 📊 Security Dashboard (`sec-dash/`)
* **Pure Python Standard Library Server:** `server.py` runs with zero external pip dependencies on `:8099`.
* **Zero Trust HTTP Stack:** Enforces canonical URL-decoded path allowlisting, strict Host validation, private-network client restriction, and tight Content Security Policy (CSP).
* **Real-Time Visuals:**
  * Leaflet map visualization of attack origin points.
  * 24-hour and 14-day attack velocity histograms.
  * "Hall of Shame" ranking top attacker IPs and targeted usernames.
* **Ultra-Low Overhead:** Server consumes ~10 MB RAM; collector runs in seconds.

---

## Quick Start & Installation

### Requirements
* Windows 10, Windows 11, or Windows Server (2016/2019/2022/2025).
* Windows PowerShell 5.1 or PowerShell 7+.
* Python 3.10+ (for `sec-dash` dashboard viewer).

### 1. Installation
Clone the repository and run the installer from an elevated Administrator prompt:

```cmd
git clone https://github.com/atomicmilkshake/rdp-guard.git C:\srv
cd C:\srv
install.bat
```

Or execute via PowerShell:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

The installer will:
1. Initialize local configuration files (`allowlist.txt`, `forgive.txt`, `bans.json`).
2. Register the `RDP-Guard (anti-spray)` Scheduled Task (runs every 60 seconds as `SYSTEM`).
3. Register the `sec-dash (security dashboard)` Scheduled Task (runs at startup).
4. Perform an initial synchronous pass to sync the firewall rule.

### 2. Configure Allowlist
Edit `rdp-guard\allowlist.txt` to add your WAN IP or office subnets so your administrative sessions are never locked out:

```text
# rdp-guard/allowlist.txt
203.0.113.10      # Home WAN IP
198.51.100.0/24   # Office subnet
```

### 3. Accessing the Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:8099/
```
*(By default, port 8099 is accessible only from localhost, LAN, and VPN/Tailscale addresses).*

---

## Management & Operations

### Control Scripts
* **`start-stack.bat`**: Enables scheduled tasks, synchronizes firewall rules, starts the web dashboard, and verifies system health.
* **`stop-stack.bat`**: Acquires global mutexes, drains active writers cleanly, disables scheduled tasks, and halts the web server (retaining active firewall bans by default).
* **`uninstall.bat`**: Cleanly unregisters scheduled tasks and removes services.

### Manual Pardons (Unbanning an IP)
To pardon an address, append the IP to `rdp-guard\forgive.txt`:
```text
203.0.113.55
```
Within 60 seconds, RDP-Guard will remove the ban, clear accumulated strikes, and remove the entry from `forgive.txt`.

---

## Documentation

Comprehensive operational specifications and architectural proofs are maintained in [`docs/`](docs/):

* [**Architecture & Invariants**](docs/ARCHITECTURE.md): Data tiers, state flow, and system invariants.
* [**Operations Runbook**](docs/RUNBOOK.md): Start/stop procedures, recovery steps, and verification commands.
* [**Threat Model & Security**](docs/SECURITY.md): Perimeter analysis, attack vectors, and exposure mitigations.
* [**Testing Standards**](docs/TESTING.md): Verification methodologies and test suites.

---

## Disclaimer & License

> **Note:** This is a personal project for my own edification. I make no warranty, express or implied, as to its functionality or performance. It's just a silly weekend curiosity project enhanced by access to the ability to vibe-code.

This project is licensed under the [MIT License](LICENSE).