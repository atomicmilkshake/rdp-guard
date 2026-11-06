# uninstall.ps1 - Unregisters RDP-Guard and removes firewall rules
param(
  [switch]$RemoveFirewallRule,
  [switch]$DeleteStateFiles
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Error "Administrator privileges required to uninstall."
  exit 1
}

Write-Host "Uninstalling RDP-Guard..." -ForegroundColor Yellow

# Unregister tasks
Unregister-ScheduledTask -TaskName "RDP-Guard (anti-spray)" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "sec-dash (security dashboard)" -Confirm:$false -ErrorAction SilentlyContinue

# Stop python server if running
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'sec-dash[\\/]server\.py' } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

if ($RemoveFirewallRule) {
  Get-NetFirewallRule -DisplayName "AUTO-BAN-SPRAY" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Host "Firewall rule AUTO-BAN-SPRAY removed." -ForegroundColor Yellow
} else {
  Write-Host "Firewall rule AUTO-BAN-SPRAY preserved. Pass -RemoveFirewallRule to delete." -ForegroundColor Green
}

Write-Host "Uninstallation complete." -ForegroundColor Green