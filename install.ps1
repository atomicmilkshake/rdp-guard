# install.ps1 - Setup and register RDP-Guard & sec-dash on Windows
# Requires Administrator privileges.
param(
  [string]$InstallPath = $PSScriptRoot,
  [switch]$SkipDashboard
)

$ErrorActionPreference = 'Stop'

# 1. Verify elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Error "Administrator privileges are required to install scheduled tasks and firewall rules. Please run as Administrator."
  exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "             RDP-Guard - Windows Installer                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Directory: $InstallPath" -ForegroundColor Gray
Write-Host ""

# 2. Check PowerShell & Python
$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwsh)) {
  $pwsh = 'powershell.exe'
  Write-Host "Note: PowerShell 7 not detected; using Windows PowerShell 5.1." -ForegroundColor Yellow
} else {
  Write-Host "Detected PowerShell 7: $pwsh" -ForegroundColor Green
}

$pyw = 'C:\Python314\pythonw.exe'
if (-not (Test-Path -LiteralPath $pyw)) {
  $pyCmd = Get-Command pythonw.exe -ErrorAction SilentlyContinue
  if ($pyCmd) { $pyw = $pyCmd.Source } else { $pyw = 'pythonw.exe' }
}

# 3. Initialize state directories & template files if missing
$guardDir = Join-Path $InstallPath 'rdp-guard'
$dashDir  = Join-Path $InstallPath 'sec-dash'

$bansJson = Join-Path $guardDir 'bans.json'
if (-not (Test-Path -LiteralPath $bansJson)) {
  Set-Content -LiteralPath $bansJson -Value '{"stateVersion":2,"updatedAt":null,"bans":{}}' -Encoding UTF8
}
$guardState = Join-Path $guardDir 'guard-state.json'
if (-not (Test-Path -LiteralPath $guardState)) {
  Set-Content -LiteralPath $guardState -Value '{"version":1,"strikes":{}}' -Encoding UTF8
}
$allowlist = Join-Path $guardDir 'allowlist.txt'
if (-not (Test-Path -LiteralPath $allowlist)) {
  Set-Content -LiteralPath $allowlist -Value "# RDP-Guard allowlist`n# Enter IP addresses or CIDR ranges here that should NEVER be banned.`n" -Encoding UTF8
}
$forgive = Join-Path $guardDir 'forgive.txt'
if (-not (Test-Path -LiteralPath $forgive)) {
  Set-Content -LiteralPath $forgive -Value "# RDP-Guard forgive list`n# Enter IP addresses to pardon here.`n" -Encoding UTF8
}

# 4. Register Scheduled Task for rdp-guard
Write-Host "[1/3] Registering Scheduled Task 'RDP-Guard (anti-spray)'..." -ForegroundColor Yellow
$guardScript = Join-Path $guardDir 'rdp-guard.ps1'
$taskActionGuard = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$guardScript`""
$taskTriggerGuard = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$taskSettingsGuard = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask -TaskName "RDP-Guard (anti-spray)" -Action $taskActionGuard -Trigger $taskTriggerGuard -Principal $taskPrincipal -Settings $taskSettingsGuard -Force | Out-Null
Write-Host "      [OK] Scheduled Task 'RDP-Guard (anti-spray)' registered (runs every 1 min as SYSTEM)." -ForegroundColor Green

# 5. Register Scheduled Task for sec-dash (if not skipped)
if (-not $SkipDashboard) {
  Write-Host "[2/3] Registering Scheduled Task 'sec-dash (security dashboard)'..." -ForegroundColor Yellow
  $serverScript = Join-Path $dashDir 'server.py'
  $taskActionDash = New-ScheduledTaskAction -Execute $pyw -Argument "`"$serverScript`"" -WorkingDirectory $dashDir
  $taskTriggerDash = New-ScheduledTaskTrigger -AtStartup
  $taskSettingsDash = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

  Register-ScheduledTask -TaskName "sec-dash (security dashboard)" -Action $taskActionDash -Trigger $taskTriggerDash -Principal $taskPrincipal -Settings $taskSettingsDash -Force | Out-Null
  Write-Host "      [OK] Scheduled Task 'sec-dash (security dashboard)' registered (runs at boot as SYSTEM)." -ForegroundColor Green
}

# 6. Initial synchronous pass
Write-Host "[3/3] Running initial synchronous pass of rdp-guard..." -ForegroundColor Yellow
& $pwsh -NoProfile -ExecutionPolicy Bypass -File $guardScript
if ($LASTEXITCODE -eq 0) {
  Write-Host "      [OK] Initial firewall rule synced." -ForegroundColor Green
} else {
  Write-Host "      [WARNING] Initial rdp-guard run exited with code $LASTEXITCODE." -ForegroundColor Yellow
}

# Start dashboard if present
if (-not $SkipDashboard) {
  try { Start-ScheduledTask -TaskName "sec-dash (security dashboard)" -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "               Installation Complete!                     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Enforcement Engine : Active (AUTO-BAN-SPRAY firewall rule)" -ForegroundColor Green
Write-Host "Dashboard Viewer   : http://127.0.0.1:8099/" -ForegroundColor Green
Write-Host ""