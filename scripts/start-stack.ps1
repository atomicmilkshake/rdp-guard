# start-stack.ps1 - Start the Windows Security Stack
# In scope of PERMIT-0002 / PERMIT-0017. Compatible with Windows PowerShell 5.1 and PowerShell 7.

$ErrorActionPreference = 'Stop'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       Windows Security Stack - Startup Manager      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Run synchronous rdp-guard.ps1 pass FIRST (under Global\RdpGuardEnforcement mutex) before enabling scheduled task
Write-Host "[1/2] Syncing firewall rules from bans.json and enabling RDP-Guard..." -ForegroundColor Yellow
$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwsh)) { $pwsh = 'powershell.exe' }
& $pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Split-Path -Parent $PSScriptRoot) 'rdp-guard\rdp-guard.ps1')
if ($LASTEXITCODE -ne 0) {
    Write-Host "      [ERROR] rdp-guard.ps1 synchronous pass failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "      [OK] rdp-guard.ps1 synchronous pass succeeded." -ForegroundColor Green

try {
    Enable-ScheduledTask -TaskName 'RDP-Guard (anti-spray)' -ErrorAction Stop | Out-Null
    Write-Host "      [OK] Scheduled task 'RDP-Guard (anti-spray)' enabled." -ForegroundColor Green
} catch {
    Write-Host "      [ERROR] Could not enable 'RDP-Guard (anti-spray)': $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. Enable sec-dash task, run synchronous collector pass so data.json + commit-manifest.json are fresh, and ensure server.py is listening
Write-Host "[2/2] Enabling and starting sec-dash (security dashboard)..." -ForegroundColor Yellow
try {
    Enable-ScheduledTask -TaskName 'sec-dash (security dashboard)' -ErrorAction Stop | Out-Null
    Write-Host "      [OK] Scheduled task 'sec-dash (security dashboard)' enabled." -ForegroundColor Green
} catch {
    Write-Host "      [ERROR] Could not enable 'sec-dash (security dashboard)': $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

& $pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Split-Path -Parent $PSScriptRoot) 'sec-dash\collect.ps1') -Root (Join-Path (Split-Path -Parent $PSScriptRoot) 'sec-dash')
if ($LASTEXITCODE -ne 0) {
    Write-Host "      [ERROR] collect.ps1 synchronous pass failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

$dashConn = @(Get-NetTCPConnection -LocalPort 8099 -State Listen -ErrorAction SilentlyContinue)
if ($dashConn.Count -eq 0) {
    Write-Host "      Starting sec-dash server process on port 8099 via Scheduled Task..." -ForegroundColor Gray
    try {
        Start-ScheduledTask -TaskName 'sec-dash (security dashboard)' -ErrorAction Stop | Out-Null
    } catch {
        $pyw = 'C:\Python314\pythonw.exe'
        if (-not (Test-Path -LiteralPath $pyw)) { $pyw = 'C:\Python314\python.exe' }
        Start-Process -FilePath $pyw -ArgumentList (Join-Path (Split-Path -Parent $PSScriptRoot) 'sec-dash\server.py') -WorkingDirectory (Join-Path (Split-Path -Parent $PSScriptRoot) 'sec-dash') -WindowStyle Hidden
    }
} else {
    Write-Host "      [OK] sec-dash is already listening on port 8099." -ForegroundColor Green
}

Write-Host ""
Write-Host "-------------------- Live Verification --------------------" -ForegroundColor Cyan

$exitCode = 0

# Check Firewall Rule
$rules = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY' -ErrorAction SilentlyContinue)
$activeRules = @($rules | Where-Object { $_.Enabled.ToString() -eq 'True' -and $_.Direction.ToString() -eq 'Inbound' -and $_.Action.ToString() -eq 'Block' })
if ($rules.Count -eq 1 -and $activeRules.Count -eq 1) {
    $count = @(($activeRules[0] | Get-NetFirewallAddressFilter).RemoteAddress).Count
    Write-Host ("  Firewall Rule : ACTIVE - {0} banned IPs blocked (1 canonical rule)" -f $count) -ForegroundColor Green
} else {
    Write-Host ("  Firewall Rule : DEGRADED (total={0}, activeBlocking={1})" -f $rules.Count, $activeRules.Count) -ForegroundColor Red
    $exitCode = 1
}

# Poll Dashboard Health (/healthz) up to 15 seconds; fail closed (exit 1) if not healthy
$healthOk = $false
$lastHealthErr = 'unreachable'
for ($attempt = 0; $attempt -lt 15; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8099/healthz' -TimeoutSec 3 -ErrorAction Stop
        if ($health.ok -and $health.firewall_effective_ok) {
            Write-Host ("  Dashboard UI  : ONLINE at http://127.0.0.1:8099/ (data age: {0}s, fwEffectiveOk: {1})" -f $health.data_age_seconds, $health.firewall_effective_ok) -ForegroundColor Green
            $healthOk = $true
            break
        } else {
            $lastHealthErr = "status=$($health.status) reasons=$($health.reasons -join ',')"
        }
    } catch {
        $lastHealthErr = $_.Exception.Message
    }
    Start-Sleep -Seconds 1
}

if (-not $healthOk) {
    Write-Host ("  Dashboard UI  : FAILED healthz verification after 15s ({0})" -f $lastHealthErr) -ForegroundColor Red
    $exitCode = 1
}

Write-Host "-----------------------------------------------------------" -ForegroundColor Cyan
exit $exitCode
