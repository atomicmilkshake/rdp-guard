# stop-stack.ps1 - Stop the Windows Security Stack
#
# In scope of PERMIT-0002 / PERMIT-0017 / PERMIT-0018. Compatible with Windows PowerShell 5.1
# and PowerShell 7 (production executes under pwsh 7.6.6 / .NET 10 - see mutex notes below).
#
# Exit codes:
#   0 = stopped cleanly
#   1 = stop completed but final verification or a listener observation failed
#   2 = aborted waiting for Global\RdpGuardEnforcement  (stack rolled back to running)
#   3 = aborted waiting for Global\SecDashCollector     (stack rolled back to running)
#   4 = abort AND rollback failure - manual attention required
#   5 = teardown could not reach quiescence/closure     (stack rolled back to running)
#
# Mutex-acquisition strategy (live defect found 2026-10-17, second live cycle). The writers
# (collect.ps1 / rdp-guard.ps1 launched by the scheduled tasks as NT AUTHORITY\SYSTEM) create
# the named mutexes with the SYSTEM token's default DACL. On .NET 10 (pwsh 7.6.6) the Mutex
# class has NO security/ACL overloads (measured: MutexSecurity is constructible but no Mutex
# ctor or Get/SetAccessControl accepts it), and an elevated admin token CANNOT open a
# SYSTEM-created mutex (measured live: UnauthorizedAccessException "Access to the path
# 'Global\SecDashCollector' is denied."). The previous revision crashed unhandled at
# `New-Object` mid-teardown (tasks already disabled) and left the stack half-stopped.
# This revision polls instead of crashing: while a SYSTEM writer is in flight the open is
# denied and the name is retried; when that writer finishes, its handle closes (the object
# evaporates with its last handle) and the next attempt creates the object under this token
# and owns it. In-flight writers are NEVER killed - they may be mid-mutation (the guard can
# be mid-firewall-update). Only writers found AFTER both locks are held are killed; by
# construction those are blocked on acquisition (both scripts acquire their lock before any
# work) and have not mutated anything.
param(
    [switch]$ReleaseFirewallBans
)

$ErrorActionPreference = 'Stop'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       Windows Security Stack - Stop Manager         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$exitCode = 0

# Rollback bookkeeping: any teardown-phase failure must restore the previous (running) state
# instead of leaving a half-stopped stack (tasks disabled + writers/server still alive).
$guardMutex = $null
$dashMutex  = $null
$hasGuard   = $false
$hasDash    = $false
$script:serverStoppedCount = 0
$script:rolledBack         = $false
$script:stopCompleted      = $false

# Writer-process discovery. Disabling a scheduled task stops NEW runs but does not cancel a
# writer that is already running or already blocked on one of the global mutexes. Such a
# process would proceed the instant the mutex is released, so it must be found and drained
# while this script still owns the locks (review risk 4).
function Get-WriterProcesses {
    @(Get-CimInstance Win32_Process -Filter "(Name='pwsh.exe' OR Name='powershell.exe')" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'collect\.ps1|rdp-guard\.ps1' -and $_.ProcessId -ne $PID })
}

function Get-ServerProcesses {
    @(Get-CimInstance Win32_Process -Filter "(Name='python.exe' OR Name='pythonw.exe')" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'sec-dash[\\/]server\.py' -and $_.ProcessId -ne $PID })
}

# Port-closure probe (review risk 4, second defect). MEASURED semantics of
# Get-NetTCPConnection on Windows (see agent-ops/reports for the evidence):
#   * port has no listener   -> raises an ObjectNotFound error record ("No matching
#                               MSFT_NetTCPConnection objects found by CIM query")
#                               when -ErrorAction Stop is in force; a silently empty
#                               result under weaker error preference
#   * query itself failed    -> a different error identity (e.g. InvalidData /
#                               ParameterBindingArgumentTransformationException, or a
#                               CIM server failure). That is NOT evidence of closure.
# The distinction below is by error identity, not by message text, and is exercised
# by agent-ops/verification/phase4_stopstack_verify.ps1 against the real cmdlet.
function Wait-PortClosed {
    param(
        [int]$Port,
        [int]$Attempts = 10,
        [int]$DelayMs = 500,
        [scriptblock]$Query
    )
    $closed   = $false
    $probeErr = $null
    $used     = 0
    for ($i = 0; $i -lt $Attempts; $i++) {
        $used = $i + 1
        try {
            $conn = @(& $Query)
            if ($conn.Count -eq 0) { $closed = $true; break }
        } catch {
            if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
                # No listener exists - this is the closed condition, not a failure.
                $closed = $true
                break
            }
            $probeErr = $_.Exception.Message
            break
        }
        Start-Sleep -Milliseconds $DelayMs
    }
    [pscustomobject]@{ Port = $Port; Closed = $closed; Error = $probeErr; Attempts = $used }
}

# Classify the `New-Object System.Threading.Mutex` failure: "object exists but this token
# lacks access" walks the exception chain for an UnauthorizedAccessException or the Win32
# ERROR_ACCESS_DENIED code (the same 0x80070005 HResult arrives either way). Anything else
# is a genuine failure and must abort the teardown, not be waited out.
function Test-MutexAccessDenied {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($null -ne $e) {
        if ($e -is [System.UnauthorizedAccessException]) { return $true }
        # ERROR_ACCESS_DENIED. .HResult is a negative Int32; compare against the signed
        # literal (-2147024891 = 0x80070005) because PowerShell's [uint32] cast of a
        # negative Int32 THROWS, and the hex literal parses as a positive Int64.
        if ($e.HResult -eq -2147024891) { return $true }
        $e = $e.InnerException
    }
    return $false
}

# Acquire a named mutex within a budget, surviving SYSTEM-created DACLs. See header.
# Returns: Acquired, Mutex (handle only when Acquired), Waited seconds, Attempts, DeniedOpens, Reason.
function Invoke-MutexAcquire {
    param(
        [string]$Name,
        [int]$BudgetSeconds,
        [int]$SliceSeconds = 5
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $attempts = 0
    $deniedOpens = 0
    $announced = $false
    while ($sw.Elapsed.TotalSeconds -lt $BudgetSeconds) {
        $attempts++
        $m = $null
        try {
            $m = New-Object System.Threading.Mutex($false, $Name)
        } catch {
            if (Test-MutexAccessDenied $_) {
                $deniedOpens++
                if (-not $announced) {
                    Write-Host "      [WAIT] $Name exists with a DACL this token cannot open (in-flight writer); polling for quiescence..." -ForegroundColor Gray
                    $announced = $true
                }
                Start-Sleep -Milliseconds 1500
                continue
            }
            return [pscustomobject]@{
                Acquired = $false; Mutex = $null; Reason = "open failed: $($_.Exception.Message)"
                Waited = [math]::Round($sw.Elapsed.TotalSeconds, 1); Attempts = $attempts; DeniedOpens = $deniedOpens
            }
        }
        while ($sw.Elapsed.TotalSeconds -lt $BudgetSeconds) {
            $remaining = $BudgetSeconds - $sw.Elapsed.TotalSeconds
            $slice = [TimeSpan]::FromSeconds([math]::Max(1, [math]::Min($SliceSeconds, [math]::Ceiling($remaining))))
            try { $got = $m.WaitOne($slice) } catch [System.Threading.AbandonedMutexException] { $got = $true }
            if ($got) {
                return [pscustomobject]@{
                    Acquired = $true; Mutex = $m; Reason = $null
                    Waited = [math]::Round($sw.Elapsed.TotalSeconds, 1); Attempts = $attempts; DeniedOpens = $deniedOpens
                }
            }
        }
        $m.Dispose()   # budget ran out with this handle open but still held
    }
    return [pscustomobject]@{
        Acquired = $false; Mutex = $null
        Reason = "timeout after ${BudgetSeconds}s (attempts=$attempts, denied-opens=$deniedOpens)"
        Waited = [math]::Round($sw.Elapsed.TotalSeconds, 1); Attempts = $attempts; DeniedOpens = $deniedOpens
    }
}

# Restore the running stack after an aborted teardown. Best effort, idempotent.
# The firewall rule is never touched here (fail-closed throughout).
function Invoke-Rollback {
    param([string]$Reason)
    if ($script:rolledBack) { return $true }
    $script:rolledBack = $true
    Write-Host ""
    Write-Host "-------------------- ROLLBACK ($Reason) -------------------" -ForegroundColor Yellow
    $ok = $true
    foreach ($tName in @('RDP-Guard (anti-spray)', 'sec-dash (security dashboard)')) {
        try {
            Enable-ScheduledTask -TaskName $tName -ErrorAction Stop | Out-Null
            Write-Host "  [OK] Re-enabled scheduled task '$tName'." -ForegroundColor Green
        } catch {
            $ok = $false
            Write-Host "  [CRITICAL] Could not re-enable task '$tName': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    if ($script:serverStoppedCount -gt 0) {
        try {
            Start-ScheduledTask -TaskName 'sec-dash (security dashboard)' -ErrorAction Stop | Out-Null
            $healthy = $false
            for ($i = 0; $i -lt 20; $i++) {
                try {
                    $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8099/healthz' -TimeoutSec 3 -ErrorAction Stop
                    if ($h.ok) { $healthy = $true; break }
                } catch {}
                Start-Sleep -Seconds 1
            }
            if ($healthy) {
                Write-Host "  [OK] sec-dash server restarted via its scheduled task (/healthz ok)." -ForegroundColor Green
            } else {
                $ok = $false
                Write-Host "  [CRITICAL] sec-dash server did not return healthy within 20s." -ForegroundColor Red
            }
        } catch {
            $ok = $false
            Write-Host "  [CRITICAL] Could not restart the sec-dash scheduled task: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "  Firewall rule untouched by rollback (fail-closed throughout)." -ForegroundColor Gray
    Write-Host "-----------------------------------------------------------" -ForegroundColor Yellow
    if (-not $ok) { Write-Host "  [CRITICAL] Rollback incomplete - stack may be mixed. Manual attention required." -ForegroundColor Red }
    return $ok
}

# Abort the teardown: roll the stack back to running, then exit non-zero.
function Abort-Stop {
    param([int]$Code, [string]$Reason)
    Write-Host "      [ERROR] $Reason - aborting stop to restore the running stack." -ForegroundColor Red
    $ok = Invoke-Rollback -Reason "aborted: $Reason"
    if ($ok) { exit $Code } else { exit 4 }
}

# 1. Disable scheduled tasks first so no new runs are triggered
Write-Host "[1/3] Disabling scheduled tasks..." -ForegroundColor Yellow
foreach ($tName in @('RDP-Guard (anti-spray)', 'sec-dash (security dashboard)')) {
    try {
        Disable-ScheduledTask -TaskName $tName -ErrorAction Stop | Out-Null
        Write-Host "      [OK] Disabled scheduled task '$tName'." -ForegroundColor Green
    } catch {
        Abort-Stop -Code 5 -Reason "could not disable task '$tName': $($_.Exception.Message)"
    }
}

# 2. Freeze the collector spawner, then acquire both writer locks (Global\RdpGuardEnforcement
#    and Global\SecDashCollector) before mutating firewall or stopping anything further.
#    The acquire polls out in-flight SYSTEM writers instead of crashing (see header).
Write-Host "[2/3] Quiescing writers (Global\RdpGuardEnforcement + Global\SecDashCollector)..." -ForegroundColor Yellow
try {
    Write-Host "      Stopping sec-dash python/pythonw server processes (collector spawner)..." -ForegroundColor Gray
    $killedServers = 0
    $serverGone = $false
    for ($i = 0; $i -lt 10; $i++) {
        $remS = @(Get-ServerProcesses)
        if ($remS.Count -eq 0) { $serverGone = $true; break }
        foreach ($p in $remS) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        $killedServers += $remS.Count
        Start-Sleep -Milliseconds 500
    }
    if (-not $serverGone) {
        Abort-Stop -Code 5 -Reason "sec-dash server processes still present after kill attempts"
    }
    if ($killedServers -gt 0) {
        $script:serverStoppedCount = $killedServers
        Write-Host ("      [OK] sec-dash server stopped ({0} process(es)); collector spawner frozen." -f $killedServers) -ForegroundColor Green
    } else {
        Write-Host "      [OK] No sec-dash server processes were running (spawner already frozen)." -ForegroundColor Green
    }

    $guardRes = Invoke-MutexAcquire -Name 'Global\RdpGuardEnforcement' -BudgetSeconds 120
    if (-not $guardRes.Acquired) {
        Abort-Stop -Code 2 -Reason "could not acquire Global\RdpGuardEnforcement ($($guardRes.Reason))"
    }
    $guardMutex = $guardRes.Mutex
    $hasGuard = $true
    Write-Host ("      [OK] RDP-Guard writer quiescent (acquired in {0}s, open-denials={1})." -f $guardRes.Waited, $guardRes.DeniedOpens) -ForegroundColor Green

    $dashRes = Invoke-MutexAcquire -Name 'Global\SecDashCollector' -BudgetSeconds 60
    if (-not $dashRes.Acquired) {
        Abort-Stop -Code 3 -Reason "could not acquire Global\SecDashCollector ($($dashRes.Reason))"
    }
    $dashMutex = $dashRes.Mutex
    $hasDash = $true
    Write-Host ("      [OK] sec-dash collector writer quiescent (acquired in {0}s, open-denials={1})." -f $dashRes.Waited, $dashRes.DeniedOpens) -ForegroundColor Green

    if ($ReleaseFirewallBans) {
        Write-Host "      Removing AUTO-BAN-SPRAY firewall rule (-ReleaseFirewallBans specified)..." -ForegroundColor Yellow
        $rules = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY' -ErrorAction SilentlyContinue)
        foreach ($r in $rules) {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
        }
        Write-Host "      [OK] Firewall rule removed (bans released)." -ForegroundColor Yellow
    } else {
        Write-Host "      Keeping AUTO-BAN-SPRAY firewall rule active (fail-closed; pass -ReleaseFirewallBans to remove)." -ForegroundColor Green
    }

    # Drain writer processes found WHILE the locks are held. Holding Global\RdpGuardEnforcement
    # and Global\SecDashCollector is what makes the quiescence lasting rather than momentary:
    # anything killed here is blocked on acquisition and has not mutated anything (review risk 4).
    Write-Host "      Draining in-flight/waiting writer processes (collect.ps1, rdp-guard.ps1)..." -ForegroundColor Gray
    $writersGone = $false
    for ($i = 0; $i -lt 20; $i++) {
        $remW = @(Get-WriterProcesses)
        if ($remW.Count -eq 0) { $writersGone = $true; break }
        foreach ($p in $remW) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
    }
    if ($writersGone) {
        Write-Host "      [OK] No writer processes remain (locks still held by this script)." -ForegroundColor Green
    } else {
        Abort-Stop -Code 5 -Reason "writer processes still present while locks are held"
    }

    $probe = Wait-PortClosed -Port 8099 -Query { Get-NetTCPConnection -LocalPort 8099 -State Listen -ErrorAction Stop }
    if ($null -ne $probe.Error) {
        Write-Host "      [ERROR] Listener query FAILED - port 8099 closure could not be verified: $($probe.Error)" -ForegroundColor Red
        $exitCode = 1
    } elseif ($probe.Closed) {
        Write-Host "      [OK] Port 8099 verified closed." -ForegroundColor Green
    } else {
        Abort-Stop -Code 5 -Reason "port 8099 is still in Listen state after stopping server processes"
    }

    $script:stopCompleted = $true
} finally {
    if ($hasDash)  { try { $dashMutex.ReleaseMutex()  } catch {} }
    if ($hasGuard) { try { $guardMutex.ReleaseMutex() } catch {} }
    if ($null -ne $dashMutex)  { try { $dashMutex.Dispose() } catch {} }
    if ($null -ne $guardMutex) { try { $guardMutex.Dispose() } catch {} }
    if (-not $script:stopCompleted) { $null = Invoke-Rollback -Reason 'stop did not complete' }
}




Write-Host ""
Write-Host "-------------------- Live Verification --------------------" -ForegroundColor Cyan
$ruleAfter = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY' -ErrorAction SilentlyContinue)
if ($ReleaseFirewallBans) {
    if ($ruleAfter.Count -eq 0) {
        Write-Host "  Firewall Rule : ABSENT (as requested by -ReleaseFirewallBans)" -ForegroundColor Yellow
    } else {
        Write-Host ("  Firewall Rule : ERROR - {0} instance(s) still present!" -f $ruleAfter.Count) -ForegroundColor Red
        $exitCode = 1
    }
} else {
    if ($ruleAfter.Count -eq 1) {
        Write-Host "  Firewall Rule : ENFORCED (1 canonical rule instance)" -ForegroundColor Green
    } else {
        Write-Host ("  Firewall Rule : WARNING - expected 1 rule instance, found {0}" -f $ruleAfter.Count) -ForegroundColor Yellow
    }
}

$taskGuard = (Get-ScheduledTask -TaskName 'RDP-Guard (anti-spray)' -ErrorAction SilentlyContinue).State
$taskDash  = (Get-ScheduledTask -TaskName 'sec-dash (security dashboard)' -ErrorAction SilentlyContinue).State
if ($taskGuard -ne 'Disabled') { $exitCode = 1 }
if ($taskDash -ne 'Disabled')  { $exitCode = 1 }
Write-Host ("  RDP-Guard Task: {0}" -f $taskGuard) -ForegroundColor $(if ($taskGuard -eq 'Disabled') { 'Green' } else { 'Red' })
Write-Host ("  sec-dash Task : {0}" -f $taskDash)  -ForegroundColor $(if ($taskDash -eq 'Disabled')  { 'Green' } else { 'Red' })
Write-Host "-----------------------------------------------------------" -ForegroundColor Cyan

exit $exitCode
