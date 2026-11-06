# RDP-Guard — automatic brute-force / spray blocker for Windows
# Managed by: rdp-guard.ps1   (scheduled task: "RDP-Guard (anti-spray)")
# Runs every minute as SYSTEM. Never bans private/local addresses or anything in allowlist.txt.
#
# POLICY (v2):
#   * failed login with a username that CANNOT log in (nonexistent, blank, OR disabled) -> PERMANENT ban
#   * 8+ failed logins for a REAL account in 15 min, or 12+ in 60 min -> 24h ban, doubling each repeat
#   * every event processed exactly once (incremental checkpoint) - nothing can fall in a blind spot
#   * 5+ SSH password failures in 15 min                            -> 24h ban, doubling on each repeat
#   * 4th offence by the same IP                                    -> PERMANENT ban
#   * anything that logged in successfully in the last hour         -> never banned
#   * private/loopback/CGNAT ranges and allowlist.txt               -> never banned

param(
  [string]$RootPath = 'C:\srv\rdp-guard',
  [hashtable]$TestHook = $null
)

$ErrorActionPreference = 'Stop'

$root          = $RootPath
$stateFile     = Join-Path $root 'bans.json'
$bakFile       = Join-Path $root 'bans.json.bak'
$allowFile     = Join-Path $root 'allowlist.txt'
$forgiveFile   = Join-Path $root 'forgive.txt'
$autoAllowFile = Join-Path $root 'auto-allow.json'
$cpFile        = Join-Path $root 'guard-state.json'
$logFile       = Join-Path $root 'guard.log'

# ---------------- config ----------------
$windowMinutes      = 15
$knownUserThreshold = 8    # real-account failures (typos) in 15 min before a ban
$slowWindowMinutes  = 60   # slow drips are caught here instead
$slowThreshold      = 12   # real-account failures across an hour -> ban
$sshThreshold       = 5
$baseBanHours       = 24   # first-offence temporary ban length (doubles each repeat)
$permaStrikes       = 4    # 4th offence = permanent
$maxBans            = 8000 # safety cap on firewall rule size; oldest bans are evicted to stay under it
$ruleName           = 'AUTO-BAN-SPRAY'
$legacyRuleName     = 'RDP-BruteForce-Block'
$stateVersion       = 2

if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }

function Write-Log([string]$m) {
  $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
  try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
  Write-Host $line
}

function Write-AtomicFile([string]$Path, [string]$BackupPath, [string]$Content) {
  $tmp = "$Path.tmp.$PID"
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($tmp, $Content, $enc)
  $lastErr = $null
  for ($attempt = 0; $attempt -lt 5; $attempt++) {
    try {
      if (Test-Path -LiteralPath $Path) {
        if ($BackupPath) {
          [System.IO.File]::Replace($tmp, $Path, $BackupPath, $true)
        } else {
          $tmpBak = "$Path.prev.$PID"
          [System.IO.File]::Replace($tmp, $Path, $tmpBak, $true)
          if (Test-Path -LiteralPath $tmpBak) { Remove-Item -LiteralPath $tmpBak -Force -ErrorAction SilentlyContinue }
        }
      } else {
        [System.IO.File]::Move($tmp, $Path)
        if ($BackupPath) {
          [System.IO.File]::Copy($Path, $BackupPath, $true)
        }
      }
      return
    } catch {
      $lastErr = $_
      Start-Sleep -Milliseconds (40 * ($attempt + 1))
    }
  }
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  throw $lastErr
}

function ConvertTo-CanonicalIP([string]$rawIp) {
  if ([string]::IsNullOrWhiteSpace($rawIp)) { return $null }
  $s = $rawIp.Trim()
  if ($s -eq '-' -or $s -eq '0.0.0.0' -or $s -eq '::') { return $null }
  if ($s.StartsWith('[') -and $s.EndsWith(']')) { $s = $s.Substring(1, $s.Length - 2) }
  $pct = $s.IndexOf('%')
  if ($pct -gt 0) { $s = $s.Substring(0, $pct) }
  if ($s -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') { $s = $Matches[1] }
  $ipObj = $null
  if (-not [System.Net.IPAddress]::TryParse($s, [ref]$ipObj)) { return $null }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    # Reject octal/short-form IPv4 strings like "10.1" that TryParse accepts
    if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    return $ipObj.ToString()
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($ipObj.IsIPv4MappedToIPv6) {
      return $ipObj.MapToIPv4().ToString()
    }
    return $ipObj.ToString().ToLowerInvariant()
  }
  return $null
}

function Test-ValidIP([string]$ip) {
  return ($null -ne (ConvertTo-CanonicalIP $ip))
}

function Test-ValidIPv4([string]$ip) {
  $c = ConvertTo-CanonicalIP $ip
  return ($null -ne $c -and $c -match '^\d{1,3}(\.\d{1,3}){3}$')
}

function Test-Private([string]$ip) {
  $c = ConvertTo-CanonicalIP $ip
  if ($null -eq $c) { return $true }
  $ipObj = [System.Net.IPAddress]::Parse($c)
  if ([System.Net.IPAddress]::IsLoopback($ipObj)) { return $true }
  $bytes = $ipObj.GetAddressBytes()
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    $b0 = [int]$bytes[0]; $b1 = [int]$bytes[1]
    if ($b0 -eq 0 -or $b0 -eq 10 -or $b0 -eq 127) { return $true }
    if ($b0 -eq 169 -and $b1 -eq 254) { return $true }
    if ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31) { return $true }
    if ($b0 -eq 192 -and $b1 -eq 168) { return $true }
    if ($b0 -eq 100 -and $b1 -ge 64 -and $b1 -le 127) { return $true }
    if ($b0 -ge 224) { return $true } # multicast (224/4) & reserved/broadcast (240/4)
    return $false
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($c -eq '::' -or $c -eq '::1') { return $true }
    $b0 = [int]$bytes[0]; $b1 = [int]$bytes[1]
    if ($b0 -eq 0xff) { return $true }                         # multicast ff00::/8
    if (($b0 -band 0xfe) -eq 0xfc) { return $true }            # unique-local fc00::/7
    if ($b0 -eq 0xfe -and ($b1 -band 0xc0) -eq 0x80) { return $true } # link-local fe80::/10
    return $false
  }
  return $true
}

function Parse-BansJsonText([string]$rawText) {
  if ([string]::IsNullOrWhiteSpace($rawText)) {
    throw "State file is empty or whitespace-only"
  }
  $obj = $rawText | ConvertFrom-Json -ErrorAction Stop
  if ($null -eq $obj -or $obj -is [array] -or $obj -is [string] -or $obj -is [ValueType]) {
    throw "State JSON root must be an object"
  }
  $parsedBans = @{}
  $parsedStrikes = @{}
  $parsedVer = 0

  $hasVerProp = ($null -ne $obj.PSObject.Properties['stateVersion'])
  if ($hasVerProp) {
    $parsedVer = [int]$obj.stateVersion
    if ($null -eq $obj.PSObject.Properties['data'] -or $null -eq $obj.data) {
      throw "State v$parsedVer missing 'data' object"
    }
    if ($null -eq $obj.data.PSObject.Properties['bans'] -or $null -eq $obj.data.bans) {
      throw "State v$parsedVer missing 'data.bans' object"
    }
    $banBlock = $obj.data.bans
    $strikeBlock = $obj.data.strikes
  } else {
    $props = @($obj.PSObject.Properties)
    if ($props.Count -eq 0) {
      throw "Legacy state object has zero properties"
    }
    $banBlock = $obj
    $strikeBlock = $null
  }

  foreach ($p in $banBlock.PSObject.Properties) {
    $canonKey = ConvertTo-CanonicalIP $p.Name
    if ($null -eq $canonKey -or (Test-Private $canonKey)) {
      throw "Invalid or private IP key in bans state: '$($p.Name)'"
    }
    $v = $p.Value
    if ($null -eq $v) {
      throw "Null ban entry for '$canonKey'"
    }
    if ($v -is [string] -or $v -is [datetime]) {
      $parsedBans[$canonKey] = @{
        until    = [datetime]::Parse([string]$v, [System.Globalization.CultureInfo]::InvariantCulture)
        reason   = 'legacy'
        bannedAt = (Get-Date).AddHours(-24)
      }
    } else {
      if ($null -eq $v.PSObject.Properties['reason'] -or [string]::IsNullOrWhiteSpace([string]$v.reason)) {
        throw "Ban entry '$canonKey' missing non-empty 'reason'"
      }
      if ($null -eq $v.PSObject.Properties['bannedAt'] -or [string]::IsNullOrWhiteSpace([string]$v.bannedAt)) {
        throw "Ban entry '$canonKey' missing 'bannedAt'"
      }
      $until = $null
      if ($null -ne $v.PSObject.Properties['until'] -and $null -ne $v.until -and -not [string]::IsNullOrWhiteSpace([string]$v.until)) {
        $until = [datetime]::Parse([string]$v.until, [System.Globalization.CultureInfo]::InvariantCulture)
      }
      $at = [datetime]::Parse([string]$v.bannedAt, [System.Globalization.CultureInfo]::InvariantCulture)
      $parsedBans[$canonKey] = @{
        until    = $until
        reason   = [string]$v.reason
        bannedAt = $at
      }
    }
  }

  if ($null -ne $strikeBlock) {
    foreach ($p in $strikeBlock.PSObject.Properties) {
      $canonKey = ConvertTo-CanonicalIP $p.Name
      if ($null -ne $canonKey -and -not (Test-Private $canonKey)) {
        $strikeVal = [int]$p.Value
        if ($strikeVal -lt 1) { throw "Invalid strike count for '$canonKey': $($p.Value)" }
        $parsedStrikes[$canonKey] = $strikeVal
      }
    }
  }

  return @{
    ver     = $parsedVer
    bans    = $parsedBans
    strikes = $parsedStrikes
  }
}

$mutexName = if ($null -ne $TestHook -and $TestHook.ContainsKey('MutexName')) { [string]$TestHook['MutexName'] } else { 'Global\RdpGuardEnforcement' }
$guardMutex = New-Object System.Threading.Mutex($false, $mutexName)
$hasGuardMutex = $false
try {
  try {
    $hasGuardMutex = $guardMutex.WaitOne([TimeSpan]::FromSeconds(30))
  } catch [System.Threading.AbandonedMutexException] {
    $hasGuardMutex = $true
  }
  if (-not $hasGuardMutex) {
    Write-Log "CRITICAL: timed out waiting 30s for $mutexName mutex - aborting run"
    exit 7
  }

# ---------------- query current firewall enforcement first (fail-closed on query error) ----------------
$oldEnforcedSet    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$legacyEnforcedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$existingPrimaryRules = @()
$existingLegacyRules  = @()
$canonicalRuleId      = '{5be24e42-4d23-451d-98b4-4b0e27195a5e}'

if ($null -ne $TestHook -and $TestHook.ContainsKey('FirewallRules')) {
  if ($TestHook.ContainsKey('SimulateFirewallReadError') -and $TestHook['SimulateFirewallReadError']) {
    Write-Log 'CRITICAL: simulated firewall discovery error - FAIL-CLOSED'
    exit 5
  }
  foreach ($r in $TestHook['FirewallRules']) {
    if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {
      foreach ($a in $r.RemoteAddress) {
        $c = ConvertTo-CanonicalIP ([string]$a)
        if ($null -ne $c -and -not (Test-Private $c)) {
          [void]$oldEnforcedSet.Add($c)
          if ($r.DisplayName -eq $legacyRuleName) { [void]$legacyEnforcedSet.Add($c) }
        }
      }
    }
  }
} else {
  try {
    try {
      $existingPrimaryRules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No MSFT_NetFirewallRule objects found') { throw }
      $existingPrimaryRules = @()
    }
    try {
      $existingLegacyRules = @(Get-NetFirewallRule -DisplayName $legacyRuleName -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No MSFT_NetFirewallRule objects found') { throw }
      $existingLegacyRules = @()
    }
    foreach ($r in $existingPrimaryRules) {
      if ($r.Enabled.ToString() -eq 'True' -and $r.Direction.ToString() -eq 'Inbound' -and $r.Action.ToString() -eq 'Block') {
        $af = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
        if ($null -eq $af) { throw "Get-NetFirewallAddressFilter returned null for $($r.Name)" }
        foreach ($a in @($af.RemoteAddress)) {
          $c = ConvertTo-CanonicalIP ([string]$a)
          if ($null -ne $c -and -not (Test-Private $c)) { [void]$oldEnforcedSet.Add($c) }
        }
      }
    }
    foreach ($r in $existingLegacyRules) {
      if ($r.Enabled.ToString() -eq 'True' -and $r.Direction.ToString() -eq 'Inbound' -and $r.Action.ToString() -eq 'Block') {
        $af = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
        if ($null -eq $af) { throw "Get-NetFirewallAddressFilter returned null for legacy $($r.Name)" }
        foreach ($a in @($af.RemoteAddress)) {
          $c = ConvertTo-CanonicalIP ([string]$a)
          if ($null -ne $c -and -not (Test-Private $c)) {
            [void]$oldEnforcedSet.Add($c)
            [void]$legacyEnforcedSet.Add($c)
          }
        }
      }
    }
  } catch {
    Write-Log "CRITICAL: firewall enforcement discovery failed ($($_.Exception.Message)) - FAIL-CLOSED"
    exit 5
  }
}

# ---------------- load state (with .bak recovery & fail-closed gate) ----------------
$bans    = @{}   # ip -> @{ until = <datetime | $null = permanent>; reason = <string>; bannedAt = <datetime> }
$strikes = @{}   # ip -> offence count (kept even after a ban expires)
$ver     = $stateVersion
$stateOk = $true

if (Test-Path -LiteralPath $stateFile) {
  try {
    $raw = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 -ErrorAction Stop
    $parsed = Parse-BansJsonText $raw
    $ver     = $parsed.ver
    $bans    = $parsed.bans
    $strikes = $parsed.strikes
  } catch {
    $primaryErr = $_.Exception.Message
    $corruptCopy = "$stateFile.corrupt-" + (Get-Date -Format 'yyyyMMdd-HHmmss')
    Copy-Item -LiteralPath $stateFile -Destination $corruptCopy -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $bakFile) {
      try {
        $bakRaw = Get-Content -LiteralPath $bakFile -Raw -Encoding UTF8 -ErrorAction Stop
        $parsedBak = Parse-BansJsonText $bakRaw
        $ver     = $parsedBak.ver
        $bans    = $parsedBak.bans
        $strikes = $parsedBak.strikes
        Write-Log "WARNING: bans.json was corrupt ($primaryErr); recovered $($bans.Count) ban(s) from bans.json.bak"
      } catch {
        $stateOk = $false
        Write-Log "CRITICAL: bans.json ($primaryErr) AND bans.json.bak ($($_.Exception.Message)) unreadable - backup: $corruptCopy - FAIL-CLOSED, aborting run without touching firewall or state"
      }
    } else {
      $stateOk = $false
      Write-Log "CRITICAL: bans.json could not be read ($primaryErr) and no bans.json.bak exists - backup: $corruptCopy - FAIL-CLOSED, aborting run without touching firewall or state"
    }
  }
} elseif (Test-Path -LiteralPath $bakFile) {
  try {
    $bakRaw = Get-Content -LiteralPath $bakFile -Raw -Encoding UTF8 -ErrorAction Stop
    $parsedBak = Parse-BansJsonText $bakRaw
    $ver     = $parsedBak.ver
    $bans    = $parsedBak.bans
    $strikes = $parsedBak.strikes
    Write-Log "WARNING: bans.json missing; recovered $($bans.Count) ban(s) from bans.json.bak"
  } catch {
    $stateOk = $false
    Write-Log "CRITICAL: bans.json missing and bans.json.bak unreadable ($($_.Exception.Message)) - FAIL-CLOSED"
  }
} elseif ($oldEnforcedSet.Count -gt 0) {
  $stateOk = $false
  Write-Log "CRITICAL: bans.json missing while firewall currently enforces $($oldEnforcedSet.Count) IP(s) - FAIL-CLOSED"
}

if (-not $stateOk) {
  exit 2
}

# Preserve union of any currently enforced firewall IPs (primary or legacy) not yet recorded in bans.json
$disableImport = ($null -ne $TestHook -and $TestHook.ContainsKey('DisableEnforcedImport') -and [bool]$TestHook['DisableEnforcedImport'])
if (-not $disableImport) {
  foreach ($enfIp in $oldEnforcedSet) {
    if (-not $bans.ContainsKey($enfIp)) {
      $srcRule = if ($legacyEnforcedSet.Contains($enfIp)) { 'legacy RDP-BruteForce-Block rule' } else { 'active AUTO-BAN-SPRAY firewall rule' }
      $bans[$enfIp] = @{
        until    = $null
        reason   = "preserved from $srcRule"
        bannedAt = (Get-Date).AddHours(-24)
      }
      if (-not $strikes.ContainsKey($enfIp)) { $strikes[$enfIp] = 1 }
      Write-Log "imported enforced IP from $srcRule into state: $enfIp"
    }
  }
} else {
  foreach ($legIp in $legacyEnforcedSet) {
    if (-not $bans.ContainsKey($legIp)) {
      $bans[$legIp] = @{
        until    = $null
        reason   = 'preserved from legacy RDP-BruteForce-Block rule'
        bannedAt = (Get-Date).AddHours(-24)
      }
      if (-not $strikes.ContainsKey($legIp)) { $strikes[$legIp] = 1 }
    }
  }
}

# one-time migration: anything already banned in the log for a nonexistent username becomes permanent
if ($ver -lt 2) {
  $converted = 0
  if (Test-Path -LiteralPath $logFile) {
    foreach ($l in (Get-Content -LiteralPath $logFile -Tail 5000 -ErrorAction SilentlyContinue)) {
      if ($l -match 'BAN ([0-9a-fA-F:.]+) .*nonexistent username') {
        $ip = ConvertTo-CanonicalIP $Matches[1]
        if ($null -ne $ip -and $bans.ContainsKey($ip)) {
          $bans[$ip].until = $null
          $bans[$ip].reason = 'nonexistent username (migrated)'
          $converted++
        }
      }
    }
  }
  Write-Log "state migrated to v2; converted $converted existing ban(s) to PERMANENT"
}

# ---------------- load allowlist.txt & forgive.txt (fail-closed on read error) ----------------
$forgive = @{}
if (Test-Path -LiteralPath $forgiveFile) {
  try {
    $fLines = @(Get-Content -LiteralPath $forgiveFile -Encoding UTF8 -ErrorAction Stop)
    foreach ($l in $fLines) {
      $t = $l.Split('#')[0].Trim()
      if (-not [string]::IsNullOrWhiteSpace($t)) {
        $c = ConvertTo-CanonicalIP $t
        if ($null -ne $c) { $forgive[$c] = $true }
      }
    }
  } catch {
    Write-Log "CRITICAL: failed to read forgive.txt ($($_.Exception.Message)) - aborting run"
    exit 4
  }
}

$allow = @{}
if (Test-Path -LiteralPath $allowFile) {
  try {
    $aLines = @(Get-Content -LiteralPath $allowFile -Encoding UTF8 -ErrorAction Stop)
    $nonCommentCount = 0
    foreach ($l in $aLines) {
      $t = $l.Split('#')[0].Trim()
      if (-not [string]::IsNullOrWhiteSpace($t)) {
        $nonCommentCount++
        $c = ConvertTo-CanonicalIP $t
        if ($null -ne $c) { $allow[$c] = $true }
      }
    }
    if ($nonCommentCount -gt 0 -and $allow.Count -eq 0) {
      Write-Log "CRITICAL: allowlist.txt has $nonCommentCount non-comment line(s) but 0 valid IPs - aborting run"
      exit 4
    }
  } catch {
    Write-Log "CRITICAL: failed to read allowlist.txt ($($_.Exception.Message)) - aborting run"
    exit 4
  }
}

$now = if ($null -ne $TestHook -and $TestHook.ContainsKey('Now')) { [datetime]$TestHook['Now'] } else { Get-Date }
$authorizedRemovalsSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

# actively unban anything present in allowlist.txt or forgive.txt (RUNBOOK §2 compliance)
$unbannedAllow = 0
foreach ($aIp in @($allow.Keys)) {
  [void]$authorizedRemovalsSet.Add($aIp)
  if ($bans.ContainsKey($aIp)) {
    $bans.Remove($aIp)
    $unbannedAllow++
    Write-Log "UNBAN $aIp (present in allowlist.txt)"
  }
}
$unbannedForgive = 0
foreach ($fIp in @($forgive.Keys)) {
  [void]$authorizedRemovalsSet.Add($fIp)
  if ($bans.ContainsKey($fIp)) {
    $bans.Remove($fIp)
    $unbannedForgive++
    Write-Log "UNBAN $fIp (present in forgive.txt)"
  }
}

# expire temporary bans (keep strike history)
$expired = @($bans.Keys | Where-Object { $null -ne $bans[$_].until -and $bans[$_].until -lt $now })
foreach ($k in $expired) {
  [void]$authorizedRemovalsSet.Add($k)
  $bans.Remove($k)
}
if ($expired.Count -gt 0) { Write-Log "expired $($expired.Count) temporary ban(s)" }

# Only ENABLED accounts are 'real'. If Get-LocalUser fails or returns 0 accounts, fail-safe by
# disabling the instant bad-username permaban heuristic ($knownUsersOk = $false) so a transient
# SAM/WMI hiccup never permabans a real operator account on a single typo.
$knownUsers = @()
$knownUsersOk = $false
try {
  if ($null -ne $TestHook -and $TestHook.ContainsKey('LocalUsers')) {
    $knownUsers = @($TestHook['LocalUsers'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
  } else {
    $knownUsers = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name | ForEach-Object { $_.ToLowerInvariant() })
  }
  if ($knownUsers.Count -gt 0) {
    $knownUsersOk = $true
  } else {
    Write-Log "WARNING: Get-LocalUser returned 0 enabled accounts - disabling bad-username instant-permaban heuristic for this run"
  }
} catch {
  Write-Log "WARNING: Get-LocalUser failed ($($_.Exception.Message)) - disabling bad-username instant-permaban heuristic for this run"
}

# ---------------------------------------------------------------------------
# REVIEW FIX (astra + grok): decisions are made ONLY from real rolling windows.
# ---------------------------------------------------------------------------
$win24 = $now.AddHours(-24)
$win60 = $now.AddMinutes(-$slowWindowMinutes)
$win15 = $now.AddMinutes(-$windowMinutes)

$badUser = @{}; $sshBadUser = @{}; $fail15 = @{}; $fail60 = @{}; $ssh15 = @{}
$suspects = @{}; $scanned = 0

# ---------------- RDP / Windows logon failures (true 24h window) ----------------
$ev = @()
if ($null -ne $TestHook -and $TestHook.ContainsKey('RdpEvents')) {
  $ev = @($TestHook['RdpEvents'])
} else {
  try {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$win24} -MaxEvents 60000 -ErrorAction Stop)
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') {
      Write-Log "WARNING: Security 4625 query error: $($_.Exception.Message)"
    }
  }
}

foreach ($e in $ev) {
  try {
    if ($null -ne $e.PSObject.Properties['IpAddress']) {
      $rawIp = [string]$e.IpAddress
      $u     = [string]$e.TargetUserName
      $lt    = [string]$e.LogonType
      $tCreated = [datetime]$e.TimeCreated
    } else {
      $x = [xml]$e.ToXml(); $d = @{}
      foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
      $rawIp = $d['IpAddress']; $u = $d['TargetUserName']; $lt = $d['LogonType']
      $tCreated = $e.TimeCreated
    }
    $ip = ConvertTo-CanonicalIP $rawIp
    if ($null -eq $ip -or (Test-Private $ip)) { continue }
    if ($allow.ContainsKey($ip)) { continue }
    # a blank username can never log in here (no such account can exist), so it is
    # exactly as hostile as an invented name -> instant permaban (ADR-0005)
    $cleanUser = ([string]$u -replace '^.*\\','').ToLowerInvariant()
    $badName   = [string]::IsNullOrWhiteSpace($u) -or ($knownUsersOk -and ($knownUsers -notcontains $cleanUser))
    $isNetwork = ($lt -eq '3' -or $lt -eq '8' -or $lt -eq '10')
    # a public IP trying a username that cannot log in here is hostile on ANY logon type
    if (-not ($isNetwork -or $badName)) { continue }
    $scanned++
    $suspects[$ip] = $true
    if ($badName) { $badUser[$ip] = $true }
    if ($isNetwork) {
      # VERIFIER FIX (agy/gemini): bound fail60 to the real 60-minute window.
      if ($tCreated -gt $win60) { $fail60[$ip] = 1 + [int]$fail60[$ip] }
      if ($tCreated -gt $win15) { $fail15[$ip] = 1 + [int]$fail15[$ip] }
    }
  } catch {}
}

# ---------------- SSH (true 24h window, anchored terminal peer regex + IPv4/IPv6) ----------------
$oev = @()
if ($null -ne $TestHook -and $TestHook.ContainsKey('SshEvents')) {
  $oev = @($TestHook['SshEvents'])
} else {
  try {
    $oev = @(Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$win24} -MaxEvents 30000 -ErrorAction Stop)
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') {
      Write-Log "WARNING: OpenSSH/Operational query error: $($_.Exception.Message)"
    }
  }
}

$sshAcceptedIps = @{}
foreach ($e in $oev) {
  try {
    $m = ([string]$e.Message) -replace '^(?i)sshd(?:\[\d+\])?:\s*', ''
    $tCreated = [datetime]$e.TimeCreated
    if ($m -match '^Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+.+?\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+\d+(?:\s+ssh2(?::.*)?)?\s*$') {
      $accIp = ConvertTo-CanonicalIP $Matches['ip']
      if ($null -ne $accIp -and $tCreated -gt $now.AddHours(-1)) {
        $sshAcceptedIps[$accIp] = $now.ToString('o')
      }
      continue
    }
    # REVIEW FIX (astra): anchor strictly to the terminal peer field at the end of the OpenSSH log line
    # and support both IPv4 and IPv6 so a crafted username containing "from 203.0.113.7 port 9"
    # before an IPv6 or IPv4 peer can NEVER frame a third-party address.
    $peerIpRaw = $null
    $isInvalidUser = $false
    $isFailedPw    = $false
    if ($m -match '^Invalid user\s+.*\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+\d+(?:\s+ssh2)?\s*$') {
      $peerIpRaw = $Matches['ip']
      $isInvalidUser = $true
    } elseif ($m -match '^Failed password for (?<inv>invalid user\s+)?.*\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+\d+(?:\s+ssh2)?\s*$') {
      $peerIpRaw = $Matches['ip']
      $isFailedPw = $true
      if ($Matches['inv']) { $isInvalidUser = $true }
    } elseif ($m -match '^Connection closed by (?<kind>invalid|authenticating) user\s+.*\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+\d+\s+\[preauth\]\s*$') {
      $peerIpRaw = $Matches['ip']
      if ($Matches['kind'] -eq 'invalid') { $isInvalidUser = $true }
    } else {
      continue
    }

    $ip = ConvertTo-CanonicalIP $peerIpRaw
    if ($null -eq $ip -or (Test-Private $ip)) { continue }
    if ($allow.ContainsKey($ip)) { continue }
    $suspects[$ip] = $true
    if ($isInvalidUser) { $sshBadUser[$ip] = 1 + [int]$sshBadUser[$ip] }
    if ($isFailedPw -and $tCreated -gt $win15) { $ssh15[$ip] = 1 + [int]$ssh15[$ip] }
  } catch {}
}
Write-Log "window scan: $($ev.Count) RDP + $($oev.Count) SSH events in 24h; thresholds use real 15/60min windows"

# ---------------- never ban anyone who logged in successfully in the last hour ----------------
$succ = @{}
# Load cached recent successful logins from auto-allow.json first so a transient 4624 query error fails closed for operator protection
if (Test-Path -LiteralPath $autoAllowFile) {
  try {
    $aaObj = Get-Content -LiteralPath $autoAllowFile -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($null -ne $aaObj) {
      foreach ($p in $aaObj.PSObject.Properties) {
        $cIp = ConvertTo-CanonicalIP $p.Name
        $ts  = [datetime]::Parse([string]$p.Value, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($null -ne $cIp -and $ts -gt $now.AddHours(-1)) {
          $succ[$cIp] = $ts.ToString('o')
        }
      }
    }
  } catch {}
}
foreach ($k in $sshAcceptedIps.Keys) { $succ[$k] = $sshAcceptedIps[$k] }

$sev = @()
if ($null -ne $TestHook -and $TestHook.ContainsKey('SuccessEvents')) {
  $sev = @($TestHook['SuccessEvents'])
} else {
  try {
    $sev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$now.AddHours(-1)} -MaxEvents 8000 -ErrorAction Stop)
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') {
      Write-Log "WARNING: Security 4624 query error ($($_.Exception.Message)); retaining $($succ.Count) cached auto-allow IP(s)"
    }
  }
}
foreach ($e in $sev) {
  try {
    if ($null -ne $e.PSObject.Properties['IpAddress']) {
      $cIp = ConvertTo-CanonicalIP ([string]$e.IpAddress)
    } else {
      $x = [xml]$e.ToXml(); $d = @{}
      foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
      $cIp = ConvertTo-CanonicalIP ([string]$d['IpAddress'])
    }
    if ($null -ne $cIp -and -not (Test-Private $cIp)) {
      $succ[$cIp] = $now.ToString('o')
    }
  } catch {}
}
try {
  Write-AtomicFile -Path $autoAllowFile -BackupPath $null -Content ($succ | ConvertTo-Json -Depth 3)
} catch {}

# ---------------- decide ----------------
$newBans = 0
Write-Log "candidates: $($suspects.Count) IP(s) seen in the last 24h"
foreach ($ip in $suspects.Keys) {
  if ($bans.ContainsKey($ip))    { continue }   # already banned
  if ($allow.ContainsKey($ip))   { continue }
  if ($forgive.ContainsKey($ip)) { continue }   # forgiven by the operator
  if ($succ.ContainsKey($ip))    { Write-Log "skip $ip (successful logon within the last hour)"; continue }

  $n15        = 0; if ($fail15.ContainsKey($ip)) { $n15 = $fail15[$ip] }
  $n60        = 0; if ($fail60.ContainsKey($ip)) { $n60 = $fail60[$ip] }
  $s          = 0; if ($ssh15.ContainsKey($ip))  { $s = $ssh15[$ip] }
  $sb         = 0; if ($sshBadUser.ContainsKey($ip)) { $sb = $sshBadUser[$ip] }
  $reason     = @()
  $permanent  = $false

  if ($badUser.ContainsKey($ip)) {
    $permanent = $true
    $reason += "RDP: tried a username that cannot log in here"
  }
  if ($sb -gt 0) {
    $permanent = $true
    $reason += "SSH: invalid/nonexistent username x$sb"
  }
  if (-not $permanent -and $n15 -ge $knownUserThreshold) {
    $reason += "$n15 failed logons for a real account in $windowMinutes min"
  }
  if (-not $permanent -and $n60 -ge $slowThreshold) {
    $reason += "$n60 failed logons across $slowWindowMinutes min (slow drip)"
  }
  if ($s -ge $sshThreshold) { $reason += "$s SSH password failures in $windowMinutes min" }
  if ($reason.Count -eq 0) { continue }

  # make room if we're at the cap: drop oldest temporary bans first, then oldest permanent ones
  if ($bans.Count -ge $maxBans) {
    # REVIEW FIX (astra): temporary bans are evicted first, permanent last.
    $sorted = $bans.Keys | ForEach-Object { [pscustomobject]@{ ip = $_; temp = ($null -ne $bans[$_].until); at = $bans[$_].bannedAt } } |
      Sort-Object @{ Expression = { if ($_.temp) { 0 } else { 1 } } }, at
    $need = ($bans.Count - $maxBans) + 1
    for ($i = 0; $i -lt $need -and $i -lt $sorted.Count; $i++) {
      $victim = $sorted[$i].ip
      Write-Log "evicting oldest ban to stay under cap: $victim"
      [void]$authorizedRemovalsSet.Add($victim)
      $bans.Remove($victim)
    }
  }

  $strikeCount = 1 + ($(if ($strikes.ContainsKey($ip)) { $strikes[$ip] } else { 0 }))
  $strikes[$ip] = $strikeCount

  if ($strikeCount -ge $permaStrikes) {
    $permanent = $true
    $reason += "offence #$strikeCount"
  }

  if ($permanent) {
    $bans[$ip] = @{ until = $null; reason = ($reason -join '; '); bannedAt = $now }
    Write-Log ("PERMABAN {0} - {1}" -f $ip, ($reason -join '; '))
  } else {
    $hours = $baseBanHours * [math]::Pow(2, $strikeCount - 1)
    if ($hours -gt 168) { $hours = 168 }   # cap at 7 days
    $bans[$ip] = @{ until = $now.AddHours($hours); reason = ($reason -join '; '); bannedAt = $now }
    Write-Log ("BAN {0} for {1}h (offence #{2}) - {3}" -f $ip, $hours, $strikeCount, ($reason -join '; '))
  }
  $newBans++
}

# ---------------- verify set-preservation shrinkage invariant ----------------
$list = @($bans.Keys | ForEach-Object { ConvertTo-CanonicalIP $_ } | Where-Object { $null -ne $_ -and -not (Test-Private $_) } | Sort-Object -Unique)
$proposedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($ip in $list) { [void]$proposedSet.Add($ip) }

$unauthorizedDrops = @($oldEnforcedSet | Where-Object { -not $proposedSet.Contains($_) -and -not $authorizedRemovalsSet.Contains($_) })
if ($unauthorizedDrops.Count -gt 0) {
  $sample = ($unauthorizedDrops | Select-Object -First 5) -join ', '
  Write-Log "CRITICAL: refusing to drop $($unauthorizedDrops.Count) enforced IP(s) not in expired/allow/forgive ($sample) - FAIL-CLOSED"
  exit 3
}

# ---------------- save state BEFORE mutating firewall (so firewall never out-runs bans.json) ----------------
$permCount = @($bans.Keys | Where-Object { $null -eq $bans[$_].until }).Count
$bansOut   = [ordered]@{}
foreach ($k in ($bans.Keys | Sort-Object)) {
  $u = $null
  if ($null -ne $bans[$k].until) { $u = $bans[$k].until.ToString('yyyy-MM-dd HH:mm:ss') }
  $bansOut[$k] = [ordered]@{
    until    = $u
    reason   = $bans[$k].reason
    bannedAt = $bans[$k].bannedAt.ToString('yyyy-MM-dd HH:mm:ss')
  }
}

try {
  $stateJson = ([ordered]@{
    stateVersion = $stateVersion
    data         = [ordered]@{
      bans    = $bansOut
      strikes = $strikes
    }
  } | ConvertTo-Json -Depth 6)
  Write-AtomicFile -Path $stateFile -BackupPath $bakFile -Content $stateJson

  $cpJson = ([ordered]@{
    lastProcessed = $now.ToString('o')
    decisionsFrom = 'rolling windows (checkpoint is observability only)'
  } | ConvertTo-Json -Depth 4)
  Write-AtomicFile -Path $cpFile -BackupPath $null -Content $cpJson
} catch {
  Write-Log "CRITICAL: state save failed before firewall update ($($_.Exception.Message)) - aborting without touching firewall"
  exit 6
}

# ---------------- apply to firewall (union verified across all 7 filters before duplicate removal) ----------------
$firewallOk = $true
if ($null -ne $TestHook -and $TestHook.ContainsKey('FirewallCallback')) {
  try {
    $TestHook['FirewallCalled'] = $true
    $TestHook['FirewallList']   = @($list)
    & $TestHook['FirewallCallback'] $list
  } catch {
    if (Test-Path -LiteralPath $bakFile) { Copy-Item -LiteralPath $bakFile -Destination $stateFile -Force -ErrorAction SilentlyContinue }
    Write-Log "CRITICAL: firewall callback FAILED ($($_.Exception.Message)) - rolled back state"
    exit 5
  }
} else {
  try {
    $existingSorted = @(
      $existingPrimaryRules |
        Sort-Object @{ Expression = { if ($_.Name -eq $canonicalRuleId) { 0 } else { 1 } } }, Name
    )
    if ($list.Count -eq 0) {
      if ($existingSorted.Count -gt 0) {
        $existingSorted | Remove-NetFirewallRule -ErrorAction Stop
        Write-Log 'ban list legitimately empty (all entries expired/allowed/forgiven) -> removed firewall rule'
      }
      if ($existingLegacyRules.Count -gt 0) {
        $existingLegacyRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
      }
    } else {
      $primaryRule = $null
      if ($existingSorted.Count -gt 0) {
        $primaryRule = $existingSorted[0]
        $curAf    = $primaryRule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $curPf    = $primaryRule | Get-NetFirewallPortFilter -ErrorAction Stop
        $curAppf  = $primaryRule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $curSvcf  = $primaryRule | Get-NetFirewallServiceFilter -ErrorAction Stop
        $curIf    = $primaryRule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $curIfA   = $primaryRule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $curSecf  = $primaryRule | Get-NetFirewallSecurityFilter -ErrorAction Stop
        $cur = @($curAf.RemoteAddress | ForEach-Object { ConvertTo-CanonicalIP ([string]$_) } | Where-Object { $_ } | Sort-Object -Unique)
        $needsUpdate = (
          $existingSorted.Count -gt 1 -or
          $existingLegacyRules.Count -gt 0 -or
          $primaryRule.Enabled.ToString() -ne 'True' -or
          $primaryRule.Direction.ToString() -ne 'Inbound' -or
          $primaryRule.Action.ToString() -ne 'Block' -or
          $primaryRule.Profile.ToString() -ne 'Any' -or
          [string]$curPf.Protocol -ne 'Any' -or
          [string]$curPf.LocalPort -ne 'Any' -or
          [string]$curPf.RemotePort -ne 'Any' -or
          [string]$curAf.LocalAddress -ne 'Any' -or
          [string]$curAppf.Program -ne 'Any' -or
          (-not [string]::IsNullOrEmpty([string]$curAppf.Package) -and [string]$curAppf.Package -ne 'Any') -or
          [string]$curSvcf.Service -ne 'Any' -or
          [string]$curIf.InterfaceType -ne 'Any' -or
          [string]$curIfA.InterfaceAlias -ne 'Any' -or
          [string]$curSecf.Authentication -ne 'NotRequired' -or
          [string]$curSecf.Encryption -ne 'NotRequired' -or
          [string]$curSecf.OverrideBlockRules.ToString() -ne 'False' -or
          (@(Compare-Object $cur $list -SyncWindow 0).Count -gt 0)
        )
        if ($needsUpdate) {
          Set-NetFirewallRule -Name $primaryRule.Name `
            -Enabled True -Direction Inbound -Action Block -Profile Any `
            -Protocol Any -LocalPort Any -RemotePort Any -LocalAddress Any `
            -Program Any -Service Any -InterfaceType Any -InterfaceAlias Any `
            -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules:$false `
            -RemoteAddress $list -ErrorAction Stop
          Write-Log "firewall rule $($primaryRule.Name) updated -> $($list.Count) IP(s) banned"
        }
      } else {
        $primaryRule = New-NetFirewallRule -Name $canonicalRuleId -DisplayName $ruleName `
          -Enabled True -Direction Inbound -Action Block -Profile Any `
          -Protocol Any -LocalPort Any -RemotePort Any -LocalAddress Any `
          -Program Any -Service Any -InterfaceType Any -InterfaceAlias Any `
          -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules:$false `
          -RemoteAddress $list `
          -Description 'Auto-bans brute-force/spray sources. Managed by RDP-Guard' -ErrorAction Stop
        Write-Log "firewall rule created -> $($list.Count) IP(s) banned"
      }

      # Read-back verification of effective primary rule across all 7 filters before removing any duplicate or legacy rules
      $verifyRule = Get-NetFirewallRule -Name $primaryRule.Name -ErrorAction Stop
      $verifyPort = $verifyRule | Get-NetFirewallPortFilter -ErrorAction Stop
      $verifyAf   = $verifyRule | Get-NetFirewallAddressFilter -ErrorAction Stop
      $verifyApp  = $verifyRule | Get-NetFirewallApplicationFilter -ErrorAction Stop
      $verifySvc  = $verifyRule | Get-NetFirewallServiceFilter -ErrorAction Stop
      $verifyIf   = $verifyRule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
      $verifyIfA  = $verifyRule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
      $verifySec  = $verifyRule | Get-NetFirewallSecurityFilter -ErrorAction Stop
      $verifyAddr = @($verifyAf.RemoteAddress | ForEach-Object { ConvertTo-CanonicalIP ([string]$_) } | Where-Object { $_ } | Sort-Object -Unique)
      if (
        $verifyRule.Enabled.ToString() -ne 'True' -or
        $verifyRule.Direction.ToString() -ne 'Inbound' -or
        $verifyRule.Action.ToString() -ne 'Block' -or
        $verifyRule.Profile.ToString() -ne 'Any' -or
        [string]$verifyPort.Protocol -ne 'Any' -or
        [string]$verifyPort.LocalPort -ne 'Any' -or
        [string]$verifyPort.RemotePort -ne 'Any' -or
        [string]$verifyAf.LocalAddress -ne 'Any' -or
        [string]$verifyApp.Program -ne 'Any' -or
        (-not [string]::IsNullOrEmpty([string]$verifyApp.Package) -and [string]$verifyApp.Package -ne 'Any') -or
        [string]$verifySvc.Service -ne 'Any' -or
        [string]$verifyIf.InterfaceType -ne 'Any' -or
        [string]$verifyIfA.InterfaceAlias -ne 'Any' -or
        [string]$verifySec.Authentication -ne 'NotRequired' -or
        [string]$verifySec.Encryption -ne 'NotRequired' -or
        [string]$verifySec.OverrideBlockRules.ToString() -ne 'False' -or
        (@(Compare-Object $verifyAddr $list -SyncWindow 0).Count -ne 0)
      ) {
        throw "Firewall read-back verification failed for $($primaryRule.Name)"
      }

      # Now that the primary rule is verified enforcing the complete union, remove duplicate AUTO-BAN-SPRAY and legacy RDP-BruteForce-Block rules
      $dupRules = @($existingSorted | Select-Object -Skip 1)
      foreach ($dup in $dupRules) {
        Remove-NetFirewallRule -Name $dup.Name -ErrorAction Stop
        Write-Log "removed duplicate $ruleName rule instance $($dup.Name)"
      }
      foreach ($leg in $existingLegacyRules) {
        Remove-NetFirewallRule -Name $leg.Name -ErrorAction Stop
        Write-Log "removed superseded $legacyRuleName rule instance $($leg.Name)"
      }
    }
  } catch {
    $firewallOk = $false
    if (Test-Path -LiteralPath $bakFile) {
      Copy-Item -LiteralPath $bakFile -Destination $stateFile -Force -ErrorAction SilentlyContinue
    }
    Write-Log "CRITICAL: firewall update/verification FAILED ($($_.Exception.Message)) - rolled back bans.json from .bak"
    exit 5
  }
}

Write-Log ("done: new={0} total={1} permanent={2} temp={3} scanned24h={4} candidates={5} fail15={6} fail60={7} ssh15={8}" -f `
  $newBans, $bans.Count, $permCount, ($bans.Count - $permCount), $scanned, $suspects.Count, $fail15.Count, $fail60.Count, $ssh15.Count)
exit 0
} finally {
  if ($hasGuardMutex) {
    try { $guardMutex.ReleaseMutex() } catch {}
  }
  $guardMutex.Dispose()
}
