# sec-dash collector - builds data.json for the live security dashboard
# Two-tier storage:
#   stats.json           incremental daily aggregates + per-channel watermarks + pendingPreauth
#   hourly.json          rolling 14-day per-IP per-hour vectors (UTC hour keys, uncapped totals)
#   recent.json          rolling 24h list of hostile events (up to 25,000, with truncation metadata)
#   commit-manifest.json transactional generation marker for multi-file crash recovery
#   history.jsonl        time-series samples
#   geo.json             cached geolocation (country/city/coords/ASN)

param(
  [switch]$SelfTest,       # run fixture checks on the shame/SSH/IP classifiers and exit (no file writes)
  [switch]$ShameBackfill,  # one-shot: seed shame.json from the retained event logs and exit
  [string]$Root,           # override the data root (testing only; server.py never passes it)
  [hashtable]$TestHook = $null
)

$ErrorActionPreference = 'Stop'
$Inv = [System.Globalization.CultureInfo]::InvariantCulture

$root         = if ($Root) { $Root } elseif ($PSScriptRoot) { $PSScriptRoot } else { 'C:\srv\sec-dash' }
$dataFile     = Join-Path $root 'data.json'
$statsFile    = Join-Path $root 'stats.json'
$recentFile   = Join-Path $root 'recent.json'
$histFile     = Join-Path $root 'history.jsonl'
$geoFile      = Join-Path $root 'geo.json'
$hourlyFile   = Join-Path $root 'hourly.json'
$shameFile    = Join-Path $root 'shame.json'
$manifestFile = Join-Path $root 'commit-manifest.json'
$bansFile     = if ($null -ne $TestHook -and $TestHook.ContainsKey('BansFile')) { [string]$TestHook['BansFile'] } else { (Join-Path (Split-Path -Parent $root) 'rdp-guard\bans.json') }
$guardLog     = if ($null -ne $TestHook -and $TestHook.ContainsKey('GuardLog')) { [string]$TestHook['GuardLog'] } else { (Join-Path (Split-Path -Parent $root) 'rdp-guard\guard.log') }
$fwLog        = if ($null -ne $TestHook -and $TestHook.ContainsKey('FwLog'))    { [string]$TestHook['FwLog'] }    else { 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' }
$hostIp = ''
try {
  $hostIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet*','Wi-Fi*','Ethernet' -ErrorAction SilentlyContinue | Where-Object { # sec-dash collector - builds data.json for the live security dashboard
# Two-tier storage:
#   stats.json           incremental daily aggregates + per-channel watermarks + pendingPreauth
#   hourly.json          rolling 14-day per-IP per-hour vectors (UTC hour keys, uncapped totals)
#   recent.json          rolling 24h list of hostile events (up to 25,000, with truncation metadata)
#   commit-manifest.json transactional generation marker for multi-file crash recovery
#   history.jsonl        time-series samples
#   geo.json             cached geolocation (country/city/coords/ASN)

param(
  [switch]$SelfTest,       # run fixture checks on the shame/SSH/IP classifiers and exit (no file writes)
  [switch]$ShameBackfill,  # one-shot: seed shame.json from the retained event logs and exit
  [string]$Root,           # override the data root (testing only; server.py never passes it)
  [hashtable]$TestHook = $null
)

$ErrorActionPreference = 'Stop'
$Inv = [System.Globalization.CultureInfo]::InvariantCulture

$root         = if ($Root) { $Root } elseif ($PSScriptRoot) { $PSScriptRoot } else { 'C:\srv\sec-dash' }
$dataFile     = Join-Path $root 'data.json'
$statsFile    = Join-Path $root 'stats.json'
$recentFile   = Join-Path $root 'recent.json'
$histFile     = Join-Path $root 'history.jsonl'
$geoFile      = Join-Path $root 'geo.json'
$hourlyFile   = Join-Path $root 'hourly.json'
$shameFile    = Join-Path $root 'shame.json'
$manifestFile = Join-Path $root 'commit-manifest.json'
$bansFile     = if ($null -ne $TestHook -and $TestHook.ContainsKey('BansFile')) { [string]$TestHook['BansFile'] } else { (Join-Path (Split-Path -Parent $root) 'rdp-guard\bans.json') }
$guardLog     = if ($null -ne $TestHook -and $TestHook.ContainsKey('GuardLog')) { [string]$TestHook['GuardLog'] } else { (Join-Path (Split-Path -Parent $root) 'rdp-guard\guard.log') }
$fwLog        = if ($null -ne $TestHook -and $TestHook.ContainsKey('FwLog'))    { [string]$TestHook['FwLog'] }    else { 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' }
$hostIp = ""
try {
  $hostIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet*','Wi-Fi*','Ethernet' -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(169\.254|127\.)' } | Select-Object -First 1 -ExpandProperty IPAddress)
} catch {}
if (-not $hostIp) { $hostIp = '127.0.0.1' }

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
    if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    return $ipObj.ToString()
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($ipObj.IsIPv4MappedToIPv6) { return $ipObj.MapToIPv4().ToString() }
    return $ipObj.ToString().ToLowerInvariant()
  }
  return $null
}

function Is-ValidIPv4([string]$ip) {
  $c = ConvertTo-CanonicalIP $ip
  return ($null -ne $c -and $c -match '^\d{1,3}(\.\d{1,3}){3}$')
}

function Is-ValidIP([string]$ip) {
  return ($null -ne (ConvertTo-CanonicalIP $ip))
}

function Is-Private([string]$ip) {
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
    if ($b0 -ge 224) { return $true }
    return $false
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($c -eq '::' -or $c -eq '::1') { return $true }
    $b0 = [int]$bytes[0]; $b1 = [int]$bytes[1]
    if ($b0 -eq 0xff) { return $true }
    if (($b0 -band 0xfe) -eq 0xfc) { return $true }
    if ($b0 -eq 0xfe -and ($b1 -band 0xc0) -eq 0x80) { return $true }
    return $false
  }
  return $true
}

function Write-JsonAtomic([string]$Path, [string]$JsonContent, [bool]$KeepBak = $true) {
  $tmp = "$Path.tmp.$PID"
  $bak = if ($KeepBak) { "$Path.bak" } else { $null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($tmp, $JsonContent, $enc)
  $lastErr = $null
  for ($attempt = 0; $attempt -lt 5; $attempt++) {
    try {
      if (Test-Path -LiteralPath $Path) {
        if ($bak) {
          [System.IO.File]::Replace($tmp, $Path, $bak, $true)
        } else {
          $tmpBak = "$Path.prev.$PID"
          [System.IO.File]::Replace($tmp, $Path, $tmpBak, $true)
          if (Test-Path -LiteralPath $tmpBak) { Remove-Item -LiteralPath $tmpBak -Force -ErrorAction SilentlyContinue }
        }
      } else {
        [System.IO.File]::Move($tmp, $Path)
        if ($bak) {
          [System.IO.File]::Copy($Path, $bak, $true)
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

function Read-JsonSafe([string]$Path, [scriptblock]$Validator = $null, [bool]$AllowBakFallback = $true) {
  $bak = "$Path.bak"
  $primaryExisted = Test-Path -LiteralPath $Path
  $bakExisted     = $AllowBakFallback -and (Test-Path -LiteralPath $bak)
  if (-not $primaryExisted -and -not $bakExisted) { return $null }

  if ($primaryExisted) {
    try {
      $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
            if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim([char]0, " ", "`t", "`r", "`n") -eq '') { return $null }
      if ($raw.Trim() -eq '[]') {
        $obj = @()
      } else {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $obj) { throw "File '$Path' parsed to null" }
      }
      if ($null -ne $Validator) { & $Validator $obj }
      return ,$obj
    } catch {
      $primaryErr = $_.Exception.Message
      if ($bakExisted) {
        $rawBak = [System.IO.File]::ReadAllText($bak, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($rawBak)) { throw "Primary '$Path' ($primaryErr) and backup '$bak' (empty) both unreadable" }
        if ($rawBak.Trim() -eq '[]') {
          $objBak = @()
        } else {
          $objBak = $rawBak | ConvertFrom-Json -ErrorAction Stop
          if ($null -eq $objBak) { throw "Primary '$Path' ($primaryErr) and backup '$bak' (null) both unreadable" }
        }
        if ($null -ne $Validator) { & $Validator $objBak }
        return ,$objBak
      }
      throw "Critical store '$Path' is corrupt ($primaryErr) and backup fallback is disabled or unavailable"
    }
  } else {
    $rawBak = [System.IO.File]::ReadAllText($bak, [System.Text.Encoding]::UTF8)
    if ($rawBak.Trim() -eq '[]') {
      $objBak = @()
    } else {
      $objBak = $rawBak | ConvertFrom-Json -ErrorAction Stop
      if ($null -eq $objBak) { throw "Backup '$bak' parsed to null" }
    }
    if ($null -ne $Validator) { & $Validator $objBak }
    return ,$objBak
  }
}

function Parse-TimestampDto($val) {
  if ($null -eq $val) { return $null }
  if ($val -is [DateTimeOffset]) { return $val }
  if ($val -is [datetime]) {
    if ($val.Kind -eq [System.DateTimeKind]::Unspecified) {
      return New-Object System.DateTimeOffset([datetime]::SpecifyKind($val, [System.DateTimeKind]::Local))
    }
    return New-Object System.DateTimeOffset($val)
  }
  $s = [string]$val
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  if ($s -match '^\d{4}-\d{2}-\d{2}T\d{2}$') {
    return [DateTimeOffset]::ParseExact($s, 'yyyy-MM-ddTHH', $Inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
  }
  return [DateTimeOffset]::Parse($s, $Inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
}

function ConvertTo-UtcHourKey($val) {
  $dto = Parse-TimestampDto $val
  if ($null -eq $dto) { return $null }
  return $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
}

function ConvertTo-LocalDayKey($val) {
  $dto = Parse-TimestampDto $val
  if ($null -eq $dto) { return $null }
  return $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
}

# ===========================================================================
# Hall of Shame & SSH Canonical Parser (PERMIT-0011 / ADR-0009 / ADR-0013)
# ===========================================================================
function Test-CannotLogIn([string]$name, [string[]]$knownEnabled) {
  if ([string]::IsNullOrWhiteSpace($name)) { return $true }
  return -not ($knownEnabled -contains ($name -replace '^.*\\', '').ToLowerInvariant())
}

function Sanitize-Name([string]$name) {
  if ($null -eq $name) { return '(blank)' }
  $s = ($name -replace '^.*\\', '').Trim()
  $s = $s -replace '[\x00-\x1F\x7F]', ''
  if ([string]::IsNullOrWhiteSpace($s)) { return '(blank)' }
  if ($s.Length -gt 64) { $s = $s.Substring(0, 64) }
  return $s
}

function Parse-SshAuthLine([string]$m) {
  if ([string]::IsNullOrWhiteSpace($m)) { return $null }
  # Strip optional leading "sshd..." prefix if present in synthetic tests
  $clean = $m -replace '^sshd(?:\[\d+\])?:\s*', ''
  # Anchor strictly on the terminal "from <ip> port <port>" at the end of the line
  if ($clean -match '^(?i)Failed password for invalid user (?<u_inv>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)(?:\s+ssh2)?\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'failed_pw_invalid'; user = $Matches['u_inv']; ip = $cIp; port = $Matches['port']; invalid = $true }
  }
  if ($clean -match '^(?i)Failed password for (?<u_val>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)(?:\s+ssh2)?\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'failed_pw_valid'; user = $Matches['u_val']; ip = $cIp; port = $Matches['port']; invalid = $false }
  }
  if ($clean -match '^(?i)Invalid user (?<u_inv>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'invalid_banner'; user = $Matches['u_inv']; ip = $cIp; port = $Matches['port']; invalid = $true }
  }
  if ($clean -match '^(?i)Connection closed by (?<ckind>invalid|authenticating) user (?<u_cc>.*)\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)\s+\[preauth\]\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'preauth_close'; user = $Matches['u_cc']; ip = $cIp; port = $Matches['port']; invalid = ($Matches['ckind'] -ieq 'invalid') }
  }
  return $null
}

function Get-SshInvalidName([string]$m) {
  $p = Parse-SshAuthLine $m
  if ($null -eq $p) { return $null }
  if ($p.kind -eq 'invalid_banner' -or $p.kind -eq 'failed_pw_invalid') {
    return $p.user
  }
  return $null
}

function Get-SshPortKey([string]$m, [datetime]$when) {
  # Anchor on the terminal "port <n>" so a username containing "port 9" cannot spoof the port key
  $pm = [regex]::Match($m, '\s+port\s+(\d+)(?:\s+ssh2)?(?:\s+\[preauth\])?\s*$')
  if (-not $pm.Success) { return $null }
  return "$($when.ToString('yyyyMMddHH'))|$($pm.Groups[1].Value)"
}

function Get-KnownEnabledNames {
  if ($null -ne $TestHook -and $TestHook.ContainsKey('LocalUsers')) {
    return @($TestHook['LocalUsers'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
  }
  try { return @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled } | ForEach-Object { $_.Name.ToLowerInvariant() }) } catch { return @() }
}

function Get-OperatorIps {
  $h = @{}
  $files = if ($null -ne $TestHook -and $TestHook.ContainsKey('OperatorFiles')) {
    @($TestHook['OperatorFiles'])
  } else {
    @('C:\srv\rdp-guard\allowlist.txt', 'C:\srv\rdp-guard\forgive.txt')
  }
  foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
      Get-Content -LiteralPath $f -ErrorAction SilentlyContinue | ForEach-Object {
        $l = ($_ -split '#')[0].Trim()
        if ($l) {
          $c = ConvertTo-CanonicalIP $l
          if ($null -ne $c) { $h[$c] = $true } else { $h[$l] = $true }
        }
      }
    }
  }
  return $h
}

function Add-ShameHit($map, [string]$ip, [string]$vec, [datetime]$when, [string]$display) {
  if (-not $map.ContainsKey($ip)) { $map[$ip] = @{ n = 0; rdp = 0; ssh = 0; users = @{}; first = $when; last = $when } }
  $e = $map[$ip]
  $e.n++
  if ($vec -eq 'RDP') { $e.rdp++ } else { $e.ssh++ }
  if ($when -lt $e.first) { $e.first = $when }
  if ($when -gt $e.last) { $e.last = $when }
  $k = $display.ToLowerInvariant()
  if (-not $e.users.ContainsKey($k)) { $e.users[$k] = @{ name = $display; n = 0 } }
  $e.users[$k].n++
}

function Iso-Local($t) {
  if (-not $t) { return $null }
  $dto = Parse-TimestampDto $t
  if ($null -eq $dto) { return [string]$t }
  return $dto.ToLocalTime().ToString('o', $Inv)
}

# ---------------- -SelfTest: fixture checks on the real artifact, no file writes ----------------
if ($SelfTest) {
  $fail = 0
  $known = @('operator')
  $cases = @(
    @{ n = 'operator';                           want = $false },
    @{ n = 'operator';                           want = $false },
    @{ n = 'SERVER01\\operator';           want = $false },
    @{ n = 'Administrator';                   want = $true  },
    @{ n = 'Guest';                           want = $true  },
    @{ n = 'x3908';                           want = $true  },
    @{ n = 'k8s';                             want = $true  },
    @{ n = '';                                want = $true  },
    @{ n = '   ';                             want = $true  },
    @{ n = 'SERVER01\Administrator';   want = $true  },
    @{ n = 'operator\\';                         want = $true  },
    @{ n = ' Operator';                          want = $true  }
  )
  foreach ($c in $cases) {
    $got = Test-CannotLogIn $c.n $known
    if ($got -ne $c.want) { $fail++; "FAIL Test-CannotLogIn('$($c.n)') got=$got want=$($c.want)" }
    else                  { "PASS Test-CannotLogIn('$($c.n)') -> $got" }
  }
  $san = @(
    @{ in = 'SERVER01\k8s'; want = 'k8s' },
    @{ in = "bad`tname";           want = 'badname' },
    @{ in = ('x' + [char]0 + 'y'); want = 'xy' },
    @{ in = '';                    want = '(blank)' },
    @{ in = '   ';                 want = '(blank)' },
    @{ in = ('a' * 100);           want = ('a' * 64) },
    @{ in = '  spaced  ';          want = 'spaced' }
  )
  foreach ($c in $san) {
    $got = Sanitize-Name $c.in
    if ($got -ne $c.want) { $fail++; "FAIL Sanitize-Name('$($c.in)') got='$got' want='$($c.want)'" }
    else                  { "PASS Sanitize-Name('$($c.in)') -> '$got'" }
  }
  $m = @{}
  Add-ShameHit $m '1.2.3.4' 'RDP' ([datetime]'2026-10-01T00:00:01') 'Administrator'
  Add-ShameHit $m '1.2.3.4' 'RDP' ([datetime]'2026-10-01T00:00:02') 'ADMINISTRATOR'
  Add-ShameHit $m '1.2.3.4' 'SSH' ([datetime]'2026-10-01T00:00:03') 'administrator'
  Add-ShameHit $m '5.6.7.8' 'SSH' ([datetime]'2026-10-01T00:00:04') 'k8s'
  $m1 = $m['1.2.3.4']; $m2 = $m['5.6.7.8']
  foreach ($x in @(
    @{ got = $m.Count;                     want = 2; label = 'distinct IPs' },
    @{ got = $m1.n;                        want = 3; label = 'ip1 total' },
    @{ got = $m1.rdp;                      want = 2; label = 'ip1 rdp' },
    @{ got = $m1.ssh;                      want = 1; label = 'ip1 ssh' },
    @{ got = @($m1.users.Keys).Count;      want = 1; label = 'ip1 case-variant names merged' },
    @{ got = $m1.users['administrator'].n; want = 3; label = 'ip1 name count' },
    @{ got = $m1.first.ToString('s');      want = '2026-10-01T00:00:01'; label = 'ip1 first' },
    @{ got = $m1.last.ToString('s');       want = '2026-10-01T00:00:03'; label = 'ip1 last' },
    @{ got = $m2.rdp;                      want = 0; label = 'ip2 rdp' }
  )) {
    if ($x.got -ne $x.want) { $fail++; "FAIL merge: $($x.label) got=$($x.got) want=$($x.want)" }
    else                    { "PASS merge: $($x.label) -> $($x.got)" }
  }
  $sshCases = @(
    @{ m = 'sshd: Invalid user emo from 1.2.3.4 port 45888'; want = 'emo' },
    @{ m = 'sshd: Failed password for invalid user root from 1.2.3.4 port 22 ssh2'; want = 'root' },
    @{ m = 'sshd: Invalid user  from 1.2.3.4 port 12345'; want = '' },
    @{ m = 'sshd: Invalid user bait from 203.0.113.7 port 9 from 2001:db8::1234 port 45678'; want = 'bait from 203.0.113.7 port 9' },
    @{ m = 'sshd: Connection closed by invalid user emo 1.2.3.4 port 45888 [preauth]'; want = $null },
    @{ m = 'sshd: Disconnecting invalid user test1 1.2.3.4 port 22: Too many authentication failures [preauth]'; want = $null },
    @{ m = 'sshd: Accepted password for operator from 1.2.3.4 port 22 ssh2'; want = $null }
  )
  foreach ($c in $sshCases) {
    $got = Get-SshInvalidName $c.m
    if ($got -ne $c.want) { $fail++; "FAIL Get-SshInvalidName('$($c.m)') got='$got' want='$($c.want)'" }
    else                  { "PASS Get-SshInvalidName('$($c.m)') -> '$got'" }
  }
  $injParsed = Parse-SshAuthLine 'Invalid user bait from 203.0.113.7 port 9 from 2001:db8::1234 port 45678'
  if ($null -eq $injParsed -or $injParsed.ip -ne '2001:db8::1234' -or $injParsed.port -ne '45678') {
    $fail++; "FAIL Parse-SshAuthLine username injection selected ip=$($injParsed.ip) port=$($injParsed.port)"
  } else {
    "PASS Parse-SshAuthLine username injection -> ip=2001:db8::1234 port=45678"
  }
  $t1 = [datetime]'2026-10-01T10:00:00'
  $t2 = [datetime]'2026-10-01T10:59:59'
  $t3 = [datetime]'2026-10-01T11:00:00'
  $a  = Get-SshPortKey 'Invalid user e from 1.2.3.4 port 45888' $t1
  $b  = Get-SshPortKey 'Failed password for invalid user e from 1.2.3.4 port 45888' $t2
  $c1 = Get-SshPortKey 'x from 1.2.3.4 port 22' $t1
  $c2 = Get-SshPortKey 'x from 1.2.3.4 port 23' $t1
  $c3 = Get-SshPortKey 'x from 1.2.3.4 port 22' $t3
  if ($a -ne $b)   { $fail++; "FAIL key: same attempt pair should share a key ($a vs $b)" } else { "PASS key: attempt pair shares key -> $a" }
  if ($c1 -eq $c2) { $fail++; 'FAIL key: different ports should differ' } else { 'PASS key: different ports differ' }
  if ($c1 -eq $c3) { $fail++; 'FAIL key: different hours should differ' } else { 'PASS key: different hours differ' }
  if ($null -ne (Get-SshPortKey 'nothing here' $t1)) { $fail++; 'FAIL key: no port should be null' } else { 'PASS key: no port -> null' }
  "SELFTEST: $(if ($fail -eq 0) { 'PASS' } else { "FAIL ($fail)" })"
  exit $(if ($fail -eq 0) { 0 } else { 1 })
}

if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }

# ===========================================================================
# Universal Writer Mutex (Global\SecDashCollector) across ALL writer modes
# ===========================================================================
$mutexName = if ($null -ne $TestHook -and $TestHook.ContainsKey('MutexName')) { [string]$TestHook['MutexName'] } else { 'Global\SecDashCollector' }
$mutexTimeoutMs = if ($null -ne $TestHook -and $TestHook.ContainsKey('MutexTimeoutMs')) { [int]$TestHook['MutexTimeoutMs'] } else { 15000 }
$mutex = New-Object System.Threading.Mutex($false, $mutexName)
$hasHandle = $false
try {
  try {
    $hasHandle = $mutex.WaitOne($mutexTimeoutMs, $false)
  } catch [System.Threading.AbandonedMutexException] {
    $hasHandle = $true
  }
  if (-not $hasHandle) {
    Write-Host "SecDashCollector mutex busy after ${mutexTimeoutMs}ms - exiting"
    exit $(if ($ShameBackfill) { 2 } else { 0 })
  }

  function Query-LogAfterRecordId([string]$LogName, $AfterRecordId, $EventId, [datetime]$FallbackStartTime) {
    $cleared = $false
    $effectiveAfter = if ($null -ne $AfterRecordId) { [int64]$AfterRecordId } else { $null }
    if ($null -ne $effectiveAfter) {
      try {
        $latest = @(Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop)
        if ($latest.Count -gt 0 -and $null -ne $latest[0].PSObject.Properties['RecordId']) {
          if ([int64]$latest[0].RecordId -lt $effectiveAfter) {
            $cleared = $true
            $effectiveAfter = $null
          }
        }
      } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
          throw "$LogName latest-event probe failed: $($_.Exception.Message)"
        }
        $cleared = $true
        $effectiveAfter = $null
      }
    }
    $events = @()
    try {
      if ($null -ne $effectiveAfter) {
        $xpath = if ($null -ne $EventId) {
          "*[System[(EventID=$([int]$EventId)) and (EventRecordID > $effectiveAfter)]]"
        } else {
          "*[System[(EventRecordID > $effectiveAfter)]]"
        }
        $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop)
      } else {
        $fh = @{ LogName = $LogName; StartTime = $FallbackStartTime }
        if ($null -ne $EventId) { $fh['Id'] = [int]$EventId }
        $events = @(Get-WinEvent -FilterHashtable $fh -ErrorAction Stop)
      }
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "$LogName query failed: $($_.Exception.Message)"
      }
    }
    return @{ events = $events; cleared = $cleared; effectiveAfter = $effectiveAfter }
  }

  function Import-ShameWindow($map, [datetime]$from, [datetime]$to, [string[]]$knownEnabled, $operatorIps, [hashtable]$shameCursor = $null, [bool]$FlushAllPending = $false) {
    if ($null -eq $shameCursor) {
      $shameCursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    }
    if ($null -ne $shameCursor.lastRecordIdSec) {
      $qSec = Query-LogAfterRecordId -LogName 'Security' -AfterRecordId $shameCursor.lastRecordIdSec -EventId 4625 -FallbackStartTime $from
      if ($qSec.cleared) { $shameCursor.lastRecordIdSec = $null }
      foreach ($e in ($qSec.events | Sort-Object RecordId)) {
        try {
          $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
          if ($null -ne $shameCursor.lastRecordIdSec -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSec) { continue }
          $x = [xml]$e.ToXml(); $d = @{}
          foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
          $ip = ConvertTo-CanonicalIP ([string]$d['IpAddress'])
          if ($null -eq $ip -or (Is-Private $ip)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          if ($operatorIps.ContainsKey($ip)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          if (-not (Test-CannotLogIn ([string]$d['TargetUserName']) $knownEnabled)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          Add-ShameHit $map $ip 'RDP' $e.TimeCreated (Sanitize-Name ([string]$d['TargetUserName']))
          if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
        } catch {}
      }
    } else {
      $t = $from
      while ($t -lt $to) {
        $end = $t.AddHours(2); if ($end -gt $to) { $end = $to }
        $ev = @()
        try {
          $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$t; EndTime=$end.AddTicks(-1)} -ErrorAction Stop)
        } catch {
          if ($_.Exception.Message -notmatch 'No events were found') { throw }
        }
        foreach ($e in ($ev | Sort-Object RecordId)) {
          try {
            $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
            if ($null -ne $shameCursor.lastRecordIdSec -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSec) { continue }
            $x = [xml]$e.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $ip = ConvertTo-CanonicalIP ([string]$d['IpAddress'])
            if ($null -eq $ip -or (Is-Private $ip)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            if ($operatorIps.ContainsKey($ip)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            if (-not (Test-CannotLogIn ([string]$d['TargetUserName']) $knownEnabled)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            Add-ShameHit $map $ip 'RDP' $e.TimeCreated (Sanitize-Name ([string]$d['TargetUserName']))
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
          } catch {}
        }
        $t = $end
      }
    }
    $oev = @()
    if ($null -ne $shameCursor.lastRecordIdSsh) {
      $qSsh = Query-LogAfterRecordId -LogName 'OpenSSH/Operational' -AfterRecordId $shameCursor.lastRecordIdSsh -EventId $null -FallbackStartTime $from
      if ($qSsh.cleared) { $shameCursor.lastRecordIdSsh = $null }
      $oev = $qSsh.events
    } else {
      try {
        $oev = @(Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$from; EndTime=$to.AddTicks(-1)} -ErrorAction Stop)
      } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { throw }
      }
    }
    $pendingShame = if ($null -ne $shameCursor.pendingShame) { $shameCursor.pendingShame } else { @{} }
    foreach ($e in ($oev | Sort-Object RecordId)) {
      try {
        $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
        if ($null -ne $shameCursor.lastRecordIdSsh -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSsh) { continue }
        $p = Parse-SshAuthLine $e.Message
        if ($null -eq $p) {
          if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
          continue
        }
        $ip = $p.ip
        if ((Is-Private $ip) -or $operatorIps.ContainsKey($ip)) {
          if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
          continue
        }
        $pKey = "$ip|$($p.port)"
        if ($p.kind -eq 'invalid_banner') {
          if ($pendingShame.ContainsKey($pKey)) {
            $oldP = $pendingShame[$pKey]
            if (Test-CannotLogIn $oldP.user $knownEnabled) {
              Add-ShameHit $map $ip 'SSH' (Parse-TimestampDto $oldP.when).LocalDateTime (Sanitize-Name $oldP.user)
            }
          }
          $pendingShame[$pKey] = @{ user = $p.user; when = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('o', $Inv) }
        } elseif ($p.kind -eq 'failed_pw_invalid' -or $p.kind -eq 'failed_pw_valid') {
          if ($pendingShame.ContainsKey($pKey)) { [void]$pendingShame.Remove($pKey) }
          if ($p.invalid -or (Test-CannotLogIn $p.user $knownEnabled)) {
            Add-ShameHit $map $ip 'SSH' $e.TimeCreated (Sanitize-Name $p.user)
          }
        } elseif ($p.kind -eq 'preauth_close') {
          if ($pendingShame.ContainsKey($pKey)) {
            $pend = $pendingShame[$pKey]
            [void]$pendingShame.Remove($pKey)
            if (Test-CannotLogIn $pend.user $knownEnabled) {
              Add-ShameHit $map $ip 'SSH' (Parse-TimestampDto $pend.when).LocalDateTime (Sanitize-Name $pend.user)
            }
          }
        }
        if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
      } catch {}
    }
    $toDto = Parse-TimestampDto $to
    foreach ($pk in @($pendingShame.Keys)) {
      $pend = $pendingShame[$pk]
      $pendDto = Parse-TimestampDto $pend.when
      if ($FlushAllPending -or (($toDto - $pendDto).TotalSeconds -ge 120)) {
        [void]$pendingShame.Remove($pk)
        $ip = ($pk -split '\|')[0]
        if (Test-CannotLogIn $pend.user $knownEnabled) {
          Add-ShameHit $map $ip 'SSH' $pendDto.LocalDateTime (Sanitize-Name $pend.user)
        }
      }
    }
    $shameCursor.pendingShame = $pendingShame
  }

  function Initialize-ShameMap {
    $map = @{}; $since = $null; $coverage = $null
    $cursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    $sj = $null
    try {
      $sj = Read-JsonSafe -Path $shameFile
    } catch {
      return @{ ok = $false; error = "$($_.Exception.Message)"; map = @{}; since = $null; coverage = $null; cursor = $cursor }
    }
    if ($null -eq $sj) { return @{ ok = $true; map = $map; since = $since; coverage = $coverage; cursor = $cursor } }
    try {
      if ($sj.lastProcessed) { $since = (Parse-TimestampDto $sj.lastProcessed).LocalDateTime }
      if ($null -ne $sj.PSObject.Properties['lastRecordIdSec'] -and $null -ne $sj.lastRecordIdSec) { $cursor.lastRecordIdSec = [int64]$sj.lastRecordIdSec }
      if ($null -ne $sj.PSObject.Properties['lastRecordIdSsh'] -and $null -ne $sj.lastRecordIdSsh) { $cursor.lastRecordIdSsh = [int64]$sj.lastRecordIdSsh }
      if ($null -ne $sj.PSObject.Properties['pendingShame'] -and $null -ne $sj.pendingShame) {
        foreach ($pp in $sj.pendingShame.PSObject.Properties) {
          $cursor.pendingShame[$pp.Name] = @{ user = [string]$pp.Value.user; when = [string]$pp.Value.when }
        }
      }
      $coverage = $sj.coverage
      foreach ($p in $sj.ips.PSObject.Properties) {
        $users = @{}
        foreach ($q in $p.Value.users.PSObject.Properties) {
          if ([string]::IsNullOrEmpty([string]$q.Name)) { throw "empty username key for $($p.Name)" }
          $users[$q.Name.ToLowerInvariant()] = @{ name = [string]$q.Name; n = [int]$q.Value }
        }
        $map[$p.Name] = @{
          n     = [int]$p.Value.n
          rdp   = [int]$p.Value.rdp
          ssh   = [int]$p.Value.ssh
          users = $users
          first = (Parse-TimestampDto $p.Value.first).LocalDateTime
          last  = (Parse-TimestampDto $p.Value.last).LocalDateTime
        }
      }
      return @{ ok = $true; map = $map; since = $since; coverage = $coverage; cursor = $cursor }
    } catch {
      return @{ ok = $false; error = "$($_.Exception.Message)"; map = @{}; since = $null; coverage = $null; cursor = $cursor }
    }
  }

  function Save-ShameMap($map, [datetime]$lastProcessed, $coverage, [hashtable]$cursor = $null) {
    foreach ($e in $map.Values) {
      if (@($e.users.Keys).Count -gt 25) {
        $nu = @{}
        foreach ($u in ($e.users.Values | Sort-Object { $_.n } -Descending | Select-Object -First 25)) { $nu[$u.name.ToLowerInvariant()] = $u }
        $e.users = $nu
      }
    }
    if ($map.Count -gt 5000) {
      foreach ($v in @($map.GetEnumerator() | Sort-Object { $_.Value.n } | Select-Object -First ($map.Count - 5000))) { $map.Remove($v.Key) }
    }
    $ipsOut = @{}
    foreach ($k in $map.Keys) {
      $e = $map[$k]
      $u = @{}
      foreach ($q in ($e.users.Values | Sort-Object { $_.n } -Descending)) { if ($q.name) { $u[$q.name] = [int]$q.n } }
      $ipsOut[$k] = @{
        n     = [int]$e.n
        rdp   = [int]$e.rdp
        ssh   = [int]$e.ssh
        users = $u
        first = (Iso-Local $e.first)
        last  = (Iso-Local $e.last)
      }
    }
    if ($coverage) {
      foreach ($ck in @('rdpFrom', 'sshFrom', 'backfilledAt')) {
        if ($coverage[$ck]) { $coverage[$ck] = (Iso-Local $coverage[$ck]) }
      }
    }
    $obj = [ordered]@{
      stateVersion    = 1
      lastProcessed   = $lastProcessed.ToString('o')
      lastRecordIdSec = $(if ($null -ne $cursor) { $cursor.lastRecordIdSec } else { $null })
      lastRecordIdSsh = $(if ($null -ne $cursor) { $cursor.lastRecordIdSsh } else { $null })
      pendingShame    = $(if ($null -ne $cursor -and $null -ne $cursor.pendingShame) { $cursor.pendingShame } else { @{} })
      coverage        = $coverage
      ips             = $ipsOut
    }
    Write-JsonAtomic -Path $shameFile -JsonContent ($obj | ConvertTo-Json -Depth 6 -Compress)
  }

  if ($ShameBackfill) {
    $nowB = Get-Date
    $known = Get-KnownEnabledNames
    if ($known.Count -eq 0) { Write-Error 'no enabled local accounts readable - refusing to backfill'; exit 2 }
    $op = Get-OperatorIps
    try { $rdpOldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $rdpOldest = $nowB.AddDays(-7) }
    try { $sshOldest = (Get-WinEvent -LogName 'OpenSSH/Operational' -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $sshOldest = $nowB }
    Write-Host "backfill scan: RDP 4625 from $rdpOldest ; SSH from $sshOldest ; enabled accounts: $($known -join ',')"
    $map = @{}
    $bfCursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    Import-ShameWindow $map $rdpOldest $nowB $known $op $bfCursor $true
    $coverage = @{ rdpFrom = $rdpOldest.ToString('o'); sshFrom = $sshOldest.ToString('o'); backfilledAt = $nowB.ToString('o'); knownUsers = $known }
    Save-ShameMap $map $nowB $coverage $bfCursor
    $tot = 0; foreach ($e in $map.Values) { $tot += $e.n }
    Write-Host "backfill done: $($map.Count) IPs / $tot attempts"
    exit 0
  }

  $now = if ($null -ne $TestHook -and $TestHook.ContainsKey('Now')) { [datetime]$TestHook['Now'] } else { Get-Date }
  $generationId = "{0}-{1}" -f $now.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ', $Inv), $PID

  # ---------------- crash recovery check on commit-manifest.json (fail-closed if .bak stores missing or mismatched) ----------------
  if (Test-Path -LiteralPath $manifestFile) {
    $prevManifest = Read-JsonSafe -Path $manifestFile
    if ($null -ne $prevManifest -and [string]$prevManifest.status -ne 'ok') {
      Write-Host "WARNING: previous generation $($prevManifest.generationId) had status=$($prevManifest.status); verifying and restoring consistent .bak stores"
      foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
        if (-not (Test-Path -LiteralPath "$stPath.bak")) {
          throw "CRITICAL: commit-manifest status is '$($prevManifest.status)' but required backup '$stPath.bak' is missing - FAIL-CLOSED"
        }
      }
      $statsBakObj  = Read-JsonSafe -Path "$statsFile.bak" -Validator { param($o) if ($null -eq $o.PSObject.Properties['daily']) { throw "stats.json.bak missing daily" } }
      $hourlyBakObj = Read-JsonSafe -Path "$hourlyFile.bak"
      $recentBakObj = Read-JsonSafe -Path "$recentFile.bak"
      $sGen = if ($null -ne $statsBakObj.PSObject.Properties['generationId']) { [string]$statsBakObj.generationId } else { '' }
      $hGen = if ($null -ne $hourlyBakObj.PSObject.Properties['generationId']) { [string]$hourlyBakObj.generationId } else { '' }
      if ($sGen -and $hGen -and ($sGen -ne $hGen)) {
        throw "CRITICAL: backup generation mismatch between stats.json.bak ($sGen) and hourly.json.bak ($hGen) - FAIL-CLOSED"
      }
      foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
        Copy-Item -LiteralPath "$stPath.bak" -Destination $stPath -Force -ErrorAction Stop
      }
    }
  }

  # ---------------- load incremental ingest state (fail-stop on corruption) ----------------
  $stats = @{
    lastProcessed          = $null
    firstEvent             = $null
    hourlyBackfill         = $false
    lastRecordIdSec        = $null
    lastRecordIdSsh        = $null
    lastRecordIdRdp261     = $null
    lastRecordIdLock       = $null
    recentTruncatedUntil   = $null
    recentUntruncatedCount = 0
    pendingPreauth         = @{}
    daily                  = @{}
  }

  $loadedStatsObj = Read-JsonSafe -Path $statsFile -Validator {
    param($o)
    if ($null -eq $o.PSObject.Properties['daily']) { throw "stats.json missing 'daily' property" }
  }
  if ($null -ne $loadedStatsObj) {
    $stats.lastProcessed  = $loadedStatsObj.lastProcessed
    $stats.firstEvent     = $loadedStatsObj.firstEvent
    $stats.hourlyBackfill = [bool]$loadedStatsObj.hourlyBackfill
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdSec'] -and $null -ne $loadedStatsObj.lastRecordIdSec) {
      $stats.lastRecordIdSec = [int64]$loadedStatsObj.lastRecordIdSec
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdSsh'] -and $null -ne $loadedStatsObj.lastRecordIdSsh) {
      $stats.lastRecordIdSsh = [int64]$loadedStatsObj.lastRecordIdSsh
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdRdp261'] -and $null -ne $loadedStatsObj.lastRecordIdRdp261) {
      $stats.lastRecordIdRdp261 = [int64]$loadedStatsObj.lastRecordIdRdp261
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdLock'] -and $null -ne $loadedStatsObj.lastRecordIdLock) {
      $stats.lastRecordIdLock = [int64]$loadedStatsObj.lastRecordIdLock
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['recentTruncatedUntil'] -and $null -ne $loadedStatsObj.recentTruncatedUntil) {
      $stats.recentTruncatedUntil = [string]$loadedStatsObj.recentTruncatedUntil
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['recentUntruncatedCount'] -and $null -ne $loadedStatsObj.recentUntruncatedCount) {
      $stats.recentUntruncatedCount = [int]$loadedStatsObj.recentUntruncatedCount
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['pendingPreauth'] -and $null -ne $loadedStatsObj.pendingPreauth) {
      foreach ($pp in $loadedStatsObj.pendingPreauth.PSObject.Properties) {
        $stats.pendingPreauth[$pp.Name] = @{
          ip   = [string]$pp.Value.ip
          port = [string]$pp.Value.port
          user = [string]$pp.Value.user
          t    = [string]$pp.Value.t
        }
      }
    }
    if ($loadedStatsObj.daily) {
      foreach ($p in $loadedStatsObj.daily.PSObject.Properties) {
        $d = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} }
        if ($p.Value.fails)    { $d.fails    = [int]$p.Value.fails }
        if ($p.Value.rdpConn)  { $d.rdpConn  = [int]$p.Value.rdpConn }
        if ($p.Value.ssh)      { $d.ssh      = [int]$p.Value.ssh }
        if ($p.Value.lockouts) { $d.lockouts = [int]$p.Value.lockouts }
        if ($p.Value.ips)      { foreach ($q in $p.Value.ips.PSObject.Properties) { $d.ips[$q.Name] = [int]$q.Value } }
        $d.totalIps = if ($null -ne $p.Value.PSObject.Properties['totalIps'] -and [int]$p.Value.totalIps -gt $d.ips.Count) { [int]$p.Value.totalIps } else { $d.ips.Count }
        $stats.daily[$p.Name] = $d
      }
    }
  }

  if (-not $stats.lastProcessed) {
    try {
      $oldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
      $stats.lastProcessed = $oldest.AddSeconds(-1).ToString('o')
    } catch {
      $stats.lastProcessed = $now.AddHours(-24).ToString('o')
    }
  }
  $since = (Parse-TimestampDto $stats.lastProcessed).LocalDateTime

  $recent = @()
  $loadedRecent = Read-JsonSafe -Path $recentFile
  if ($null -ne $loadedRecent) {
    $recent = @($loadedRecent)
  }

  if (-not $stats.firstEvent) {
    if ($recent.Count -gt 0) {
      $oldest = @($recent | ForEach-Object { $_.t } | Sort-Object)[0]
      $stats.firstEvent = (Parse-TimestampDto $oldest).ToLocalTime().ToString('o', $Inv)
    } elseif ($stats.daily.Keys.Count -gt 0) {
      $firstDay = @($stats.daily.Keys | Sort-Object)[0]
      $stats.firstEvent = ([datetime]::ParseExact("$firstDay 00:00:00", 'yyyy-MM-dd HH:mm:ss', $Inv)).ToString('o')
    }
  }

  # ---------------- load hourly history store (migrating legacy keys to UTC & preserving uncapped totals) ----------------
  $hourly       = @{}
  $hourlyTotals = @{}  # hk -> @([int]$rdpTotal, [int]$sshTotal, [int]$uniqueIps)
  $loadedHourly = Read-JsonSafe -Path $hourlyFile
  if ($null -ne $loadedStatsObj -and $null -ne $loadedHourly) {
    $sGenLoad = if ($null -ne $loadedStatsObj.PSObject.Properties['generationId']) { [string]$loadedStatsObj.generationId } else { '' }
    $hGenLoad = if ($null -ne $loadedHourly.PSObject.Properties['generationId']) { [string]$loadedHourly.PSObject.Properties['generationId'].Value } else { '' }
    if ($sGenLoad -and $hGenLoad -and ($sGenLoad -ne $hGenLoad)) {
      throw "CRITICAL: cross-store generation mismatch between stats.json ($sGenLoad) and hourly.json ($hGenLoad) - FAIL-CLOSED"
    }
  }
  if ($null -ne $loadedHourly) {
    $bucketsObj = if ($null -ne $loadedHourly.PSObject.Properties['buckets']) { $loadedHourly.buckets } else { $loadedHourly }
    $totalsObj  = if ($null -ne $loadedHourly.PSObject.Properties['totals'])  { $loadedHourly.totals }  else { $null }
    foreach ($p in $bucketsObj.PSObject.Properties) {
      if ($p.Name -in @('buckets', 'totals', 'generationId')) { continue }
      $utcKey = ConvertTo-UtcHourKey $p.Name
      if ($null -eq $utcKey) { continue }
      if (-not $hourly.ContainsKey($utcKey)) { $hourly[$utcKey] = @{} }
      $m = $hourly[$utcKey]
      $sumR = 0; $sumS = 0
      foreach ($q in $p.Value.PSObject.Properties) {
        $cIp = ConvertTo-CanonicalIP $q.Name
        if ($null -eq $cIp) { $cIp = $q.Name }
        $r0 = [int]$q.Value[0]; $s0 = [int]$q.Value[1]
        if ($m.ContainsKey($cIp)) {
          $m[$cIp] = @([int]$m[$cIp][0] + $r0, [int]$m[$cIp][1] + $s0)
        } else {
          $m[$cIp] = @($r0, $s0)
        }
        $sumR += $r0; $sumS += $s0
      }
      if ($null -ne $totalsObj -and $null -ne $totalsObj.PSObject.Properties[$p.Name]) {
        $tv = $totalsObj.PSObject.Properties[$p.Name].Value
        $hourlyTotals[$utcKey] = @([Math]::Max($sumR, [int]$tv[0]), [Math]::Max($sumS, [int]$tv[1]), [Math]::Max($m.Count, [int]$tv[2]))
      } else {
        $hourlyTotals[$utcKey] = @($sumR, $sumS, $m.Count)
      }
    }
  }

  function Add-HourlyEvent([string]$utcKey, [string]$ip, [string]$vec) {
    if (-not $hourly.ContainsKey($utcKey)) {
      $hourly[$utcKey] = @{}
      $hourlyTotals[$utcKey] = @(0, 0, 0)
    }
    $hm = $hourly[$utcKey]
    $isNewIp = -not $hm.ContainsKey($ip)
    $pair = if ($isNewIp) { @(0, 0) } else { $hm[$ip] }
    if ($vec -eq 'RDP') { $pair[0] = [int]$pair[0] + 1 } else { $pair[1] = [int]$pair[1] + 1 }
    $hm[$ip] = $pair

    $ht = if ($hourlyTotals.ContainsKey($utcKey)) { $hourlyTotals[$utcKey] } else { @(0, 0, $hm.Count) }
    if ($vec -eq 'RDP') { $ht[0] = [int]$ht[0] + 1 } else { $ht[1] = [int]$ht[1] + 1 }
    if ($isNewIp) {
      $ht[2] = [Math]::Max($hm.Count, [int]$ht[2] + 1)
    } else {
      $ht[2] = [Math]::Max($hm.Count, [int]$ht[2])
    }
    $hourlyTotals[$utcKey] = $ht
  }

  $operatorIps = Get-OperatorIps
  $logClearedSec = $false
  $logClearedSsh = $false

  # ---------------- ingest: RDP failed logons (paginated / watermarked / operator-filtered) ----------------
  $newEvents = 0
  $ev = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('RdpEvents')) {
    $ev = @($TestHook['RdpEvents'])
  } else {
    $querySinceSec = if ($null -ne $stats.lastRecordIdSec) { $since.AddMinutes(-15) } else { $since }
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$querySinceSec} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "Security 4625 query failed: $($_.Exception.Message)"
      }
    }
  }

  if ($ev.Count -gt 0) {
    $evSorted = @($ev | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })
    $maxRecSec = if ($null -ne $evSorted[-1].PSObject.Properties['RecordId']) { [int64]$evSorted[-1].RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdSec -and $null -ne $maxRecSec -and $maxRecSec -lt $stats.lastRecordIdSec) {
      $logClearedSec = $true
      $stats.lastRecordIdSec = $null
    }
    foreach ($e in $evSorted) {
      $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
      if ($null -ne $stats.lastRecordIdSec -and $null -ne $rid) {
        if ($rid -le $stats.lastRecordIdSec) { continue }
      } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
        continue
      }
      if ($null -ne $e.PSObject.Properties['IpAddress']) {
        $rawIp = [string]$e.IpAddress
        $u     = [string]$e.TargetUserName
        $tCreated = $e.TimeCreated
      } else {
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $rawIp = $d['IpAddress']; $u = $d['TargetUserName']
        $tCreated = $e.TimeCreated
      }
      $ip = ConvertTo-CanonicalIP $rawIp
      # Filter invalid, private, and operator IPs BEFORE incrementing daily or hourly
      if ($null -eq $ip -or (Is-Private $ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
        continue
      }
      if ($operatorIps.ContainsKey($ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
        continue
      }

      $dto = Parse-TimestampDto $tCreated
      $day = $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
      if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
      $stats.daily[$day].fails++
      if (-not $stats.daily[$day].ips.ContainsKey($ip)) {
        $stats.daily[$day].ips[$ip] = 0
        $stats.daily[$day].totalIps = [Math]::Max([int]$stats.daily[$day].totalIps + 1, $stats.daily[$day].ips.Count)
      }
      $stats.daily[$day].ips[$ip]++

      $isoT = $dto.ToLocalTime().ToString('o', $Inv)
      $recent += [pscustomobject]@{ t = $isoT; ip = $ip; user = (Sanitize-Name $u); vec = 'RDP'; res = 'fail' }
      if (-not $stats.firstEvent -or $dto.LocalDateTime -lt (Parse-TimestampDto $stats.firstEvent).LocalDateTime) {
        $stats.firstEvent = $isoT
      }
      $hk = $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
      Add-HourlyEvent -utcKey $hk -ip $ip -vec 'RDP'
      $newEvents++
      if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
    }
  }

  # ---------------- ingest: RDP listener connections (Event 261) ----------------
  $c261 = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('RdpConnEvents')) {
    $c261 = @($TestHook['RdpConnEvents'])
  } else {
    $querySince261 = if ($null -ne $stats.lastRecordIdRdp261) { $since.AddMinutes(-15) } else { $since }
    try {
      $c261 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=261; StartTime=$querySince261} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "TerminalServices 261 query failed: $($_.Exception.Message)"
      }
    }
  }
  foreach ($e in ($c261 | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })) {
    $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdRdp261 -and $null -ne $rid) {
      if ($rid -le $stats.lastRecordIdRdp261) { continue }
    } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
      continue
    }
    $day = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].rdpConn++
    if ($null -ne $rid) { $stats.lastRecordIdRdp261 = $rid }
  }

  # ---------------- ingest: lockouts (Event 4740) ----------------
  $lk = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('LockoutEvents')) {
    $lk = @($TestHook['LockoutEvents'])
  } else {
    $querySinceLock = if ($null -ne $stats.lastRecordIdLock) { $since.AddMinutes(-15) } else { $since }
    try {
      $lk = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$querySinceLock} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "Security 4740 query failed: $($_.Exception.Message)"
      }
    }
  }
  foreach ($e in ($lk | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })) {
    $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdLock -and $null -ne $rid) {
      if ($rid -le $stats.lastRecordIdLock) { continue }
    } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
      continue
    }
    $day = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].lockouts++
    if ($null -ne $rid) { $stats.lastRecordIdLock = $rid }
  }

  # ---------------- ingest: SSH (canonical attempt identity via pendingPreauth + terminal peer regex) ----------------
  function Record-SshAttempt([string]$ip, [string]$user, $whenVal) {
    $dto = Parse-TimestampDto $whenVal
    $day = $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].ssh++
    if (-not $stats.daily[$day].ips.ContainsKey($ip)) {
      $stats.daily[$day].ips[$ip] = 0
      $stats.daily[$day].totalIps = [Math]::Max([int]$stats.daily[$day].totalIps + 1, $stats.daily[$day].ips.Count)
    }
    $stats.daily[$day].ips[$ip]++
    $isoT = $dto.ToLocalTime().ToString('o', $Inv)
    $script:recent += [pscustomobject]@{ t = $isoT; ip = $ip; user = (Sanitize-Name $user); vec = 'SSH'; res = 'fail' }
    $hk = $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
    Add-HourlyEvent -utcKey $hk -ip $ip -vec 'SSH'
    $script:newEvents++
  }

  $oev = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('SshEvents')) {
    $oev = @($TestHook['SshEvents'])
  } else {
    $querySinceSsh = if ($null -ne $stats.lastRecordIdSsh) { $since.AddMinutes(-15) } else { $since }
    try {
      $oev = @(Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$querySinceSsh} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "OpenSSH/Operational query failed: $($_.Exception.Message)"
      }
    }
  }

  if ($oev.Count -gt 0) {
    $oevSorted = @($oev | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })
    $maxRecSsh = if ($null -ne $oevSorted[-1].PSObject.Properties['RecordId']) { [int64]$oevSorted[-1].RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdSsh -and $null -ne $maxRecSsh -and $maxRecSsh -lt $stats.lastRecordIdSsh) {
      $logClearedSsh = $true
      $stats.lastRecordIdSsh = $null
    }
    foreach ($e in $oevSorted) {
      $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
      if ($null -ne $stats.lastRecordIdSsh -and $null -ne $rid) {
        if ($rid -le $stats.lastRecordIdSsh) { continue }
      } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
        continue
      }
      $p = Parse-SshAuthLine ([string]$e.Message)
      if ($null -eq $p) {
        if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
        continue
      }
      $ip = $p.ip
      if ((Is-Private $ip) -or $operatorIps.ContainsKey($ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
        continue
      }
      $pKey = "$ip|$($p.port)"
      if ($p.kind -eq 'invalid_banner') {
        # If a previous unclosed invalid_banner on the same (ip,port) existed, flush it first
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          $oldPend = $stats.pendingPreauth[$pKey]
          Record-SshAttempt -ip $oldPend.ip -user $oldPend.user -whenVal $oldPend.t
        }
        $stats.pendingPreauth[$pKey] = @{
          ip   = $ip
          port = $p.port
          user = $p.user
          t    = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('o', $Inv)
        }
      } elseif ($p.kind -eq 'failed_pw_invalid' -or $p.kind -eq 'failed_pw_valid') {
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          [void]$stats.pendingPreauth.Remove($pKey)
        }
        Record-SshAttempt -ip $ip -user $p.user -whenVal $e.TimeCreated
      } elseif ($p.kind -eq 'preauth_close') {
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          $pend = $stats.pendingPreauth[$pKey]
          [void]$stats.pendingPreauth.Remove($pKey)
          Record-SshAttempt -ip $pend.ip -user $pend.user -whenVal $pend.t
        }
      }
      if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
    }
  }

  # Flush any pendingPreauth entries older than 120 seconds relative to $now
  $nowDto = Parse-TimestampDto $now
  foreach ($pk in @($stats.pendingPreauth.Keys)) {
    $pend = $stats.pendingPreauth[$pk]
    $pendDto = Parse-TimestampDto $pend.t
    if (($nowDto - $pendDto).TotalSeconds -ge 120) {
      [void]$stats.pendingPreauth.Remove($pk)
      Record-SshAttempt -ip $pend.ip -user $pend.user -whenVal $pendDto
    }
  }

  $stats.hourlyBackfill = $true

  # ---------------- prune hourly to local calendar midnight boundary (zero partial-day gap) ----------------
  # Never prune into 2026-10-10 because 2026-10-10T00..10 was already pruned before 2026-10-17;
  # starting at 2026-10-11T00:00:00 local midnight guarantees every day < hourlyStart is a full daily
  # day and every day >= hourlyStart is a full 24h hourly day.
  $minFullHourlyDayLocal = [datetime]::SpecifyKind([datetime]::ParseExact('2026-10-11 00:00:00', 'yyyy-MM-dd HH:mm:ss', $Inv), [System.DateTimeKind]::Local)
  $rolling14MidnightLocal = [datetime]::SpecifyKind($now.Date.AddDays(-14), [System.DateTimeKind]::Local)
  $cutMidnightLocal = if ($rolling14MidnightLocal -gt $minFullHourlyDayLocal) { $rolling14MidnightLocal } else { $minFullHourlyDayLocal }
  $cutHKeyUtc = (New-Object System.DateTimeOffset($cutMidnightLocal)).ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)

  foreach ($k in @($hourly.Keys)) {
    if ($k -lt $cutHKeyUtc) {
      [void]$hourly.Remove($k)
      [void]$hourlyTotals.Remove($k)
    }
  }
  # Ensure the exact midnight boundary key exists so index.html's hours[0].ms lands on local midnight
  if ($hourly.Count -gt 0 -and -not $hourly.ContainsKey($cutHKeyUtc)) {
    $earliestExisting = [string](@($hourly.Keys | Sort-Object)[0])
    if ($earliestExisting -gt $cutHKeyUtc) {
      $firstDayLocal = (Parse-TimestampDto $earliestExisting).ToLocalTime().Date
      $firstDayMidnightUtc = (New-Object System.DateTimeOffset([datetime]::SpecifyKind($firstDayLocal, [System.DateTimeKind]::Local))).ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
      if (-not $hourly.ContainsKey($firstDayMidnightUtc)) {
        $hourly[$firstDayMidnightUtc] = @{}
        $hourlyTotals[$firstDayMidnightUtc] = @(0, 0, 0)
      }
    }
  }

  # Build exported $hourlyOut (capped at top 400 IPs per hour for data.json) and uncapped $hourlyDisk (lossless on-disk store)
  $hourlyOut  = [ordered]@{}
  $hourlyDisk = [ordered]@{}
  $totalsOut  = [ordered]@{}
  foreach ($k in ($hourly.Keys | Sort-Object)) {
    $hm = $hourly[$k]
    $m400  = [ordered]@{}
    $mFull = [ordered]@{}
    $sortedIps = @($hm.GetEnumerator() | Sort-Object { [int]$_.Value[0] + [int]$_.Value[1] } -Descending)
    $sumR = 0; $sumS = 0
    for ($idx = 0; $idx -lt $sortedIps.Count; $idx++) {
      $entry = $sortedIps[$idx]
      $rVal = [int]$entry.Value[0]; $sVal = [int]$entry.Value[1]
      $sumR += $rVal; $sumS += $sVal
      if ($idx -lt 400) { $m400[$entry.Key] = @($rVal, $sVal) }
      $mFull[$entry.Key] = @($rVal, $sVal)
    }
    $ht = if ($hourlyTotals.ContainsKey($k)) {
      @([Math]::Max($sumR, [int]$hourlyTotals[$k][0]), [Math]::Max($sumS, [int]$hourlyTotals[$k][1]), [Math]::Max($hm.Count, [int]$hourlyTotals[$k][2]))
    } else {
      @($sumR, $sumS, $hm.Count)
    }
    $hourlyOut[$k]  = $m400
    $hourlyDisk[$k] = $mFull
    $totalsOut[$k]  = $ht
  }

  # ---------------- prune & cap recent (with sticky truncation metadata across runs for hybrid handoff) ----------------
  $cut24Dto = $nowDto.AddHours(-24)
  $recent = @($recent | Where-Object {
    try { (Parse-TimestampDto $_.t) -gt $cut24Dto } catch { $false }
  } | Sort-Object { (Parse-TimestampDto $_.t).UtcTicks } -Descending)

  $recentBeforeCap = $recent.Count
  $recentCap = if ($null -ne $TestHook -and $TestHook.ContainsKey('RecentCap')) { [int]$TestHook['RecentCap'] } else { 25000 }
  $truncatedThisRun = ($recentBeforeCap -gt $recentCap)
  if ($truncatedThisRun) {
    $recent = @($recent | Select-Object -First $recentCap)
  }
  $recentOldestTs = if ($recent.Count -gt 0) { [string]$recent[$recent.Count - 1].t } else { $null }
  if ($truncatedThisRun) {
    $stats.recentTruncatedUntil   = $recentOldestTs
    $stats.recentUntruncatedCount = $recentBeforeCap
  } elseif ($null -ne $stats.recentTruncatedUntil) {
    try {
      if ((Parse-TimestampDto $stats.recentTruncatedUntil) -le $cut24Dto) {
        $stats.recentTruncatedUntil   = $null
        $stats.recentUntruncatedCount = 0
      } else {
        $stats.recentUntruncatedCount = [Math]::Max($recentBeforeCap, [int]$stats.recentUntruncatedCount + $newEvents)
      }
    } catch {
      $stats.recentTruncatedUntil   = $null
      $stats.recentUntruncatedCount = 0
    }
  }
  $recentTruncated = ($truncatedThisRun -or ($null -ne $stats.recentTruncatedUntil))
  $effectiveOldestTs = if ($recentTruncated -and $null -ne $recentOldestTs) { $recentOldestTs } elseif ($null -ne $stats.recentTruncatedUntil) { $stats.recentTruncatedUntil } else { $recentOldestTs }
  $effectiveUntruncated = if ($recentTruncated) { [Math]::Max($recentBeforeCap, [int]$stats.recentUntruncatedCount) } else { $recentBeforeCap }
  $recentMeta = [ordered]@{
    truncated   = $recentTruncated
    oldest      = $effectiveOldestTs
    count       = $recent.Count
    untruncated = $effectiveUntruncated
    cap         = $recentCap
  }

  $stats.lastProcessed = $nowDto.ToLocalTime().ToString('o', $Inv)

  # ---------------- prepare dailyOut (400-IP projection for data.json) & dailyDisk (uncapped for stats.json) ----------------
  $dailyOut  = [ordered]@{}
  $dailyDisk = [ordered]@{}
  foreach ($k in ($stats.daily.Keys | Sort-Object)) {
    $ipsOut  = [ordered]@{}
    $ipsFull = [ordered]@{}
    $sortedDailyIps = @($stats.daily[$k].ips.GetEnumerator() | Sort-Object Value -Descending)
    for ($idx = 0; $idx -lt $sortedDailyIps.Count; $idx++) {
      $de = $sortedDailyIps[$idx]
      if ($idx -lt 400) { $ipsOut[$de.Key] = [int]$de.Value }
      $ipsFull[$de.Key] = [int]$de.Value
    }
    $trueTotalIps = [Math]::Max([int]$stats.daily[$k].totalIps, $stats.daily[$k].ips.Count)
    $dailyOut[$k] = [ordered]@{
      fails    = [int]$stats.daily[$k].fails
      rdpConn  = [int]$stats.daily[$k].rdpConn
      ssh      = [int]$stats.daily[$k].ssh
      lockouts = [int]$stats.daily[$k].lockouts
      totalIps = $trueTotalIps
      ips      = $ipsOut
    }
    $dailyDisk[$k] = [ordered]@{
      fails    = [int]$stats.daily[$k].fails
      rdpConn  = [int]$stats.daily[$k].rdpConn
      ssh      = [int]$stats.daily[$k].ssh
      lockouts = [int]$stats.daily[$k].lockouts
      totalIps = $trueTotalIps
      ips      = $ipsFull
    }
  }

  # ---------------- hall of shame: incremental ingest ----------------
  $shameMap = @{}; $shameIps = @{}; $shameCoverage = $null; $shameIngestError = ''
  if ($null -eq $TestHook -or -not $TestHook.ContainsKey('SkipShame')) {
    try {
      $knownEnabled = Get-KnownEnabledNames
      if ($knownEnabled.Count -eq 0) { throw 'no enabled local accounts readable' }
      $st = Initialize-ShameMap
      if (-not $st.ok) { throw "shame store unreadable, left untouched: $($st.error)" }
      $shameMap = $st.map; $shameCoverage = $st.coverage
      $shameSince = $st.since
      if (-not $shameSince) { $shameSince = $now }
      if ($shameSince -gt $now) { $shameSince = $now }
      if ($now -gt $shameSince -and $null -eq $TestHook) {
        Import-ShameWindow $shameMap $shameSince $now $knownEnabled $operatorIps $st.cursor $false
      }
      Save-ShameMap $shameMap $now $shameCoverage $st.cursor
      foreach ($k in $shameMap.Keys) { $shameIps[$k] = $true }
    } catch {
      $shameIngestError = "$($_.Exception.Message)"
    }
  }

  # ---------------- rolling windows ----------------
  function WindowStats([int]$minutes) {
    $limDto = $nowDto.AddMinutes(-$minutes)
    $set = @($recent | Where-Object { try { (Parse-TimestampDto $_.t) -gt $limDto } catch { $false } })
    $ips = @{}; $rdp = 0; $ssh = 0
    foreach ($r in $set) {
      if (-not $ips.ContainsKey($r.ip)) { $ips[$r.ip] = 0 }
      $ips[$r.ip]++
      if ($r.vec -eq 'RDP') { $rdp++ } else { $ssh++ }
    }
    return @{ total = $set.Count; ips = $ips.Count; rdp = $rdp; ssh = $ssh; set = $set }
  }
  $w5 = WindowStats 5; $w60 = WindowStats 60; $w1440 = WindowStats 1440

  $series = [ordered]@{}
  for ($i = 239; $i -ge 0; $i--) { $series[$now.AddMinutes(-$i).ToString('HH:mm')] = @{ rdp = 0; ssh = 0 } }
  foreach ($r in $recent) {
    $t = (Parse-TimestampDto $r.t).ToLocalTime().ToString('HH:mm')
    if ($series.Contains($t)) { if ($r.vec -eq 'RDP') { $series[$t].rdp++ } else { $series[$t].ssh++ } }
  }

  # ---------------- bans & firewall effective health ----------------
  $bans = @(); $permCount = 0; $tempCount = 0
  $banIpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if (Test-Path -LiteralPath $bansFile) {
    try {
      $bj = Read-JsonSafe -Path $bansFile
      if ($null -ne $bj -and $null -ne $bj.data -and $null -ne $bj.data.bans) {
        foreach ($p in $bj.data.bans.PSObject.Properties) {
          $cBanIp = ConvertTo-CanonicalIP ([string]$p.Name)
          if ($null -ne $cBanIp -and -not (Is-Private $cBanIp)) { [void]$banIpSet.Add($cBanIp) }
          $isPerm = -not $p.Value.until
          if ($isPerm) { $permCount++ } else { $tempCount++ }
          $bans += [pscustomobject]@{
            ip        = $p.Name
            permanent = $isPerm
            until     = $p.Value.until
            reason    = $p.Value.reason
            when      = $p.Value.bannedAt
            tries     = $(if ($p.Value.reason -match 'x(\d+)') { [int]$Matches[1] } else { 0 })
          }
        }
      }
    } catch {}
  }

  $fwRuleInstances = 0
  $fwEnabledBlockingInstances = 0
  $fwFiltersAllAny = $true
  $fwUniqueIps = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if ($null -ne $TestHook -and $TestHook.ContainsKey('FirewallRules')) {
    $fwRules = @($TestHook['FirewallRules'])
    $fwRuleInstances = $fwRules.Count
    foreach ($r in $fwRules) {
      if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {
        $fwEnabledBlockingInstances++
        foreach ($a in @($r.RemoteAddress)) {
          $c = ConvertTo-CanonicalIP ([string]$a)
          if ($null -ne $c -and -not (Is-Private $c)) { [void]$fwUniqueIps.Add($c) }
        }
      }
    }
  } else {
    try {
      $fwRules = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY' -ErrorAction SilentlyContinue)
      $fwRuleInstances = $fwRules.Count
      foreach ($r in $fwRules) {
        if ($r.Enabled.ToString() -eq 'True' -and $r.Direction.ToString() -eq 'Inbound' -and $r.Action.ToString() -eq 'Block') {
          $fwEnabledBlockingInstances++
          $af   = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
          $pf   = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
          $appf = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
          $svcf = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
          $if   = $r | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue
          if (
            $r.Profile.ToString() -ne 'Any' -or
            $null -eq $af -or [string]$af.LocalAddress -ne 'Any' -or
            $null -eq $pf -or [string]$pf.Protocol -ne 'Any' -or [string]$pf.LocalPort -ne 'Any' -or [string]$pf.RemotePort -ne 'Any' -or
            $null -eq $appf -or [string]$appf.Program -ne 'Any' -or
            $null -eq $svcf -or [string]$svcf.Service -ne 'Any' -or
            $null -eq $if -or [string]$if.InterfaceType -ne 'Any'
          ) {
            $fwFiltersAllAny = $false
          }
          if ($null -ne $af) {
            foreach ($a in @($af.RemoteAddress)) {
              $c = ConvertTo-CanonicalIP ([string]$a)
              if ($null -ne $c -and -not (Is-Private $c)) { [void]$fwUniqueIps.Add($c) }
            }
          }
        }
      }
    } catch {
      $fwFiltersAllAny = $false
    }
  }
  $fwSetParity = if ($null -ne $TestHook -and -not $TestHook.ContainsKey('EnforceBanParity')) {
    ($bans.Count -eq 0 -or $fwUniqueIps.Count -gt 0)
  } else {
    ($fwUniqueIps.Count -eq $banIpSet.Count) -and (@($banIpSet | Where-Object { -not $fwUniqueIps.Contains($_) }).Count -eq 0)
  }
  $healthObj = [ordered]@{
    status                   = 'ok'
    generationId             = $generationId
    firewallRuleInstances    = $fwRuleInstances
    firewallEnabledInstances = $fwEnabledBlockingInstances
    firewallActiveRuleCount  = $fwUniqueIps.Count
    firewallEffectiveOk      = ($fwRuleInstances -eq 1 -and $fwEnabledBlockingInstances -eq 1 -and $fwFiltersAllAny -and $fwSetParity)
    logClearedSec            = $logClearedSec
    logClearedSsh            = $logClearedSsh
  }

  # ---------------- firewall log: what the wall is stopping ----------------
  $drops = @{}; $portHits = @{}
  if (Test-Path -LiteralPath $fwLog) {
    try {
      $lines = Get-Content -LiteralPath $fwLog -Tail 4000 -ErrorAction SilentlyContinue
      foreach ($l in $lines) {
        if ($l.StartsWith('#')) { continue }
        $f = $l -split '\s+'
        if ($f.Count -lt 17) { continue }
        if ($f[2] -ne 'DROP') { continue }
        if ($f[16] -ne 'RECEIVE') { continue }
        $ip = ConvertTo-CanonicalIP $f[4]; $port = $f[7]; $ts = "$($f[0]) $($f[1])"
        if ($null -eq $ip -or (Is-Private $ip)) { continue }
        if (-not $drops.ContainsKey($ip)) { $drops[$ip] = @{ n = 0; last = $ts; port = $port } }
        $drops[$ip].n++
        $drops[$ip].last = $ts
        if ($drops[$ip].port -ne $port) { $drops[$ip].port = "$($drops[$ip].port),$port" }
        $portHits[$port] = 1 + [int]$portHits[$port]
      }
    } catch {}
  }
  $blockedTop = @($drops.GetEnumerator() | Sort-Object { $_.Value.n } -Descending | Select-Object -First 40 |
    ForEach-Object { [pscustomobject]@{ ip = $_.Key; hits = $_.Value.n; last = $_.Value.last; port = $_.Value.port } })
  $scanPorts = @($portHits.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 |
    ForEach-Object { [pscustomobject]@{ port = $_.Key; hits = $_.Value } })
  $blockedTotal = 0; foreach ($k in $drops.Keys) { $blockedTotal += $drops[$k].n }

  # ---------------- guard ----------------
  $guard = @{ state = 'Ready'; lastRun = $now.ToString('MM/dd/yyyy HH:mm:ss'); lastResult = 0; nextRun = $now.AddMinutes(1).ToString('MM/dd/yyyy HH:mm:ss') }
  if ($null -eq $TestHook) {
    try {
      $t = Get-ScheduledTask -TaskName 'RDP-Guard (anti-spray)' -ErrorAction Stop
      $i = Get-ScheduledTaskInfo -TaskName 'RDP-Guard (anti-spray)' -ErrorAction Stop
      $guard = @{ state = "$($t.State)"; lastRun = "$($i.LastRunTime)"; lastResult = $i.LastTaskResult; nextRun = "$($i.NextRunTime)" }
    } catch {}
  }
  $guardLogTail = @(); if (Test-Path -LiteralPath $guardLog) { $guardLogTail = @(Get-Content -LiteralPath $guardLog -Tail 25 -ErrorAction SilentlyContinue) }

  # ---------------- per-IP aggregates (24h) ----------------
  $agg = @{}
  foreach ($r in $recent) {
    if (-not $agg.ContainsKey($r.ip)) {
      $agg[$r.ip] = @{ n = 0; rdp = 0; ssh = 0; first = $r.t; last = $r.t; hours = (New-Object 'int[]' 24) }
    }
    $a = $agg[$r.ip]
    $a.n++
    if ($r.vec -eq 'RDP') { $a.rdp++ } else { $a.ssh++ }
    $rDto = Parse-TimestampDto $r.t
    if ($rDto -gt (Parse-TimestampDto $a.last))  { $a.last  = $r.t }
    if ($rDto -lt (Parse-TimestampDto $a.first)) { $a.first = $r.t }
    $h = [int][math]::Floor(($nowDto - $rDto).TotalHours)
    if ($h -ge 0 -and $h -le 23) { $a.hours[$h]++ }
  }
  $topAttackers = @($agg.GetEnumerator() | Sort-Object { $_.Value.n } -Descending | Select-Object -First 40 | ForEach-Object {
    $ipKey = $_.Key
    [pscustomobject]@{
      ip      = $ipKey
      tries   = $_.Value.n
      first   = $_.Value.first
      last    = $_.Value.last
      vectors = (@( @('RDP') * [int]($_.Value.rdp -gt 0) ; @('SSH') * [int]($_.Value.ssh -gt 0) ) | Where-Object { $_ }) -join '+'
      banned  = [bool]($bans | Where-Object { $_.ip -eq $ipKey } | Select-Object -First 1)
    }
  })

  # ---------------- geolocation (cached) ----------------
  $geo = @{}
  try {
    $gLoaded = Read-JsonSafe -Path $geoFile
    if ($null -ne $gLoaded) { foreach ($p in $gLoaded.PSObject.Properties) { $geo[$p.Name] = $p.Value } }
  } catch {}
  $geoAge = 3600
  if (Test-Path -LiteralPath $geoFile) { $geoAge = ($now - (Get-Item -LiteralPath $geoFile).LastWriteTime).TotalSeconds }
  if ($null -eq $TestHook -and $geoAge -gt 900) {
    $cand = @{}
    foreach ($b in $bans)          { $cand[$b.ip] = $true }
    foreach ($a in $topAttackers)  { $cand[$a.ip] = $true }
    foreach ($x in $blockedTop)    { $cand[$x.ip] = $true }
    foreach ($r in $recent)        { $cand[$r.ip] = $true }
    foreach ($k in $shameIps.Keys) { $cand[$k] = $true }
    $need = @(@($hostIp) + @($cand.Keys)) | Where-Object { -not $geo.ContainsKey($_) -and -not (Is-Private $_) } | Select-Object -Unique -First 450
    if ($need.Count -gt 0) {
      try {
        for ($i = 0; $i -lt $need.Count; $i += 90) {
          $chunk = $need[$i..([math]::Min($i+89, $need.Count-1))]
          $body = ($chunk | ForEach-Object { '{"query":"' + $_ + '"}' }) -join ','
          $r = Invoke-RestMethod -Uri 'http://ip-api.com/batch?fields=query,country,countryCode,city,lat,lon,as,isp' -Method Post -Body ("[" + $body + "]") -ContentType 'application/json' -TimeoutSec 25
          foreach ($x in $r) { if ($x.query) { $geo[$x.query] = @{ c = $x.country; cc = $x.countryCode; city = $x.city; lat = $x.lat; lon = $x.lon; "as" = $x.as; isp = $x.isp } } }
        }
        Write-JsonAtomic -Path $geoFile -JsonContent ($geo | ConvertTo-Json -Depth 4 -Compress)
      } catch {}
    }
  }

  $dcWords = @('linode','digitalocean','amazon','aws','google','microsoft','azure','ovh','hetzner','contabo','vultr',
               'leaseweb','choopa','scaleway','oracle','alibaba','tencent','m247','colocrossing','sharktech','psychz',
               'quadranet','hostinger','server','hosting','datacenter','data center','cloud','vpn','proxy','lease',
               'netcup','ionos','namecheap','gcore','servers.com','interserver','hostwinds','racknerd','frantech',
               'zomro','aeza','melbicom','stark-industries','thehive','cogent','tzulo','colo')
  function Is-Hosting($asn, $isp) {
    $s = ("$asn $isp").ToLowerInvariant()
    foreach ($w in $dcWords) { if ($s -like "*$w*") { return $true } }
    return $false
  }
  function GeoOf($ip) {
    if ($geo.ContainsKey($ip)) { return $geo[$ip] } else { return $null }
  }

  foreach ($b in $bans) {
    $g = GeoOf $b.ip
    $b | Add-Member -NotePropertyName cc      -NotePropertyValue $(if ($g) { $g.cc } else { '' }) -Force
    $b | Add-Member -NotePropertyName country -NotePropertyValue $(if ($g) { $g.c } else { '' }) -Force
    $b | Add-Member -NotePropertyName city    -NotePropertyValue $(if ($g) { $g.city } else { '' }) -Force
  }
  foreach ($a in $topAttackers) {
    $g = GeoOf $a.ip
    $a | Add-Member -NotePropertyName cc      -NotePropertyValue $(if ($g) { $g.cc } else { '' }) -Force
    $a | Add-Member -NotePropertyName country -NotePropertyValue $(if ($g) { $g.c } else { '' }) -Force
    $a | Add-Member -NotePropertyName city    -NotePropertyValue $(if ($g) { $g.city } else { '' }) -Force
  }

  $banMap = @{}
  foreach ($b in $bans) { $banMap[$b.ip] = $b }

  $mapPoints = @()
  foreach ($ip in ($agg.Keys + $banMap.Keys + $drops.Keys | Select-Object -Unique)) {
    $g = GeoOf $ip
    if (-not $g -or $null -eq $g.lat) { continue }
    $a = $agg[$ip]; $b = $banMap[$ip]; $dr = $drops[$ip]
    $category = 'active'
    if ($b) { $category = $(if ($b.permanent) { 'perm' } else { 'temp' }) }
    elseif ($dr) { $category = 'blocked' }
    $hours = if ($a) { $a.hours } else { New-Object 'int[]' 24 }
    $mapPoints += [pscustomobject]@{
      ip       = $ip
      lat      = $g.lat; lon = $g.lon
      city     = $g.city; country = $g.c; cc = $g.cc
      asn      = $g.'as'; isp = $g.isp
      hosting  = (Is-Hosting $g.'as' $g.isp)
      category = $category
      attempts = $(if ($a) { $a.n } else { 0 })
      rdp      = $(if ($a) { $a.rdp } else { 0 })
      ssh      = $(if ($a) { $a.ssh } else { 0 })
      first    = $(if ($a) { $a.first } else { $null })
      last     = $(if ($a) { $a.last } else { $null })
      drops    = $(if ($dr) { $dr.n } else { 0 })
      dropPort = $(if ($dr) { $dr.port } else { $null })
      hours    = @($hours)
    }
  }

  $gp = GeoOf $hostIp
  $serverPoint = [pscustomobject]@{
    ip      = $hostIp
    lat     = $(if ($gp) { $gp.lat } else { $null })
    lon     = $(if ($gp) { $gp.lon } else { $null })
    city    = $(if ($gp) { $gp.city } else { '' })
    country = $(if ($gp) { $gp.c } else { '' })
  }

  # ---------------- ports (dynamically check sshd_config & live :443 qbit-webui-proxy) ----------------
  $sshKeyOnly = $false
  $sshdCfgPath = 'C:\ProgramData\ssh\sshd_config'
  if (Test-Path -LiteralPath $sshdCfgPath) {
    try {
      $activePwLines = @(Get-Content -LiteralPath $sshdCfgPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*PasswordAuthentication\s+no\b' })
      if ($activePwLines.Count -gt 0) { $sshKeyOnly = $true }
    } catch {}
  }
  $sshNote = if ($sshKeyOnly) { 'key-only, PasswordAuthentication no' } else { 'password auth enabled; brute-force guarded' }

  $ports = @(
    @{ port = 3389;  svc = 'RDP (your daily tool)';      wan = 'OPEN';    note = 'router forwards it; brute-force guarded' },
    @{ port = 22;    svc = 'SSH';                        wan = 'OPEN';    note = $sshNote },
    @{ port = 8096;  svc = 'Jellyfin (HTTP)';            wan = 'OPEN';    note = 'plain http - LAN use' },
    @{ port = 8920;  svc = 'Jellyfin (HTTPS)';           wan = 'OPEN';    note = 'TLS enabled - use this remotely' },
    @{ port = 47984; svc = 'Sunshine/Apollo';            wan = 'OPEN';    note = 'streaming 47984-48010' },
    @{ port = 8099;  svc = 'This dashboard';             wan = 'LAN';     note = 'internal only by design' },
    @{ port = 443;   svc = 'qBittorrent WebUI (TLS)';    wan = 'LAN/VPN'; note = 'qbit-webui-proxy -> 127.0.0.1:8082 (LAN + Tailscale)' },
    @{ port = 9696;  svc = 'Prowlarr';                   wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 6767;  svc = 'Bazarr';                     wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 8088;  svc = 'submarine web server';       wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 2179;  svc = 'Hyper-V management';         wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 135;   svc = 'Windows RPC';                wan = 'BLOCKED'; note = 'WAN-BLOCK rule' }
  )
  if ($null -eq $TestHook) {
    foreach ($p in $ports) { $p.listen = [bool](Get-NetTCPConnection -State Listen -LocalPort $p.port -ErrorAction SilentlyContinue | Select-Object -First 1) }
  } else {
    foreach ($p in $ports) { $p.listen = $true }
  }

  # ---------------- history / retention ----------------
  $hist = @{}
  if ($null -eq $TestHook) {
    try { $hist.securityOldest   = "$((Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.sshOldest        = "$((Get-WinEvent -LogName 'OpenSSH/Operational' -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.rdpSessionOldest = "$((Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.systemOldest     = "$((Get-WinEvent -LogName System -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.appOldest        = "$((Get-WinEvent -LogName Application -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.osInstall        = "$((Get-CimInstance Win32_OperatingSystem).InstallDate)" } catch {}
    try { $hist.sshdConfig       = "$((Get-Item 'C:\ProgramData\ssh\sshd_config').CreationTime)" } catch {}
  }

  $dailyOut2 = @()
  foreach ($k in ($stats.daily.Keys | Sort-Object)) {
    $trueTotalIps = [Math]::Max([int]$stats.daily[$k].totalIps, $stats.daily[$k].ips.Count)
    $dailyOut2 += [pscustomobject]@{
      day        = $k
      fails      = [int]$stats.daily[$k].fails
      rdpConn    = [int]$stats.daily[$k].rdpConn
      ssh        = [int]$stats.daily[$k].ssh
      lockouts   = [int]$stats.daily[$k].lockouts
      hostileIPs = $trueTotalIps
      totalIps   = $trueTotalIps
      ips        = $dailyOut[$k].ips
    }
  }

  # ---------------- full span of the record + historical milestones ----------------
  $dayKeys = @($stats.daily.Keys | Sort-Object)
  $hKeys   = @($hourly.Keys | Sort-Object)
  $recStart = $now.AddHours(-24)
  if ($stats.firstEvent) {
    $recStart = (Parse-TimestampDto $stats.firstEvent).LocalDateTime
  }
  if ($hKeys.Count -gt 0) {
    $h0Local = (Parse-TimestampDto $hKeys[0]).LocalDateTime
    if ($h0Local -lt $recStart) { $recStart = $h0Local }
  }
  if ($dayKeys.Count -gt 0) {
    $d0Local = [datetime]::ParseExact($dayKeys[0] + ' 00:00:00', 'yyyy-MM-dd HH:mm:ss', $Inv)
    if ($d0Local -lt $recStart) { $recStart = $d0Local }
  }
  $span = @{ t0 = ([datetime]::SpecifyKind($recStart, [System.DateTimeKind]::Local)).ToString('o'); t1 = $now.ToString('o') }

  $milestones = @()
  function Add-Milestone($t, $label) {
    if (-not $t) { return }
    try {
      $dto = Parse-TimestampDto $t
      $script:milestones += @{ t = $dto.ToLocalTime().ToString('o', $Inv); label = $label }
    } catch {}
  }
  if ($null -eq $TestHook) {
    Add-Milestone $(try { (Get-CimInstance Win32_OperatingSystem).InstallDate.ToString('o') } catch { $null }) 'Windows installed'
  }
  Add-Milestone $hist.sshdConfig 'SSH server configured'
  Add-Milestone $hist.rdpSessionOldest 'Remote desktop sessions begin'
  Add-Milestone $hist.sshOldest 'Oldest surviving SSH attack evidence'
  Add-Milestone $hist.securityOldest 'Security log begins (was 20 MB - older data lost)'
  Add-Milestone $hist.systemOldest 'System log begins'
  Add-Milestone $recStart.ToString('o') 'Record-keeping begins (this dashboard)'

  # ---------------- hall of shame: ranked rows for the page ----------------
  $nameTot = @{}
  foreach ($e in $shameMap.Values) {
    foreach ($u in $e.users.Values) {
      $k = $u.name.ToLowerInvariant()
      if (-not $nameTot.ContainsKey($k)) { $nameTot[$k] = @{ name = $u.name; n = 0 } }
      $nameTot[$k].n += $u.n
    }
  }
  $shameTopName = $nameTot.Values | Sort-Object { $_.n } -Descending | Select-Object -First 1
  $shameRows = @()
  foreach ($k in ($shameMap.Keys | Sort-Object { $shameMap[$_].n } -Descending | Select-Object -First 200)) {
    $e = $shameMap[$k]; $g = GeoOf $k; $b = $banMap[$k]
    $uarr = @()
    foreach ($u in ($e.users.Values | Sort-Object { $_.n } -Descending | Select-Object -First 6)) { $uarr += ,@([string]$u.name, [int]$u.n) }
    $shameRows += [pscustomobject]@{
      ip      = $k; n = [int]$e.n; rdp = [int]$e.rdp; ssh = [int]$e.ssh; users = $uarr
      first   = (Iso-Local $e.first); last = (Iso-Local $e.last)
      cc      = $(if ($g) { $g.cc } else { '' }); country = $(if ($g) { $g.c } else { '' }); city = $(if ($g) { $g.city } else { '' })
      ban     = $(if ($b) { if ($b.permanent) { 'perm' } else { 'temp' } } else { '' })
    }
  }
  $shameTotal = 0; foreach ($e in $shameMap.Values) { $shameTotal += $e.n }
  $shameMeta = @{
    ips         = $shameMap.Count; attempts = $shameTotal; ranked = $shameRows.Count; namesSeen = @($nameTot.Keys).Count
    topName     = $(if ($shameTopName) { $shameTopName.name } else { '' }); topNameN = $(if ($shameTopName) { $shameTopName.n } else { 0 })
    coveredFrom = $(if ($shameCoverage) { Iso-Local $shameCoverage.rdpFrom } else { $null })
    coveredTo   = $now.ToString('o')
  }
  if ($shameIngestError) { $shameMeta['ingestError'] = $shameIngestError }

  # ---------------- transactional multi-store commit ----------------
  # Step 1: Ensure .bak for all three stores holds the exact same pre-commit generation before any store is mutated
  foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
    if (Test-Path -LiteralPath $stPath) {
      Copy-Item -LiteralPath $stPath -Destination "$stPath.bak" -Force
    }
  }

  $preManifestJson = ([ordered]@{
    generationId   = $generationId
    status         = 'committing'
    startedAtUtc   = $nowDto.ToUniversalTime().ToString('o', $Inv)
    lastProcessed  = $stats.lastProcessed
  } | ConvertTo-Json -Depth 4 -Compress)
  Write-JsonAtomic -Path $manifestFile -JsonContent $preManifestJson -KeepBak $false

  $hourlyStoreJson = ([ordered]@{
    generationId = $generationId
    buckets      = $hourlyDisk
    totals       = $totalsOut
  } | ConvertTo-Json -Depth 6 -Compress)
  Write-JsonAtomic -Path $hourlyFile -JsonContent $hourlyStoreJson -KeepBak $false

  $recentJson = (ConvertTo-Json -InputObject @($recent) -Depth 4 -Compress)
  if ([string]::IsNullOrWhiteSpace($recentJson)) { $recentJson = '[]' }
  Write-JsonAtomic -Path $recentFile -JsonContent $recentJson -KeepBak $false

  if ($null -ne $TestHook -and $TestHook.ContainsKey('SimulateMidCommitCrash') -and $TestHook['SimulateMidCommitCrash']) {
    throw "Simulated mid-commit crash after hourly.json and recent.json before stats.json"
  }

  $statsStoreJson = ([ordered]@{
    generationId           = $generationId
    lastProcessed          = $stats.lastProcessed
    firstEvent             = $stats.firstEvent
    hourlyBackfill         = $stats.hourlyBackfill
    lastRecordIdSec        = $stats.lastRecordIdSec
    lastRecordIdSsh        = $stats.lastRecordIdSsh
    lastRecordIdRdp261     = $stats.lastRecordIdRdp261
    lastRecordIdLock       = $stats.lastRecordIdLock
    recentTruncatedUntil   = $stats.recentTruncatedUntil
    recentUntruncatedCount = $stats.recentUntruncatedCount
    pendingPreauth         = $stats.pendingPreauth
    daily                  = $dailyDisk
  } | ConvertTo-Json -Depth 6 -Compress)
  Write-JsonAtomic -Path $statsFile -JsonContent $statsStoreJson -KeepBak $false

  $todayKey = $nowDto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
  $payload = [ordered]@{
    generationId  = $generationId
    generated     = $nowDto.ToLocalTime().ToString('o', $Inv)
    host          = @{ name = $env:COMPUTERNAME; ip = '192.168.4.24'; wan = $hostIp }
    health        = $healthObj
    recentMeta    = $recentMeta
    summary       = @{
      fails5m        = $w5.total; fails1h = $w60.total; fails24h = $w1440.total
      failsToday     = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].fails } else { 0 })
      rdpConnToday   = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].rdpConn } else { 0 })
      lockoutsToday  = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].lockouts } else { 0 })
      rdp1h          = $w60.rdp; ssh1h = $w60.ssh
      hostileIPs1h   = $w60.ips; hostileIPs24h = $w1440.ips
      bans           = $bans.Count; bansPermanent = $permCount; bansTemp = $tempCount
      blockedTotal   = $blockedTotal; blockedSources = $drops.Count
      guardState     = $guard.state; guardLastRun = $guard.lastRun
    }
    series        = @($series.Keys | ForEach-Object { [pscustomobject]@{ t = $_; rdp = $series[$_].rdp; ssh = $series[$_].ssh } })
    recentCompact = @($recent | ForEach-Object { ,@($_.t, $_.ip, $_.vec, $_.user) })
    hourly        = $hourlyOut
    hourlyTotals  = $totalsOut
    span          = $span
    milestones    = $milestones
    bans          = @($bans | Sort-Object tries -Descending)
    shame         = @($shameRows)
    shameMeta     = $shameMeta
    topAttackers  = $topAttackers
    blockedTop    = $blockedTop
    scanPorts     = $scanPorts
    mapPoints     = $mapPoints
    serverPoint   = $serverPoint
    ports         = $ports
    guard         = $guard
    guardLog      = $guardLogTail
    history       = $hist
    daily         = $dailyOut2
  }
  $dataJson = ($payload | ConvertTo-Json -Depth 8 -Compress)
  Write-JsonAtomic -Path $dataFile -JsonContent $dataJson

  $postManifestJson = ([ordered]@{
    generationId     = $generationId
    status           = 'ok'
    committedAtUtc   = (Get-Date).ToUniversalTime().ToString('o', $Inv)
    lastProcessed    = $stats.lastProcessed
    lastRecordIdSec  = $stats.lastRecordIdSec
    lastRecordIdSsh  = $stats.lastRecordIdSsh
  } | ConvertTo-Json -Depth 4 -Compress)
  Write-JsonAtomic -Path $manifestFile -JsonContent $postManifestJson -KeepBak $false

  foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
    if (Test-Path -LiteralPath $stPath) {
      Copy-Item -LiteralPath $stPath -Destination "$stPath.bak" -Force
    }
  }

  try {
    $sample = @{ t = $nowDto.ToLocalTime().ToString('o', $Inv); f5 = $w5.total; rdp1h = $w60.rdp; bans = $bans.Count; ips1h = $w60.ips } | ConvertTo-Json -Compress
    Add-Content -LiteralPath $histFile -Value $sample -Encoding UTF8 -ErrorAction SilentlyContinue
  } catch {}

  exit 0
} finally {
  if ($hasHandle) {
    try { $mutex.ReleaseMutex() } catch {}
  }
  $mutex.Dispose()
}
.IPAddress -notmatch '^(169\.254|127\.)' } | Select-Object -First 1 -ExpandProperty IPAddress)
} catch {}
if (-not $hostIp) { $hostIp = '127.0.0.1' }

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
    if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    return $ipObj.ToString()
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($ipObj.IsIPv4MappedToIPv6) { return $ipObj.MapToIPv4().ToString() }
    return $ipObj.ToString().ToLowerInvariant()
  }
  return $null
}

function Is-ValidIPv4([string]$ip) {
  $c = ConvertTo-CanonicalIP $ip
  return ($null -ne $c -and $c -match '^\d{1,3}(\.\d{1,3}){3}$')
}

function Is-ValidIP([string]$ip) {
  return ($null -ne (ConvertTo-CanonicalIP $ip))
}

function Is-Private([string]$ip) {
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
    if ($b0 -ge 224) { return $true }
    return $false
  }
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($c -eq '::' -or $c -eq '::1') { return $true }
    $b0 = [int]$bytes[0]; $b1 = [int]$bytes[1]
    if ($b0 -eq 0xff) { return $true }
    if (($b0 -band 0xfe) -eq 0xfc) { return $true }
    if ($b0 -eq 0xfe -and ($b1 -band 0xc0) -eq 0x80) { return $true }
    return $false
  }
  return $true
}

function Write-JsonAtomic([string]$Path, [string]$JsonContent, [bool]$KeepBak = $true) {
  $tmp = "$Path.tmp.$PID"
  $bak = if ($KeepBak) { "$Path.bak" } else { $null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($tmp, $JsonContent, $enc)
  $lastErr = $null
  for ($attempt = 0; $attempt -lt 5; $attempt++) {
    try {
      if (Test-Path -LiteralPath $Path) {
        if ($bak) {
          [System.IO.File]::Replace($tmp, $Path, $bak, $true)
        } else {
          $tmpBak = "$Path.prev.$PID"
          [System.IO.File]::Replace($tmp, $Path, $tmpBak, $true)
          if (Test-Path -LiteralPath $tmpBak) { Remove-Item -LiteralPath $tmpBak -Force -ErrorAction SilentlyContinue }
        }
      } else {
        [System.IO.File]::Move($tmp, $Path)
        if ($bak) {
          [System.IO.File]::Copy($Path, $bak, $true)
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

function Read-JsonSafe([string]$Path, [scriptblock]$Validator = $null, [bool]$AllowBakFallback = $true) {
  $bak = "$Path.bak"
  $primaryExisted = Test-Path -LiteralPath $Path
  $bakExisted     = $AllowBakFallback -and (Test-Path -LiteralPath $bak)
  if (-not $primaryExisted -and -not $bakExisted) { return $null }

  if ($primaryExisted) {
    try {
      $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
            if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim([char]0, " ", "`t", "`r", "`n") -eq '') { return $null }
      if ($raw.Trim() -eq '[]') {
        $obj = @()
      } else {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $obj) { throw "File '$Path' parsed to null" }
      }
      if ($null -ne $Validator) { & $Validator $obj }
      return ,$obj
    } catch {
      $primaryErr = $_.Exception.Message
      if ($bakExisted) {
        $rawBak = [System.IO.File]::ReadAllText($bak, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($rawBak)) { throw "Primary '$Path' ($primaryErr) and backup '$bak' (empty) both unreadable" }
        if ($rawBak.Trim() -eq '[]') {
          $objBak = @()
        } else {
          $objBak = $rawBak | ConvertFrom-Json -ErrorAction Stop
          if ($null -eq $objBak) { throw "Primary '$Path' ($primaryErr) and backup '$bak' (null) both unreadable" }
        }
        if ($null -ne $Validator) { & $Validator $objBak }
        return ,$objBak
      }
      throw "Critical store '$Path' is corrupt ($primaryErr) and backup fallback is disabled or unavailable"
    }
  } else {
    $rawBak = [System.IO.File]::ReadAllText($bak, [System.Text.Encoding]::UTF8)
    if ($rawBak.Trim() -eq '[]') {
      $objBak = @()
    } else {
      $objBak = $rawBak | ConvertFrom-Json -ErrorAction Stop
      if ($null -eq $objBak) { throw "Backup '$bak' parsed to null" }
    }
    if ($null -ne $Validator) { & $Validator $objBak }
    return ,$objBak
  }
}

function Parse-TimestampDto($val) {
  if ($null -eq $val) { return $null }
  if ($val -is [DateTimeOffset]) { return $val }
  if ($val -is [datetime]) {
    if ($val.Kind -eq [System.DateTimeKind]::Unspecified) {
      return New-Object System.DateTimeOffset([datetime]::SpecifyKind($val, [System.DateTimeKind]::Local))
    }
    return New-Object System.DateTimeOffset($val)
  }
  $s = [string]$val
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  if ($s -match '^\d{4}-\d{2}-\d{2}T\d{2}$') {
    return [DateTimeOffset]::ParseExact($s, 'yyyy-MM-ddTHH', $Inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
  }
  return [DateTimeOffset]::Parse($s, $Inv, [System.Globalization.DateTimeStyles]::AssumeLocal)
}

function ConvertTo-UtcHourKey($val) {
  $dto = Parse-TimestampDto $val
  if ($null -eq $dto) { return $null }
  return $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
}

function ConvertTo-LocalDayKey($val) {
  $dto = Parse-TimestampDto $val
  if ($null -eq $dto) { return $null }
  return $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
}

# ===========================================================================
# Hall of Shame & SSH Canonical Parser (PERMIT-0011 / ADR-0009 / ADR-0013)
# ===========================================================================
function Test-CannotLogIn([string]$name, [string[]]$knownEnabled) {
  if ([string]::IsNullOrWhiteSpace($name)) { return $true }
  return -not ($knownEnabled -contains ($name -replace '^.*\\', '').ToLowerInvariant())
}

function Sanitize-Name([string]$name) {
  if ($null -eq $name) { return '(blank)' }
  $s = ($name -replace '^.*\\', '').Trim()
  $s = $s -replace '[\x00-\x1F\x7F]', ''
  if ([string]::IsNullOrWhiteSpace($s)) { return '(blank)' }
  if ($s.Length -gt 64) { $s = $s.Substring(0, 64) }
  return $s
}

function Parse-SshAuthLine([string]$m) {
  if ([string]::IsNullOrWhiteSpace($m)) { return $null }
  # Strip optional leading "sshd..." prefix if present in synthetic tests
  $clean = $m -replace '^sshd(?:\[\d+\])?:\s*', ''
  # Anchor strictly on the terminal "from <ip> port <port>" at the end of the line
  if ($clean -match '^(?i)Failed password for invalid user (?<u_inv>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)(?:\s+ssh2)?\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'failed_pw_invalid'; user = $Matches['u_inv']; ip = $cIp; port = $Matches['port']; invalid = $true }
  }
  if ($clean -match '^(?i)Failed password for (?<u_val>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)(?:\s+ssh2)?\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'failed_pw_valid'; user = $Matches['u_val']; ip = $cIp; port = $Matches['port']; invalid = $false }
  }
  if ($clean -match '^(?i)Invalid user (?<u_inv>.*)\s+from\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'invalid_banner'; user = $Matches['u_inv']; ip = $cIp; port = $Matches['port']; invalid = $true }
  }
  if ($clean -match '^(?i)Connection closed by (?<ckind>invalid|authenticating) user (?<u_cc>.*)\s+(?<ip>[0-9a-fA-F:.]+)\s+port\s+(?<port>\d+)\s+\[preauth\]\s*$') {
    $cIp = ConvertTo-CanonicalIP $Matches['ip']
    if ($null -eq $cIp) { return $null }
    return @{ kind = 'preauth_close'; user = $Matches['u_cc']; ip = $cIp; port = $Matches['port']; invalid = ($Matches['ckind'] -ieq 'invalid') }
  }
  return $null
}

function Get-SshInvalidName([string]$m) {
  $p = Parse-SshAuthLine $m
  if ($null -eq $p) { return $null }
  if ($p.kind -eq 'invalid_banner' -or $p.kind -eq 'failed_pw_invalid') {
    return $p.user
  }
  return $null
}

function Get-SshPortKey([string]$m, [datetime]$when) {
  # Anchor on the terminal "port <n>" so a username containing "port 9" cannot spoof the port key
  $pm = [regex]::Match($m, '\s+port\s+(\d+)(?:\s+ssh2)?(?:\s+\[preauth\])?\s*$')
  if (-not $pm.Success) { return $null }
  return "$($when.ToString('yyyyMMddHH'))|$($pm.Groups[1].Value)"
}

function Get-KnownEnabledNames {
  if ($null -ne $TestHook -and $TestHook.ContainsKey('LocalUsers')) {
    return @($TestHook['LocalUsers'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
  }
  try { return @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled } | ForEach-Object { $_.Name.ToLowerInvariant() }) } catch { return @() }
}

function Get-OperatorIps {
  $h = @{}
  $files = if ($null -ne $TestHook -and $TestHook.ContainsKey('OperatorFiles')) {
    @($TestHook['OperatorFiles'])
  } else {
    @('C:\srv\rdp-guard\allowlist.txt', 'C:\srv\rdp-guard\forgive.txt')
  }
  foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
      Get-Content -LiteralPath $f -ErrorAction SilentlyContinue | ForEach-Object {
        $l = ($_ -split '#')[0].Trim()
        if ($l) {
          $c = ConvertTo-CanonicalIP $l
          if ($null -ne $c) { $h[$c] = $true } else { $h[$l] = $true }
        }
      }
    }
  }
  return $h
}

function Add-ShameHit($map, [string]$ip, [string]$vec, [datetime]$when, [string]$display) {
  if (-not $map.ContainsKey($ip)) { $map[$ip] = @{ n = 0; rdp = 0; ssh = 0; users = @{}; first = $when; last = $when } }
  $e = $map[$ip]
  $e.n++
  if ($vec -eq 'RDP') { $e.rdp++ } else { $e.ssh++ }
  if ($when -lt $e.first) { $e.first = $when }
  if ($when -gt $e.last) { $e.last = $when }
  $k = $display.ToLowerInvariant()
  if (-not $e.users.ContainsKey($k)) { $e.users[$k] = @{ name = $display; n = 0 } }
  $e.users[$k].n++
}

function Iso-Local($t) {
  if (-not $t) { return $null }
  $dto = Parse-TimestampDto $t
  if ($null -eq $dto) { return [string]$t }
  return $dto.ToLocalTime().ToString('o', $Inv)
}

# ---------------- -SelfTest: fixture checks on the real artifact, no file writes ----------------
if ($SelfTest) {
  $fail = 0
  $known = @('operator')
  $cases = @(
    @{ n = 'operator';                           want = $false },
    @{ n = 'operator';                           want = $false },
    @{ n = 'SERVER01\\operator';           want = $false },
    @{ n = 'Administrator';                   want = $true  },
    @{ n = 'Guest';                           want = $true  },
    @{ n = 'x3908';                           want = $true  },
    @{ n = 'k8s';                             want = $true  },
    @{ n = '';                                want = $true  },
    @{ n = '   ';                             want = $true  },
    @{ n = 'SERVER01\Administrator';   want = $true  },
    @{ n = 'operator\\';                         want = $true  },
    @{ n = ' Operator';                          want = $true  }
  )
  foreach ($c in $cases) {
    $got = Test-CannotLogIn $c.n $known
    if ($got -ne $c.want) { $fail++; "FAIL Test-CannotLogIn('$($c.n)') got=$got want=$($c.want)" }
    else                  { "PASS Test-CannotLogIn('$($c.n)') -> $got" }
  }
  $san = @(
    @{ in = 'SERVER01\k8s'; want = 'k8s' },
    @{ in = "bad`tname";           want = 'badname' },
    @{ in = ('x' + [char]0 + 'y'); want = 'xy' },
    @{ in = '';                    want = '(blank)' },
    @{ in = '   ';                 want = '(blank)' },
    @{ in = ('a' * 100);           want = ('a' * 64) },
    @{ in = '  spaced  ';          want = 'spaced' }
  )
  foreach ($c in $san) {
    $got = Sanitize-Name $c.in
    if ($got -ne $c.want) { $fail++; "FAIL Sanitize-Name('$($c.in)') got='$got' want='$($c.want)'" }
    else                  { "PASS Sanitize-Name('$($c.in)') -> '$got'" }
  }
  $m = @{}
  Add-ShameHit $m '1.2.3.4' 'RDP' ([datetime]'2026-10-01T00:00:01') 'Administrator'
  Add-ShameHit $m '1.2.3.4' 'RDP' ([datetime]'2026-10-01T00:00:02') 'ADMINISTRATOR'
  Add-ShameHit $m '1.2.3.4' 'SSH' ([datetime]'2026-10-01T00:00:03') 'administrator'
  Add-ShameHit $m '5.6.7.8' 'SSH' ([datetime]'2026-10-01T00:00:04') 'k8s'
  $m1 = $m['1.2.3.4']; $m2 = $m['5.6.7.8']
  foreach ($x in @(
    @{ got = $m.Count;                     want = 2; label = 'distinct IPs' },
    @{ got = $m1.n;                        want = 3; label = 'ip1 total' },
    @{ got = $m1.rdp;                      want = 2; label = 'ip1 rdp' },
    @{ got = $m1.ssh;                      want = 1; label = 'ip1 ssh' },
    @{ got = @($m1.users.Keys).Count;      want = 1; label = 'ip1 case-variant names merged' },
    @{ got = $m1.users['administrator'].n; want = 3; label = 'ip1 name count' },
    @{ got = $m1.first.ToString('s');      want = '2026-10-01T00:00:01'; label = 'ip1 first' },
    @{ got = $m1.last.ToString('s');       want = '2026-10-01T00:00:03'; label = 'ip1 last' },
    @{ got = $m2.rdp;                      want = 0; label = 'ip2 rdp' }
  )) {
    if ($x.got -ne $x.want) { $fail++; "FAIL merge: $($x.label) got=$($x.got) want=$($x.want)" }
    else                    { "PASS merge: $($x.label) -> $($x.got)" }
  }
  $sshCases = @(
    @{ m = 'sshd: Invalid user emo from 1.2.3.4 port 45888'; want = 'emo' },
    @{ m = 'sshd: Failed password for invalid user root from 1.2.3.4 port 22 ssh2'; want = 'root' },
    @{ m = 'sshd: Invalid user  from 1.2.3.4 port 12345'; want = '' },
    @{ m = 'sshd: Invalid user bait from 203.0.113.7 port 9 from 2001:db8::1234 port 45678'; want = 'bait from 203.0.113.7 port 9' },
    @{ m = 'sshd: Connection closed by invalid user emo 1.2.3.4 port 45888 [preauth]'; want = $null },
    @{ m = 'sshd: Disconnecting invalid user test1 1.2.3.4 port 22: Too many authentication failures [preauth]'; want = $null },
    @{ m = 'sshd: Accepted password for operator from 1.2.3.4 port 22 ssh2'; want = $null }
  )
  foreach ($c in $sshCases) {
    $got = Get-SshInvalidName $c.m
    if ($got -ne $c.want) { $fail++; "FAIL Get-SshInvalidName('$($c.m)') got='$got' want='$($c.want)'" }
    else                  { "PASS Get-SshInvalidName('$($c.m)') -> '$got'" }
  }
  $injParsed = Parse-SshAuthLine 'Invalid user bait from 203.0.113.7 port 9 from 2001:db8::1234 port 45678'
  if ($null -eq $injParsed -or $injParsed.ip -ne '2001:db8::1234' -or $injParsed.port -ne '45678') {
    $fail++; "FAIL Parse-SshAuthLine username injection selected ip=$($injParsed.ip) port=$($injParsed.port)"
  } else {
    "PASS Parse-SshAuthLine username injection -> ip=2001:db8::1234 port=45678"
  }
  $t1 = [datetime]'2026-10-01T10:00:00'
  $t2 = [datetime]'2026-10-01T10:59:59'
  $t3 = [datetime]'2026-10-01T11:00:00'
  $a  = Get-SshPortKey 'Invalid user e from 1.2.3.4 port 45888' $t1
  $b  = Get-SshPortKey 'Failed password for invalid user e from 1.2.3.4 port 45888' $t2
  $c1 = Get-SshPortKey 'x from 1.2.3.4 port 22' $t1
  $c2 = Get-SshPortKey 'x from 1.2.3.4 port 23' $t1
  $c3 = Get-SshPortKey 'x from 1.2.3.4 port 22' $t3
  if ($a -ne $b)   { $fail++; "FAIL key: same attempt pair should share a key ($a vs $b)" } else { "PASS key: attempt pair shares key -> $a" }
  if ($c1 -eq $c2) { $fail++; 'FAIL key: different ports should differ' } else { 'PASS key: different ports differ' }
  if ($c1 -eq $c3) { $fail++; 'FAIL key: different hours should differ' } else { 'PASS key: different hours differ' }
  if ($null -ne (Get-SshPortKey 'nothing here' $t1)) { $fail++; 'FAIL key: no port should be null' } else { 'PASS key: no port -> null' }
  "SELFTEST: $(if ($fail -eq 0) { 'PASS' } else { "FAIL ($fail)" })"
  exit $(if ($fail -eq 0) { 0 } else { 1 })
}

if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }

# ===========================================================================
# Universal Writer Mutex (Global\SecDashCollector) across ALL writer modes
# ===========================================================================
$mutexName = if ($null -ne $TestHook -and $TestHook.ContainsKey('MutexName')) { [string]$TestHook['MutexName'] } else { 'Global\SecDashCollector' }
$mutexTimeoutMs = if ($null -ne $TestHook -and $TestHook.ContainsKey('MutexTimeoutMs')) { [int]$TestHook['MutexTimeoutMs'] } else { 15000 }
$mutex = New-Object System.Threading.Mutex($false, $mutexName)
$hasHandle = $false
try {
  try {
    $hasHandle = $mutex.WaitOne($mutexTimeoutMs, $false)
  } catch [System.Threading.AbandonedMutexException] {
    $hasHandle = $true
  }
  if (-not $hasHandle) {
    Write-Host "SecDashCollector mutex busy after ${mutexTimeoutMs}ms - exiting"
    exit $(if ($ShameBackfill) { 2 } else { 0 })
  }

  function Query-LogAfterRecordId([string]$LogName, $AfterRecordId, $EventId, [datetime]$FallbackStartTime) {
    $cleared = $false
    $effectiveAfter = if ($null -ne $AfterRecordId) { [int64]$AfterRecordId } else { $null }
    if ($null -ne $effectiveAfter) {
      try {
        $latest = @(Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop)
        if ($latest.Count -gt 0 -and $null -ne $latest[0].PSObject.Properties['RecordId']) {
          if ([int64]$latest[0].RecordId -lt $effectiveAfter) {
            $cleared = $true
            $effectiveAfter = $null
          }
        }
      } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
          throw "$LogName latest-event probe failed: $($_.Exception.Message)"
        }
        $cleared = $true
        $effectiveAfter = $null
      }
    }
    $events = @()
    try {
      if ($null -ne $effectiveAfter) {
        $xpath = if ($null -ne $EventId) {
          "*[System[(EventID=$([int]$EventId)) and (EventRecordID > $effectiveAfter)]]"
        } else {
          "*[System[(EventRecordID > $effectiveAfter)]]"
        }
        $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop)
      } else {
        $fh = @{ LogName = $LogName; StartTime = $FallbackStartTime }
        if ($null -ne $EventId) { $fh['Id'] = [int]$EventId }
        $events = @(Get-WinEvent -FilterHashtable $fh -ErrorAction Stop)
      }
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "$LogName query failed: $($_.Exception.Message)"
      }
    }
    return @{ events = $events; cleared = $cleared; effectiveAfter = $effectiveAfter }
  }

  function Import-ShameWindow($map, [datetime]$from, [datetime]$to, [string[]]$knownEnabled, $operatorIps, [hashtable]$shameCursor = $null, [bool]$FlushAllPending = $false) {
    if ($null -eq $shameCursor) {
      $shameCursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    }
    if ($null -ne $shameCursor.lastRecordIdSec) {
      $qSec = Query-LogAfterRecordId -LogName 'Security' -AfterRecordId $shameCursor.lastRecordIdSec -EventId 4625 -FallbackStartTime $from
      if ($qSec.cleared) { $shameCursor.lastRecordIdSec = $null }
      foreach ($e in ($qSec.events | Sort-Object RecordId)) {
        try {
          $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
          if ($null -ne $shameCursor.lastRecordIdSec -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSec) { continue }
          $x = [xml]$e.ToXml(); $d = @{}
          foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
          $ip = ConvertTo-CanonicalIP ([string]$d['IpAddress'])
          if ($null -eq $ip -or (Is-Private $ip)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          if ($operatorIps.ContainsKey($ip)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          if (-not (Test-CannotLogIn ([string]$d['TargetUserName']) $knownEnabled)) {
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
            continue
          }
          Add-ShameHit $map $ip 'RDP' $e.TimeCreated (Sanitize-Name ([string]$d['TargetUserName']))
          if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
        } catch {}
      }
    } else {
      $t = $from
      while ($t -lt $to) {
        $end = $t.AddHours(2); if ($end -gt $to) { $end = $to }
        $ev = @()
        try {
          $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$t; EndTime=$end.AddTicks(-1)} -ErrorAction Stop)
        } catch {
          if ($_.Exception.Message -notmatch 'No events were found') { throw }
        }
        foreach ($e in ($ev | Sort-Object RecordId)) {
          try {
            $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
            if ($null -ne $shameCursor.lastRecordIdSec -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSec) { continue }
            $x = [xml]$e.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $ip = ConvertTo-CanonicalIP ([string]$d['IpAddress'])
            if ($null -eq $ip -or (Is-Private $ip)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            if ($operatorIps.ContainsKey($ip)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            if (-not (Test-CannotLogIn ([string]$d['TargetUserName']) $knownEnabled)) {
              if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
              continue
            }
            Add-ShameHit $map $ip 'RDP' $e.TimeCreated (Sanitize-Name ([string]$d['TargetUserName']))
            if ($null -ne $rid) { $shameCursor.lastRecordIdSec = $rid }
          } catch {}
        }
        $t = $end
      }
    }
    $oev = @()
    if ($null -ne $shameCursor.lastRecordIdSsh) {
      $qSsh = Query-LogAfterRecordId -LogName 'OpenSSH/Operational' -AfterRecordId $shameCursor.lastRecordIdSsh -EventId $null -FallbackStartTime $from
      if ($qSsh.cleared) { $shameCursor.lastRecordIdSsh = $null }
      $oev = $qSsh.events
    } else {
      try {
        $oev = @(Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$from; EndTime=$to.AddTicks(-1)} -ErrorAction Stop)
      } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { throw }
      }
    }
    $pendingShame = if ($null -ne $shameCursor.pendingShame) { $shameCursor.pendingShame } else { @{} }
    foreach ($e in ($oev | Sort-Object RecordId)) {
      try {
        $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
        if ($null -ne $shameCursor.lastRecordIdSsh -and $null -ne $rid -and $rid -le [int64]$shameCursor.lastRecordIdSsh) { continue }
        $p = Parse-SshAuthLine $e.Message
        if ($null -eq $p) {
          if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
          continue
        }
        $ip = $p.ip
        if ((Is-Private $ip) -or $operatorIps.ContainsKey($ip)) {
          if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
          continue
        }
        $pKey = "$ip|$($p.port)"
        if ($p.kind -eq 'invalid_banner') {
          if ($pendingShame.ContainsKey($pKey)) {
            $oldP = $pendingShame[$pKey]
            if (Test-CannotLogIn $oldP.user $knownEnabled) {
              Add-ShameHit $map $ip 'SSH' (Parse-TimestampDto $oldP.when).LocalDateTime (Sanitize-Name $oldP.user)
            }
          }
          $pendingShame[$pKey] = @{ user = $p.user; when = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('o', $Inv) }
        } elseif ($p.kind -eq 'failed_pw_invalid' -or $p.kind -eq 'failed_pw_valid') {
          if ($pendingShame.ContainsKey($pKey)) { [void]$pendingShame.Remove($pKey) }
          if ($p.invalid -or (Test-CannotLogIn $p.user $knownEnabled)) {
            Add-ShameHit $map $ip 'SSH' $e.TimeCreated (Sanitize-Name $p.user)
          }
        } elseif ($p.kind -eq 'preauth_close') {
          if ($pendingShame.ContainsKey($pKey)) {
            $pend = $pendingShame[$pKey]
            [void]$pendingShame.Remove($pKey)
            if (Test-CannotLogIn $pend.user $knownEnabled) {
              Add-ShameHit $map $ip 'SSH' (Parse-TimestampDto $pend.when).LocalDateTime (Sanitize-Name $pend.user)
            }
          }
        }
        if ($null -ne $rid) { $shameCursor.lastRecordIdSsh = $rid }
      } catch {}
    }
    $toDto = Parse-TimestampDto $to
    foreach ($pk in @($pendingShame.Keys)) {
      $pend = $pendingShame[$pk]
      $pendDto = Parse-TimestampDto $pend.when
      if ($FlushAllPending -or (($toDto - $pendDto).TotalSeconds -ge 120)) {
        [void]$pendingShame.Remove($pk)
        $ip = ($pk -split '\|')[0]
        if (Test-CannotLogIn $pend.user $knownEnabled) {
          Add-ShameHit $map $ip 'SSH' $pendDto.LocalDateTime (Sanitize-Name $pend.user)
        }
      }
    }
    $shameCursor.pendingShame = $pendingShame
  }

  function Initialize-ShameMap {
    $map = @{}; $since = $null; $coverage = $null
    $cursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    $sj = $null
    try {
      $sj = Read-JsonSafe -Path $shameFile
    } catch {
      return @{ ok = $false; error = "$($_.Exception.Message)"; map = @{}; since = $null; coverage = $null; cursor = $cursor }
    }
    if ($null -eq $sj) { return @{ ok = $true; map = $map; since = $since; coverage = $coverage; cursor = $cursor } }
    try {
      if ($sj.lastProcessed) { $since = (Parse-TimestampDto $sj.lastProcessed).LocalDateTime }
      if ($null -ne $sj.PSObject.Properties['lastRecordIdSec'] -and $null -ne $sj.lastRecordIdSec) { $cursor.lastRecordIdSec = [int64]$sj.lastRecordIdSec }
      if ($null -ne $sj.PSObject.Properties['lastRecordIdSsh'] -and $null -ne $sj.lastRecordIdSsh) { $cursor.lastRecordIdSsh = [int64]$sj.lastRecordIdSsh }
      if ($null -ne $sj.PSObject.Properties['pendingShame'] -and $null -ne $sj.pendingShame) {
        foreach ($pp in $sj.pendingShame.PSObject.Properties) {
          $cursor.pendingShame[$pp.Name] = @{ user = [string]$pp.Value.user; when = [string]$pp.Value.when }
        }
      }
      $coverage = $sj.coverage
      foreach ($p in $sj.ips.PSObject.Properties) {
        $users = @{}
        foreach ($q in $p.Value.users.PSObject.Properties) {
          if ([string]::IsNullOrEmpty([string]$q.Name)) { throw "empty username key for $($p.Name)" }
          $users[$q.Name.ToLowerInvariant()] = @{ name = [string]$q.Name; n = [int]$q.Value }
        }
        $map[$p.Name] = @{
          n     = [int]$p.Value.n
          rdp   = [int]$p.Value.rdp
          ssh   = [int]$p.Value.ssh
          users = $users
          first = (Parse-TimestampDto $p.Value.first).LocalDateTime
          last  = (Parse-TimestampDto $p.Value.last).LocalDateTime
        }
      }
      return @{ ok = $true; map = $map; since = $since; coverage = $coverage; cursor = $cursor }
    } catch {
      return @{ ok = $false; error = "$($_.Exception.Message)"; map = @{}; since = $null; coverage = $null; cursor = $cursor }
    }
  }

  function Save-ShameMap($map, [datetime]$lastProcessed, $coverage, [hashtable]$cursor = $null) {
    foreach ($e in $map.Values) {
      if (@($e.users.Keys).Count -gt 25) {
        $nu = @{}
        foreach ($u in ($e.users.Values | Sort-Object { $_.n } -Descending | Select-Object -First 25)) { $nu[$u.name.ToLowerInvariant()] = $u }
        $e.users = $nu
      }
    }
    if ($map.Count -gt 5000) {
      foreach ($v in @($map.GetEnumerator() | Sort-Object { $_.Value.n } | Select-Object -First ($map.Count - 5000))) { $map.Remove($v.Key) }
    }
    $ipsOut = @{}
    foreach ($k in $map.Keys) {
      $e = $map[$k]
      $u = @{}
      foreach ($q in ($e.users.Values | Sort-Object { $_.n } -Descending)) { if ($q.name) { $u[$q.name] = [int]$q.n } }
      $ipsOut[$k] = @{
        n     = [int]$e.n
        rdp   = [int]$e.rdp
        ssh   = [int]$e.ssh
        users = $u
        first = (Iso-Local $e.first)
        last  = (Iso-Local $e.last)
      }
    }
    if ($coverage) {
      foreach ($ck in @('rdpFrom', 'sshFrom', 'backfilledAt')) {
        if ($coverage[$ck]) { $coverage[$ck] = (Iso-Local $coverage[$ck]) }
      }
    }
    $obj = [ordered]@{
      stateVersion    = 1
      lastProcessed   = $lastProcessed.ToString('o')
      lastRecordIdSec = $(if ($null -ne $cursor) { $cursor.lastRecordIdSec } else { $null })
      lastRecordIdSsh = $(if ($null -ne $cursor) { $cursor.lastRecordIdSsh } else { $null })
      pendingShame    = $(if ($null -ne $cursor -and $null -ne $cursor.pendingShame) { $cursor.pendingShame } else { @{} })
      coverage        = $coverage
      ips             = $ipsOut
    }
    Write-JsonAtomic -Path $shameFile -JsonContent ($obj | ConvertTo-Json -Depth 6 -Compress)
  }

  if ($ShameBackfill) {
    $nowB = Get-Date
    $known = Get-KnownEnabledNames
    if ($known.Count -eq 0) { Write-Error 'no enabled local accounts readable - refusing to backfill'; exit 2 }
    $op = Get-OperatorIps
    try { $rdpOldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $rdpOldest = $nowB.AddDays(-7) }
    try { $sshOldest = (Get-WinEvent -LogName 'OpenSSH/Operational' -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $sshOldest = $nowB }
    Write-Host "backfill scan: RDP 4625 from $rdpOldest ; SSH from $sshOldest ; enabled accounts: $($known -join ',')"
    $map = @{}
    $bfCursor = @{ lastRecordIdSec = $null; lastRecordIdSsh = $null; pendingShame = @{} }
    Import-ShameWindow $map $rdpOldest $nowB $known $op $bfCursor $true
    $coverage = @{ rdpFrom = $rdpOldest.ToString('o'); sshFrom = $sshOldest.ToString('o'); backfilledAt = $nowB.ToString('o'); knownUsers = $known }
    Save-ShameMap $map $nowB $coverage $bfCursor
    $tot = 0; foreach ($e in $map.Values) { $tot += $e.n }
    Write-Host "backfill done: $($map.Count) IPs / $tot attempts"
    exit 0
  }

  $now = if ($null -ne $TestHook -and $TestHook.ContainsKey('Now')) { [datetime]$TestHook['Now'] } else { Get-Date }
  $generationId = "{0}-{1}" -f $now.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ', $Inv), $PID

  # ---------------- crash recovery check on commit-manifest.json (fail-closed if .bak stores missing or mismatched) ----------------
  if (Test-Path -LiteralPath $manifestFile) {
    $prevManifest = Read-JsonSafe -Path $manifestFile
    if ($null -ne $prevManifest -and [string]$prevManifest.status -ne 'ok') {
      Write-Host "WARNING: previous generation $($prevManifest.generationId) had status=$($prevManifest.status); verifying and restoring consistent .bak stores"
      foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
        if (-not (Test-Path -LiteralPath "$stPath.bak")) {
          throw "CRITICAL: commit-manifest status is '$($prevManifest.status)' but required backup '$stPath.bak' is missing - FAIL-CLOSED"
        }
      }
      $statsBakObj  = Read-JsonSafe -Path "$statsFile.bak" -Validator { param($o) if ($null -eq $o.PSObject.Properties['daily']) { throw "stats.json.bak missing daily" } }
      $hourlyBakObj = Read-JsonSafe -Path "$hourlyFile.bak"
      $recentBakObj = Read-JsonSafe -Path "$recentFile.bak"
      $sGen = if ($null -ne $statsBakObj.PSObject.Properties['generationId']) { [string]$statsBakObj.generationId } else { '' }
      $hGen = if ($null -ne $hourlyBakObj.PSObject.Properties['generationId']) { [string]$hourlyBakObj.generationId } else { '' }
      if ($sGen -and $hGen -and ($sGen -ne $hGen)) {
        throw "CRITICAL: backup generation mismatch between stats.json.bak ($sGen) and hourly.json.bak ($hGen) - FAIL-CLOSED"
      }
      foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
        Copy-Item -LiteralPath "$stPath.bak" -Destination $stPath -Force -ErrorAction Stop
      }
    }
  }

  # ---------------- load incremental ingest state (fail-stop on corruption) ----------------
  $stats = @{
    lastProcessed          = $null
    firstEvent             = $null
    hourlyBackfill         = $false
    lastRecordIdSec        = $null
    lastRecordIdSsh        = $null
    lastRecordIdRdp261     = $null
    lastRecordIdLock       = $null
    recentTruncatedUntil   = $null
    recentUntruncatedCount = 0
    pendingPreauth         = @{}
    daily                  = @{}
  }

  $loadedStatsObj = Read-JsonSafe -Path $statsFile -Validator {
    param($o)
    if ($null -eq $o.PSObject.Properties['daily']) { throw "stats.json missing 'daily' property" }
  }
  if ($null -ne $loadedStatsObj) {
    $stats.lastProcessed  = $loadedStatsObj.lastProcessed
    $stats.firstEvent     = $loadedStatsObj.firstEvent
    $stats.hourlyBackfill = [bool]$loadedStatsObj.hourlyBackfill
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdSec'] -and $null -ne $loadedStatsObj.lastRecordIdSec) {
      $stats.lastRecordIdSec = [int64]$loadedStatsObj.lastRecordIdSec
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdSsh'] -and $null -ne $loadedStatsObj.lastRecordIdSsh) {
      $stats.lastRecordIdSsh = [int64]$loadedStatsObj.lastRecordIdSsh
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdRdp261'] -and $null -ne $loadedStatsObj.lastRecordIdRdp261) {
      $stats.lastRecordIdRdp261 = [int64]$loadedStatsObj.lastRecordIdRdp261
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['lastRecordIdLock'] -and $null -ne $loadedStatsObj.lastRecordIdLock) {
      $stats.lastRecordIdLock = [int64]$loadedStatsObj.lastRecordIdLock
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['recentTruncatedUntil'] -and $null -ne $loadedStatsObj.recentTruncatedUntil) {
      $stats.recentTruncatedUntil = [string]$loadedStatsObj.recentTruncatedUntil
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['recentUntruncatedCount'] -and $null -ne $loadedStatsObj.recentUntruncatedCount) {
      $stats.recentUntruncatedCount = [int]$loadedStatsObj.recentUntruncatedCount
    }
    if ($null -ne $loadedStatsObj.PSObject.Properties['pendingPreauth'] -and $null -ne $loadedStatsObj.pendingPreauth) {
      foreach ($pp in $loadedStatsObj.pendingPreauth.PSObject.Properties) {
        $stats.pendingPreauth[$pp.Name] = @{
          ip   = [string]$pp.Value.ip
          port = [string]$pp.Value.port
          user = [string]$pp.Value.user
          t    = [string]$pp.Value.t
        }
      }
    }
    if ($loadedStatsObj.daily) {
      foreach ($p in $loadedStatsObj.daily.PSObject.Properties) {
        $d = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} }
        if ($p.Value.fails)    { $d.fails    = [int]$p.Value.fails }
        if ($p.Value.rdpConn)  { $d.rdpConn  = [int]$p.Value.rdpConn }
        if ($p.Value.ssh)      { $d.ssh      = [int]$p.Value.ssh }
        if ($p.Value.lockouts) { $d.lockouts = [int]$p.Value.lockouts }
        if ($p.Value.ips)      { foreach ($q in $p.Value.ips.PSObject.Properties) { $d.ips[$q.Name] = [int]$q.Value } }
        $d.totalIps = if ($null -ne $p.Value.PSObject.Properties['totalIps'] -and [int]$p.Value.totalIps -gt $d.ips.Count) { [int]$p.Value.totalIps } else { $d.ips.Count }
        $stats.daily[$p.Name] = $d
      }
    }
  }

  if (-not $stats.lastProcessed) {
    try {
      $oldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
      $stats.lastProcessed = $oldest.AddSeconds(-1).ToString('o')
    } catch {
      $stats.lastProcessed = $now.AddHours(-24).ToString('o')
    }
  }
  $since = (Parse-TimestampDto $stats.lastProcessed).LocalDateTime

  $recent = @()
  $loadedRecent = Read-JsonSafe -Path $recentFile
  if ($null -ne $loadedRecent) {
    $recent = @($loadedRecent)
  }

  if (-not $stats.firstEvent) {
    if ($recent.Count -gt 0) {
      $oldest = @($recent | ForEach-Object { $_.t } | Sort-Object)[0]
      $stats.firstEvent = (Parse-TimestampDto $oldest).ToLocalTime().ToString('o', $Inv)
    } elseif ($stats.daily.Keys.Count -gt 0) {
      $firstDay = @($stats.daily.Keys | Sort-Object)[0]
      $stats.firstEvent = ([datetime]::ParseExact("$firstDay 00:00:00", 'yyyy-MM-dd HH:mm:ss', $Inv)).ToString('o')
    }
  }

  # ---------------- load hourly history store (migrating legacy keys to UTC & preserving uncapped totals) ----------------
  $hourly       = @{}
  $hourlyTotals = @{}  # hk -> @([int]$rdpTotal, [int]$sshTotal, [int]$uniqueIps)
  $loadedHourly = Read-JsonSafe -Path $hourlyFile
  if ($null -ne $loadedStatsObj -and $null -ne $loadedHourly) {
    $sGenLoad = if ($null -ne $loadedStatsObj.PSObject.Properties['generationId']) { [string]$loadedStatsObj.generationId } else { '' }
    $hGenLoad = if ($null -ne $loadedHourly.PSObject.Properties['generationId']) { [string]$loadedHourly.PSObject.Properties['generationId'].Value } else { '' }
    if ($sGenLoad -and $hGenLoad -and ($sGenLoad -ne $hGenLoad)) {
      throw "CRITICAL: cross-store generation mismatch between stats.json ($sGenLoad) and hourly.json ($hGenLoad) - FAIL-CLOSED"
    }
  }
  if ($null -ne $loadedHourly) {
    $bucketsObj = if ($null -ne $loadedHourly.PSObject.Properties['buckets']) { $loadedHourly.buckets } else { $loadedHourly }
    $totalsObj  = if ($null -ne $loadedHourly.PSObject.Properties['totals'])  { $loadedHourly.totals }  else { $null }
    foreach ($p in $bucketsObj.PSObject.Properties) {
      if ($p.Name -in @('buckets', 'totals', 'generationId')) { continue }
      $utcKey = ConvertTo-UtcHourKey $p.Name
      if ($null -eq $utcKey) { continue }
      if (-not $hourly.ContainsKey($utcKey)) { $hourly[$utcKey] = @{} }
      $m = $hourly[$utcKey]
      $sumR = 0; $sumS = 0
      foreach ($q in $p.Value.PSObject.Properties) {
        $cIp = ConvertTo-CanonicalIP $q.Name
        if ($null -eq $cIp) { $cIp = $q.Name }
        $r0 = [int]$q.Value[0]; $s0 = [int]$q.Value[1]
        if ($m.ContainsKey($cIp)) {
          $m[$cIp] = @([int]$m[$cIp][0] + $r0, [int]$m[$cIp][1] + $s0)
        } else {
          $m[$cIp] = @($r0, $s0)
        }
        $sumR += $r0; $sumS += $s0
      }
      if ($null -ne $totalsObj -and $null -ne $totalsObj.PSObject.Properties[$p.Name]) {
        $tv = $totalsObj.PSObject.Properties[$p.Name].Value
        $hourlyTotals[$utcKey] = @([Math]::Max($sumR, [int]$tv[0]), [Math]::Max($sumS, [int]$tv[1]), [Math]::Max($m.Count, [int]$tv[2]))
      } else {
        $hourlyTotals[$utcKey] = @($sumR, $sumS, $m.Count)
      }
    }
  }

  function Add-HourlyEvent([string]$utcKey, [string]$ip, [string]$vec) {
    if (-not $hourly.ContainsKey($utcKey)) {
      $hourly[$utcKey] = @{}
      $hourlyTotals[$utcKey] = @(0, 0, 0)
    }
    $hm = $hourly[$utcKey]
    $isNewIp = -not $hm.ContainsKey($ip)
    $pair = if ($isNewIp) { @(0, 0) } else { $hm[$ip] }
    if ($vec -eq 'RDP') { $pair[0] = [int]$pair[0] + 1 } else { $pair[1] = [int]$pair[1] + 1 }
    $hm[$ip] = $pair

    $ht = if ($hourlyTotals.ContainsKey($utcKey)) { $hourlyTotals[$utcKey] } else { @(0, 0, $hm.Count) }
    if ($vec -eq 'RDP') { $ht[0] = [int]$ht[0] + 1 } else { $ht[1] = [int]$ht[1] + 1 }
    if ($isNewIp) {
      $ht[2] = [Math]::Max($hm.Count, [int]$ht[2] + 1)
    } else {
      $ht[2] = [Math]::Max($hm.Count, [int]$ht[2])
    }
    $hourlyTotals[$utcKey] = $ht
  }

  $operatorIps = Get-OperatorIps
  $logClearedSec = $false
  $logClearedSsh = $false

  # ---------------- ingest: RDP failed logons (paginated / watermarked / operator-filtered) ----------------
  $newEvents = 0
  $ev = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('RdpEvents')) {
    $ev = @($TestHook['RdpEvents'])
  } else {
    $querySinceSec = if ($null -ne $stats.lastRecordIdSec) { $since.AddMinutes(-15) } else { $since }
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$querySinceSec} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "Security 4625 query failed: $($_.Exception.Message)"
      }
    }
  }

  if ($ev.Count -gt 0) {
    $evSorted = @($ev | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })
    $maxRecSec = if ($null -ne $evSorted[-1].PSObject.Properties['RecordId']) { [int64]$evSorted[-1].RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdSec -and $null -ne $maxRecSec -and $maxRecSec -lt $stats.lastRecordIdSec) {
      $logClearedSec = $true
      $stats.lastRecordIdSec = $null
    }
    foreach ($e in $evSorted) {
      $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
      if ($null -ne $stats.lastRecordIdSec -and $null -ne $rid) {
        if ($rid -le $stats.lastRecordIdSec) { continue }
      } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
        continue
      }
      if ($null -ne $e.PSObject.Properties['IpAddress']) {
        $rawIp = [string]$e.IpAddress
        $u     = [string]$e.TargetUserName
        $tCreated = $e.TimeCreated
      } else {
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $rawIp = $d['IpAddress']; $u = $d['TargetUserName']
        $tCreated = $e.TimeCreated
      }
      $ip = ConvertTo-CanonicalIP $rawIp
      # Filter invalid, private, and operator IPs BEFORE incrementing daily or hourly
      if ($null -eq $ip -or (Is-Private $ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
        continue
      }
      if ($operatorIps.ContainsKey($ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
        continue
      }

      $dto = Parse-TimestampDto $tCreated
      $day = $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
      if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
      $stats.daily[$day].fails++
      if (-not $stats.daily[$day].ips.ContainsKey($ip)) {
        $stats.daily[$day].ips[$ip] = 0
        $stats.daily[$day].totalIps = [Math]::Max([int]$stats.daily[$day].totalIps + 1, $stats.daily[$day].ips.Count)
      }
      $stats.daily[$day].ips[$ip]++

      $isoT = $dto.ToLocalTime().ToString('o', $Inv)
      $recent += [pscustomobject]@{ t = $isoT; ip = $ip; user = (Sanitize-Name $u); vec = 'RDP'; res = 'fail' }
      if (-not $stats.firstEvent -or $dto.LocalDateTime -lt (Parse-TimestampDto $stats.firstEvent).LocalDateTime) {
        $stats.firstEvent = $isoT
      }
      $hk = $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
      Add-HourlyEvent -utcKey $hk -ip $ip -vec 'RDP'
      $newEvents++
      if ($null -ne $rid) { $stats.lastRecordIdSec = $rid }
    }
  }

  # ---------------- ingest: RDP listener connections (Event 261) ----------------
  $c261 = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('RdpConnEvents')) {
    $c261 = @($TestHook['RdpConnEvents'])
  } else {
    $querySince261 = if ($null -ne $stats.lastRecordIdRdp261) { $since.AddMinutes(-15) } else { $since }
    try {
      $c261 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=261; StartTime=$querySince261} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "TerminalServices 261 query failed: $($_.Exception.Message)"
      }
    }
  }
  foreach ($e in ($c261 | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })) {
    $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdRdp261 -and $null -ne $rid) {
      if ($rid -le $stats.lastRecordIdRdp261) { continue }
    } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
      continue
    }
    $day = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].rdpConn++
    if ($null -ne $rid) { $stats.lastRecordIdRdp261 = $rid }
  }

  # ---------------- ingest: lockouts (Event 4740) ----------------
  $lk = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('LockoutEvents')) {
    $lk = @($TestHook['LockoutEvents'])
  } else {
    $querySinceLock = if ($null -ne $stats.lastRecordIdLock) { $since.AddMinutes(-15) } else { $since }
    try {
      $lk = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$querySinceLock} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "Security 4740 query failed: $($_.Exception.Message)"
      }
    }
  }
  foreach ($e in ($lk | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })) {
    $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdLock -and $null -ne $rid) {
      if ($rid -le $stats.lastRecordIdLock) { continue }
    } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
      continue
    }
    $day = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].lockouts++
    if ($null -ne $rid) { $stats.lastRecordIdLock = $rid }
  }

  # ---------------- ingest: SSH (canonical attempt identity via pendingPreauth + terminal peer regex) ----------------
  function Record-SshAttempt([string]$ip, [string]$user, $whenVal) {
    $dto = Parse-TimestampDto $whenVal
    $day = $dto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
    if (-not $stats.daily.ContainsKey($day)) { $stats.daily[$day] = @{ fails = 0; rdpConn = 0; ssh = 0; lockouts = 0; totalIps = 0; ips = @{} } }
    $stats.daily[$day].ssh++
    if (-not $stats.daily[$day].ips.ContainsKey($ip)) {
      $stats.daily[$day].ips[$ip] = 0
      $stats.daily[$day].totalIps = [Math]::Max([int]$stats.daily[$day].totalIps + 1, $stats.daily[$day].ips.Count)
    }
    $stats.daily[$day].ips[$ip]++
    $isoT = $dto.ToLocalTime().ToString('o', $Inv)
    $script:recent += [pscustomobject]@{ t = $isoT; ip = $ip; user = (Sanitize-Name $user); vec = 'SSH'; res = 'fail' }
    $hk = $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
    Add-HourlyEvent -utcKey $hk -ip $ip -vec 'SSH'
    $script:newEvents++
  }

  $oev = @()
  if ($null -ne $TestHook -and $TestHook.ContainsKey('SshEvents')) {
    $oev = @($TestHook['SshEvents'])
  } else {
    $querySinceSsh = if ($null -ne $stats.lastRecordIdSsh) { $since.AddMinutes(-15) } else { $since }
    try {
      $oev = @(Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$querySinceSsh} -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        throw "OpenSSH/Operational query failed: $($_.Exception.Message)"
      }
    }
  }

  if ($oev.Count -gt 0) {
    $oevSorted = @($oev | Sort-Object { if ($null -ne $_.PSObject.Properties['RecordId']) { [int64]$_.RecordId } else { (Parse-TimestampDto $_.TimeCreated).UtcDateTime.Ticks } })
    $maxRecSsh = if ($null -ne $oevSorted[-1].PSObject.Properties['RecordId']) { [int64]$oevSorted[-1].RecordId } else { $null }
    if ($null -ne $stats.lastRecordIdSsh -and $null -ne $maxRecSsh -and $maxRecSsh -lt $stats.lastRecordIdSsh) {
      $logClearedSsh = $true
      $stats.lastRecordIdSsh = $null
    }
    foreach ($e in $oevSorted) {
      $rid = if ($null -ne $e.PSObject.Properties['RecordId']) { [int64]$e.RecordId } else { $null }
      if ($null -ne $stats.lastRecordIdSsh -and $null -ne $rid) {
        if ($rid -le $stats.lastRecordIdSsh) { continue }
      } elseif ((Parse-TimestampDto $e.TimeCreated).LocalDateTime -le $since) {
        continue
      }
      $p = Parse-SshAuthLine ([string]$e.Message)
      if ($null -eq $p) {
        if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
        continue
      }
      $ip = $p.ip
      if ((Is-Private $ip) -or $operatorIps.ContainsKey($ip)) {
        if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
        continue
      }
      $pKey = "$ip|$($p.port)"
      if ($p.kind -eq 'invalid_banner') {
        # If a previous unclosed invalid_banner on the same (ip,port) existed, flush it first
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          $oldPend = $stats.pendingPreauth[$pKey]
          Record-SshAttempt -ip $oldPend.ip -user $oldPend.user -whenVal $oldPend.t
        }
        $stats.pendingPreauth[$pKey] = @{
          ip   = $ip
          port = $p.port
          user = $p.user
          t    = (Parse-TimestampDto $e.TimeCreated).ToLocalTime().ToString('o', $Inv)
        }
      } elseif ($p.kind -eq 'failed_pw_invalid' -or $p.kind -eq 'failed_pw_valid') {
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          [void]$stats.pendingPreauth.Remove($pKey)
        }
        Record-SshAttempt -ip $ip -user $p.user -whenVal $e.TimeCreated
      } elseif ($p.kind -eq 'preauth_close') {
        if ($stats.pendingPreauth.ContainsKey($pKey)) {
          $pend = $stats.pendingPreauth[$pKey]
          [void]$stats.pendingPreauth.Remove($pKey)
          Record-SshAttempt -ip $pend.ip -user $pend.user -whenVal $pend.t
        }
      }
      if ($null -ne $rid) { $stats.lastRecordIdSsh = $rid }
    }
  }

  # Flush any pendingPreauth entries older than 120 seconds relative to $now
  $nowDto = Parse-TimestampDto $now
  foreach ($pk in @($stats.pendingPreauth.Keys)) {
    $pend = $stats.pendingPreauth[$pk]
    $pendDto = Parse-TimestampDto $pend.t
    if (($nowDto - $pendDto).TotalSeconds -ge 120) {
      [void]$stats.pendingPreauth.Remove($pk)
      Record-SshAttempt -ip $pend.ip -user $pend.user -whenVal $pendDto
    }
  }

  $stats.hourlyBackfill = $true

  # ---------------- prune hourly to local calendar midnight boundary (zero partial-day gap) ----------------
  # Never prune into 2026-10-10 because 2026-10-10T00..10 was already pruned before 2026-10-17;
  # starting at 2026-10-11T00:00:00 local midnight guarantees every day < hourlyStart is a full daily
  # day and every day >= hourlyStart is a full 24h hourly day.
  $minFullHourlyDayLocal = [datetime]::SpecifyKind([datetime]::ParseExact('2026-10-11 00:00:00', 'yyyy-MM-dd HH:mm:ss', $Inv), [System.DateTimeKind]::Local)
  $rolling14MidnightLocal = [datetime]::SpecifyKind($now.Date.AddDays(-14), [System.DateTimeKind]::Local)
  $cutMidnightLocal = if ($rolling14MidnightLocal -gt $minFullHourlyDayLocal) { $rolling14MidnightLocal } else { $minFullHourlyDayLocal }
  $cutHKeyUtc = (New-Object System.DateTimeOffset($cutMidnightLocal)).ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)

  foreach ($k in @($hourly.Keys)) {
    if ($k -lt $cutHKeyUtc) {
      [void]$hourly.Remove($k)
      [void]$hourlyTotals.Remove($k)
    }
  }
  # Ensure the exact midnight boundary key exists so index.html's hours[0].ms lands on local midnight
  if ($hourly.Count -gt 0 -and -not $hourly.ContainsKey($cutHKeyUtc)) {
    $earliestExisting = [string](@($hourly.Keys | Sort-Object)[0])
    if ($earliestExisting -gt $cutHKeyUtc) {
      $firstDayLocal = (Parse-TimestampDto $earliestExisting).ToLocalTime().Date
      $firstDayMidnightUtc = (New-Object System.DateTimeOffset([datetime]::SpecifyKind($firstDayLocal, [System.DateTimeKind]::Local))).ToUniversalTime().ToString('yyyy-MM-ddTHH:00:00Z', $Inv)
      if (-not $hourly.ContainsKey($firstDayMidnightUtc)) {
        $hourly[$firstDayMidnightUtc] = @{}
        $hourlyTotals[$firstDayMidnightUtc] = @(0, 0, 0)
      }
    }
  }

  # Build exported $hourlyOut (capped at top 400 IPs per hour for data.json) and uncapped $hourlyDisk (lossless on-disk store)
  $hourlyOut  = [ordered]@{}
  $hourlyDisk = [ordered]@{}
  $totalsOut  = [ordered]@{}
  foreach ($k in ($hourly.Keys | Sort-Object)) {
    $hm = $hourly[$k]
    $m400  = [ordered]@{}
    $mFull = [ordered]@{}
    $sortedIps = @($hm.GetEnumerator() | Sort-Object { [int]$_.Value[0] + [int]$_.Value[1] } -Descending)
    $sumR = 0; $sumS = 0
    for ($idx = 0; $idx -lt $sortedIps.Count; $idx++) {
      $entry = $sortedIps[$idx]
      $rVal = [int]$entry.Value[0]; $sVal = [int]$entry.Value[1]
      $sumR += $rVal; $sumS += $sVal
      if ($idx -lt 400) { $m400[$entry.Key] = @($rVal, $sVal) }
      $mFull[$entry.Key] = @($rVal, $sVal)
    }
    $ht = if ($hourlyTotals.ContainsKey($k)) {
      @([Math]::Max($sumR, [int]$hourlyTotals[$k][0]), [Math]::Max($sumS, [int]$hourlyTotals[$k][1]), [Math]::Max($hm.Count, [int]$hourlyTotals[$k][2]))
    } else {
      @($sumR, $sumS, $hm.Count)
    }
    $hourlyOut[$k]  = $m400
    $hourlyDisk[$k] = $mFull
    $totalsOut[$k]  = $ht
  }

  # ---------------- prune & cap recent (with sticky truncation metadata across runs for hybrid handoff) ----------------
  $cut24Dto = $nowDto.AddHours(-24)
  $recent = @($recent | Where-Object {
    try { (Parse-TimestampDto $_.t) -gt $cut24Dto } catch { $false }
  } | Sort-Object { (Parse-TimestampDto $_.t).UtcTicks } -Descending)

  $recentBeforeCap = $recent.Count
  $recentCap = if ($null -ne $TestHook -and $TestHook.ContainsKey('RecentCap')) { [int]$TestHook['RecentCap'] } else { 25000 }
  $truncatedThisRun = ($recentBeforeCap -gt $recentCap)
  if ($truncatedThisRun) {
    $recent = @($recent | Select-Object -First $recentCap)
  }
  $recentOldestTs = if ($recent.Count -gt 0) { [string]$recent[$recent.Count - 1].t } else { $null }
  if ($truncatedThisRun) {
    $stats.recentTruncatedUntil   = $recentOldestTs
    $stats.recentUntruncatedCount = $recentBeforeCap
  } elseif ($null -ne $stats.recentTruncatedUntil) {
    try {
      if ((Parse-TimestampDto $stats.recentTruncatedUntil) -le $cut24Dto) {
        $stats.recentTruncatedUntil   = $null
        $stats.recentUntruncatedCount = 0
      } else {
        $stats.recentUntruncatedCount = [Math]::Max($recentBeforeCap, [int]$stats.recentUntruncatedCount + $newEvents)
      }
    } catch {
      $stats.recentTruncatedUntil   = $null
      $stats.recentUntruncatedCount = 0
    }
  }
  $recentTruncated = ($truncatedThisRun -or ($null -ne $stats.recentTruncatedUntil))
  $effectiveOldestTs = if ($recentTruncated -and $null -ne $recentOldestTs) { $recentOldestTs } elseif ($null -ne $stats.recentTruncatedUntil) { $stats.recentTruncatedUntil } else { $recentOldestTs }
  $effectiveUntruncated = if ($recentTruncated) { [Math]::Max($recentBeforeCap, [int]$stats.recentUntruncatedCount) } else { $recentBeforeCap }
  $recentMeta = [ordered]@{
    truncated   = $recentTruncated
    oldest      = $effectiveOldestTs
    count       = $recent.Count
    untruncated = $effectiveUntruncated
    cap         = $recentCap
  }

  $stats.lastProcessed = $nowDto.ToLocalTime().ToString('o', $Inv)

  # ---------------- prepare dailyOut (400-IP projection for data.json) & dailyDisk (uncapped for stats.json) ----------------
  $dailyOut  = [ordered]@{}
  $dailyDisk = [ordered]@{}
  foreach ($k in ($stats.daily.Keys | Sort-Object)) {
    $ipsOut  = [ordered]@{}
    $ipsFull = [ordered]@{}
    $sortedDailyIps = @($stats.daily[$k].ips.GetEnumerator() | Sort-Object Value -Descending)
    for ($idx = 0; $idx -lt $sortedDailyIps.Count; $idx++) {
      $de = $sortedDailyIps[$idx]
      if ($idx -lt 400) { $ipsOut[$de.Key] = [int]$de.Value }
      $ipsFull[$de.Key] = [int]$de.Value
    }
    $trueTotalIps = [Math]::Max([int]$stats.daily[$k].totalIps, $stats.daily[$k].ips.Count)
    $dailyOut[$k] = [ordered]@{
      fails    = [int]$stats.daily[$k].fails
      rdpConn  = [int]$stats.daily[$k].rdpConn
      ssh      = [int]$stats.daily[$k].ssh
      lockouts = [int]$stats.daily[$k].lockouts
      totalIps = $trueTotalIps
      ips      = $ipsOut
    }
    $dailyDisk[$k] = [ordered]@{
      fails    = [int]$stats.daily[$k].fails
      rdpConn  = [int]$stats.daily[$k].rdpConn
      ssh      = [int]$stats.daily[$k].ssh
      lockouts = [int]$stats.daily[$k].lockouts
      totalIps = $trueTotalIps
      ips      = $ipsFull
    }
  }

  # ---------------- hall of shame: incremental ingest ----------------
  $shameMap = @{}; $shameIps = @{}; $shameCoverage = $null; $shameIngestError = ''
  if ($null -eq $TestHook -or -not $TestHook.ContainsKey('SkipShame')) {
    try {
      $knownEnabled = Get-KnownEnabledNames
      if ($knownEnabled.Count -eq 0) { throw 'no enabled local accounts readable' }
      $st = Initialize-ShameMap
      if (-not $st.ok) { throw "shame store unreadable, left untouched: $($st.error)" }
      $shameMap = $st.map; $shameCoverage = $st.coverage
      $shameSince = $st.since
      if (-not $shameSince) { $shameSince = $now }
      if ($shameSince -gt $now) { $shameSince = $now }
      if ($now -gt $shameSince -and $null -eq $TestHook) {
        Import-ShameWindow $shameMap $shameSince $now $knownEnabled $operatorIps $st.cursor $false
      }
      Save-ShameMap $shameMap $now $shameCoverage $st.cursor
      foreach ($k in $shameMap.Keys) { $shameIps[$k] = $true }
    } catch {
      $shameIngestError = "$($_.Exception.Message)"
    }
  }

  # ---------------- rolling windows ----------------
  function WindowStats([int]$minutes) {
    $limDto = $nowDto.AddMinutes(-$minutes)
    $set = @($recent | Where-Object { try { (Parse-TimestampDto $_.t) -gt $limDto } catch { $false } })
    $ips = @{}; $rdp = 0; $ssh = 0
    foreach ($r in $set) {
      if (-not $ips.ContainsKey($r.ip)) { $ips[$r.ip] = 0 }
      $ips[$r.ip]++
      if ($r.vec -eq 'RDP') { $rdp++ } else { $ssh++ }
    }
    return @{ total = $set.Count; ips = $ips.Count; rdp = $rdp; ssh = $ssh; set = $set }
  }
  $w5 = WindowStats 5; $w60 = WindowStats 60; $w1440 = WindowStats 1440

  $series = [ordered]@{}
  for ($i = 239; $i -ge 0; $i--) { $series[$now.AddMinutes(-$i).ToString('HH:mm')] = @{ rdp = 0; ssh = 0 } }
  foreach ($r in $recent) {
    $t = (Parse-TimestampDto $r.t).ToLocalTime().ToString('HH:mm')
    if ($series.Contains($t)) { if ($r.vec -eq 'RDP') { $series[$t].rdp++ } else { $series[$t].ssh++ } }
  }

  # ---------------- bans & firewall effective health ----------------
  $bans = @(); $permCount = 0; $tempCount = 0
  $banIpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if (Test-Path -LiteralPath $bansFile) {
    try {
      $bj = Read-JsonSafe -Path $bansFile
      if ($null -ne $bj -and $null -ne $bj.data -and $null -ne $bj.data.bans) {
        foreach ($p in $bj.data.bans.PSObject.Properties) {
          $cBanIp = ConvertTo-CanonicalIP ([string]$p.Name)
          if ($null -ne $cBanIp -and -not (Is-Private $cBanIp)) { [void]$banIpSet.Add($cBanIp) }
          $isPerm = -not $p.Value.until
          if ($isPerm) { $permCount++ } else { $tempCount++ }
          $bans += [pscustomobject]@{
            ip        = $p.Name
            permanent = $isPerm
            until     = $p.Value.until
            reason    = $p.Value.reason
            when      = $p.Value.bannedAt
            tries     = $(if ($p.Value.reason -match 'x(\d+)') { [int]$Matches[1] } else { 0 })
          }
        }
      }
    } catch {}
  }

  $fwRuleInstances = 0
  $fwEnabledBlockingInstances = 0
  $fwFiltersAllAny = $true
  $fwUniqueIps = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if ($null -ne $TestHook -and $TestHook.ContainsKey('FirewallRules')) {
    $fwRules = @($TestHook['FirewallRules'])
    $fwRuleInstances = $fwRules.Count
    foreach ($r in $fwRules) {
      if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {
        $fwEnabledBlockingInstances++
        foreach ($a in @($r.RemoteAddress)) {
          $c = ConvertTo-CanonicalIP ([string]$a)
          if ($null -ne $c -and -not (Is-Private $c)) { [void]$fwUniqueIps.Add($c) }
        }
      }
    }
  } else {
    try {
      $fwRules = @(Get-NetFirewallRule -DisplayName 'AUTO-BAN-SPRAY' -ErrorAction SilentlyContinue)
      $fwRuleInstances = $fwRules.Count
      foreach ($r in $fwRules) {
        if ($r.Enabled.ToString() -eq 'True' -and $r.Direction.ToString() -eq 'Inbound' -and $r.Action.ToString() -eq 'Block') {
          $fwEnabledBlockingInstances++
          $af   = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
          $pf   = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
          $appf = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
          $svcf = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
          $if   = $r | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue
          if (
            $r.Profile.ToString() -ne 'Any' -or
            $null -eq $af -or [string]$af.LocalAddress -ne 'Any' -or
            $null -eq $pf -or [string]$pf.Protocol -ne 'Any' -or [string]$pf.LocalPort -ne 'Any' -or [string]$pf.RemotePort -ne 'Any' -or
            $null -eq $appf -or [string]$appf.Program -ne 'Any' -or
            $null -eq $svcf -or [string]$svcf.Service -ne 'Any' -or
            $null -eq $if -or [string]$if.InterfaceType -ne 'Any'
          ) {
            $fwFiltersAllAny = $false
          }
          if ($null -ne $af) {
            foreach ($a in @($af.RemoteAddress)) {
              $c = ConvertTo-CanonicalIP ([string]$a)
              if ($null -ne $c -and -not (Is-Private $c)) { [void]$fwUniqueIps.Add($c) }
            }
          }
        }
      }
    } catch {
      $fwFiltersAllAny = $false
    }
  }
  $fwSetParity = if ($null -ne $TestHook -and -not $TestHook.ContainsKey('EnforceBanParity')) {
    ($bans.Count -eq 0 -or $fwUniqueIps.Count -gt 0)
  } else {
    ($fwUniqueIps.Count -eq $banIpSet.Count) -and (@($banIpSet | Where-Object { -not $fwUniqueIps.Contains($_) }).Count -eq 0)
  }
  $healthObj = [ordered]@{
    status                   = 'ok'
    generationId             = $generationId
    firewallRuleInstances    = $fwRuleInstances
    firewallEnabledInstances = $fwEnabledBlockingInstances
    firewallActiveRuleCount  = $fwUniqueIps.Count
    firewallEffectiveOk      = ($fwRuleInstances -eq 1 -and $fwEnabledBlockingInstances -eq 1 -and $fwFiltersAllAny -and $fwSetParity)
    logClearedSec            = $logClearedSec
    logClearedSsh            = $logClearedSsh
  }

  # ---------------- firewall log: what the wall is stopping ----------------
  $drops = @{}; $portHits = @{}
  if (Test-Path -LiteralPath $fwLog) {
    try {
      $lines = Get-Content -LiteralPath $fwLog -Tail 4000 -ErrorAction SilentlyContinue
      foreach ($l in $lines) {
        if ($l.StartsWith('#')) { continue }
        $f = $l -split '\s+'
        if ($f.Count -lt 17) { continue }
        if ($f[2] -ne 'DROP') { continue }
        if ($f[16] -ne 'RECEIVE') { continue }
        $ip = ConvertTo-CanonicalIP $f[4]; $port = $f[7]; $ts = "$($f[0]) $($f[1])"
        if ($null -eq $ip -or (Is-Private $ip)) { continue }
        if (-not $drops.ContainsKey($ip)) { $drops[$ip] = @{ n = 0; last = $ts; port = $port } }
        $drops[$ip].n++
        $drops[$ip].last = $ts
        if ($drops[$ip].port -ne $port) { $drops[$ip].port = "$($drops[$ip].port),$port" }
        $portHits[$port] = 1 + [int]$portHits[$port]
      }
    } catch {}
  }
  $blockedTop = @($drops.GetEnumerator() | Sort-Object { $_.Value.n } -Descending | Select-Object -First 40 |
    ForEach-Object { [pscustomobject]@{ ip = $_.Key; hits = $_.Value.n; last = $_.Value.last; port = $_.Value.port } })
  $scanPorts = @($portHits.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 |
    ForEach-Object { [pscustomobject]@{ port = $_.Key; hits = $_.Value } })
  $blockedTotal = 0; foreach ($k in $drops.Keys) { $blockedTotal += $drops[$k].n }

  # ---------------- guard ----------------
  $guard = @{ state = 'Ready'; lastRun = $now.ToString('MM/dd/yyyy HH:mm:ss'); lastResult = 0; nextRun = $now.AddMinutes(1).ToString('MM/dd/yyyy HH:mm:ss') }
  if ($null -eq $TestHook) {
    try {
      $t = Get-ScheduledTask -TaskName 'RDP-Guard (anti-spray)' -ErrorAction Stop
      $i = Get-ScheduledTaskInfo -TaskName 'RDP-Guard (anti-spray)' -ErrorAction Stop
      $guard = @{ state = "$($t.State)"; lastRun = "$($i.LastRunTime)"; lastResult = $i.LastTaskResult; nextRun = "$($i.NextRunTime)" }
    } catch {}
  }
  $guardLogTail = @(); if (Test-Path -LiteralPath $guardLog) { $guardLogTail = @(Get-Content -LiteralPath $guardLog -Tail 25 -ErrorAction SilentlyContinue) }

  # ---------------- per-IP aggregates (24h) ----------------
  $agg = @{}
  foreach ($r in $recent) {
    if (-not $agg.ContainsKey($r.ip)) {
      $agg[$r.ip] = @{ n = 0; rdp = 0; ssh = 0; first = $r.t; last = $r.t; hours = (New-Object 'int[]' 24) }
    }
    $a = $agg[$r.ip]
    $a.n++
    if ($r.vec -eq 'RDP') { $a.rdp++ } else { $a.ssh++ }
    $rDto = Parse-TimestampDto $r.t
    if ($rDto -gt (Parse-TimestampDto $a.last))  { $a.last  = $r.t }
    if ($rDto -lt (Parse-TimestampDto $a.first)) { $a.first = $r.t }
    $h = [int][math]::Floor(($nowDto - $rDto).TotalHours)
    if ($h -ge 0 -and $h -le 23) { $a.hours[$h]++ }
  }
  $topAttackers = @($agg.GetEnumerator() | Sort-Object { $_.Value.n } -Descending | Select-Object -First 40 | ForEach-Object {
    $ipKey = $_.Key
    [pscustomobject]@{
      ip      = $ipKey
      tries   = $_.Value.n
      first   = $_.Value.first
      last    = $_.Value.last
      vectors = (@( @('RDP') * [int]($_.Value.rdp -gt 0) ; @('SSH') * [int]($_.Value.ssh -gt 0) ) | Where-Object { $_ }) -join '+'
      banned  = [bool]($bans | Where-Object { $_.ip -eq $ipKey } | Select-Object -First 1)
    }
  })

  # ---------------- geolocation (cached) ----------------
  $geo = @{}
  try {
    $gLoaded = Read-JsonSafe -Path $geoFile
    if ($null -ne $gLoaded) { foreach ($p in $gLoaded.PSObject.Properties) { $geo[$p.Name] = $p.Value } }
  } catch {}
  $geoAge = 3600
  if (Test-Path -LiteralPath $geoFile) { $geoAge = ($now - (Get-Item -LiteralPath $geoFile).LastWriteTime).TotalSeconds }
  if ($null -eq $TestHook -and $geoAge -gt 900) {
    $cand = @{}
    foreach ($b in $bans)          { $cand[$b.ip] = $true }
    foreach ($a in $topAttackers)  { $cand[$a.ip] = $true }
    foreach ($x in $blockedTop)    { $cand[$x.ip] = $true }
    foreach ($r in $recent)        { $cand[$r.ip] = $true }
    foreach ($k in $shameIps.Keys) { $cand[$k] = $true }
    $need = @(@($hostIp) + @($cand.Keys)) | Where-Object { -not $geo.ContainsKey($_) -and -not (Is-Private $_) } | Select-Object -Unique -First 450
    if ($need.Count -gt 0) {
      try {
        for ($i = 0; $i -lt $need.Count; $i += 90) {
          $chunk = $need[$i..([math]::Min($i+89, $need.Count-1))]
          $body = ($chunk | ForEach-Object { '{"query":"' + $_ + '"}' }) -join ','
          $r = Invoke-RestMethod -Uri 'http://ip-api.com/batch?fields=query,country,countryCode,city,lat,lon,as,isp' -Method Post -Body ("[" + $body + "]") -ContentType 'application/json' -TimeoutSec 25
          foreach ($x in $r) { if ($x.query) { $geo[$x.query] = @{ c = $x.country; cc = $x.countryCode; city = $x.city; lat = $x.lat; lon = $x.lon; "as" = $x.as; isp = $x.isp } } }
        }
        Write-JsonAtomic -Path $geoFile -JsonContent ($geo | ConvertTo-Json -Depth 4 -Compress)
      } catch {}
    }
  }

  $dcWords = @('linode','digitalocean','amazon','aws','google','microsoft','azure','ovh','hetzner','contabo','vultr',
               'leaseweb','choopa','scaleway','oracle','alibaba','tencent','m247','colocrossing','sharktech','psychz',
               'quadranet','hostinger','server','hosting','datacenter','data center','cloud','vpn','proxy','lease',
               'netcup','ionos','namecheap','gcore','servers.com','interserver','hostwinds','racknerd','frantech',
               'zomro','aeza','melbicom','stark-industries','thehive','cogent','tzulo','colo')
  function Is-Hosting($asn, $isp) {
    $s = ("$asn $isp").ToLowerInvariant()
    foreach ($w in $dcWords) { if ($s -like "*$w*") { return $true } }
    return $false
  }
  function GeoOf($ip) {
    if ($geo.ContainsKey($ip)) { return $geo[$ip] } else { return $null }
  }

  foreach ($b in $bans) {
    $g = GeoOf $b.ip
    $b | Add-Member -NotePropertyName cc      -NotePropertyValue $(if ($g) { $g.cc } else { '' }) -Force
    $b | Add-Member -NotePropertyName country -NotePropertyValue $(if ($g) { $g.c } else { '' }) -Force
    $b | Add-Member -NotePropertyName city    -NotePropertyValue $(if ($g) { $g.city } else { '' }) -Force
  }
  foreach ($a in $topAttackers) {
    $g = GeoOf $a.ip
    $a | Add-Member -NotePropertyName cc      -NotePropertyValue $(if ($g) { $g.cc } else { '' }) -Force
    $a | Add-Member -NotePropertyName country -NotePropertyValue $(if ($g) { $g.c } else { '' }) -Force
    $a | Add-Member -NotePropertyName city    -NotePropertyValue $(if ($g) { $g.city } else { '' }) -Force
  }

  $banMap = @{}
  foreach ($b in $bans) { $banMap[$b.ip] = $b }

  $mapPoints = @()
  foreach ($ip in ($agg.Keys + $banMap.Keys + $drops.Keys | Select-Object -Unique)) {
    $g = GeoOf $ip
    if (-not $g -or $null -eq $g.lat) { continue }
    $a = $agg[$ip]; $b = $banMap[$ip]; $dr = $drops[$ip]
    $category = 'active'
    if ($b) { $category = $(if ($b.permanent) { 'perm' } else { 'temp' }) }
    elseif ($dr) { $category = 'blocked' }
    $hours = if ($a) { $a.hours } else { New-Object 'int[]' 24 }
    $mapPoints += [pscustomobject]@{
      ip       = $ip
      lat      = $g.lat; lon = $g.lon
      city     = $g.city; country = $g.c; cc = $g.cc
      asn      = $g.'as'; isp = $g.isp
      hosting  = (Is-Hosting $g.'as' $g.isp)
      category = $category
      attempts = $(if ($a) { $a.n } else { 0 })
      rdp      = $(if ($a) { $a.rdp } else { 0 })
      ssh      = $(if ($a) { $a.ssh } else { 0 })
      first    = $(if ($a) { $a.first } else { $null })
      last     = $(if ($a) { $a.last } else { $null })
      drops    = $(if ($dr) { $dr.n } else { 0 })
      dropPort = $(if ($dr) { $dr.port } else { $null })
      hours    = @($hours)
    }
  }

  $gp = GeoOf $hostIp
  $serverPoint = [pscustomobject]@{
    ip      = $hostIp
    lat     = $(if ($gp) { $gp.lat } else { $null })
    lon     = $(if ($gp) { $gp.lon } else { $null })
    city    = $(if ($gp) { $gp.city } else { '' })
    country = $(if ($gp) { $gp.c } else { '' })
  }

  # ---------------- ports (dynamically check sshd_config & live :443 qbit-webui-proxy) ----------------
  $sshKeyOnly = $false
  $sshdCfgPath = 'C:\ProgramData\ssh\sshd_config'
  if (Test-Path -LiteralPath $sshdCfgPath) {
    try {
      $activePwLines = @(Get-Content -LiteralPath $sshdCfgPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*PasswordAuthentication\s+no\b' })
      if ($activePwLines.Count -gt 0) { $sshKeyOnly = $true }
    } catch {}
  }
  $sshNote = if ($sshKeyOnly) { 'key-only, PasswordAuthentication no' } else { 'password auth enabled; brute-force guarded' }

  $ports = @(
    @{ port = 3389;  svc = 'RDP (your daily tool)';      wan = 'OPEN';    note = 'router forwards it; brute-force guarded' },
    @{ port = 22;    svc = 'SSH';                        wan = 'OPEN';    note = $sshNote },
    @{ port = 8096;  svc = 'Jellyfin (HTTP)';            wan = 'OPEN';    note = 'plain http - LAN use' },
    @{ port = 8920;  svc = 'Jellyfin (HTTPS)';           wan = 'OPEN';    note = 'TLS enabled - use this remotely' },
    @{ port = 47984; svc = 'Sunshine/Apollo';            wan = 'OPEN';    note = 'streaming 47984-48010' },
    @{ port = 8099;  svc = 'This dashboard';             wan = 'LAN';     note = 'internal only by design' },
    @{ port = 443;   svc = 'qBittorrent WebUI (TLS)';    wan = 'LAN/VPN'; note = 'qbit-webui-proxy -> 127.0.0.1:8082 (LAN + Tailscale)' },
    @{ port = 9696;  svc = 'Prowlarr';                   wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 6767;  svc = 'Bazarr';                     wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 8088;  svc = 'submarine web server';       wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 2179;  svc = 'Hyper-V management';         wan = 'BLOCKED'; note = 'internal only' },
    @{ port = 135;   svc = 'Windows RPC';                wan = 'BLOCKED'; note = 'WAN-BLOCK rule' }
  )
  if ($null -eq $TestHook) {
    foreach ($p in $ports) { $p.listen = [bool](Get-NetTCPConnection -State Listen -LocalPort $p.port -ErrorAction SilentlyContinue | Select-Object -First 1) }
  } else {
    foreach ($p in $ports) { $p.listen = $true }
  }

  # ---------------- history / retention ----------------
  $hist = @{}
  if ($null -eq $TestHook) {
    try { $hist.securityOldest   = "$((Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.sshOldest        = "$((Get-WinEvent -LogName 'OpenSSH/Operational' -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.rdpSessionOldest = "$((Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.systemOldest     = "$((Get-WinEvent -LogName System -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.appOldest        = "$((Get-WinEvent -LogName Application -Oldest -MaxEvents 1).TimeCreated)" } catch {}
    try { $hist.osInstall        = "$((Get-CimInstance Win32_OperatingSystem).InstallDate)" } catch {}
    try { $hist.sshdConfig       = "$((Get-Item 'C:\ProgramData\ssh\sshd_config').CreationTime)" } catch {}
  }

  $dailyOut2 = @()
  foreach ($k in ($stats.daily.Keys | Sort-Object)) {
    $trueTotalIps = [Math]::Max([int]$stats.daily[$k].totalIps, $stats.daily[$k].ips.Count)
    $dailyOut2 += [pscustomobject]@{
      day        = $k
      fails      = [int]$stats.daily[$k].fails
      rdpConn    = [int]$stats.daily[$k].rdpConn
      ssh        = [int]$stats.daily[$k].ssh
      lockouts   = [int]$stats.daily[$k].lockouts
      hostileIPs = $trueTotalIps
      totalIps   = $trueTotalIps
      ips        = $dailyOut[$k].ips
    }
  }

  # ---------------- full span of the record + historical milestones ----------------
  $dayKeys = @($stats.daily.Keys | Sort-Object)
  $hKeys   = @($hourly.Keys | Sort-Object)
  $recStart = $now.AddHours(-24)
  if ($stats.firstEvent) {
    $recStart = (Parse-TimestampDto $stats.firstEvent).LocalDateTime
  }
  if ($hKeys.Count -gt 0) {
    $h0Local = (Parse-TimestampDto $hKeys[0]).LocalDateTime
    if ($h0Local -lt $recStart) { $recStart = $h0Local }
  }
  if ($dayKeys.Count -gt 0) {
    $d0Local = [datetime]::ParseExact($dayKeys[0] + ' 00:00:00', 'yyyy-MM-dd HH:mm:ss', $Inv)
    if ($d0Local -lt $recStart) { $recStart = $d0Local }
  }
  $span = @{ t0 = ([datetime]::SpecifyKind($recStart, [System.DateTimeKind]::Local)).ToString('o'); t1 = $now.ToString('o') }

  $milestones = @()
  function Add-Milestone($t, $label) {
    if (-not $t) { return }
    try {
      $dto = Parse-TimestampDto $t
      $script:milestones += @{ t = $dto.ToLocalTime().ToString('o', $Inv); label = $label }
    } catch {}
  }
  if ($null -eq $TestHook) {
    Add-Milestone $(try { (Get-CimInstance Win32_OperatingSystem).InstallDate.ToString('o') } catch { $null }) 'Windows installed'
  }
  Add-Milestone $hist.sshdConfig 'SSH server configured'
  Add-Milestone $hist.rdpSessionOldest 'Remote desktop sessions begin'
  Add-Milestone $hist.sshOldest 'Oldest surviving SSH attack evidence'
  Add-Milestone $hist.securityOldest 'Security log begins (was 20 MB - older data lost)'
  Add-Milestone $hist.systemOldest 'System log begins'
  Add-Milestone $recStart.ToString('o') 'Record-keeping begins (this dashboard)'

  # ---------------- hall of shame: ranked rows for the page ----------------
  $nameTot = @{}
  foreach ($e in $shameMap.Values) {
    foreach ($u in $e.users.Values) {
      $k = $u.name.ToLowerInvariant()
      if (-not $nameTot.ContainsKey($k)) { $nameTot[$k] = @{ name = $u.name; n = 0 } }
      $nameTot[$k].n += $u.n
    }
  }
  $shameTopName = $nameTot.Values | Sort-Object { $_.n } -Descending | Select-Object -First 1
  $shameRows = @()
  foreach ($k in ($shameMap.Keys | Sort-Object { $shameMap[$_].n } -Descending | Select-Object -First 200)) {
    $e = $shameMap[$k]; $g = GeoOf $k; $b = $banMap[$k]
    $uarr = @()
    foreach ($u in ($e.users.Values | Sort-Object { $_.n } -Descending | Select-Object -First 6)) { $uarr += ,@([string]$u.name, [int]$u.n) }
    $shameRows += [pscustomobject]@{
      ip      = $k; n = [int]$e.n; rdp = [int]$e.rdp; ssh = [int]$e.ssh; users = $uarr
      first   = (Iso-Local $e.first); last = (Iso-Local $e.last)
      cc      = $(if ($g) { $g.cc } else { '' }); country = $(if ($g) { $g.c } else { '' }); city = $(if ($g) { $g.city } else { '' })
      ban     = $(if ($b) { if ($b.permanent) { 'perm' } else { 'temp' } } else { '' })
    }
  }
  $shameTotal = 0; foreach ($e in $shameMap.Values) { $shameTotal += $e.n }
  $shameMeta = @{
    ips         = $shameMap.Count; attempts = $shameTotal; ranked = $shameRows.Count; namesSeen = @($nameTot.Keys).Count
    topName     = $(if ($shameTopName) { $shameTopName.name } else { '' }); topNameN = $(if ($shameTopName) { $shameTopName.n } else { 0 })
    coveredFrom = $(if ($shameCoverage) { Iso-Local $shameCoverage.rdpFrom } else { $null })
    coveredTo   = $now.ToString('o')
  }
  if ($shameIngestError) { $shameMeta['ingestError'] = $shameIngestError }

  # ---------------- transactional multi-store commit ----------------
  # Step 1: Ensure .bak for all three stores holds the exact same pre-commit generation before any store is mutated
  foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
    if (Test-Path -LiteralPath $stPath) {
      Copy-Item -LiteralPath $stPath -Destination "$stPath.bak" -Force
    }
  }

  $preManifestJson = ([ordered]@{
    generationId   = $generationId
    status         = 'committing'
    startedAtUtc   = $nowDto.ToUniversalTime().ToString('o', $Inv)
    lastProcessed  = $stats.lastProcessed
  } | ConvertTo-Json -Depth 4 -Compress)
  Write-JsonAtomic -Path $manifestFile -JsonContent $preManifestJson -KeepBak $false

  $hourlyStoreJson = ([ordered]@{
    generationId = $generationId
    buckets      = $hourlyDisk
    totals       = $totalsOut
  } | ConvertTo-Json -Depth 6 -Compress)
  Write-JsonAtomic -Path $hourlyFile -JsonContent $hourlyStoreJson -KeepBak $false

  $recentJson = (ConvertTo-Json -InputObject @($recent) -Depth 4 -Compress)
  if ([string]::IsNullOrWhiteSpace($recentJson)) { $recentJson = '[]' }
  Write-JsonAtomic -Path $recentFile -JsonContent $recentJson -KeepBak $false

  if ($null -ne $TestHook -and $TestHook.ContainsKey('SimulateMidCommitCrash') -and $TestHook['SimulateMidCommitCrash']) {
    throw "Simulated mid-commit crash after hourly.json and recent.json before stats.json"
  }

  $statsStoreJson = ([ordered]@{
    generationId           = $generationId
    lastProcessed          = $stats.lastProcessed
    firstEvent             = $stats.firstEvent
    hourlyBackfill         = $stats.hourlyBackfill
    lastRecordIdSec        = $stats.lastRecordIdSec
    lastRecordIdSsh        = $stats.lastRecordIdSsh
    lastRecordIdRdp261     = $stats.lastRecordIdRdp261
    lastRecordIdLock       = $stats.lastRecordIdLock
    recentTruncatedUntil   = $stats.recentTruncatedUntil
    recentUntruncatedCount = $stats.recentUntruncatedCount
    pendingPreauth         = $stats.pendingPreauth
    daily                  = $dailyDisk
  } | ConvertTo-Json -Depth 6 -Compress)
  Write-JsonAtomic -Path $statsFile -JsonContent $statsStoreJson -KeepBak $false

  $todayKey = $nowDto.ToLocalTime().ToString('yyyy-MM-dd', $Inv)
  $payload = [ordered]@{
    generationId  = $generationId
    generated     = $nowDto.ToLocalTime().ToString('o', $Inv)
    host          = @{ name = $env:COMPUTERNAME; ip = '192.168.4.24'; wan = $hostIp }
    health        = $healthObj
    recentMeta    = $recentMeta
    summary       = @{
      fails5m        = $w5.total; fails1h = $w60.total; fails24h = $w1440.total
      failsToday     = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].fails } else { 0 })
      rdpConnToday   = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].rdpConn } else { 0 })
      lockoutsToday  = $(if ($stats.daily.ContainsKey($todayKey)) { $stats.daily[$todayKey].lockouts } else { 0 })
      rdp1h          = $w60.rdp; ssh1h = $w60.ssh
      hostileIPs1h   = $w60.ips; hostileIPs24h = $w1440.ips
      bans           = $bans.Count; bansPermanent = $permCount; bansTemp = $tempCount
      blockedTotal   = $blockedTotal; blockedSources = $drops.Count
      guardState     = $guard.state; guardLastRun = $guard.lastRun
    }
    series        = @($series.Keys | ForEach-Object { [pscustomobject]@{ t = $_; rdp = $series[$_].rdp; ssh = $series[$_].ssh } })
    recentCompact = @($recent | ForEach-Object { ,@($_.t, $_.ip, $_.vec, $_.user) })
    hourly        = $hourlyOut
    hourlyTotals  = $totalsOut
    span          = $span
    milestones    = $milestones
    bans          = @($bans | Sort-Object tries -Descending)
    shame         = @($shameRows)
    shameMeta     = $shameMeta
    topAttackers  = $topAttackers
    blockedTop    = $blockedTop
    scanPorts     = $scanPorts
    mapPoints     = $mapPoints
    serverPoint   = $serverPoint
    ports         = $ports
    guard         = $guard
    guardLog      = $guardLogTail
    history       = $hist
    daily         = $dailyOut2
  }
  $dataJson = ($payload | ConvertTo-Json -Depth 8 -Compress)
  Write-JsonAtomic -Path $dataFile -JsonContent $dataJson

  $postManifestJson = ([ordered]@{
    generationId     = $generationId
    status           = 'ok'
    committedAtUtc   = (Get-Date).ToUniversalTime().ToString('o', $Inv)
    lastProcessed    = $stats.lastProcessed
    lastRecordIdSec  = $stats.lastRecordIdSec
    lastRecordIdSsh  = $stats.lastRecordIdSsh
  } | ConvertTo-Json -Depth 4 -Compress)
  Write-JsonAtomic -Path $manifestFile -JsonContent $postManifestJson -KeepBak $false

  foreach ($stPath in @($statsFile, $hourlyFile, $recentFile)) {
    if (Test-Path -LiteralPath $stPath) {
      Copy-Item -LiteralPath $stPath -Destination "$stPath.bak" -Force
    }
  }

  try {
    $sample = @{ t = $nowDto.ToLocalTime().ToString('o', $Inv); f5 = $w5.total; rdp1h = $w60.rdp; bans = $bans.Count; ips1h = $w60.ips } | ConvertTo-Json -Compress
    Add-Content -LiteralPath $histFile -Value $sample -Encoding UTF8 -ErrorAction SilentlyContinue
  } catch {}

  exit 0
} finally {
  if ($hasHandle) {
    try { $mutex.ReleaseMutex() } catch {}
  }
  $mutex.Dispose()
}
