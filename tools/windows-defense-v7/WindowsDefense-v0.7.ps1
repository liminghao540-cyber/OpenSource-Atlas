# Windows Defense v0.7 - correlated monitoring with approval-gated temporary outbound blocks
# Target: Windows 10 / Windows PowerShell 5.1
[CmdletBinding()]
param([switch]$Once)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $root 'config.json'
$dataDir = Join-Path $root 'data'
$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $dataDir,$logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $logDir "WindowsDefense-v0.7-$stamp.log"
$eventsPath = Join-Path $dataDir 'events.jsonl'
$ledgerPath = Join-Path $dataDir 'response-ledger-v0.7.jsonl'
$statePath = Join-Path $dataDir 'state-v0.7.json'

$cfg = @{
    PollSeconds = 8
    HighRiskThreshold = 60
    MediumRiskThreshold = 35
    NewConnectionAlert = $true
    AlertOnNewListener = $true
    MonitorFirewall = $true
    ReadDefenderEvents = $true
    MaxEventsPerRun = 500
    MaxSeenEventKeys = 1500
    ResponseMode = 'MonitorOnly'
    EnableApprovalBlocks = $false
    TemporaryBlockMinutes = 10
    MaxOwnedFirewallRules = 5
}
try {
    if (Test-Path -LiteralPath $cfgPath) {
        $u = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        if ($u.PollSeconds -ge 5 -and $u.PollSeconds -le 60) { $cfg.PollSeconds = [int]$u.PollSeconds }
        if ($u.HighRiskThreshold -ge 40 -and $u.HighRiskThreshold -le 100) { $cfg.HighRiskThreshold = [int]$u.HighRiskThreshold }
        if ($u.MediumRiskThreshold -ge 20 -and $u.MediumRiskThreshold -lt $cfg.HighRiskThreshold) { $cfg.MediumRiskThreshold = [int]$u.MediumRiskThreshold }
        foreach ($k in @('NewConnectionAlert','AlertOnNewListener','MonitorFirewall','ReadDefenderEvents','EnableApprovalBlocks')) {
            if ($null -ne $u.$k) { $cfg[$k] = [bool]$u.$k }
        }
        if ($u.MaxEventsPerRun -ge 100 -and $u.MaxEventsPerRun -le 2000) { $cfg.MaxEventsPerRun = [int]$u.MaxEventsPerRun }
        if ($u.MaxSeenEventKeys -ge 100 -and $u.MaxSeenEventKeys -le 5000) { $cfg.MaxSeenEventKeys = [int]$u.MaxSeenEventKeys }
        if (@('MonitorOnly','Approval') -contains [string]$u.ResponseMode) { $cfg.ResponseMode = [string]$u.ResponseMode }
        if ($u.TemporaryBlockMinutes -ge 1 -and $u.TemporaryBlockMinutes -le 60) { $cfg.TemporaryBlockMinutes = [int]$u.TemporaryBlockMinutes }
        if ($u.MaxOwnedFirewallRules -ge 1 -and $u.MaxOwnedFirewallRules -le 10) { $cfg.MaxOwnedFirewallRules = [int]$u.MaxOwnedFirewallRules }
    }
} catch { Write-Warning 'Invalid config; safe defaults will be used.' }

$script:Seen = @{}
$script:LastDefenderRecord = 0L
$script:PreviousConnections = @{}
$script:PreviousListeners = @{}
$script:PreviousFirewall = @()
$script:ProcessCache = @{}
$script:ProcessConnectionCounts = @{}
$script:OwnedRules = @{}
$script:FirewallOwnershipMarker = 'ManagedBy=WindowsDefense-v0.7;Scope=TemporaryOutboundBlock'

function Write-Log([string]$Level,[string]$Message) {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
    switch ($Level) {
        'ALERT' { Write-Host $line -ForegroundColor Red }
        'HIGH' { Write-Host $line -ForegroundColor Magenta }
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line -ForegroundColor Cyan }
    }
}
function Get-Fingerprint([string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Save-State {
    try {
        $keys = @($script:Seen.Keys | Select-Object -Last $cfg.MaxSeenEventKeys)
        [ordered]@{ UpdatedAt=(Get-Date).ToString('o'); LastDefenderRecord=$script:LastDefenderRecord; SeenKeys=$keys; OwnedRules=@($script:OwnedRules.Values) } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    } catch { Write-Log 'WARN' 'Could not save deduplication state.' }
}
function Add-Event([string]$Type,[string]$Key,[int]$Score,[string]$Severity,[string]$Summary,[object]$Evidence) {
    if ($script:Seen.ContainsKey($Key)) { return $false }
    $script:Seen[$Key] = Get-Date
    $record = [pscustomobject]@{
        Timestamp=(Get-Date).ToString('o'); Type=$Type; EventKey=$Key
        RiskScore=$Score; Severity=$Severity; Summary=$Summary; Evidence=$Evidence
    }
    try {
        ($record | ConvertTo-Json -Depth 7 -Compress) | Add-Content -LiteralPath $eventsPath -Encoding UTF8
        Write-Log $Severity "RISK=$Score/100 type=$Type $Summary"
    } catch { Write-Log 'WARN' 'Could not append event record.' }
    return $true
}
function Get-ProcessEvidence([int]$Id) {
    $name='unknown'; $path=$null; $signature='Unavailable'; $hash=$null
    try {
        $p=Get-Process -Id $Id -ErrorAction Stop
        $name=$p.ProcessName
        try { $path=$p.Path } catch {}
    } catch {}
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $cacheKey="$Id|$path"
        if ($script:ProcessCache.ContainsKey($cacheKey)) { return $script:ProcessCache[$cacheKey] }
        try { $signature=[string](Get-AuthenticodeSignature -FilePath $path).Status } catch { $signature='CheckFailed' }
        try { $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch {}
    }
    $e=[pscustomobject]@{ PID=$Id; Name=$name; Path=$path; Signature=$signature; SHA256=$hash }
    if ($script:ProcessCache.Count -gt 300) { $script:ProcessCache.Clear() }
    $script:ProcessCache["$Id|$path"]=$e
    return $e
}
function Get-Risk([object]$Process,[int]$RemotePort,[int]$Fanout) {
    $score=10; $why=New-Object 'System.Collections.Generic.List[string]'
    if ($Process.Name -match '^(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)$') { $score+=25; $why.Add('script-or-system-tool') }
    if ($Process.Path -and $Process.Path -match '\\(AppData|Temp|Downloads)\\') { $score+=20; $why.Add('user-writable-location') }
    if ($Process.Signature -eq 'NotSigned') { $score+=15; $why.Add('unsigned-binary') }
    if ($Process.Signature -eq 'HashMismatch') { $score+=40; $why.Add('signature-hash-mismatch') }
    if ($Fanout -ge 20) { $score+=20; $why.Add('high-connection-fanout') }
    if ($RemotePort -eq 23 -or $RemotePort -eq 2323) { $score+=10; $why.Add('unusual-remote-port') }
    $score=[Math]::Min(100,$score)
    $severity='INFO'
    if ($score -ge $cfg.HighRiskThreshold) { $severity='HIGH' }
    elseif ($score -ge $cfg.MediumRiskThreshold) { $severity='WARN' }
    return [pscustomobject]@{ Score=$score; Severity=$severity; Evidence=@($why.ToArray()) }
}
function Get-TcpSnapshot([string]$State) {
    $out=@()
    try {
        foreach ($c in @(Get-NetTCPConnection -State $State -ErrorAction Stop)) {
            $id=[int]$c.OwningProcess
            $p=Get-ProcessEvidence $id
            if ($State -eq 'Established') {
                $key='{0}:{1}|{2}:{3}|{4}' -f $c.LocalAddress,$c.LocalPort,$c.RemoteAddress,$c.RemotePort,$id
                $out += [pscustomobject]@{ Key=$key; PID=$id; LocalAddress=[string]$c.LocalAddress; LocalPort=[int]$c.LocalPort; RemoteAddress=[string]$c.RemoteAddress; RemotePort=[int]$c.RemotePort; Process=$p }
            } else {
                $key='{0}|{1}|{2}' -f $c.LocalAddress,$c.LocalPort,$id
                $out += [pscustomobject]@{ Key=$key; PID=$id; Address=[string]$c.LocalAddress; Port=[int]$c.LocalPort; Process=$p }
            }
        }
    } catch { Write-Log 'WARN' "Could not query TCP state $State; check Windows 10 and PowerShell networking cmdlets." }
    return @($out)
}
function Get-FirewallState {
    try { return @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { '{0}|Enabled={1}|Inbound={2}|Outbound={3}' -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction } | Sort-Object) }
    catch { return @('UNAVAILABLE') }
}
function Read-DefenderEvents {
    if (-not $cfg.ReadDefenderEvents) { return }
    try {
        $items=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117} -MaxEvents $cfg.MaxEventsPerRun -ErrorAction Stop | Where-Object { [long]$_.RecordId -gt $script:LastDefenderRecord } | Sort-Object RecordId)
        foreach ($ev in $items) {
            $script:LastDefenderRecord=[Math]::Max($script:LastDefenderRecord,[long]$ev.RecordId)
            $msg=($ev.Message -replace '\s+',' ').Trim()
            if ($msg.Length -gt 350) { $msg=$msg.Substring(0,350) }
            $key="Defender|$($ev.RecordId)"
            $defenderScore=20; $defenderSeverity='INFO'; $defenderType='DefenderAction'
            if ($ev.Id -eq 1116) { $defenderScore=85; $defenderSeverity='ALERT'; $defenderType='DefenderDetection' }
            Add-Event $defenderType $key $defenderScore $defenderSeverity "Defender event id=$($ev.Id) record=$($ev.RecordId) $msg" ([pscustomobject]@{RecordId=$ev.RecordId;EventId=$ev.Id})
        }
    } catch { Write-Log 'INFO' 'Defender event log unavailable or not readable; continuing other checks.' }
}

function Add-Ledger([string]$Key,[string]$Action,[string]$Status,[string]$Details) {
    $entry=[pscustomobject]@{At=(Get-Date).ToString('o');EventKey=$Key;Action=$Action;Status=$Status;Details=$Details}
    try { ($entry | ConvertTo-Json -Depth 5 -Compress) | Add-Content -LiteralPath $ledgerPath -Encoding UTF8 }
    catch { Write-Log 'WARN' 'Could not write response ledger.' }
}
function Test-PublicUnicastAddress([string]$RawAddress) {
    $ip=$null
    if (-not [System.Net.IPAddress]::TryParse($RawAddress,[ref]$ip)) { return $false }
    if ([System.Net.IPAddress]::IsLoopback($ip) -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6Multicast -or $ip.IsIPv6SiteLocal -or $ip.IsIPv4MappedToIPv6) { return $false }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b=$ip.GetAddressBytes()
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { return $false }
    } elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $v6bytes=$ip.GetAddressBytes()
        if (($v6bytes[0] -band 0xFE) -eq 0xFC) { return $false }
    } else { return $false }
    return $true
}
function Test-OwnedRule([object]$Rule,[string]$ExpectedName) {
    return ($Rule.Name -eq $ExpectedName -and $Rule.Description -eq $script:FirewallOwnershipMarker -and
        $Rule.DisplayName -like 'WindowsDefense-v7-TemporaryOutboundBlock-*' -and
        $Rule.Group -eq 'WindowsDefense-v0.7' -and $Rule.Direction -eq 'Outbound' -and $Rule.Action -eq 'Block')
}
function Remove-ExpiredOwnedRules {
    $now=Get-Date
    foreach ($key in @($script:OwnedRules.Keys)) {
        $record=$script:OwnedRules[$key];$expiry=[datetime]::MinValue
        if ([datetime]::TryParse([string]$record.ExpiresAt,[ref]$expiry) -and $expiry -gt $now) { continue }
        try {
            $rules=@();if ($record.Name) { $rules=@(Get-NetFirewallRule -Name ([string]$record.Name) -ErrorAction SilentlyContinue) }
            if ($rules.Count -gt 0) {
                $verified=@($rules | Where-Object { Test-OwnedRule $_ ([string]$record.Name) })
                if ($verified.Count -ne 1) { throw 'Ownership verification failed; refusing removal.' }
                Remove-NetFirewallRule -Name ([string]$record.Name) -ErrorAction Stop
            }
            Write-Log 'RECOVERY' "Expired owned rule removed or already absent: $key"
            Add-Ledger $key 'RemoveTemporaryOutboundBlock' 'SUCCESS' 'Verified owned rule removed or already absent.'
            $script:OwnedRules.Remove($key)
        } catch {
            Write-Log 'WARN' "Could not safely remove expired rule $key; record retained."
            Add-Ledger $key 'RemoveTemporaryOutboundBlock' 'FAILED' 'Ownership check/removal failed.'
        }
    }
    Save-State
}
function Invoke-ApprovalBlock([string]$EventKey,[string]$RemoteAddress,[int]$RiskScore) {
    if ($cfg.ResponseMode -ne 'Approval' -or -not $cfg.EnableApprovalBlocks -or $RiskScore -lt $cfg.HighRiskThreshold) { return }
    if (-not (Test-PublicUnicastAddress $RemoteAddress)) {
        Add-Ledger $EventKey 'TemporaryOutboundBlock' 'SKIPPED' 'Address is invalid, private, or special-purpose.'
        return
    }
    if ($script:OwnedRules.Count -ge $cfg.MaxOwnedFirewallRules) {
        Add-Ledger $EventKey 'TemporaryOutboundBlock' 'LIMIT_REACHED' 'Maximum owned rule count reached.'
        return
    }
    $hash=(Get-Fingerprint $RemoteAddress).Substring(0,16)
    $ruleName="WDv7-TempOut-$hash";$displayName="WindowsDefense-v7-TemporaryOutboundBlock-$hash"
    if ($script:OwnedRules.ContainsKey($ruleName)) { return }
    Write-Host ''
    Write-Host "HIGH-RISK CONNECTION: $RemoteAddress | score $RiskScore/100" -ForegroundColor Yellow
    Write-Host 'This creates a TEMPORARY OUTBOUND block and may interrupt legitimate services.'
    $answer=Read-Host 'Type BLOCK to approve; anything else skips'
    if ($answer -cne 'BLOCK') {
        Add-Ledger $EventKey 'TemporaryOutboundBlock' 'DECLINED' 'User did not type BLOCK.'
        return
    }
    try {
        New-NetFirewallRule -Name $ruleName -DisplayName $displayName -Group 'WindowsDefense-v0.7' -Description $script:FirewallOwnershipMarker -Direction Outbound -Action Block -RemoteAddress $RemoteAddress -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        $expires=(Get-Date).AddMinutes($cfg.TemporaryBlockMinutes).ToString('o')
        $script:OwnedRules[$ruleName]=[pscustomobject]@{Name=$ruleName;DisplayName=$displayName;RemoteAddress=$RemoteAddress;ExpiresAt=$expires;EventKey=$EventKey}
        Save-State
        Write-Log 'ACTION' "Approved temporary outbound block for $RemoteAddress; expires $expires."
        Add-Ledger $EventKey 'TemporaryOutboundBlock' 'SUCCESS' "Rule=$ruleName; expires=$expires"
    } catch {
        Write-Log 'WARN' "Could not create temporary outbound rule for $RemoteAddress; check elevation and policy."
        Add-Ledger $EventKey 'TemporaryOutboundBlock' 'FAILED' 'Rule creation failed; no success assumed.'
    }
}

if (Test-Path -LiteralPath $statePath) {
    try {
        $saved=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $script:LastDefenderRecord=[long]$saved.LastDefenderRecord
        foreach ($k in @($saved.SeenKeys)) { if ($k) { $script:Seen[[string]$k]=Get-Date } }
        foreach ($r in @($saved.OwnedRules)) { if ($r.Name -like 'WDv7-TempOut-*') { $script:OwnedRules[[string]$r.Name]=$r } }
    } catch { Write-Log 'WARN' 'Could not restore prior deduplication state.' }
}
Write-Host ''
Write-Host 'Windows Defense v0.7 - Correlated Monitoring + Approval Response' -ForegroundColor Cyan
Write-Host "Mode: $($cfg.ResponseMode) | Poll: $($cfg.PollSeconds)s | High risk: $($cfg.HighRiskThreshold)+"
Write-Host 'Default is MONITOR ONLY. Optional outbound blocks require approval and typing BLOCK.'
Write-Host "Response ledger: $ledgerPath"
Write-Host "Log: $logPath"
Write-Host "Events: $eventsPath"
Write-Host 'Press Ctrl+C to stop.'
Write-Log 'INFO' 'v0.7 monitor started.'
Remove-ExpiredOwnedRules
$script:PreviousConnections=@{}
foreach($c in (Get-TcpSnapshot 'Established')) { $script:PreviousConnections[$c.Key]=$true }
$script:PreviousListeners=@{}
foreach($l in (Get-TcpSnapshot 'Listen')) { $script:PreviousListeners[$l.Key]=$true }
if ($cfg.MonitorFirewall) { $script:PreviousFirewall=Get-FirewallState }
$cycle=0
try {
    do {
        $cycle++
        $connections=Get-TcpSnapshot 'Established'
        $counts=@{}
        foreach($c in $connections) { $k=[string]$c.PID; if(-not $counts.ContainsKey($k)){$counts[$k]=0}; $counts[$k]++ }
        foreach($c in $connections) {
            if($cfg.NewConnectionAlert -and -not $script:PreviousConnections.ContainsKey($c.Key)) {
                $fanout=[int]$counts[[string]$c.PID]
                $risk=Get-Risk $c.Process $c.RemotePort $fanout
                $summary="process=$($c.Process.Name) pid=$($c.PID) remote=$($c.RemoteAddress):$($c.RemotePort) signature=$($c.Process.Signature) fanout=$fanout"
                $key=Get-Fingerprint("Connection|$($c.Key)")
                if (Add-Event 'NewConnection' $key $risk.Score $risk.Severity $summary ([pscustomobject]@{Process=$c.Process;RemoteAddress=$c.RemoteAddress;RemotePort=$c.RemotePort;Fanout=$fanout;RiskEvidence=$risk.Evidence})) {
                    Invoke-ApprovalBlock $key $c.RemoteAddress $risk.Score
                }
            }
        }
        $next=@{}; foreach($c in $connections){$next[$c.Key]=$true}; $script:PreviousConnections=$next

        $listeners=Get-TcpSnapshot 'Listen'
        foreach($l in $listeners) {
            if($cfg.AlertOnNewListener -and -not $script:PreviousListeners.ContainsKey($l.Key)) {
                $risk=Get-Risk $l.Process 0 0
                $summary="new-listener address=$($l.Address):$($l.Port) process=$($l.Process.Name) pid=$($l.PID) signature=$($l.Process.Signature)"
                $key=Get-Fingerprint("Listener|$($l.Key)")
                Add-Event 'NewListener' $key ([Math]::Max(25,$risk.Score)) $risk.Severity $summary ([pscustomobject]@{Process=$l.Process;Address=$l.Address;Port=$l.Port;RiskEvidence=$risk.Evidence})
            }
        }
        $nextL=@{}; foreach($l in $listeners){$nextL[$l.Key]=$true}; $script:PreviousListeners=$nextL

        if($cfg.MonitorFirewall) {
            $fw=Get-FirewallState
            if(($fw -join ';') -ne ($script:PreviousFirewall -join ';')) {
                Add-Event 'FirewallChange' (Get-Fingerprint("Firewall|$($fw -join ';')")) 50 'WARN' ("Firewall profile state changed: "+($fw -join ';')) ([pscustomobject]@{Profiles=$fw})
                $script:PreviousFirewall=$fw
            }
            if(@($fw | Where-Object {$_ -match 'Enabled=False'}).Count -gt 0) {
                Add-Event 'FirewallDisabled' (Get-Fingerprint("FirewallDisabled|$($fw -join ';')")) 75 'ALERT' ("One or more firewall profiles report Enabled=False: "+($fw -join ';')) ([pscustomobject]@{Profiles=$fw})
            } elseif(@($fw | Where-Object {$_ -eq 'UNAVAILABLE'}).Count -gt 0) {
                Add-Event 'FirewallStatusUnavailable' (Get-Fingerprint("FirewallStatusUnavailable|$($fw -join ';')")) 20 'WARN' 'Firewall profile state could not be read; this is not evidence that the firewall is disabled.' ([pscustomobject]@{Profiles=$fw})
            }
        }
        Read-DefenderEvents
        Remove-ExpiredOwnedRules
        if(($cycle % 10) -eq 0) { Save-State }
        if($Once) { break }
        Start-Sleep -Seconds $cfg.PollSeconds
    } while($true)
} finally {
    Save-State
    Write-Log 'INFO' 'v0.7 monitor stopped.'
}
