# Windows Defense v0.6 - correlated, deduplicated, monitor-only
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
$logPath = Join-Path $logDir "WindowsDefense-v0.6-$stamp.log"
$eventsPath = Join-Path $dataDir 'events.jsonl'
$statePath = Join-Path $dataDir 'state-v0.6.json'

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
}
try {
    if (Test-Path -LiteralPath $cfgPath) {
        $u = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        if ($u.PollSeconds -ge 5 -and $u.PollSeconds -le 60) { $cfg.PollSeconds = [int]$u.PollSeconds }
        if ($u.HighRiskThreshold -ge 40 -and $u.HighRiskThreshold -le 100) { $cfg.HighRiskThreshold = [int]$u.HighRiskThreshold }
        if ($u.MediumRiskThreshold -ge 20 -and $u.MediumRiskThreshold -lt $cfg.HighRiskThreshold) { $cfg.MediumRiskThreshold = [int]$u.MediumRiskThreshold }
        foreach ($k in @('NewConnectionAlert','AlertOnNewListener','MonitorFirewall','ReadDefenderEvents')) {
            if ($null -ne $u.$k) { $cfg[$k] = [bool]$u.$k }
        }
        if ($u.MaxEventsPerRun -ge 100 -and $u.MaxEventsPerRun -le 2000) { $cfg.MaxEventsPerRun = [int]$u.MaxEventsPerRun }
        if ($u.MaxSeenEventKeys -ge 100 -and $u.MaxSeenEventKeys -le 5000) { $cfg.MaxSeenEventKeys = [int]$u.MaxSeenEventKeys }
    }
} catch { Write-Warning 'Invalid config; safe defaults will be used.' }

$script:Seen = @{}
$script:LastDefenderRecord = 0L
$script:PreviousConnections = @{}
$script:PreviousListeners = @{}
$script:PreviousFirewall = @()
$script:ProcessCache = @{}
$script:ProcessConnectionCounts = @{}

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
        [ordered]@{ UpdatedAt=(Get-Date).ToString('o'); LastDefenderRecord=$script:LastDefenderRecord; SeenKeys=$keys } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    } catch { Write-Log 'WARN' 'Could not save deduplication state.' }
}
function Add-Event([string]$Type,[string]$Key,[int]$Score,[string]$Severity,[string]$Summary,[object]$Evidence) {
    if ($script:Seen.ContainsKey($Key)) { return }
    $script:Seen[$Key] = Get-Date
    $record = [pscustomobject]@{
        Timestamp=(Get-Date).ToString('o'); Type=$Type; EventKey=$Key
        RiskScore=$Score; Severity=$Severity; Summary=$Summary; Evidence=$Evidence
    }
    try {
        ($record | ConvertTo-Json -Depth 7 -Compress) | Add-Content -LiteralPath $eventsPath -Encoding UTF8
        Write-Log $Severity "RISK=$Score/100 type=$Type $Summary"
    } catch { Write-Log 'WARN' 'Could not append event record.' }
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
        $items=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117} -MaxEvents 30 -ErrorAction Stop | Where-Object { [long]$_.RecordId -gt $script:LastDefenderRecord } | Sort-Object RecordId)
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
if (Test-Path -LiteralPath $statePath) {
    try {
        $saved=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $script:LastDefenderRecord=[long]$saved.LastDefenderRecord
        foreach ($k in @($saved.SeenKeys)) { if ($k) { $script:Seen[[string]$k]=Get-Date } }
    } catch { Write-Log 'WARN' 'Could not restore prior deduplication state.' }
}
Write-Host ''
Write-Host 'Windows Defense v0.6 - Correlated Monitoring' -ForegroundColor Cyan
Write-Host "Mode: MONITOR ONLY | Poll: $($cfg.PollSeconds)s | High risk: $($cfg.HighRiskThreshold)+"
Write-Host 'No firewall rules are created or changed. No process is stopped and no file is deleted.'
Write-Host "Log: $logPath"
Write-Host "Events: $eventsPath"
Write-Host 'Press Ctrl+C to stop.'
Write-Log 'INFO' 'v0.6 monitor started.'
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
                Add-Event 'NewConnection' $key $risk.Score $risk.Severity $summary ([pscustomobject]@{Process=$c.Process;RemoteAddress=$c.RemoteAddress;RemotePort=$c.RemotePort;Fanout=$fanout;RiskEvidence=$risk.Evidence})
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
            if(@($fw | Where-Object {$_ -match 'Enabled=False' -or $_ -eq 'UNAVAILABLE'}).Count -gt 0) {
                Add-Event 'FirewallDegraded' (Get-Fingerprint("FirewallDegraded|$($fw -join ';')")) 75 'ALERT' ("Firewall disabled or status unavailable: "+($fw -join ';')) ([pscustomobject]@{Profiles=$fw})
            }
        }
        Read-DefenderEvents
        if(($cycle % 10) -eq 0) { Save-State }
        if($Once) { break }
        Start-Sleep -Seconds $cfg.PollSeconds
    } while($true)
} finally {
    Save-State
    Write-Log 'INFO' 'v0.6 monitor stopped. No automatic response was performed.'
}
