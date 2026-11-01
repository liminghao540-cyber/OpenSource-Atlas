# Windows Defense v0.5 - monitored, audited, reversible
# Compatible target: Windows PowerShell 5.1 on Windows 10.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $root 'config.json'
$dataDir = Join-Path $root 'data'
$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $dataDir,$logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $logDir "WindowsDefense-v0.5-$stamp.log"
$statePath = Join-Path $dataDir 'state.json'
$ledgerPath = Join-Path $dataDir 'response-ledger.json'

$cfg = @{
    PollSeconds = 8
    ResponseMode = 'MonitorOnly'
    AlertOnNewListener = $true
    AlertOnFirewallChange = $true
    ReadDefenderEvents = $true
    AutoQuickScanOnThreat = $false
    MaxQuickScansPerHour = 2
    EnableApprovedTemporaryBlocks = $false
    ApprovedBlockList = @()
    TemporaryBlockMinutes = 10
    MaxOwnedFirewallRules = 10
}
try {
    if (Test-Path -LiteralPath $cfgPath) {
        $userConfig = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        if ($userConfig.PollSeconds -ge 5 -and $userConfig.PollSeconds -le 60) { $cfg.PollSeconds = [int]$userConfig.PollSeconds }
        if (@('MonitorOnly','Approval','Auto') -contains [string]$userConfig.ResponseMode) { $cfg.ResponseMode = [string]$userConfig.ResponseMode }
        foreach ($key in @('AlertOnNewListener','AlertOnFirewallChange','ReadDefenderEvents','AutoQuickScanOnThreat','EnableApprovedTemporaryBlocks')) {
            if ($null -ne $userConfig.$key) { $cfg[$key] = [bool]$userConfig.$key }
        }
        if ($userConfig.MaxQuickScansPerHour -ge 0 -and $userConfig.MaxQuickScansPerHour -le 6) { $cfg.MaxQuickScansPerHour = [int]$userConfig.MaxQuickScansPerHour }
        if ($userConfig.TemporaryBlockMinutes -ge 1 -and $userConfig.TemporaryBlockMinutes -le 60) { $cfg.TemporaryBlockMinutes = [int]$userConfig.TemporaryBlockMinutes }
        if ($userConfig.MaxOwnedFirewallRules -ge 1 -and $userConfig.MaxOwnedFirewallRules -le 20) { $cfg.MaxOwnedFirewallRules = [int]$userConfig.MaxOwnedFirewallRules }
        if ($null -ne $userConfig.ApprovedBlockList) { $cfg.ApprovedBlockList = @($userConfig.ApprovedBlockList | ForEach-Object { [string]$_ }) }
    }
} catch {
    Write-Warning 'Could not read config.json; safe defaults will be used.'
}

$script:OwnedRules = @{}
$script:QuickScanTimes = New-Object 'System.Collections.Generic.List[datetime]'
$script:LastDefenderRecord = 0L
$script:SeenConnections = @{}
$script:ProcessEvidenceCache = @{}
$script:FirewallOwnershipMarker = 'ManagedBy=WindowsDefense-v0.5;Scope=TemporaryInboundBlock'

function Write-Log([string]$Level, [string]$Message) {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
    switch ($Level) {
        'ALERT' { Write-Host $line -ForegroundColor Red }
        'ACTION' { Write-Host $line -ForegroundColor Yellow }
        'RECOVERY' { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line -ForegroundColor Cyan }
    }
}

function Add-Ledger([string]$Key, [string]$Action, [string]$Status, [string]$Details) {
    $entry = [pscustomobject]@{ At=(Get-Date).ToString('o'); EventKey=$Key; Action=$Action; Status=$Status; Details=$Details }
    try {
        $old = @()
        if (Test-Path -LiteralPath $ledgerPath) { $old = @(Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json) }
        @($old) + @($entry) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ledgerPath -Encoding UTF8
    } catch { Write-Log 'WARN' 'Could not append response ledger entry.' }
}

function Save-State {
    try {
        [ordered]@{ UpdatedAt=(Get-Date).ToString('o'); OwnedRules=@($script:OwnedRules.Values) } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding UTF8
    } catch { Write-Log 'WARN' 'Could not persist temporary-rule state.' }
}

function Get-ProcessEvidence([int]$ProcessId) {
    $name = 'unknown'
    $path = $null
    $signature = 'Unavailable'
    $sha256 = $null
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        $name = $proc.ProcessName
        try { $path = $proc.Path } catch {}
    } catch {}
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $cacheKey = "$ProcessId|$path"
        try { $cacheStamp = (Get-Item -LiteralPath $path -ErrorAction Stop).LastWriteTimeUtc.Ticks } catch { $cacheStamp = 0 }
        $cacheKey = "$cacheKey|$cacheStamp"
        if ($script:ProcessEvidenceCache.ContainsKey($cacheKey)) { return $script:ProcessEvidenceCache[$cacheKey] }
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            $signature = [string]$sig.Status
        } catch { $signature = 'CheckFailed' }
        try { $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch {}
        $evidence = [pscustomobject]@{ Name=$name; Path=$path; Signature=$signature; SHA256=$sha256 }
        if ($script:ProcessEvidenceCache.Count -ge 256) { $script:ProcessEvidenceCache.Clear() }
        $script:ProcessEvidenceCache[$cacheKey] = $evidence
        return $evidence
    }
    [pscustomobject]@{ Name=$name; Path=$path; Signature=$signature; SHA256=$sha256 }
}

function Get-ListenerSnapshot {
    $items = @()
    try {
        foreach ($item in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $pidValue = [int]$item.OwningProcess
            $evidence = Get-ProcessEvidence $pidValue
            $key = '{0}|{1}|{2}' -f $item.LocalAddress,$item.LocalPort,$pidValue
            $items += [pscustomobject]@{
                Key=$key; Address=[string]$item.LocalAddress; Port=[int]$item.LocalPort; PID=$pidValue
                Process=$evidence.Name; Path=$evidence.Path; Signature=$evidence.Signature; SHA256=$evidence.SHA256
            }
        }
    } catch { Write-Log 'WARN' 'TCP listener inventory unavailable; check Windows version and permissions.' }
    return @($items)
}

function Get-ConnectionSnapshot {
    $items = @()
    try {
        foreach ($item in @(Get-NetTCPConnection -State Established -ErrorAction Stop)) {
            $pidValue = [int]$item.OwningProcess
            $evidence = Get-ProcessEvidence $pidValue
            $key = '{0}:{1}|{2}:{3}|{4}' -f $item.LocalAddress,$item.LocalPort,$item.RemoteAddress,$item.RemotePort,$pidValue
            $items += [pscustomobject]@{
                Key=$key; LocalAddress=[string]$item.LocalAddress; LocalPort=[int]$item.LocalPort
                RemoteAddress=[string]$item.RemoteAddress; RemotePort=[int]$item.RemotePort; PID=$pidValue
                Process=$evidence.Name; Path=$evidence.Path; Signature=$evidence.Signature; SHA256=$evidence.SHA256
            }
        }
    } catch { Write-Log 'WARN' 'Established TCP connection inventory unavailable.' }
    return @($items)
}

function Get-FirewallSnapshot {
    try {
        return @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            '{0}|Enabled={1}|Inbound={2}|Outbound={3}' -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction
        } | Sort-Object)
    } catch { return @('UNAVAILABLE') }
}

function Get-RiskScore([string]$ProcessName, [string]$Path, [string]$Signature) {
    $score = 15
    $evidence = @()
    if ($ProcessName -match '^(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)$') {
        $score += 25; $evidence += 'script-or-lolbin-process'
    }
    if ($Path -and $Path -match '\\(AppData|Temp|Downloads)\\') {
        $score += 20; $evidence += 'user-writable-path'
    }
    if ($Signature -eq 'NotSigned') {
        $score += 15; $evidence += 'unsigned-file'
    } elseif ($Signature -eq 'HashMismatch') {
        $score += 35; $evidence += 'signature-hash-mismatch'
    }
    if ($Signature -eq 'Unavailable' -or $Signature -eq 'CheckFailed') {
        $evidence += 'signature-unavailable'
    }
    return [pscustomobject]@{ Score=[Math]::Min(100,$score); Evidence=($evidence -join ',') }
}

function Invoke-QuickScan([string]$Reason) {
    $now = Get-Date
    while ($script:QuickScanTimes.Count -gt 0 -and ($now - $script:QuickScanTimes[0]).TotalMinutes -ge 60) {
        $script:QuickScanTimes.RemoveAt(0)
    }
    if ($script:QuickScanTimes.Count -ge $cfg.MaxQuickScansPerHour) {
        Write-Log 'WARN' 'Defender quick-scan rate limit reached.'
        return
    }
    try {
        if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) { throw 'Start-MpScan unavailable' }
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        $script:QuickScanTimes.Add($now)
        Write-Log 'ACTION' "Requested Microsoft Defender quick scan for $Reason"
        Add-Ledger $Reason 'DefenderQuickScan' 'REQUESTED' 'Verify the result in Windows Security.'
    } catch {
        Write-Log 'WARN' 'Could not request Defender quick scan; review Windows Security manually.'
        Add-Ledger $Reason 'DefenderQuickScan' 'FAILED' 'No scan result was assumed.'
    }
}

function Remove-ExpiredOwnedRules {
    $now = Get-Date
    foreach ($displayName in @($script:OwnedRules.Keys)) {
        $record = $script:OwnedRules[$displayName]
        $expiry = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$record.ExpiresAt,[ref]$expiry) -or $expiry -le $now) {
            try {
                $ruleName = [string]$record.Name
                $owned = @()
                if ($ruleName) { $owned = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) }
                if ($owned.Count -gt 0) {
                    $verified = @($owned | Where-Object {
                        $_.Description -eq $script:FirewallOwnershipMarker -and
                        $_.DisplayName -like 'WindowsDefense-v5-TemporaryBlock-*'
                    })
                    if ($verified.Count -eq 1) {
                        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
                    } else {
                        throw 'Firewall rule ownership marker did not match; refusing to remove it.'
                    }
                }
                Write-Log 'RECOVERY' "Expired verified v0.5 rule removed or already absent: $displayName"
                Add-Ledger $displayName 'RemoveTemporaryRule' 'SUCCESS' 'Expired owned rule removed or absent.'
            } catch {
                Write-Log 'WARN' "Could not remove expired rule $displayName; use the rollback script after review."
                Add-Ledger $displayName 'RemoveTemporaryRule' 'FAILED' 'Manual review required.'
            }
            $script:OwnedRules.Remove($displayName)
        }
    }
    Save-State
}

function Invoke-ApprovedBlocks {
    if (-not $cfg.EnableApprovedTemporaryBlocks -or $cfg.ResponseMode -eq 'MonitorOnly') { return }
    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Log 'WARN' 'Windows Firewall cmdlets unavailable; no temporary block was created.'
        return
    }
    foreach ($rawAddress in @($cfg.ApprovedBlockList)) {
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($rawAddress,[ref]$parsedAddress)) {
            Write-Log 'WARN' "Ignoring invalid approved IP entry: $rawAddress"; continue
        }
        if ([System.Net.IPAddress]::IsLoopback($parsedAddress) -or $parsedAddress.IsIPv6LinkLocal -or $parsedAddress.IsIPv6Multicast -or $parsedAddress.IsIPv4MappedToIPv6) {
            Write-Log 'WARN' "Ignoring special-purpose IP entry: $rawAddress"; continue
        }
        $safeAddress = $rawAddress -replace '[^0-9A-Fa-f:.]','_'
        $displayName = "WindowsDefense-v5-TemporaryBlock-$safeAddress"
        $addressBytes = [System.Text.Encoding]::UTF8.GetBytes($rawAddress)
        $addressHash = ([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash($addressBytes))).Replace('-','').Substring(0,12)
        $ruleName = "WDv5-TempBlock-$addressHash"
        if ($script:OwnedRules.ContainsKey($displayName)) { continue }
        if ($script:OwnedRules.Count -ge $cfg.MaxOwnedFirewallRules) {
            Write-Log 'WARN' 'Owned firewall rule limit reached; remaining approved entries skipped.'; break
        }
        if ($cfg.ResponseMode -eq 'Approval') {
            $answer = Read-Host "Create temporary INBOUND firewall block for $rawAddress? Type BLOCK to approve"
            if ($answer -cne 'BLOCK') {
                Write-Log 'INFO' "Block not approved for $rawAddress."
                Add-Ledger $rawAddress 'TemporaryInboundBlock' 'DECLINED' 'User did not type BLOCK.'
                continue
            }
        }
        try {
            New-NetFirewallRule -Name $ruleName -DisplayName $displayName -Group 'WindowsDefense-v0.5' -Description $script:FirewallOwnershipMarker -Direction Inbound -Action Block -RemoteAddress $rawAddress -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            $expires = (Get-Date).AddMinutes($cfg.TemporaryBlockMinutes).ToString('o')
            $script:OwnedRules[$displayName] = [pscustomobject]@{ Name=$ruleName; DisplayName=$displayName; RemoteAddress=$rawAddress; ExpiresAt=$expires }
            Save-State
            Write-Log 'ACTION' "Created approved temporary INBOUND block for $rawAddress; expires $expires. Uses Windows Firewall."
            Add-Ledger $rawAddress 'TemporaryInboundBlock' 'SUCCESS' "Rule=$displayName; Expires=$expires"
        } catch {
            Write-Log 'WARN' "Could not create temporary rule for $rawAddress; check permissions and policy."
            Add-Ledger $rawAddress 'TemporaryInboundBlock' 'FAILED' 'Rule creation failed.'
        }
    }
    Save-State
}

if (Test-Path -LiteralPath $statePath) {
    try {
        $savedState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        foreach ($record in @($savedState.OwnedRules)) {
            if ($record.Name -like 'WindowsDefense-v5-TemporaryBlock-*') { $script:OwnedRules[$record.Name] = $record }
        }
    } catch { Write-Log 'WARN' 'Could not restore saved owned-rule state; rollback script remains available.' }
}

Write-Host ''
Write-Host 'Windows Defense v0.5 — Monitored, Audited, Reversible' -ForegroundColor Cyan
Write-Host "Response mode: $($cfg.ResponseMode). Poll interval: $($cfg.PollSeconds)s."
Write-Host 'Monitoring is read-only by default. Firewall response uses Windows Firewall and is opt-in.'
Write-Host "Log: $logPath"
Write-Host 'Press Ctrl+C to stop.'
Write-Log 'INFO' 'Monitor started.'
Remove-ExpiredOwnedRules
Invoke-ApprovedBlocks

$previousListeners = @{}
foreach ($listener in (Get-ListenerSnapshot)) { $previousListeners[$listener.Key] = $true }
$previousConnections = @{}
foreach ($connection in (Get-ConnectionSnapshot)) { $previousConnections[$connection.Key] = $true }
$previousFirewall = Get-FirewallSnapshot
$firewallAlerted = $false
try {
    if ($cfg.ReadDefenderEvents) {
        $latest = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117 } -MaxEvents 1 -ErrorAction Stop
        if ($latest) { $script:LastDefenderRecord = [long]$latest.RecordId }
    }
} catch { Write-Log 'INFO' 'Defender Operational log is unavailable or not readable; other monitoring remains active.' }

try {
    while ($true) {
        Remove-ExpiredOwnedRules
        $currentListeners = Get-ListenerSnapshot
        $currentMap = @{}
        foreach ($listener in $currentListeners) {
            $currentMap[$listener.Key] = $true
            if ($cfg.AlertOnNewListener -and -not $previousListeners.ContainsKey($listener.Key)) {
                $risk = Get-RiskScore $listener.Process $listener.Path $listener.Signature
                $message = "RISK=$($risk.Score)/100 evidence=$($risk.Evidence) listener=$($listener.Address):$($listener.Port) PID=$($listener.PID) process=$($listener.Process) signature=$($listener.Signature) SHA256=$($listener.SHA256)"
                Write-Log 'ALERT' $message
                Add-Ledger $listener.Key 'ObserveNewListener' 'LOGGED' $message
            }
        }
        $previousListeners = $currentMap

        $currentConnections = Get-ConnectionSnapshot
        $connectionMap = @{}
        foreach ($connection in $currentConnections) {
            $connectionMap[$connection.Key] = $true
            if (-not $previousConnections.ContainsKey($connection.Key)) {
                $risk = Get-RiskScore $connection.Process $connection.Path $connection.Signature
                $message = "RISK=$($risk.Score)/100 evidence=$($risk.Evidence) established=$($connection.LocalAddress):$($connection.LocalPort)->$($connection.RemoteAddress):$($connection.RemotePort) PID=$($connection.PID) process=$($connection.Process) signature=$($connection.Signature)"
                Write-Log 'INFO' $message
                Add-Ledger $connection.Key 'ObserveEstablishedConnection' 'LOGGED' $message
            }
        }
        $previousConnections = $connectionMap

        $firewall = Get-FirewallSnapshot
        if (($firewall -join ';') -ne ($previousFirewall -join ';')) {
            if ($cfg.AlertOnFirewallChange) { Write-Log 'ALERT' ("Firewall profile state changed: " + ($firewall -join ';')) }
            $previousFirewall = $firewall
            $firewallAlerted = $false
        }
        $firewallBad = @($firewall | Where-Object { $_ -match 'Enabled=False' -or $_ -eq 'UNAVAILABLE' }).Count -gt 0
        if ($firewallBad -and -not $firewallAlerted) {
            Write-Log 'ALERT' ("Firewall disabled or unconfirmed: " + ($firewall -join ';'))
            Add-Ledger 'FirewallProfileState' 'FirewallStateAlert' 'LOGGED' ($firewall -join ';')
            $firewallAlerted = $true
        } elseif (-not $firewallBad -and $firewallAlerted) {
            Write-Log 'RECOVERY' 'Firewall profiles now report enabled; verify status in Windows Security.'
            $firewallAlerted = $false
        }

        if ($cfg.ReadDefenderEvents) {
            try {
                $newEvents = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117 } -MaxEvents 30 -ErrorAction Stop |
                    Where-Object { [long]$_.RecordId -gt $script:LastDefenderRecord } | Sort-Object RecordId)
                foreach ($eventRecord in $newEvents) {
                    $script:LastDefenderRecord = [Math]::Max($script:LastDefenderRecord,[long]$eventRecord.RecordId)
                    $description = ($eventRecord.Message -replace '\s+',' ').Trim()
                    if ($description.Length -gt 400) { $description = $description.Substring(0,400) }
                    $eventKey = "DefenderEvent-$($eventRecord.RecordId)"
                    Write-Log 'ALERT' "Defender event $($eventRecord.Id), record $($eventRecord.RecordId): $description"
                    Add-Ledger $eventKey 'DefenderEvent' 'LOGGED' "EventId=$($eventRecord.Id)"
                    if ($eventRecord.Id -eq 1116 -and $cfg.AutoQuickScanOnThreat) { Invoke-QuickScan $eventKey }
                }
            } catch {}
        }
        Start-Sleep -Seconds $cfg.PollSeconds
    }
} finally {
    Write-Log 'INFO' 'Monitor stopping; checking only expired v0.5-owned firewall rules.'
    Remove-ExpiredOwnedRules
    Write-Log 'INFO' 'Stopped. Unexpired rules remain until expiry or explicit rollback.'
}
