$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$script=Join-Path $root 'WindowsDefense-v0.6.ps1'
$rollbackFree=$true
$tokens=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($script,[ref]$tokens,[ref]$errors) | Out-Null
if($errors.Count -gt 0){ throw ("PowerShell parse errors: "+($errors -join '; ')) }
$src=Get-Content -LiteralPath $script -Raw
foreach($forbidden in @('Stop-Process','Remove-NetFirewallRule','New-NetFirewallRule','Set-NetFirewallProfile','Remove-Item')) {
    if($src -match [regex]::Escape($forbidden)){ throw "Unsafe command found in monitor-only script: $forbidden" }
}
foreach($required in @('Get-NetTCPConnection','Get-ProcessEvidence','Get-Risk','Get-Fingerprint','events.jsonl','state-v0.6.json','Read-DefenderEvents','MonitorFirewall')) {
    if($src -notmatch [regex]::Escape($required)){ throw "Required feature missing: $required" }
}
$cfg=Get-Content -LiteralPath (Join-Path $root 'config.json') -Raw | ConvertFrom-Json
if($cfg.PollSeconds -lt 5 -or $cfg.PollSeconds -gt 60){throw 'PollSeconds out of range'}
if($cfg.HighRiskThreshold -lt 40 -or $cfg.HighRiskThreshold -gt 100){throw 'HighRiskThreshold out of range'}
if($cfg.MediumRiskThreshold -lt 20 -or $cfg.MediumRiskThreshold -ge $cfg.HighRiskThreshold){throw 'MediumRiskThreshold invalid'}
if($cfg.MaxSeenEventKeys -lt 100 -or $cfg.MaxSeenEventKeys -gt 5000){throw 'MaxSeenEventKeys out of range'}
if(-not $src.Contains("FirewallStatusUnavailable")){throw 'Unavailable firewall status must be classified separately'}
if(-not $src.Contains("FirewallDisabled")){throw 'Disabled firewall profile detection missing'}
if($src -notmatch '-MaxEvents \$cfg\.MaxEventsPerRun'){throw 'MaxEventsPerRun configuration is not applied'}
if($src -match "\$_ -eq 'UNAVAILABLE'.*ALERT"){throw 'Unavailable firewall status must not be treated as an alert that it is disabled'}
if(-not $src.Contains('$ev.Id -eq 1116')){throw 'Defender detection event 1116 must be handled separately'}
if($src -notmatch "DefenderAction"){throw 'Defender action event classification missing'}
Write-Host 'PASS: PowerShell syntax, monitor-only safety, feature presence, and config bounds.'
