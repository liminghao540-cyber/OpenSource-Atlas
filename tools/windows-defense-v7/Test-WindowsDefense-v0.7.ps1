$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$script=Join-Path $root 'WindowsDefense-v0.7.ps1'
$t=$null;$e=$null
[System.Management.Automation.Language.Parser]::ParseFile($script,[ref]$t,[ref]$e)|Out-Null
if($e.Count){throw ("PowerShell parse errors: "+($e -join '; '))}
$s=Get-Content $script -Raw
foreach($x in @('Get-NetTCPConnection','Get-ProcessEvidence','Get-Risk','Get-Fingerprint','events.jsonl','response-ledger-v0.7.jsonl','DefenderDetection','FirewallStatusUnavailable','Invoke-ApprovalBlock','Test-PublicUnicastAddress','Remove-ExpiredOwnedRules','Test-OwnedRule')){if($s -notmatch [regex]::Escape($x)){throw "Missing feature: $x"}}
foreach($x in @('Stop-Process','Remove-Item','Set-NetFirewallProfile','Set-MpPreference')){if($s -match [regex]::Escape($x)){throw "Forbidden command: $x"}}
if($s -notmatch "ResponseMode = 'MonitorOnly'"){throw 'Default must be MonitorOnly'}
if($s -notmatch 'EnableApprovalBlocks = \\$false'){throw 'Approval disabled by default'}
if($s -notmatch 'Type BLOCK to approve'){throw 'Explicit approval prompt missing'}
if($s -notmatch '-Direction Outbound -Action Block -RemoteAddress'){throw 'Must block remote IP outbound'}
if($s -notmatch 'TemporaryBlockMinutes -le 60'){throw 'TTL bound missing'}
$c=Get-Content (Join-Path $root 'config.json') -Raw|ConvertFrom-Json
if($c.ResponseMode -ne 'MonitorOnly' -or $c.EnableApprovalBlocks){throw 'Unsafe config defaults'}
if($c.TemporaryBlockMinutes -lt 1 -or $c.TemporaryBlockMinutes -gt 60){throw 'TTL out of bounds'}
if($c.MaxOwnedFirewallRules -lt 1 -or $c.MaxOwnedFirewallRules -gt 10){throw 'Rule cap out of bounds'}
Write-Host 'PASS: syntax, safe defaults, approval gate, outbound scope, TTL and ownership checks.'
