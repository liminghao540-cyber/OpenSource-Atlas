# Windows Defense v0.4 - independent monitor + bounded response
# Windows PowerShell 5.1. Monitoring is independent of Windows Firewall; optional temporary IP blocks use it.
$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $root 'config.json'
$dataDir = Join-Path $root 'data'; $logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $dataDir,$logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $logDir "WindowsDefense-$stamp.log"
$statePath = Join-Path $dataDir 'state.json'; $ledgerPath = Join-Path $dataDir 'response-ledger.json'
$cfg = @{ PollSeconds=10; AlertOnNewListener=$true; AlertOnFirewallChange=$true; AutoQuickScanOnDefenderThreat=$true; EnableTemporaryFirewallBlock=$false; TemporaryBlockMinutes=10; ExplicitBlockList=@(); MaxAutoQuickScansPerHour=2 }
if (Test-Path $cfgPath) {
 try {
  $u=Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
  if ($u.PollSeconds -ge 5 -and $u.PollSeconds -le 60) {$cfg.PollSeconds=[int]$u.PollSeconds}
  foreach($k in @('AlertOnNewListener','AlertOnFirewallChange','AutoQuickScanOnDefenderThreat','EnableTemporaryFirewallBlock')) {if($null -ne $u.$k){$cfg[$k]=[bool]$u.$k}}
  if($u.TemporaryBlockMinutes -ge 1 -and $u.TemporaryBlockMinutes -le 60){$cfg.TemporaryBlockMinutes=[int]$u.TemporaryBlockMinutes}
  if($u.MaxAutoQuickScansPerHour -ge 0 -and $u.MaxAutoQuickScansPerHour -le 6){$cfg.MaxAutoQuickScansPerHour=[int]$u.MaxAutoQuickScansPerHour}
  if($null -ne $u.ExplicitBlockList){$cfg.ExplicitBlockList=@($u.ExplicitBlockList | ForEach-Object {[string]$_})}
 } catch {}
}
$script:QuickScanTimes=New-Object 'System.Collections.Generic.List[datetime]'
$script:OwnedRules=@{}
function Write-Log([string]$Level,[string]$Message) {
 $line="{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
 Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
 if($Level -eq 'ALERT'){Write-Host $line -ForegroundColor Red} elseif($Level -eq 'ACTION'){Write-Host $line -ForegroundColor Yellow} elseif($Level -eq 'RECOVERY'){Write-Host $line -ForegroundColor Green} else {Write-Host $line -ForegroundColor Cyan}
}
function Save-State {
 try {$o=[ordered]@{UpdatedAt=(Get-Date).ToString('o');OwnedRules=@($script:OwnedRules.Values)};$o | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8} catch {}
}
function Get-Listeners {
 try {@(Get-NetTCPConnection -State Listen | ForEach-Object {
  $pidValue=[int]$_.OwningProcess;$procName='unknown';$procPath=$null
  try {$p=Get-Process -Id $pidValue -ErrorAction Stop;$procName=$p.ProcessName;try{$procPath=$p.Path}catch{}} catch {}
  [pscustomobject]@{Key=('{0}|{1}|{2}' -f $_.LocalAddress,$_.LocalPort,$pidValue);Address=$_.LocalAddress;Port=[int]$_.LocalPort;PID=$pidValue;Process=$procName;Path=$procPath}
 })} catch {@()}
}
function Get-FirewallState {
 try {@(Get-NetFirewallProfile | ForEach-Object {'{0}|Enabled={1}|In={2}|Out={3}' -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction} | Sort-Object)} catch {@('UNAVAILABLE')}
}
function Get-RiskScore([string]$Kind,[string]$Details) {
 $score=10
 switch($Kind) {'NewListener'{$score=25} 'FirewallDisabled'{$score=60} 'DefenderThreat'{$score=90} 'DefenderAction'{$score=35}}
 if($Details -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32'){$score=[Math]::Min(100,$score+10)}
 return $score
}
function Add-ResponseLedger([string]$EventKey,[string]$Action,[string]$Status,[string]$Details) {
 $entry=[pscustomobject]@{At=(Get-Date).ToString('o');EventKey=$EventKey;Action=$Action;Status=$Status;Details=$Details}
 try {$old=@();if(Test-Path $ledgerPath){$old=@(Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json)};@($old)+@($entry) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ledgerPath -Encoding UTF8} catch {}
}
function Invoke-QuickScan([string]$Reason) {
 $now=Get-Date
 while($script:QuickScanTimes.Count -gt 0 -and ($now-$script:QuickScanTimes[0]).TotalMinutes -ge 60){$script:QuickScanTimes.RemoveAt(0)}
 if($script:QuickScanTimes.Count -ge $cfg.MaxAutoQuickScansPerHour){Write-Log 'WARN' 'Quick-scan rate limit reached; no additional scan started.';return}
 try {if(-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)){throw 'Start-MpScan unavailable'};Start-MpScan -ScanType QuickScan;$script:QuickScanTimes.Add($now);Write-Log 'ACTION' "Requested Microsoft Defender quick scan. Reason: $Reason";Add-ResponseLedger $Reason 'DefenderQuickScan' 'REQUESTED' 'Check Windows Security for result.'}
 catch {Write-Log 'WARN' 'Could not request Defender quick scan; review Windows Security.';Add-ResponseLedger $Reason 'DefenderQuickScan' 'FAILED' 'Manual review required.'}
}
function Remove-ExpiredOwnedRules {
 $now=Get-Date
 foreach($name in @($script:OwnedRules.Keys)){
  $entry=$script:OwnedRules[$name]
  if([datetime]$entry.ExpiresAt -le $now){
   try {Remove-NetFirewallRule -DisplayName $name -ErrorAction Stop;Write-Log 'RECOVERY' "Removed expired temporary rule: $name";Add-ResponseLedger $name 'RemoveTemporaryRule' 'SUCCESS' 'Expired rule removed.'}
   catch {Write-Log 'WARN' "Could not remove expired rule $name; inspect firewall manually.";Add-ResponseLedger $name 'RemoveTemporaryRule' 'FAILED' 'Manual review required.'}
   $script:OwnedRules.Remove($name)
  }
 }
 Save-State
}
function Invoke-ExplicitTemporaryBlocks {
 if(-not $cfg.EnableTemporaryFirewallBlock -or $cfg.ExplicitBlockList.Count -eq 0){return}
 if(-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)){Write-Log 'WARN' 'Firewall cmdlets unavailable; cannot create temporary block.';return}
 foreach($rawIp in $cfg.ExplicitBlockList){
  $ip=$null
  if(-not [System.Net.IPAddress]::TryParse($rawIp,[ref]$ip)){Write-Log 'WARN' "Ignoring invalid IP entry: $rawIp";continue}
  if([System.Net.IPAddress]::IsLoopback($ip) -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6Multicast -or $ip.IsIPv4MappedToIPv6){Write-Log 'WARN' "Ignoring special IP entry: $rawIp";continue}
  $safe=($rawIp -replace '[^0-9A-Fa-f:.]','_');$name="WindowsDefense-TemporaryBlock-$safe"
  if($script:OwnedRules.ContainsKey($name)){continue}
  try {
   New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -RemoteAddress $rawIp -Profile Any -Enabled True -ErrorAction Stop | Out-Null
   $expiry=(Get-Date).AddMinutes($cfg.TemporaryBlockMinutes).ToString('o')
   $script:OwnedRules[$name]=[pscustomobject]@{Name=$name;RemoteAddress=$rawIp;ExpiresAt=$expiry}
   Write-Log 'ACTION' "Created temporary inbound block for explicitly configured IP $rawIp; expires $expiry. This uses Windows Firewall."
   Add-ResponseLedger $rawIp 'TemporaryInboundBlock' 'SUCCESS' "Rule=$name; Expires=$expiry"
  } catch {Write-Log 'WARN' "Could not create temporary rule for $rawIp; check permissions and policy.";Add-ResponseLedger $rawIp 'TemporaryInboundBlock' 'FAILED' 'Rule creation failed.'}
 }
 Save-State
}
if(Test-Path $statePath){try {$saved=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json;foreach($r in @($saved.OwnedRules)){if($r.Name -like 'WindowsDefense-TemporaryBlock-*'){$script:OwnedRules[$r.Name]=$r}}} catch {}}
Write-Host '';Write-Host 'Windows Defense v0.4 - Independent Monitor + Bounded Response' -ForegroundColor Cyan
Write-Host 'Monitoring does not depend on Windows Firewall. Optional temporary inbound blocking does use it.' -ForegroundColor Green
Write-Host "Log: $logPath";Write-Host "Poll interval: $($cfg.PollSeconds)s. Press Ctrl+C to stop."
Write-Log 'INFO' 'Monitor started.';Remove-ExpiredOwnedRules;Invoke-ExplicitTemporaryBlocks
$lastListeners=Get-Listeners;$lastFirewall=Get-FirewallState;$lastFirewallAlerted=$false;$lastDefenderRecord=0L
try {$ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117} -MaxEvents 1;if($ev){$lastDefenderRecord=[long]$ev.RecordId}} catch {}
try {
 while($true){
  Remove-ExpiredOwnedRules
  $listeners=Get-Listeners
  foreach($l in $listeners){if($cfg.AlertOnNewListener -and @($lastListeners | Where-Object {$_.Key -eq $l.Key}).Count -eq 0){
   $score=Get-RiskScore 'NewListener' ($l.Process+' '+$l.Path)
   Write-Log 'ALERT' "RISK=$score/100 New listener $($l.Address):$($l.Port), PID=$($l.PID), process=$($l.Process), path=$($l.Path). New listener alone is not proof of malware."
   Add-ResponseLedger $l.Key 'ObserveNewListener' 'LOGGED' "Risk=$score; no automatic termination."
  }}
  $lastListeners=$listeners
  $fw=Get-FirewallState
  if(($fw -join ';') -ne ($lastFirewall -join ';')){if($cfg.AlertOnFirewallChange){Write-Log 'ALERT' ("Firewall state changed: "+($fw -join ';'))};$lastFirewall=$fw;$lastFirewallAlerted=$false}
  $isBad=@($fw | Where-Object {$_ -match 'Enabled=False' -or $_ -eq 'UNAVAILABLE'}).Count -gt 0
  if($isBad -and -not $lastFirewallAlerted){Write-Log 'ALERT' ("RISK=60/100 Firewall disabled/unconfirmed: "+($fw -join ';'));$lastFirewallAlerted=$true}
  if(-not $isBad -and $lastFirewallAlerted){Write-Log 'RECOVERY' 'Firewall profiles now report enabled; verify in Windows Security.';$lastFirewallAlerted=$false}
  try {
   $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117} -MaxEvents 30 | Where-Object {[long]$_.RecordId -gt $lastDefenderRecord} | Sort-Object RecordId)
   foreach($ev in $events){
    $lastDefenderRecord=[Math]::Max($lastDefenderRecord,[long]$ev.RecordId)
    $msg=($ev.Message -replace '\s+',' ').Trim();if($msg.Length -gt 500){$msg=$msg.Substring(0,500)}
    $kind=if($ev.Id -eq 1116){'DefenderThreat'}else{'DefenderAction'};$score=Get-RiskScore $kind $msg;$key="DefenderEvent-$($ev.RecordId)"
    Write-Log 'ALERT' "RISK=$score/100 Defender event $($ev.Id), record $($ev.RecordId): $msg"
    Add-ResponseLedger $key 'DefenderEvent' 'LOGGED' "EventId=$($ev.Id); Risk=$score"
    if($ev.Id -eq 1116 -and $cfg.AutoQuickScanOnDefenderThreat){Invoke-QuickScan $key}
   }
  } catch {}
  Start-Sleep -Seconds $cfg.PollSeconds
 }
} finally {
 Write-Log 'INFO' 'Monitor stopping; checking expiry of tool-owned temporary rules.'
 Remove-ExpiredOwnedRules
 Write-Log 'INFO' 'Stopped. Unexpired rules remain until expiry and are cleaned on next run.'
}
