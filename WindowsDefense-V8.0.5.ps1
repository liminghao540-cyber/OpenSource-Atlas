[CmdletBinding()]
param([ValidateSet('Snapshot','Monitor')][string]$Mode='Snapshot',
      [ValidateRange(5,60)][int]$PollSeconds=8,
      [ValidateRange(1,60)][int]$DurationMinutes=5)
$ErrorActionPreference='Continue'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$data=Join-Path $root 'data';$logs=Join-Path $root 'logs'
New-Item -ItemType Directory -Path $data,$logs -Force | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath=Join-Path $logs "WindowsDefense-V8.0.5-$stamp.log"
$eventsPath=Join-Path $data 'events-V8.0.5.jsonl'
$script:Seen=@{}
function Log([string]$Level,[string]$Message) {
 $line='{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
 Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
 if($Level -eq 'HIGH'){Write-Host $line -ForegroundColor Red}
 elseif($Level -eq 'WARN'){Write-Host $line -ForegroundColor Yellow}
 else{Write-Host $line -ForegroundColor Cyan}
}
function ProcessEvidence([int]$Id) {
 $name='unknown';$path=$null;$sig='Unavailable';$hash=$null
 try{$p=Get-Process -Id $Id -ErrorAction Stop;$name=[string]$p.ProcessName;try{$path=[string]$p.Path}catch{}}catch{}
 if($path -and (Test-Path -LiteralPath $path -PathType Leaf)){
  try{$sig=[string](Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop).Status}catch{$sig='CheckFailed'}
  try{$f=Get-Item -LiteralPath $path -ErrorAction Stop;if($f.Length -le 104857600){$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}}catch{}
 }
 [pscustomobject]@{PID=$Id;Name=$name;Path=$path;Signature=$sig;SHA256=$hash}
}
function Snapshot {
 $errors=New-Object 'System.Collections.Generic.List[string]'
 $est=@();$listen=@();$profiles=@();$defender=@()
 foreach($state in @('Established','Listen')){
  try{
   foreach($c in @(Get-NetTCPConnection -State $state -ErrorAction Stop | Select-Object -First 500)){
    $p=[int]$c.OwningProcess
    $row=[pscustomobject]@{PID=$p;LocalAddress=[string]$c.LocalAddress;LocalPort=[int]$c.LocalPort;RemoteAddress=[string]$c.RemoteAddress;RemotePort=[int]$c.RemotePort;Process=(ProcessEvidence $p)}
    if($state -eq 'Established'){$est+= $row}else{$listen+= $row}
   }
  }catch{$errors.Add("TCP $state unavailable: $($_.Exception.Message)")}
 }
 try{$profiles=@(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Name=[string]$_.Name;Enabled=[bool]$_.Enabled;InboundAction=[string]$_.DefaultInboundAction;OutboundAction=[string]$_.DefaultOutboundAction}})}catch{$errors.Add("Firewall profile state unavailable: $($_.Exception.Message)")}
 try{
  $defender=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=@(1116,1117)} -MaxEvents 50 -ErrorAction Stop | Sort-Object RecordId | ForEach-Object {
   $m=[string]$_.Message;if($m.Length -gt 350){$m=$m.Substring(0,350)}
   [pscustomobject]@{EventId=[int]$_.Id;RecordId=[long]$_.RecordId;TimeCreated=if($_.TimeCreated){$_.TimeCreated.ToUniversalTime().ToString('o')}else{$null};Message=$m}
  })
 }catch{$errors.Add("Defender log unavailable or unreadable: $($_.Exception.Message)")}
 [pscustomobject]@{CollectedAt=(Get-Date).ToString('o');ComputerName=$env:COMPUTERNAME;Established=$est;Listeners=$listen;FirewallProfiles=$profiles;DefenderEvents=$defender;CollectionErrors=@($errors.ToArray());ReadOnly=$true}
}
function Finding([string]$Key,[string]$Type,[int]$Score,[string]$Severity,[string]$Summary,[object]$Evidence){
 if($script:Seen.ContainsKey($Key)){return};$script:Seen[$Key]=$true
 $r=[pscustomobject]@{Timestamp=(Get-Date).ToString('o');Type=$Type;EventKey=$Key;RiskScore=$Score;Severity=$Severity;Summary=$Summary;Evidence=$Evidence}
 try{($r|ConvertTo-Json -Depth 7 -Compress)|Add-Content -LiteralPath $eventsPath -Encoding UTF8}catch{}
 Log $Severity "RISK=$Score/100 $Type $Summary"
}
function Analyze($s,[hashtable]$Previous,[bool]$OnlyNew){
 $counts=@{};foreach($c in $s.Established){$k=[string]$c.PID;if(!$counts.ContainsKey($k)){$counts[$k]=0};$counts[$k]++}
 foreach($c in $s.Established){
  $key="$($c.LocalAddress):$($c.LocalPort)|$($c.RemoteAddress):$($c.RemotePort)|$($c.PID)"
  if($OnlyNew -and $Previous.ContainsKey($key)){continue}
  $score=10;$why=@();$p=$c.Process
  if($p.Name -match '^(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)$'){$score+=25;$why+= 'script-or-system-tool'}
  if($p.Path -match '\\(AppData|Temp|Downloads)\\'){$score+=20;$why+='user-writable-location'}
  if($p.Signature -eq 'NotSigned'){$score+=15;$why+='unsigned-binary'}
  if($p.Signature -eq 'HashMismatch'){$score+=40;$why+='signature-hash-mismatch'}
  if($counts[[string]$c.PID] -ge 20){$score+=20;$why+='high-connection-fanout'}
  if($c.RemotePort -in @(23,2323)){$score+=10;$why+='unusual-remote-port'}
  $score=[Math]::Min(100,$score);$sev=if($score -ge 60){'HIGH'}elseif($score -ge 35){'WARN'}else{'INFO'}
  Finding $key 'TCPConnection' $score $sev "$($p.Name) PID=$($c.PID) -> $($c.RemoteAddress):$($c.RemotePort)" $why
 }
 foreach($l in $s.Listeners){
  $key="LISTEN|$($l.LocalAddress):$($l.LocalPort)|$($l.PID)"
  if($OnlyNew -and $Previous.ContainsKey($key)){continue}
  Finding $key 'TCPListener' 25 'INFO' "$($l.Process.Name) PID=$($l.PID) listening on $($l.LocalAddress):$($l.LocalPort)" $l.Process
 }
 foreach($p in $s.FirewallProfiles){if(!$p.Enabled){Finding "FW|$($p.Name)|disabled" 'FirewallProfileDisabled' 85 'HIGH' "Firewall profile $($p.Name) is disabled" $p}}
 foreach($e in $s.DefenderEvents){if($e.EventId -eq 1116){Finding "DEF|$($e.RecordId)" 'DefenderDetection' 85 'HIGH' "Defender detection: $($e.Message)" $e}elseif($e.EventId -eq 1117){Finding "DEF|$($e.RecordId)" 'DefenderAction' 20 'INFO' "Defender remediation: $($e.Message)" $e}}
}
Write-Host 'OpenSource Atlas - Windows Defense V8.0.5 (Native PowerShell)' -ForegroundColor Cyan
Write-Host 'Read-only. No firewall rules or system settings are changed.' -ForegroundColor Green
Log 'INFO' "Started mode=$Mode"
if($Mode -eq 'Snapshot'){
 $s=Snapshot;$s|ConvertTo-Json -Depth 8
 foreach($e in $s.CollectionErrors){Log 'WARN' $e}
 Analyze $s @{} $false
}else{
 $deadline=(Get-Date).AddMinutes($DurationMinutes);$previous=@{};$previousFw='';$poll=0
 try{
  while((Get-Date) -lt $deadline -and $poll -lt [int](($DurationMinutes*60)/$PollSeconds)){
   $poll++;$s=Snapshot;$current=@{}
   foreach($c in $s.Established){$current["$($c.LocalAddress):$($c.LocalPort)|$($c.RemoteAddress):$($c.RemotePort)|$($c.PID)"]=$true}
   foreach($l in $s.Listeners){$current["LISTEN|$($l.LocalAddress):$($l.LocalPort)|$($l.PID)"]=$true}
   if($poll -eq 1){$previous=$current;$previousFw=($s.FirewallProfiles|ConvertTo-Json -Compress);Log 'INFO' "Baseline ready. Poll=$PollSeconds seconds; limit=$DurationMinutes minutes."}
   else{
    Analyze $s $previous $true;$fw=($s.FirewallProfiles|ConvertTo-Json -Compress)
    if($previousFw -and $fw -ne $previousFw){Finding "FWCHANGE|$fw" 'FirewallProfileChanged' 70 'HIGH' 'Firewall profile state changed' $s.FirewallProfiles}
    $previous=$current;$previousFw=$fw
   }
   foreach($e in $s.CollectionErrors){Log 'WARN' $e}
   Start-Sleep -Seconds $PollSeconds
  }
 }finally{Log 'INFO' 'Bounded monitoring stopped.'}
}
Write-Host 'Finished. No automatic response or firewall changes were performed.' -ForegroundColor Green
