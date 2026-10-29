# Windows Defense Safe Audit v0.2
# Read-only local audit for Windows PowerShell 5.1. No remediation or network scanning.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$reportDir = Join-Path $root 'reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$txtPath = Join-Path $reportDir "WindowsDefense-$stamp.txt"
$jsonPath = Join-Path $reportDir "WindowsDefense-$stamp.json"
function Get-ProcInfo([int]$Id) {
    try { $p = Get-Process -Id $Id -ErrorAction Stop; $path=$null; try {$path=$p.Path} catch {}; [pscustomobject]@{Id=$Id;Name=$p.ProcessName;Path=$path} }
    catch { [pscustomobject]@{Id=$Id;Name='(process unavailable)';Path=$null} }
}
function Has-Command([string]$Name) { try { [void](Get-Command $Name -ErrorAction Stop); return $true } catch { return $false } }
Write-Host ''; Write-Host 'Windows Defense - Safe Audit v0.2' -ForegroundColor Cyan
Write-Host 'Read-only checks. No settings will be changed.' -ForegroundColor Green
$report = [ordered]@{
 GeneratedAt=(Get-Date).ToString('o'); ComputerName=$env:COMPUTERNAME; UserName=$env:USERNAME; OS=$null
 FirewallProfiles=@(); FirewallPolicyRegistry=@(); FirewallService=$null
 Defender=[ordered]@{QueryAvailable=$false;Status='UNKNOWN';Details=$null}
 TcpListeners=@(); EstablishedTcp=@(); StartupEntries=@(); RecentHotfixes=@(); Notes=@(); Findings=@()
}
try {$report.OS=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture} catch {$report.Notes += "OS query failed: $($_.Exception.Message)"}
try {$report.FirewallProfiles=@(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)} catch {$report.Notes += "Firewall query failed: $($_.Exception.Message)"}
try {$report.FirewallService=Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" | Select-Object Name,State,StartMode} catch {$report.Notes += "Firewall service query failed: $($_.Exception.Message)"}
$policyPath='HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
foreach($n in @('DomainProfile','PrivateProfile','PublicProfile')){
 $e=[ordered]@{Profile=$n;RegistryKeyFound=$false;EnableFirewall=$null}
 try {$v=Get-ItemProperty -LiteralPath (Join-Path $policyPath $n) -ErrorAction Stop;$e.RegistryKeyFound=$true;if($null -ne $v.EnableFirewall){$e.EnableFirewall=[int]$v.EnableFirewall}} catch {}
 $report.FirewallPolicyRegistry += [pscustomobject]$e
}
if(Has-Command 'Get-MpComputerStatus'){
 $report.Defender.QueryAvailable=$true
 try {$d=Get-MpComputerStatus -ErrorAction Stop;$report.Defender.Status='QUERIED';$report.Defender.Details=$d | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated}
 catch {$report.Defender.Status='QUERY_FAILED';$report.Defender.Details=$_.Exception.Message}
} else {
 $report.Defender.Status='COMMAND_UNAVAILABLE'
 try {$report.Defender.Details=Get-CimInstance Win32_Service -Filter "Name='WinDefend'" | Select-Object Name,State,StartMode} catch {}
}
try {$report.TcpListeners=@(Get-NetTCPConnection -State Listen | ForEach-Object {$p=Get-ProcInfo ([int]$_.OwningProcess);[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;ProcessId=$p.Id;ProcessName=$p.Name;ProcessPath=$p.Path}} | Sort-Object LocalPort,LocalAddress)} catch {$report.Notes += "Listener query failed: $($_.Exception.Message)"}
try {$report.EstablishedTcp=@(Get-NetTCPConnection -State Established | ForEach-Object {$p=Get-ProcInfo ([int]$_.OwningProcess);[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;ProcessId=$p.Id;ProcessName=$p.Name;ProcessPath=$p.Path}} | Sort-Object ProcessName,RemoteAddress,RemotePort)} catch {$report.Notes += "Connection query failed: $($_.Exception.Message)"}
foreach($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')){
 try {$props=Get-ItemProperty -LiteralPath $path -ErrorAction Stop;foreach($prop in $props.PSObject.Properties){if($prop.Name -notmatch '^PS'){$report.StartupEntries += [pscustomobject]@{Source=$path;Name=$prop.Name;Command=[string]$prop.Value}}}} catch {}
}
foreach($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){
 if($folder -and (Test-Path $folder)){Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {$report.StartupEntries += [pscustomobject]@{Source=$folder;Name=$_.Name;Command=$_.FullName}}}
}
try {$report.RecentHotfixes=@(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,Description,InstalledOn)} catch {}
$alerts=[System.Collections.Generic.List[string]]::new()
if(@($report.FirewallProfiles | Where-Object {$_.Enabled -ne $true}).Count -gt 0){$alerts.Add('REVIEW: One or more firewall profiles are disabled or unconfirmed.')}
if(@($report.FirewallPolicyRegistry | Where-Object {$_.EnableFirewall -eq 0}).Count -gt 0){$alerts.Add('REVIEW: Policy registry contains EnableFirewall=0. Identify policy source before changing registry.')}
if($report.Defender.Status -ne 'QUERIED'){$alerts.Add('UNKNOWN: Defender status was not fully confirmed; this does not prove Defender is off.')}
if(@($report.TcpListeners | Where-Object {$_.LocalAddress -in @('0.0.0.0','::')}).Count -gt 0){$alerts.Add('INFO: A service listens on all local IPv4/IPv6 interfaces. Review its process; this alone is not malicious.')}
if($alerts.Count -eq 0){$alerts.Add('OK: No rule-based findings from completed checks. This is not a guarantee of safety.')}
$report.Findings=@($alerts)
$lines=[System.Collections.Generic.List[string]]::new()
$lines.Add('Windows Defense - Safe Audit v0.2');$lines.Add("Generated: $($report.GeneratedAt)");$lines.Add("Computer: $($report.ComputerName)")
$lines.Add('Read-only, rule-based local audit. No remediation, remote scan, or AI verdict.')
$lines.Add('');$lines.Add('=== Findings ===');foreach($x in $report.Findings){$lines.Add($x)}
$lines.Add('');$lines.Add('=== OS ===');$lines.Add(($report.OS | Format-List | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Firewall Profiles ===');$lines.Add(($report.FirewallProfiles | Format-Table -AutoSize | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Firewall Policy Registry ===');$lines.Add(($report.FirewallPolicyRegistry | Format-Table -AutoSize | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Firewall Service ===');$lines.Add(($report.FirewallService | Format-List | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Defender ===');$lines.Add(($report.Defender | ConvertTo-Json -Depth 5).TrimEnd())
$lines.Add('');$lines.Add('=== TCP Listeners with process ===');$lines.Add(($report.TcpListeners | Format-Table -Wrap -AutoSize | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Established TCP with process ===');$lines.Add(($report.EstablishedTcp | Format-Table -Wrap -AutoSize | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Startup Entries ===');$lines.Add(($report.StartupEntries | Format-List | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Recent Hotfixes ===');$lines.Add(($report.RecentHotfixes | Format-Table -AutoSize | Out-String).TrimEnd())
$lines.Add('');$lines.Add('=== Notes ===');foreach($n in $report.Notes){$lines.Add($n)}
$lines | Set-Content -LiteralPath $txtPath -Encoding UTF8
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Host '';Write-Host '=== Findings ===' -ForegroundColor Cyan;foreach($x in $report.Findings){Write-Host $x}
Write-Host '';Write-Host 'Reports saved:' -ForegroundColor Green;Write-Host $txtPath;Write-Host $jsonPath
Write-Host 'Review reports before sharing; they may contain usernames, paths, and local/remote IP addresses.'
