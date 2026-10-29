# Windows Defense v0.3 - continuous monitor for Windows PowerShell 5.1
# Safe defaults: monitor and log; optional Defender quick scan on a Defender threat event.
$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $root 'config.json'
$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$logPath = Join-Path $logDir ("WindowsDefense-Monitor-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$cfg = @{ PollSeconds=10; AutoQuickScanOnThreat=$true; ShowConsoleAlerts=$true }
if (Test-Path $cfgPath) {
  try { $userCfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json; if ($userCfg.PollSeconds -ge 5 -and $userCfg.PollSeconds -le 60) {$cfg.PollSeconds=[int]$userCfg.PollSeconds}; if ($null -ne $userCfg.AutoQuickScanOnThreat) {$cfg.AutoQuickScanOnThreat=[bool]$userCfg.AutoQuickScanOnThreat}; if ($null -ne $userCfg.ShowConsoleAlerts) {$cfg.ShowConsoleAlerts=[bool]$userCfg.ShowConsoleAlerts} } catch {}
}
function Write-Event([string]$Level,[string]$Message) {
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
  Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
  if ($cfg.ShowConsoleAlerts) {
    if ($Level -eq 'ALERT') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'ACTION') { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line -ForegroundColor Cyan }
  }
}
function Get-ListenerSnapshot {
  try { @(Get-NetTCPConnection -State Listen | ForEach-Object { '{0}|{1}|{2}' -f $_.LocalAddress,$_.LocalPort,$_.OwningProcess } | Sort-Object -Unique) } catch { @() }
}
function Get-FirewallSnapshot {
  try { @(Get-NetFirewallProfile | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction } | Sort-Object) } catch { @('UNKNOWN') }
}
function Start-SafeQuickScan {
  try {
    $cmd = Get-Command Start-MpScan -ErrorAction Stop
    & $cmd -ScanType QuickScan
    Write-Event 'ACTION' 'Defender quick scan was requested after a Defender threat event. Check Windows Security for scan results.'
  } catch { Write-Event 'WARN' 'Could not start Defender quick scan automatically; open Windows Security and review protection history.' }
}
Write-Host ''
Write-Host 'Windows Defense v0.3 - Continuous Monitor' -ForegroundColor Cyan
Write-Host 'Monitoring only; no IP blocking, process killing, registry edits, or firewall changes.' -ForegroundColor Green
Write-Host ("Log: {0}" -f $logPath)
Write-Host ("Poll interval: {0}s. Press Ctrl+C to stop." -f $cfg.PollSeconds)
Write-Event 'INFO' 'Monitor started.'
$lastListeners = Get-ListenerSnapshot
$lastFirewall = Get-FirewallSnapshot
$lastDefenderRecord = 0L
try {
  $latest = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} -MaxEvents 1
  if ($latest) { $lastDefenderRecord = [long]$latest.RecordId }
} catch {}
while ($true) {
  $listeners = Get-ListenerSnapshot
  foreach ($item in $listeners) {
    if ($lastListeners -notcontains $item) { Write-Event 'ALERT' ("New TCP listener observed: {0}. Verify the owning process before taking action." -f $item) }
  }
  $lastListeners = $listeners
  $fw = Get-FirewallSnapshot
  if (($fw -join ';') -ne ($lastFirewall -join ';')) { Write-Event 'ALERT' ("Firewall profile state/policy changed: {0}" -f ($fw -join ';')); $lastFirewall=$fw }
  if (@($fw | Where-Object { $_ -match '\|False\|' -or $_ -eq 'UNKNOWN' }).Count -gt 0) { Write-Event 'ALERT' 'At least one firewall profile is disabled or could not be confirmed. Review Windows Security / firewall policy.' }
  try {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} -MaxEvents 20 | Where-Object { [long]$_.RecordId -gt $lastDefenderRecord } | Sort-Object RecordId)
    foreach ($ev in $events) {
      $lastDefenderRecord=[Math]::Max($lastDefenderRecord,[long]$ev.RecordId)
      $msg=($ev.Message -replace '\s+',' ').Trim()
      if ($msg.Length -gt 700) {$msg=$msg.Substring(0,700)}
      Write-Event 'ALERT' ("Windows Defender event {0}: {1}" -f $ev.Id,$msg)
      if ($ev.Id -eq 1116 -and $cfg.AutoQuickScanOnThreat) { Start-SafeQuickScan }
    }
  } catch {}
  Start-Sleep -Seconds $cfg.PollSeconds
}
