[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$WhatIfOnly)
$ErrorActionPreference='Continue'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$path=Join-Path (Join-Path $root 'data') 'state-v0.7.json'
$marker='ManagedBy=WindowsDefense-v0.7;Scope=TemporaryOutboundBlock'
if(-not(Test-Path -LiteralPath $path)){Write-Host 'No v0.7 state; nothing changed.';exit 0}
try{$state=Get-Content $path -Raw|ConvertFrom-Json}catch{Write-Warning 'State unreadable; refusing cleanup.';exit 1}
$removed=0;$skipped=0
foreach($r in @($state.OwnedRules)){
 $name=[string]$r.Name
 if($name -notlike 'WDv7-TempOut-*'){Write-Warning "Skipped unexpected name: $name";$skipped++;continue}
 try{
  $rules=@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
  if(!$rules.Count){Write-Host "Already absent: $name";continue}
  $ok=@($rules|Where-Object{$_.Name -eq $name -and $_.Description -eq $marker -and $_.DisplayName -like 'WindowsDefense-v7-TemporaryOutboundBlock-*' -and $_.Group -eq 'WindowsDefense-v0.7' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'})
  if($ok.Count -ne 1){Write-Warning "Ownership mismatch; skipped: $name";$skipped++;continue}
  if($WhatIfOnly){Write-Host "Would remove: $name";continue}
  if($PSCmdlet.ShouldProcess($name,'Remove verified v0.7 rule')){Remove-NetFirewallRule -Name $name -ErrorAction Stop;Write-Host "Removed: $name";$removed++}
 }catch{Write-Warning "Failed: $name";$skipped++}
}
Write-Host "Finished. Removed=$removed Skipped=$skipped. State retained for audit."
