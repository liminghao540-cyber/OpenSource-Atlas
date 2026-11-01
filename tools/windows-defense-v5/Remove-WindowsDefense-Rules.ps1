[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$prefix = 'WindowsDefense-v5-TemporaryBlock-'
$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -like "$prefix*" })

if ($rules.Count -eq 0) {
    Write-Host "No Windows Defense v0.5 temporary rules were found."
    exit 0
}

Write-Host ("Found {0} rule(s) owned by this tool:" -f $rules.Count)
$rules | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize

foreach ($rule in $rules) {
    if ($Force -or $PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove this exact Windows Defense v0.5 firewall rule')) {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        Write-Host ("Removed: {0}" -f $rule.DisplayName)
    }
}
