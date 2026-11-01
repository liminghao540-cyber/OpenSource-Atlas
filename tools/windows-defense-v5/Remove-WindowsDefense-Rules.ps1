[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$prefix = 'WindowsDefense-v5-TemporaryBlock-'
$marker = 'ManagedBy=WindowsDefense-v0.5;Scope=TemporaryInboundBlock'
$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
    $_.DisplayName -like "$prefix*" -and $_.Description -eq $marker
})

if ($rules.Count -eq 0) {
    Write-Host "No verified Windows Defense v0.5 temporary rules were found."
    exit 0
}

Write-Host ("Found {0} verified rule(s) owned by this tool:" -f $rules.Count)
$rules | Select-Object Name, DisplayName, Description, Enabled, Direction, Action | Format-Table -AutoSize

foreach ($rule in $rules) {
    if ($Force -or $PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove this exact marker-verified Windows Defense v0.5 firewall rule')) {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        Write-Host ("Removed: {0}" -f $rule.DisplayName)
    }
}
