$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $root 'WindowsDefense-v0.5.ps1'
$configPath = Join-Path $root 'config.json'
$rollbackPath = Join-Path $root 'Remove-WindowsDefense-Rules.ps1'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Host "PASS: $Message" -ForegroundColor Green
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'Main PowerShell script parses without syntax errors'

$rollbackTokens = $null
$rollbackErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($rollbackPath, [ref]$rollbackTokens, [ref]$rollbackErrors)
Assert-True ($rollbackErrors.Count -eq 0) 'Rollback PowerShell script parses without syntax errors'

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
Assert-True ($config.ResponseMode -eq 'MonitorOnly') 'Response mode defaults to MonitorOnly'
Assert-True ($config.EnableApprovedTemporaryBlocks -eq $false) 'Temporary firewall response defaults to disabled'
Assert-True (@($config.ApprovedBlockList).Count -eq 0) 'Approved block list defaults to empty'
Assert-True ($config.TemporaryBlockMinutes -ge 1 -and $config.TemporaryBlockMinutes -le 60) 'Configured firewall TTL is within 1–60 minutes'

$source = Get-Content -LiteralPath $scriptPath -Raw
Assert-True ($source -notmatch '(?im)\b(Stop-Process|Remove-Item|Set-ItemProperty)\b') 'Main monitor contains no process-kill, file-delete, or registry-write command'
Assert-True ($source -match 'WindowsDefense-v5-TemporaryBlock-') 'Firewall rules use a dedicated v0.5 display-name prefix'
Assert-True ($source -match 'ManagedBy=WindowsDefense-v0.5;Scope=TemporaryInboundBlock') 'Firewall cleanup requires an ownership marker'
Assert-True ($source -match 'Remove-NetFirewallRule -Name \$ruleName') 'Expiry cleanup removes only a marker-verified rule name'
Assert-True ($source -match 'ResponseMode = ''MonitorOnly''') 'Main script safe response default is MonitorOnly'

$rollbackSource = Get-Content -LiteralPath $rollbackPath -Raw
Assert-True ($rollbackSource -match '\$_.Description -eq \$marker') 'Rollback requires the exact ownership marker'
Assert-True ($rollbackSource -match 'Remove-NetFirewallRule -Name \$rule.Name') 'Rollback removes by exact verified firewall rule name'

Write-Host 'All static safety checks passed. Runtime behavior still requires a controlled Windows test.' -ForegroundColor Cyan
