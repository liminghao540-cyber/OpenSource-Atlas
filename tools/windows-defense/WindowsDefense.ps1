# Windows Defense - Safe Audit v0.1
# Windows PowerShell 5.1 compatible. Read-only: no settings are changed.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([string]$Area, [string]$Status, [string]$Summary, [string]$Details = '')
    $script:Findings.Add([pscustomobject]@{
        area = $Area; status = $Status; summary = $Summary
        details = $Details; time = (Get-Date).ToString('o')
    }) | Out-Null
}

$started = Get-Date
Write-Host ''
Write-Host 'Windows Defense - Safe Audit v0.1' -ForegroundColor Cyan
Write-Host 'Read-only local checks. No settings will be changed.' -ForegroundColor Gray

try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Finding 'System' 'INFO' ("OS: {0}; version {1}; build {2}" -f $os.Caption, $os.Version, $os.BuildNumber) ("Last boot: {0}" -f $os.LastBootUpTime)
} catch { Add-Finding 'System' 'UNKNOWN' 'Could not read operating-system details.' $_.Exception.Message }

try {
    $mp = Get-MpComputerStatus
    if ($null -eq $mp) { throw 'Defender status was not returned.' }
    $rt = [bool]$mp.RealTimeProtectionEnabled
    $av = [bool]$mp.AntivirusEnabled
    if ($rt -and $av) {
        Add-Finding 'Defender' 'OK' 'Microsoft Defender antivirus and real-time protection report enabled.' ("Signature age (days): {0}" -f $mp.AntivirusSignatureAge)
    } else {
        Add-Finding 'Defender' 'REVIEW' 'One or more Defender protection flags are disabled.' ("AntivirusEnabled={0}; RealTimeProtectionEnabled={1}; SignatureAgeDays={2}. Verify in Windows Security; another antivirus may manage protection." -f $av, $rt, $mp.AntivirusSignatureAge)
    }
} catch { Add-Finding 'Defender' 'UNKNOWN' 'Could not query Defender status.' 'Check Virus & threat protection in Windows Security.' }

try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($profiles.Count -gt 0) {
        $off = @($profiles | Where-Object { -not $_.Enabled })
        if ($off.Count -eq 0) {
            Add-Finding 'Firewall' 'OK' 'Windows Firewall is enabled for all profiles.' (($profiles | ForEach-Object { '{0}=On' -f $_.Name }) -join '; ')
        } else {
            Add-Finding 'Firewall' 'REVIEW' 'Windows Firewall appears disabled for one or more profiles.' (($profiles | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }) -join '; ')
        }
    } else { Add-Finding 'Firewall' 'UNKNOWN' 'No firewall profile information returned.' }
} catch { Add-Finding 'Firewall' 'UNKNOWN' 'Could not query Windows Firewall profiles.' $_.Exception.Message }

try {
    $listeners = @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort, OwningProcess -Unique)
    $items = @($listeners | Select-Object -First 60 | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess
        '{0}:{1} PID={2} Process={3}' -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess, $(if ($proc) { $proc.ProcessName } else { 'unknown' })
    })
    $details = $items -join [Environment]::NewLine
    if ($listeners.Count -gt 60) { $details += [Environment]::NewLine + 'Only first 60 shown.' }
    Add-Finding 'Network' 'INFO' ("Found {0} local TCP listening endpoint(s)." -f $listeners.Count) $details
} catch { Add-Finding 'Network' 'UNKNOWN' 'Could not inventory local TCP listening endpoints.' 'A listening port alone does not indicate an attack.' }

try {
    $connections = @(Get-NetTCPConnection -State Established | Select-Object -First 80)
    $items = @($connections | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess
        '{0}:{1} -> {2}:{3} PID={4} Process={5}' -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.OwningProcess, $(if ($proc) { $proc.ProcessName } else { 'unknown' })
    })
    Add-Finding 'Network' 'INFO' ("Captured {0} established TCP connection(s), maximum 80 displayed." -f $connections.Count) ($items -join [Environment]::NewLine)
} catch { Add-Finding 'Network' 'UNKNOWN' 'Could not query established TCP connections.' $_.Exception.Message }

try {
    $startup = @(Get-CimInstance Win32_StartupCommand | Select-Object -First 100)
    $items = @($startup | ForEach-Object { 'Name={0}; User={1}; Location={2}; Command={3}' -f $_.Name, $_.User, $_.Location, $_.Command })
    Add-Finding 'Startup' 'INFO' ("Enumerated {0} startup item(s), maximum 100 displayed." -f $startup.Count) ($items -join [Environment]::NewLine)
} catch { Add-Finding 'Startup' 'UNKNOWN' 'Could not enumerate startup items.' $_.Exception.Message }

try {
    $hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5)
    $items = @($hotfixes | ForEach-Object { '{0} installed {1}' -f $_.HotFixID, $_.InstalledOn })
    Add-Finding 'Updates' 'INFO' 'Recent listed hotfixes; this is not a full update-compliance test.' ($items -join [Environment]::NewLine)
} catch { Add-Finding 'Updates' 'UNKNOWN' 'Could not list recent hotfixes.' 'Check Settings > Update & Security > Windows Update.' }

$reviewCount = @($script:Findings | Where-Object { $_.status -eq 'REVIEW' }).Count
$unknownCount = @($script:Findings | Where-Object { $_.status -eq 'UNKNOWN' }).Count
if ($reviewCount -gt 0) {
    Add-Finding 'Guidance' 'REVIEW' 'Review items marked REVIEW before taking action.' 'This tool does not determine that a machine is infected. Verify findings in Windows Security or with a trusted administrator.'
} elseif ($unknownCount -gt 0) {
    Add-Finding 'Guidance' 'INFO' 'Some checks could not be completed.' 'Open relevant Windows settings and verify manually.'
} else {
    Add-Finding 'Guidance' 'INFO' 'No obvious disabled protection flag was detected by these limited checks.' 'This is not a malware scan and does not guarantee the device is secure.'
}

$finished = Get-Date
$report = [pscustomobject]@{
    product = 'Windows Defense - Safe Audit'; version = '0.1.0'
    started = $started.ToString('o'); finished = $finished.ToString('o')
    computer = $env:COMPUTERNAME; user = $env:USERNAME; mode = 'read-only'
    findings = @($script:Findings)
    limitations = @('Not a replacement for antivirus.', 'Network inventory is not proof of malicious activity.', 'No system settings are modified.', 'No remote host or AI service is contacted.')
}
$reportDir = Join-Path $PSScriptRoot 'reports'
try {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $reportDir ("audit-{0}.json" -f $stamp)
    $txtPath = Join-Path $reportDir ("audit-{0}.txt" -f $stamp)
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Windows Defense - Safe Audit v0.1.0')
    $lines.Add(('Computer: {0}; User: {1}' -f $env:COMPUTERNAME, $env:USERNAME))
    $lines.Add(('Started: {0}' -f $started))
    $lines.Add('')
    foreach ($f in $script:Findings) {
        $lines.Add(('[{0}] {1}: {2}' -f $f.status, $f.area, $f.summary))
        if ($f.details) { $lines.Add([string]$f.details) }
        $lines.Add('')
    }
    $lines.Add('Inventory findings are not proof of compromise.')
    $lines | Set-Content -LiteralPath $txtPath -Encoding UTF8
    Write-Host ("Text report: {0}" -f $txtPath) -ForegroundColor Green
    Write-Host ("JSON report: {0}" -f $jsonPath) -ForegroundColor Green
} catch { Write-Host ("Could not save report: {0}" -f $_.Exception.Message) -ForegroundColor Red }

Write-Host ''
Write-Host 'Summary:' -ForegroundColor Cyan
foreach ($f in $script:Findings) {
    $color = switch ($f.status) { 'OK' { 'Green' } 'REVIEW' { 'Yellow' } 'UNKNOWN' { 'DarkYellow' } default { 'Gray' } }
    Write-Host ('[{0}] {1} - {2}' -f $f.status, $f.area, $f.summary) -ForegroundColor $color
}
Write-Host ''
Write-Host 'No automatic remediation was performed.' -ForegroundColor Gray
