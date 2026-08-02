Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$errorsFound = New-Object System.Collections.Generic.List[string]
$files = @((Join-Path $root 'VoidGuard.ps1')) + @(
    Get-ChildItem -LiteralPath (Join-Path $root 'Modules') -Filter '*.psm1' -File |
        Select-Object -ExpandProperty FullName
)

foreach ($file in $files) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) | Out-Null
    foreach ($parseError in @($parseErrors)) {
        $errorsFound.Add("${file}:$($parseError.Extent.StartLineNumber): $($parseError.Message)")
    }
}
if ($errorsFound.Count -gt 0) {
    $errorsFound | ForEach-Object { Write-Error $_ }
    throw "PowerShell parser found $($errorsFound.Count) error(s)."
}

$requiredFiles = @(
    'VoidGuard.cmd',
    'VERSION',
    'Config\settings.json',
    'Assets\skulls\main.txt',
    'Rules\known-bad-hashes.json',
    'Modules\VoidGuard.Persistence.psm1',
    'Modules\VoidGuard.Remediation.psm1'
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) {
        throw "Required file is missing: $relative"
    }
}

$settings = Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw | ConvertFrom-Json
if ([int]$settings.maxFilesPerScan -lt 1) { throw 'maxFilesPerScan must be positive.' }
if ([int]$settings.minimumPersistenceScore -lt 1) { throw 'minimumPersistenceScore must be positive.' }
if ([int]$settings.maximumDisplayedFindings -lt 1) { throw 'maximumDisplayedFindings must be positive.' }

try {
    $statusOutput = & (Join-Path $root 'VoidGuard.ps1') -Mode Status -Professional -NoAnimation -Json
    $statusText = $statusOutput | Out-String
    if ([string]::IsNullOrWhiteSpace($statusText)) { throw 'Status command returned no output.' }
    $status = $statusText | ConvertFrom-Json
    if (-not $status.PSObject.Properties.Name.Contains('IsAdministrator')) {
        throw 'Status output is missing IsAdministrator.'
    }
} catch {
    throw "Status smoke test failed: $($_.Exception.Message)"
}

$moduleOrder = @(
    'VoidGuard.Animation.psm1',
    'VoidGuard.Protection.psm1',
    'VoidGuard.Scanner.psm1',
    'VoidGuard.System.psm1',
    'VoidGuard.Persistence.psm1',
    'VoidGuard.Remediation.psm1',
    'VoidGuard.Quarantine.psm1',
    'VoidGuard.UI.psm1'
)
foreach ($moduleName in $moduleOrder) {
    Import-Module (Join-Path $root "Modules\$moduleName") -Force -DisableNameChecking
}

foreach ($commandName in @(
    'Get-VoidGuardPersistenceFindings',
    'Get-VoidGuardFileLockOwners',
    'Register-VoidGuardDeleteOnReboot',
    'Get-VoidGuardPendingRemediations',
    'Test-VoidGuardProcessSafeToStop'
)) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Exported command is missing: $commandName"
    }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-Test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $samplePath = Join-Path $tempRoot 'invoice.pdf.cmd'
    '@echo off`r`npowershell.exe -WindowStyle Hidden -EncodedCommand AAAA' | Set-Content -LiteralPath $samplePath -Encoding ASCII
    $context = New-VoidGuardContext -RootPath $root -Settings $settings -Professional -NoAnimation
    $finding = Test-VoidGuardFile -Path $samplePath -Context $context -KnownBadHashes @{}
    if (-not $finding -or $finding.Score -lt 20) {
        throw 'Heuristic sample did not cross the expected score.'
    }
    $policy = Test-VoidGuardProtectedTarget -Path $samplePath
    if (-not $policy.Allowed) {
        throw 'A normal temporary test file was unexpectedly blocked by policy.'
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'VoidGuard v0.2 smoke tests passed.' -ForegroundColor Green
