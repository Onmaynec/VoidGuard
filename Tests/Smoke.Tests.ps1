Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$errorsFound = New-Object System.Collections.Generic.List[string]

$files = @(
    (Join-Path $root 'VoidGuard.ps1')
) + @(Get-ChildItem -LiteralPath (Join-Path $root 'Modules') -Filter '*.psm1' -File | Select-Object -ExpandProperty FullName)

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
    'Rules\known-bad-hashes.json'
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) {
        throw "Required file is missing: $relative"
    }
}

$settings = Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw | ConvertFrom-Json
if ([int]$settings.maxFilesPerScan -lt 1) {
    throw 'maxFilesPerScan must be positive.'
}

try {
    $statusOutput = & (Join-Path $root 'VoidGuard.ps1') -Mode Status -Professional -NoAnimation -Json
    $statusText = $statusOutput | Out-String
    if ([string]::IsNullOrWhiteSpace($statusText)) {
        throw 'Status command returned no output.'
    }
    $null = $statusText | ConvertFrom-Json
} catch {
    throw "Status smoke test failed: $($_.Exception.Message)"
}

Write-Host 'VoidGuard smoke tests passed.' -ForegroundColor Green
