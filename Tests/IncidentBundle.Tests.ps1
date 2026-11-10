#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
foreach ($name in @(
    'VoidGuard.Animation','VoidGuard.Protection','VoidGuard.RulePacks','VoidGuard.Scanner',
    'VoidGuard.System','VoidGuard.Persistence','VoidGuard.Remediation',
    'VoidGuard.IntegritySnapshot','VoidGuard.IntegrityBaseline','VoidGuard.Reporting',
    'VoidGuard.UI','VoidGuard.IncidentBundle'
)) {
    Import-Module (Join-Path $root "Modules\$name.psm1") -Force -DisableNameChecking
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-IncidentTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $settings=Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.maxFilesPerScan=15
    $ctx=New-VoidGuardContext -RootPath $root -Settings $settings -Professional -NoAnimation
    $output=Join-Path $temp 'incident.zip'
    $sample=Join-Path $temp 'safe.ps1'
    'Write-Host safe' | Set-Content -LiteralPath $sample -Encoding ASCII

    $preview=Get-VGIncidentPreview -OutputPath $output -ScanPath $sample
    if ($preview.Status -ne 'READY' -or -not $preview.RequiresConfirmation -or $preview.IncludeSensitive) {
        throw 'Default privacy preview is invalid.'
    }
    if (@($preview.Categories).Count -lt 5 -or (Test-Path -LiteralPath $output)) {
        throw 'Preview should disclose categories without creating files.'
    }
    $sensitive=Get-VGIncidentPreview -OutputPath $output -IncludeSensitive -IncludeEventLogs
    if (-not $sensitive.IncludeSensitive -or -not $sensitive.IncludeEventLogs) {
        throw 'Sensitive preview did not disclose the requested additional data.'
    }

    $denied=Export-VGIncidentBundle -Context $ctx -OutputPath $output -ScanPath $sample
    if ($denied.Status -ne 'CONFIRMATION_REQUIRED' -or (Test-Path -LiteralPath $output)) {
        throw 'Incident export did not require confirmation.'
    }
    $dry=Export-VGIncidentBundle -Context $ctx -OutputPath $output -ScanPath $sample -Confirmed -WhatIf
    if ($dry.Status -ne 'DRY_RUN' -or (Test-Path -LiteralPath $output)) {
        throw 'Incident -WhatIf changed the file system.'
    }

    $export=Export-VGIncidentBundle -Context $ctx -OutputPath $output -ScanPath $sample -Confirmed
    if (-not $export.Success -or $export.Status -notin @('COMPLETE','PARTIAL') -or -not (Test-Path -LiteralPath $output)) {
        throw "Local incident archive was not created: $($export.Status)"
    }
    if ($export.ContainsSensitiveData -or $export.SHA256 -notmatch '^[A-F0-9]{64}$') {
        throw 'Privacy or SHA-256 digest contract failed.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $extracted=Join-Path $temp 'extracted'
    [IO.Compression.ZipFile]::ExtractToDirectory($output,$extracted)
    $actual=@(Get-ChildItem -LiteralPath $extracted -File | Select-Object -ExpandProperty Name | Sort-Object)
    $expected=@('diagnostics.json','manifest.json','SHA256SUMS.txt' | Sort-Object)
    if (($actual -join ',') -ne ($expected -join ',')) { throw 'Unexpected ZIP contents.' }

    $data=Get-Content -LiteralPath (Join-Path $extracted 'diagnostics.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$data.SchemaVersion -ne 1 -or $data.ContainsSensitiveData -or $data.ComputerName -ne '[REDACTED]') {
        throw 'Sensitive identifiers were included in default bundle.'
    }
    if (-not $data.Sections.PSObject.Properties['Security'] -or -not $data.Sections.PSObject.Properties['Scan']) {
        throw 'Expected incident sections are missing.'
    }
    $json=Get-Content -LiteralPath (Join-Path $extracted 'diagnostics.json') -Raw -Encoding UTF8
    foreach ($rawField in @('"CommandLine"','"DefenderExclusions"','"TargetPath"','"Connections"','"Message"')) {
        if ($json.Contains($rawField)) { throw "Default incident bundle leaked raw field $rawField" }
    }
    $checksums=Get-Content -LiteralPath (Join-Path $extracted 'SHA256SUMS.txt') -Raw -Encoding UTF8
    if (-not $checksums.Contains((Get-FileHash -LiteralPath (Join-Path $extracted 'diagnostics.json') -Algorithm SHA256).Hash)) {
        throw 'Diagnostic content hash is absent from the checksum manifest.'
    }

    $overwritten=$false
    try { Export-VGIncidentBundle -Context $ctx -OutputPath $output -Confirmed | Out-Null }
    catch { $overwritten=$true }
    if (-not $overwritten) { throw 'Existing ZIP destination was overwritten.' }

    $uncBlocked=$false
    try { Get-VGIncidentPreview -OutputPath '\\example.invalid\share\incident.zip' | Out-Null }
    catch { $uncBlocked=$true }
    if (-not $uncBlocked) { throw 'UNC incident output path was allowed.' }

    Write-Host '[OK] Incident Bundle: privacy preview, confirmation, WhatIf, ZIP integrity, redaction and no overwrite.' -ForegroundColor Green
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
