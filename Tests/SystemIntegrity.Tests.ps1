#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$root=Split-Path -Parent $PSScriptRoot
foreach ($name in @('VoidGuard.Protection','VoidGuard.System','VoidGuard.IntegritySnapshot','VoidGuard.IntegrityBaseline','VoidGuard.DefenderOffline')) {
    Import-Module (Join-Path $root "Modules\$name.psm1") -Force -DisableNameChecking
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-Integrity-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $file=Join-Path $temp 'sample.cmd'
    $baseline=Join-Path $temp 'baseline.json'
    '@echo off' | Set-Content -LiteralPath $file -Encoding ASCII
    $created=New-VGIntegrityBaseline -BaselinePath $baseline -SelectedPaths @($file) -Sections @('Files') -IncludeHosts:$false
    if ($created.Status -ne 'COMPLETE' -or -not (Test-Path -LiteralPath $baseline)) { throw 'Baseline was not created.' }
    if ($created.SHA256 -notmatch '^[A-F0-9]{64}$') { throw 'Baseline digest is missing.' }
    $same=Compare-VGIntegrityBaseline -BaselinePath $baseline
    if ($same.Status -ne 'UNCHANGED' -or $same.ChangesCount -ne 0 -or -not $same.Complete) { throw 'Unchanged baseline diff failed.' }

    '@echo changed' | Set-Content -LiteralPath $file -Encoding ASCII
    $changed=Compare-VGIntegrityBaseline -BaselinePath $baseline
    if ($changed.Status -ne 'CHANGED' -or $changed.ChangesCount -ne 1 -or $changed.Changed -ne 1) { throw 'File SHA-256 change was not detected.' }
    if ($changed.Changes[0].Section -ne 'Files' -or $changed.Changes[0].Kind -ne 'CHANGED') { throw 'Incorrect diff details.' }

    $overwriteBlocked=$false
    try { New-VGIntegrityBaseline -BaselinePath $baseline -SelectedPaths @($file) -Sections @('Files') -IncludeHosts:$false | Out-Null }
    catch { $overwriteBlocked=$true }
    if (-not $overwriteBlocked) { throw 'Existing baseline could be overwritten.' }

    $before=Get-Content -LiteralPath $baseline -Raw -Encoding UTF8 | ConvertFrom-Json
    $after=Get-Content -LiteralPath $baseline -Raw -Encoding UTF8 | ConvertFrom-Json
    $after.Sections.Files.Records[0].Value='SHA256:CHANGED;SIZE:3'
    $diff=Compare-VGIntegritySnapshots -Baseline $before -Current $after
    if ($diff.Status -ne 'CHANGED' -or $diff.Changed -ne 1) { throw 'Pure diff failed.' }

    $after.Sections.Files.State='PARTIAL'
    $partial=Compare-VGIntegritySnapshots -Baseline $before -Current $after
    if ($partial.Status -ne 'PARTIAL' -or $partial.ChangesCount -ne 0 -or $partial.Complete) {
        throw 'Partial section was mistaken for a real change.'
    }

    $after.Sections.Files.State='COMPLETE'
    $after.Sections.Files.Records=@($after.Sections.Files.Records[0],$after.Sections.Files.Records[0])
    $duplicateBlocked=$false
    try { Compare-VGIntegritySnapshots -Baseline $before -Current $after | Out-Null }
    catch { $duplicateBlocked=$true }
    if (-not $duplicateBlocked) { throw 'Duplicate snapshot keys were accepted.' }

    $readiness=[pscustomobject]@{Ready=$true}
    if ((Get-VGDefenderOfflineDecision -Readiness $readiness) -ne 'CONFIRMATION_REQUIRED') { throw 'Offline scan requires confirmation.' }
    if ((Get-VGDefenderOfflineDecision -Readiness $readiness -Confirmed) -ne 'CONFIRMATION_REQUIRED') { throw 'Restart acknowledgment is required.' }
    if ((Get-VGDefenderOfflineDecision -Readiness ([pscustomobject]@{Ready=$false}) -Confirmed -RebootAcknowledged) -ne 'BLOCKED') { throw 'Blocked offline scan allowed.' }
    if ((Get-VGDefenderOfflineDecision -Readiness $readiness -Confirmed -RebootAcknowledged) -ne 'READY_TO_LAUNCH') { throw 'Decision validation failed.' }
    # Никогда не вызываем реальный Start-MpWDOScan в CI.
    $preview=Invoke-VGDefenderOffline
    if ($preview.Status -notin @('BLOCKED','CONFIRMATION_REQUIRED')) { throw 'Readiness preview caused an unexpected action.' }

    Write-Host '[OK] System Integrity: snapshots, drift, partial, schema, and safe Defender preview.' -ForegroundColor Green
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
