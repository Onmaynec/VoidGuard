#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$entry = Join-Path $root 'VoidGuard.ps1'
$settingsPath = Join-Path $root 'Config\settings.json'
$settingsBackup = [IO.File]::ReadAllBytes($settingsPath)
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-FullRegression-' + [guid]::NewGuid().ToString('N'))
$failures = New-Object System.Collections.Generic.List[string]
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

function Add-VGFailure {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Problem)
    $failures.Add("[$Name] $Problem")
    Write-Host "[FAIL] $Name" -ForegroundColor Red
    Write-Host $Problem -ForegroundColor DarkRed
}

function Invoke-VGProcessTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$ExpectJson
    )

    $stdout = Join-Path $tempRoot ($Name + '.stdout.txt')
    $stderr = Join-Path $tempRoot ($Name + '.stderr.txt')
    $process = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList (@('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $entry) + $Arguments) `
        -WorkingDirectory $root `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr

    $outText = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw -Encoding UTF8 } else { '' }
    $errText = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw -Encoding UTF8 } else { '' }
    $problem = $null

    if ($process.ExitCode -ne 0) {
        $problem = "код $($process.ExitCode); STDOUT:`n$outText`nSTDERR:`n$errText"
    } elseif (-not [string]::IsNullOrWhiteSpace($errText)) {
        $problem = "данные в STDERR:`n$errText"
    } elseif ($ExpectJson) {
        if ([string]::IsNullOrWhiteSpace($outText)) {
            $problem = 'JSON отсутствует.'
        } else {
            try { $null = $outText | ConvertFrom-Json -ErrorAction Stop }
            catch { $problem = "невалидный JSON:`n$outText`n$($_.Exception.Message)" }
        }
    }

    if ($problem) {
        Add-VGFailure -Name $Name -Problem $problem
        return
    }

    Write-Host "[OK] $Name" -ForegroundColor Green
}

try {
    $testSettings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $testSettings.maxFilesPerScan = 25
    $testSettings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $settingsPath -Encoding UTF8

    $sample = Join-Path $tempRoot 'sample.txt'
    'VoidGuard regression sample' | Set-Content -LiteralPath $sample -Encoding UTF8
    $scanDirectory = Join-Path $tempRoot 'scan'
    New-Item -ItemType Directory -Path $scanDirectory -Force | Out-Null
    'Write-Host safe' | Set-Content -LiteralPath (Join-Path $scanDirectory 'safe.ps1') -Encoding UTF8

    Invoke-VGProcessTest -Name 'SelfTest' -Arguments @('-Mode', 'SelfTest', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Status' -Arguments @('-Mode', 'Status', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Processes' -Arguments @('-Mode', 'Processes', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Persistence' -Arguments @('-Mode', 'Persistence', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Pending' -Arguments @('-Mode', 'Pending', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'RulePacks' -Arguments @('-Mode', 'RulePacks', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'QuickScan' -Arguments @('-Mode', 'QuickScan', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'CustomScan' -Arguments @('-Mode', 'CustomScan', '-Path', $scanDirectory, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Locks' -Arguments @('-Mode', 'Locks', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Yara' -Arguments @('-Mode', 'Yara', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    $integritySource=Join-Path $tempRoot 'integrity.txt'
    'baseline-v1' | Set-Content -LiteralPath $integritySource -Encoding ASCII
    $integrityJson=Join-Path $tempRoot 'baseline.json'
    Invoke-VGProcessTest -Name 'BaselineCreate' -Arguments @('-Mode','BaselineCreate','-BaselinePath',$integrityJson,'-IntegrityPaths',$integritySource,'-IntegritySections','Files','-NoHosts','-Professional','-NoAnimation','-Json') -ExpectJson
    if (-not (Test-Path -LiteralPath $integrityJson -PathType Leaf)) { Add-VGFailure -Name 'BaselineCreate' -Problem 'Baseline JSON not created.' }
    'baseline-v2' | Set-Content -LiteralPath $integritySource -Encoding ASCII
    Invoke-VGProcessTest -Name 'BaselineDiff' -Arguments @('-Mode','BaselineDiff','-BaselinePath',$integrityJson,'-Professional','-NoAnimation','-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'DefenderOfflinePreview' -Arguments @('-Mode','DefenderOffline','-Professional','-NoAnimation','-Json') -ExpectJson

    Invoke-VGProcessTest -Name 'RemediateDryRun' -Arguments @('-Mode', 'Remediate', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson

    $reportBase = Join-Path $tempRoot 'reports\custom-scan'
    Invoke-VGProcessTest -Name 'CustomScanReport' -Arguments @('-Mode', 'CustomScan', '-Path', $scanDirectory, '-Professional', '-NoAnimation', '-ReportPath', $reportBase, '-ReportFormat', 'Both')
    foreach ($reportPath in @("$reportBase.json", "$reportBase.html")) {
        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            Add-VGFailure -Name 'CustomScanReport' -Problem "Отчёт не создан: $reportPath"
        }
    }

    Invoke-VGProcessTest -Name 'Demo' -Arguments @('-Mode', 'Demo', '-Professional', '-NoAnimation')

    if ($failures.Count -gt 0) {
        throw ("Полный регрессионный прогон обнаружил $($failures.Count) ошибок:`n`n" + ($failures -join "`n`n"))
    }

    Write-Host '[OK] Полный безопасный регрессионный прогон завершён.' -ForegroundColor Green
} finally {
    [IO.File]::WriteAllBytes($settingsPath, $settingsBackup)
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
