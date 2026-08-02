#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$entry = Join-Path $root 'VoidGuard.ps1'
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-FullRegression-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

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

    if ($process.ExitCode -ne 0) {
        throw "Режим $Name завершился с кодом $($process.ExitCode). STDOUT:`n$outText`nSTDERR:`n$errText"
    }
    if (-not [string]::IsNullOrWhiteSpace($errText)) {
        throw "Режим $Name записал ошибку в STDERR:`n$errText"
    }
    if ($ExpectJson) {
        if ([string]::IsNullOrWhiteSpace($outText)) {
            throw "Режим $Name не вернул JSON."
        }
        try { $null = $outText | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Режим $Name вернул невалидный JSON:`n$outText`n$($_.Exception.Message)" }
    }

    Write-Host "[OK] $Name" -ForegroundColor Green
}

try {
    $sample = Join-Path $tempRoot 'sample.txt'
    'VoidGuard regression sample' | Set-Content -LiteralPath $sample -Encoding UTF8
    $scanDirectory = Join-Path $tempRoot 'scan'
    New-Item -ItemType Directory -Path $scanDirectory -Force | Out-Null
    'Write-Host safe' | Set-Content -LiteralPath (Join-Path $scanDirectory 'safe.ps1') -Encoding UTF8

    Invoke-VGProcessTest -Name 'Status' -Arguments @('-Mode', 'Status', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Processes' -Arguments @('-Mode', 'Processes', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Persistence' -Arguments @('-Mode', 'Persistence', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Pending' -Arguments @('-Mode', 'Pending', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'RulePacks' -Arguments @('-Mode', 'RulePacks', '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'CustomScan' -Arguments @('-Mode', 'CustomScan', '-Path', $scanDirectory, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Locks' -Arguments @('-Mode', 'Locks', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Yara' -Arguments @('-Mode', 'Yara', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'RemediateDryRun' -Arguments @('-Mode', 'Remediate', '-Path', $sample, '-Professional', '-NoAnimation', '-Json') -ExpectJson
    Invoke-VGProcessTest -Name 'Demo' -Arguments @('-Mode', 'Demo', '-Professional', '-NoAnimation')

    Write-Host '[OK] Полный безопасный регрессионный прогон завершён.' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
