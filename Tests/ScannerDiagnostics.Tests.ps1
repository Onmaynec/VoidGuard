#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
foreach ($name in @('VoidGuard.Protection','VoidGuard.RulePacks','VoidGuard.Scanner','VoidGuard.UI')) {
    Import-Module (Join-Path $root "Modules\$name.psm1") -Force -DisableNameChecking
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-ScannerDiagnostics-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $one = Join-Path $tempRoot 'one.cmd'
    $two = Join-Path $tempRoot 'two.cmd'
    '@echo off' | Set-Content -LiteralPath $one -Encoding ASCII
    '@echo off' | Set-Content -LiteralPath $two -Encoding ASCII

    $settings = Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.maxFilesPerScan = 1
    $ctx = New-VoidGuardContext -RootPath $root -Settings $settings -Professional -NoAnimation
    $limited = Invoke-VoidGuardPathScan -Path $tempRoot -Context $ctx
    if ($limited.ScanStatus -ne 'PARTIAL' -or $limited.Complete -or -not $limited.ScanLimitReached) {
        throw 'Сканирование с достигнутым лимитом ошибочно признано полным.'
    }
    if ([int]$limited.FilesDiscovered -ne 1 -or [int]$limited.FilesScanned -ne 1 -or [int]$limited.FilesFailed -ne 0) {
        throw 'Счётчики прохода с лимитом неверны.'
    }

    $settings.maxFilesPerScan = 10
    $complete = Invoke-VoidGuardPathScan -Path $one -Context $ctx
    if ($complete.ScanStatus -ne 'COMPLETE' -or -not $complete.Complete) {
        throw 'Полная проверка отдельного файла неверно помечена как частичная.'
    }
    if ([int]$complete.FilesDiscovered -ne 1 -or [int]$complete.FilesScanned -ne 1 -or [int]$complete.FilesFailed -ne 0) {
        throw 'Счётчики полной проверки неверны.'
    }
    if ($null -eq $complete.FileErrors -or $null -eq $complete.EnumerationErrors) {
        throw 'Диагностика сканирования отсутствует.'
    }
    Write-Host '[OK] Счётчики и PARTIAL/COMPLETE для сканирования проверены.' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
