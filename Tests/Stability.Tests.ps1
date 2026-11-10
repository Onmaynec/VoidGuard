#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
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
    'VoidGuard.UI.psm1',
    'VoidGuard.ConsoleFix.psm1',
    'VoidGuard.Stability.psm1'
)

foreach ($moduleName in $moduleOrder) {
    Import-Module (Join-Path $root "Modules\$moduleName") -Force -DisableNameChecking
}

Set-VoidGuardAnimationOptions -Enabled:$false -DelayScale 0
Show-VGLoadingBar -Label 'STABILITY TEST'

$health = Get-VoidGuardRuntimeHealth
if (-not $health.Healthy) {
    throw "Самопроверка обнаружила отсутствующие команды: $($health.MissingCommands -join ', ')"
}
if ($health.CheckedCommands -lt 10) {
    throw "Самопроверка охватывает слишком мало команд: $($health.CheckedCommands)."
}

$uiModule = Get-Module -Name 'VoidGuard.UI' -ErrorAction Stop | Select-Object -First 1
$consoleCommand = & $uiModule {
    Get-Command -Name Start-VoidGuardConsole -CommandType Function -ErrorAction Stop
}
$consoleDefinition = $consoleCommand.ScriptBlock.ToString()

foreach ($requiredFragment in @(
    'SYSTEM SELF-TEST',
    'SYSTEM INTEGRITY / BASELINES',
    'MICROSOFT DEFENDER OFFLINE',
    'Операция завершилась ошибкой, но VoidGuard продолжает работу',
    'Invoke-VoidGuardQuickScan',
    'Invoke-VoidGuardPathScan'
)) {
    if ($consoleDefinition -notmatch [regex]::Escape($requiredFragment)) {
        throw "Защищённый цикл меню не содержит обязательный фрагмент: $requiredFragment"
    }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-Stability-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $sample = Join-Path $tempRoot 'single.ps1'
    'Write-Host safe' | Set-Content -LiteralPath $sample -Encoding UTF8
    $settings = Get-Content -LiteralPath (Join-Path $root 'Config\settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.maxFilesPerScan = 10
    $context = New-VoidGuardContext -RootPath $root -Settings $settings -Professional -NoAnimation
    $result = Invoke-VoidGuardPathScan -Path $sample -Context $context

    if ($null -eq $result) { throw 'Custom Scan не вернул результат.' }
    if ([int]$result.FilesScanned -ne 1) {
        throw "Однофайловое сканирование обработало неверное число файлов: $($result.FilesScanned)."
    }
    if ($null -eq $result.Findings) { throw 'Поле Findings отсутствует.' }
    if ([int]$result.FilesDiscovered -ne 1 -or [int]$result.FilesFailed -ne 0 -or [int]$result.FilesSkipped -ne 0 -or -not $result.Complete) {
        throw 'Счётчики однофайлового сканирования или статус завершения неверны.'
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$stabilitySource = Get-Content -LiteralPath (Join-Path $root 'Modules\VoidGuard.Stability.psm1') -Raw -Encoding UTF8
if ($stabilitySource -match 'Set-Item\s+-Path\s+Function:|\[scriptblock\]::Create') {
    throw 'Stability не должен подменять функции других модулей во время выполнения.'
}
Write-Host '[OK] Сканеры и защищённый цикл меню работают без runtime-подмен.' -ForegroundColor Green
