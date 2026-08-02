#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Modules\VoidGuard.Animation.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'Modules\VoidGuard.UI.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'Modules\VoidGuard.ConsoleFix.psm1') -Force -DisableNameChecking

function Get-TestVisibleBounds {
    param([Parameter(Mandatory)][string[]]$Lines)

    $blank = [char]0x2800
    $left = [int]::MaxValue
    $right = -1

    foreach ($line in $Lines) {
        for ($index = 0; $index -lt $line.Length; $index++) {
            $character = $line[$index]
            if ($character -ne ' ' -and $character -ne $blank -and $character -ne "`t") {
                if ($index -lt $left) { $left = $index }
                if ($index -gt $right) { $right = $index }
            }
        }
    }

    if ($right -lt 0) { return $null }
    [pscustomobject]@{ Left = $left; Right = $right; Width = ($right - $left + 1) }
}

$menuLine = Format-VoidGuardMenuLine -Prefix '▶' -Number 1 -Label 'QUICK THREAT SCAN' -Width 76
if ($menuLine.Length -ne 76) {
    throw "Строка меню имеет неверную ширину: $($menuLine.Length)."
}
if (-not $menuLine.Contains('[01] QUICK THREAT SCAN')) {
    throw "Номер или подпись пункта меню отформатированы неверно: $menuLine"
}

$uiModule = Get-Module | Where-Object {
    $_.Path -and [IO.Path]::GetFileName($_.Path) -eq 'VoidGuard.UI.psm1'
} | Select-Object -First 1
if ($null -eq $uiModule) {
    throw 'VoidGuard.UI.psm1 не импортирован.'
}
$menuDefinition = & $uiModule {
    (Get-Item -Path Function:script:Read-VoidGuardMenu).Definition
}
if ($menuDefinition -notmatch 'Format-VoidGuardMenuLine') {
    throw 'Исправленная реализация Read-VoidGuardMenu не установлена в области модуля UI.'
}

$blank = [char]0x2800
$sample = "$blank$blank##$blank$blank`n$blank####$blank"
$centeredSample = ConvertTo-VoidGuardCenteredBlock -Text $sample -TargetWidth 10
$sampleBounds = Get-TestVisibleBounds -Lines @($centeredSample -split "`r?`n")
if ($null -eq $sampleBounds -or $sampleBounds.Left -ne 3 -or $sampleBounds.Right -ne 6) {
    throw 'Центрирование тестового блока нарушено.'
}

$skullPath = Join-Path $root 'Assets\skulls\main.txt'
$skull = Get-Content -LiteralPath $skullPath -Raw -Encoding UTF8
$centeredSkull = ConvertTo-VoidGuardCenteredBlock -Text $skull -TargetWidth 76
$skullBounds = Get-TestVisibleBounds -Lines @($centeredSkull -split "`r?`n")
if ($null -eq $skullBounds) {
    throw 'После центрирования череп стал пустым.'
}
$leftMargin = $skullBounds.Left
$rightMargin = 75 - $skullBounds.Right
if ([Math]::Abs($leftMargin - $rightMargin) -gt 1) {
    throw "Череп расположен не по центру: слева $leftMargin, справа $rightMargin."
}

Write-Host '[OK] Исправление меню и центрирование стартового черепа проверены.' -ForegroundColor Green
