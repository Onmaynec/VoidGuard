Set-StrictMode -Version Latest

function Format-VoidGuardMenuLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Prefix,
        [Parameter(Mandatory)][ValidateRange(0, 999)][int]$Number,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Label,
        [ValidateRange(1, 500)][int]$Width = 76
    )

    # Передаём аргументы оператору -f единым массивом. Без массива выражение
    # "$index + 1" в Windows PowerShell 5.1 может быть разобрано неоднозначно,
    # из-за чего форматная строка получает меньше аргументов, чем заполнителей.
    $line = '  {0} [{1:00}] {2}' -f @($Prefix, $Number, $Label)
    if ($line.Length -gt $Width) {
        return $line.Substring(0, $Width)
    }
    return $line.PadRight($Width)
}

function Get-VoidGuardVisibleBounds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string[]]$Lines)

    $blank = [char]0x2800
    $left = [int]::MaxValue
    $right = -1
    $firstRow = -1
    $lastRow = -1

    for ($row = 0; $row -lt $Lines.Count; $row++) {
        $line = [string]$Lines[$row]
        $lineLeft = -1
        $lineRight = -1

        for ($column = 0; $column -lt $line.Length; $column++) {
            $character = $line[$column]
            if ($character -ne ' ' -and $character -ne $blank -and $character -ne "`t") {
                if ($lineLeft -lt 0) { $lineLeft = $column }
                $lineRight = $column
            }
        }

        if ($lineLeft -ge 0) {
            if ($firstRow -lt 0) { $firstRow = $row }
            $lastRow = $row
            if ($lineLeft -lt $left) { $left = $lineLeft }
            if ($lineRight -gt $right) { $right = $lineRight }
        }
    }

    if ($firstRow -lt 0) {
        return $null
    }

    return [pscustomobject]@{
        Left = $left
        Right = $right
        FirstRow = $firstRow
        LastRow = $lastRow
        Width = ($right - $left + 1)
    }
}

function ConvertTo-VoidGuardCenteredBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateRange(1, 500)][int]$TargetWidth
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    $lines = @($Text -split "`r?`n")
    $bounds = Get-VoidGuardVisibleBounds -Lines $lines
    if ($null -eq $bounds) { return '' }

    $leftPadding = [Math]::Max(0, [int][Math]::Floor(($TargetWidth - $bounds.Width) / 2.0))
    $blank = [char]0x2800
    $trimEndCharacters = [char[]]@(' ', $blank, "`t")
    $output = New-Object System.Collections.Generic.List[string]

    for ($row = $bounds.FirstRow; $row -le $bounds.LastRow; $row++) {
        $line = [string]$lines[$row]
        if ($line.Length -le $bounds.Left) {
            $cropped = ''
        } else {
            $length = [Math]::Min($bounds.Width, $line.Length - $bounds.Left)
            $cropped = $line.Substring($bounds.Left, $length)
        }

        if ($cropped.Length -lt $bounds.Width) {
            $cropped = $cropped.PadRight($bounds.Width, $blank)
        }

        $output.Add(((' ' * $leftPadding) + $cropped.TrimEnd($trimEndCharacters)))
    }

    return ($output -join [Environment]::NewLine)
}

function Set-VoidGuardMenuFormattingFix {
    [CmdletBinding()]
    param()

    $uiModule = Get-Module | Where-Object {
        $_.Path -and [IO.Path]::GetFileName($_.Path) -eq 'VoidGuard.UI.psm1'
    } | Select-Object -First 1

    if ($null -eq $uiModule) {
        throw 'Модуль VoidGuard.UI.psm1 должен быть импортирован до VoidGuard.ConsoleFix.psm1.'
    }

    $definition = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][object[]]$Items,
    [string]$Title = 'SELECT SECURITY OPERATION'
)

if ($null -eq $Items -or $Items.Count -eq 0) {
    throw 'Меню VoidGuard не содержит доступных пунктов.'
}

$selected = 0
while ($true) {
    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen
    $titleLine = ('  ' + $Title).PadRight(76)
    if ($titleLine.Length -gt 76) { $titleLine = $titleLine.Substring(0, 76) }
    Write-Host ('║' + $titleLine + '║') -ForegroundColor Cyan
    Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen

    for ($index = 0; $index -lt $Items.Count; $index++) {
        $prefix = if ($index -eq $selected) { '▶' } else { ' ' }
        $label = [string]$Items[$index].Label
        $line = VoidGuard.ConsoleFix\Format-VoidGuardMenuLine `
            -Prefix $prefix `
            -Number ($index + 1) `
            -Label $label `
            -Width 76

        if ($index -eq $selected) {
            Write-Host ('║' + $line + '║') -ForegroundColor Black -BackgroundColor Green
        } else {
            Write-Host ('║' + $line + '║') -ForegroundColor Gray
        }
    }

    Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen
    Write-Host ('╠' + ('═' * 76) + '╣') -ForegroundColor DarkGreen
    Write-Host ('║ ↑ ↓ Навигация    ENTER Выбор    ESC Назад    F1 Помощь'.PadRight(77) + '║') -ForegroundColor DarkGray
    Write-Host ('╚' + ('═' * 76) + '╝') -ForegroundColor DarkGreen

    $key = [Console]::ReadKey($true)
    switch ($key.Key) {
        'UpArrow' {
            $selected--
            if ($selected -lt 0) { $selected = $Items.Count - 1 }
        }
        'DownArrow' {
            $selected++
            if ($selected -ge $Items.Count) { $selected = 0 }
        }
        'Enter' { return $Items[$selected] }
        'Escape' { return $null }
        'F1' {
            Clear-Host
            Show-VoidGuardHeader -Context $Context
            Write-Host 'VOIDGUARD HELP' -ForegroundColor Cyan
            Write-Host 'Стрелки выбирают действие. ENTER открывает. ESC возвращает назад.' -ForegroundColor Gray
            Write-Host '[VISUAL] — декоративный эффект, а не доказательство заражения.' -ForegroundColor Yellow
            Write-Host 'Реальные действия помечены [SCAN], [OK], [WARN], [BLOCK], [ERROR].' -ForegroundColor Yellow
            Write-Host 'Принудительная остановка разрешена только для точного файла-цели.' -ForegroundColor Yellow
            Wait-VoidGuardKey
        }
    }
}
'@

    & $uiModule {
        param([string]$FunctionDefinition)
        $implementation = [scriptblock]::Create($FunctionDefinition)
        Set-Item -Path Function:script:Read-VoidGuardMenu -Value $implementation -Force
    } $definition
}

function Show-VoidGuardBootSequence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RootPath)

    Clear-Host

    $logoLines = @(
        ' ██╗   ██╗ ██████╗ ██╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗',
        ' ██║   ██║██╔═══██╗██║██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗',
        ' ██║   ██║██║   ██║██║██║  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║',
        ' ╚██╗ ██╔╝██║   ██║██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║',
        '  ╚████╔╝ ╚██████╔╝██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝',
        '   ╚═══╝   ╚═════╝ ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝'
    )
    $logoWidth = [int](($logoLines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum)

    $skullPath = Join-Path $RootPath 'Assets\skulls\main.txt'
    if (Test-Path -LiteralPath $skullPath -PathType Leaf) {
        $skull = Get-Content -LiteralPath $skullPath -Raw -Encoding UTF8
        $centeredSkull = ConvertTo-VoidGuardCenteredBlock -Text $skull -TargetWidth $logoWidth
        if (-not [string]::IsNullOrWhiteSpace($centeredSkull)) {
            Write-Host $centeredSkull -ForegroundColor DarkGreen
        }
    }

    Write-Host ($logoLines -join [Environment]::NewLine) -ForegroundColor Green
    Show-VGGlitchText -Text 'WINDOWS THREAT ANALYSIS CONSOLE // DEFENSIVE MODE'
    Show-VGProgressSequence -Label 'LOADING PROTECTION POLICY'
    Show-VGCodeBurst -Lines 5
    Show-VGProgressSequence -Label 'ENGINE ONLINE'
    Start-Sleep -Milliseconds 180
}

Set-VoidGuardMenuFormattingFix

Export-ModuleMember -Function @(
    'Format-VoidGuardMenuLine',
    'ConvertTo-VoidGuardCenteredBlock',
    'Show-VoidGuardBootSequence'
)
