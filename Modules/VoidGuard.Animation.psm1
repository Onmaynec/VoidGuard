Set-StrictMode -Version Latest

$script:AnimationEnabled = $true
$script:DelayScale = 1.0

function Set-VoidGuardAnimationOptions {
    [CmdletBinding()]
    param(
        [bool]$Enabled = $true,
        [ValidateRange(0.0, 5.0)]
        [double]$DelayScale = 1.0
    )

    $script:AnimationEnabled = $Enabled
    $script:DelayScale = $DelayScale
}

function Start-VGSleep {
    param([int]$Milliseconds)
    if ($script:AnimationEnabled -and $Milliseconds -gt 0) {
        Start-Sleep -Milliseconds ([Math]::Max(1, [int]($Milliseconds * $script:DelayScale)))
    }
}

function Get-VGAssetText {
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$RelativePath
    )

    $assetPath = Join-Path $RootPath $RelativePath
    if (Test-Path -LiteralPath $assetPath -PathType Leaf) {
        return Get-Content -LiteralPath $assetPath -Raw -Encoding UTF8
    }
    return ''
}

function Write-VGTypewriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Green,
        [ValidateRange(0, 500)][int]$DelayMilliseconds = 7
    )

    if (-not $script:AnimationEnabled) {
        Write-Host $Text -ForegroundColor $Color
        return
    }

    foreach ($character in $Text.ToCharArray()) {
        Write-Host $character -NoNewline -ForegroundColor $Color
        Start-VGSleep -Milliseconds $DelayMilliseconds
    }
    Write-Host
}

function Write-VGProgressBar {
    [CmdletBinding()]
    param(
        [ValidateRange(0, 100)][int]$Percent,
        [string]$Label = 'PROCESSING',
        [switch]$NoNewLine
    )

    $segments = 10
    $filled = [Math]::Floor(($Percent / 100.0) * $segments)
    $bar = ('▰' * $filled) + ('▱' * ($segments - $filled))
    $palette = @('DarkGreen', 'Green', 'Cyan', 'DarkCyan')
    $color = $palette[[Math]::Min($palette.Count - 1, [Math]::Floor($Percent / 26))]
    $line = "{0} {1,3}%  {2}" -f $bar, $Percent, $Label

    if ($NoNewLine) {
        Write-Host "`r$line" -NoNewline -ForegroundColor $color
    } else {
        Write-Host $line -ForegroundColor $color
    }
}

function Show-VGProgressSequence {
    [CmdletBinding()]
    param([string]$Label = 'INITIALIZING')

    if (-not $script:AnimationEnabled) {
        Write-VGProgressBar -Percent 100 -Label $Label
        return
    }

    foreach ($value in 0, 10, 20, 35, 50, 67, 82, 94, 100) {
        Write-VGProgressBar -Percent $value -Label $Label -NoNewLine
        Start-VGSleep -Milliseconds (Get-Random -Minimum 45 -Maximum 120)
    }
    Write-Host
}

function Show-VGGlitchText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Green
    )

    if (-not $script:AnimationEnabled) {
        Write-Host $Text -ForegroundColor $Color
        return
    }

    $glyphs = '01#@%&?<>[]{}:/\|ZXCV'
    for ($frame = 0; $frame -lt 4; $frame++) {
        $chars = $Text.ToCharArray()
        for ($i = 0; $i -lt $chars.Count; $i++) {
            if ($chars[$i] -ne ' ' -and (Get-Random -Minimum 0 -Maximum 100) -lt 18) {
                $chars[$i] = $glyphs[(Get-Random -Minimum 0 -Maximum $glyphs.Length)]
            }
        }
        Write-Host "`r$(-join $chars)" -NoNewline -ForegroundColor (@('DarkGreen','Green','Cyan','White')[$frame])
        Start-VGSleep -Milliseconds 55
    }
    Write-Host "`r$Text" -ForegroundColor $Color
}

function Show-VGCodeBurst {
    [CmdletBinding()]
    param([ValidateRange(1, 40)][int]$Lines = 8)

    for ($i = 0; $i -lt $Lines; $i++) {
        $address = '0x{0:X8}' -f (Get-Random -Minimum 4096 -Maximum 2147483647)
        $bytes = 1..8 | ForEach-Object { '{0:X2}' -f (Get-Random -Minimum 0 -Maximum 256) }
        $labels = @('SIGNATURE_MAP', 'PROCESS_TREE', 'STARTUP_VECTOR', 'ACCESS_MATRIX', 'HASH_PIPELINE')
        $label = $labels[(Get-Random -Minimum 0 -Maximum $labels.Count)]
        Write-Host ("[VISUAL] {0}  {1}  {2}::OK" -f $address, ($bytes -join ' '), $label) -ForegroundColor DarkGreen
        Start-VGSleep -Milliseconds 28
    }
}

function Show-VGTreeAnimation {
    [CmdletBinding()]
    param([string]$RootLabel = 'C:\SYSTEM')

    $nodes = @(
        '├── process-table',
        '│   ├── signed-images',
        '│   └── unknown-images',
        '├── startup-vectors',
        '│   ├── registry-run',
        '│   ├── scheduled-tasks',
        '│   └── startup-folders',
        '└── file-signatures'
    )

    Write-Host $RootLabel -ForegroundColor DarkCyan
    foreach ($node in $nodes) {
        Write-Host $node -ForegroundColor DarkGreen
        Start-VGSleep -Milliseconds 45
    }
}

function Show-VoidGuardBootSequence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RootPath)

    Clear-Host
    $skull = Get-VGAssetText -RootPath $RootPath -RelativePath 'Assets\skulls\main.txt'
    if ($skull) {
        Write-Host $skull -ForegroundColor DarkGreen
    }

    Write-Host @'
 ██╗   ██╗ ██████╗ ██╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██║   ██║██╔═══██╗██║██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██║   ██║██║██║  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ╚██╗ ██╔╝██║   ██║██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚████╔╝ ╚██████╔╝██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
'@ -ForegroundColor Green

    Show-VGGlitchText -Text 'WINDOWS THREAT ANALYSIS CONSOLE // DEFENSIVE MODE'
    Show-VGProgressSequence -Label 'LOADING PROTECTION POLICY'
    Show-VGCodeBurst -Lines 5
    Show-VGProgressSequence -Label 'ENGINE ONLINE'
    Start-VGSleep -Milliseconds 180
}

function Show-VoidGuardVisualDemo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RootPath)

    Clear-Host
    Write-Host (Get-VGAssetText -RootPath $RootPath -RelativePath 'Assets\skulls\alert.txt') -ForegroundColor Red
    Show-VGGlitchText -Text 'THREAT VISUALIZATION CHANNEL ACTIVE' -Color Yellow
    Show-VGTreeAnimation -RootLabel 'C:\VOIDGUARD\SCAN'
    Show-VGCodeBurst -Lines 12
    Show-VGProgressSequence -Label 'SIMULATED ACTION'
    Write-Host '[VISUAL] Demo completed. No system changes were made.' -ForegroundColor Cyan
}

Export-ModuleMember -Function @(
    'Set-VoidGuardAnimationOptions',
    'Write-VGTypewriter',
    'Write-VGProgressBar',
    'Show-VGProgressSequence',
    'Show-VGGlitchText',
    'Show-VGCodeBurst',
    'Show-VGTreeAnimation',
    'Show-VoidGuardBootSequence',
    'Show-VoidGuardVisualDemo'
)
