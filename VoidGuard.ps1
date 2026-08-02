#requires -Version 5.1
<#
.SYNOPSIS
    VoidGuard - cinematic Windows threat inspection console.
.DESCRIPTION
    A defensive PowerShell utility for inspecting common persistence locations,
    risky files, running processes, and Windows security status. Destructive
    operations are intentionally conservative and protected by policy checks.
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive', 'QuickScan', 'CustomScan', 'Status', 'Demo')]
    [string]$Mode = 'Interactive',

    [string]$Path,

    [switch]$NoAnimation,

    [switch]$Professional,

    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:VoidGuardRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:VOIDGUARD_ROOT = $script:VoidGuardRoot

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = [Console]::OutputEncoding
} catch {
    # Some redirected hosts do not expose a mutable console encoding.
}

$moduleOrder = @(
    'VoidGuard.Animation.psm1',
    'VoidGuard.Protection.psm1',
    'VoidGuard.Scanner.psm1',
    'VoidGuard.System.psm1',
    'VoidGuard.Quarantine.psm1',
    'VoidGuard.UI.psm1'
)

foreach ($moduleName in $moduleOrder) {
    $modulePath = Join-Path $script:VoidGuardRoot "Modules\$moduleName"
    Import-Module $modulePath -Force -DisableNameChecking
}

$settingsPath = Join-Path $script:VoidGuardRoot 'Config\settings.json'
$settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json

$animationEnabled = -not $NoAnimation -and -not $Professional
Set-VoidGuardAnimationOptions -Enabled:$animationEnabled -DelayScale ([double]$settings.animationDelayScale)
$context = New-VoidGuardContext -RootPath $script:VoidGuardRoot -Settings $settings -Professional:$Professional -NoAnimation:$NoAnimation

function Write-ResultOutput {
    param([Parameter(Mandatory)]$Value)

    if ($Json) {
        $Value | ConvertTo-Json -Depth 8
    } else {
        $Value
    }
}

try {
    switch ($Mode) {
        'Interactive' {
            if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
                throw 'Interactive mode requires a real console. Use -Mode QuickScan, CustomScan, Status, or Demo.'
            }

            if (-not $Professional -and -not $NoAnimation) {
                Show-VoidGuardBootSequence -RootPath $script:VoidGuardRoot
            }
            Start-VoidGuardConsole -Context $context
        }

        'QuickScan' {
            $result = Invoke-VoidGuardQuickScan -Context $context -ShowProgress:(-not $Json)
            Write-ResultOutput -Value $result
        }

        'CustomScan' {
            if ([string]::IsNullOrWhiteSpace($Path)) {
                throw 'CustomScan requires -Path.'
            }
            $result = Invoke-VoidGuardPathScan -Path $Path -Context $context -ShowProgress:(-not $Json)
            Write-ResultOutput -Value $result
        }

        'Status' {
            $result = Get-VoidGuardSecurityStatus
            Write-ResultOutput -Value $result
        }

        'Demo' {
            Show-VoidGuardVisualDemo -RootPath $script:VoidGuardRoot
        }
    }
} catch {
    if ($Json) {
        [pscustomobject]@{
            success = $false
            error   = $_.Exception.Message
        } | ConvertTo-Json -Depth 4
    } else {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}
