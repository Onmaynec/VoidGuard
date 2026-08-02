#requires -Version 5.1
<#
.SYNOPSIS
    VoidGuard - cinematic Windows threat inspection and safe remediation console.
.DESCRIPTION
    A defensive PowerShell utility for inspecting risky files, processes,
    persistence mechanisms, Windows security status, and locked-file remediation.
    Destructive operations are conservative, auditable, and protected by policy.
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive', 'QuickScan', 'CustomScan', 'Status', 'Processes', 'Persistence', 'Locks', 'Remediate', 'Pending', 'Demo')]
    [string]$Mode = 'Interactive',

    [string]$Path,

    [int]$TargetProcessId,

    [switch]$StopTargetProcess,

    [switch]$ScheduleOnReboot,

    [switch]$Confirmed,

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
}

$moduleOrder = @(
    'VoidGuard.Animation.psm1',
    'VoidGuard.Protection.psm1',
    'VoidGuard.Scanner.psm1',
    'VoidGuard.System.psm1',
    'VoidGuard.Persistence.psm1',
    'VoidGuard.Remediation.psm1',
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
    if ($Json) { $Value | ConvertTo-Json -Depth 10 } else { $Value }
}

try {
    switch ($Mode) {
        'Interactive' {
            if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
                throw 'Interactive mode requires a real console. Use a non-interactive -Mode value.'
            }
            if (-not $Professional -and -not $NoAnimation) {
                Show-VoidGuardBootSequence -RootPath $script:VoidGuardRoot
            }
            Start-VoidGuardConsole -Context $context
        }
        'QuickScan' {
            Write-ResultOutput (Invoke-VoidGuardQuickScan -Context $context -ShowProgress:(-not $Json))
        }
        'CustomScan' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'CustomScan requires -Path.' }
            Write-ResultOutput (Invoke-VoidGuardPathScan -Path $Path -Context $context -ShowProgress:(-not $Json))
        }
        'Status' {
            Write-ResultOutput (Get-VoidGuardSecurityStatus)
        }
        'Processes' {
            Write-ResultOutput (Get-VoidGuardProcessFindings -Context $context)
        }
        'Persistence' {
            Write-ResultOutput (Get-VoidGuardPersistenceFindings -Context $context)
        }
        'Locks' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Locks requires -Path.' }
            Write-ResultOutput (Get-VoidGuardFileLockOwners -Path $Path)
        }
        'Remediate' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Remediate requires -Path.' }
            $result = [ordered]@{
                Path            = $Path
                ProcessAction   = $null
                Quarantine      = $null
                RebootDeletion  = $null
            }
            if ($StopTargetProcess) {
                if ($TargetProcessId -le 0) { throw '-StopTargetProcess requires -TargetProcessId.' }
                $result.ProcessAction = Stop-VoidGuardTargetProcess -Id $TargetProcessId -TargetPath $Path -Confirmed:$Confirmed
            }
            $result.Quarantine = Invoke-VoidGuardQuarantine -Path $Path -Confirmed:$Confirmed
            if (-not $result.Quarantine.Success -and $ScheduleOnReboot) {
                $result.RebootDeletion = Register-VoidGuardDeleteOnReboot -Path $Path -Confirmed:$Confirmed
            }
            Write-ResultOutput ([pscustomobject]$result)
        }
        'Pending' {
            Write-ResultOutput (Get-VoidGuardPendingRemediations -Verify)
        }
        'Demo' {
            Show-VoidGuardVisualDemo -RootPath $script:VoidGuardRoot
        }
    }
} catch {
    if ($Json) {
        [pscustomobject]@{ success = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 5
    } else {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}
