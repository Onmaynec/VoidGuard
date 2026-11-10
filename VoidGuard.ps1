#requires -Version 5.1
<#
.SYNOPSIS
    VoidGuard - cinematic Windows threat inspection and safe remediation console.
.DESCRIPTION
    Defensive PowerShell utility for inspecting risky files, processes,
    persistence, Windows security state, trusted rule packs, optional YARA,
    offline reports, and locked-file remediation.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Interactive', 'QuickScan', 'CustomScan', 'Status', 'Processes', 'Persistence', 'Locks', 'Remediate', 'Pending', 'RulePacks', 'Yara', 'Demo', 'SelfTest', 'BaselineCreate', 'BaselineDiff', 'DefenderOffline')]
    [string]$Mode = 'Interactive',

    [string]$Path,

    [int]$TargetProcessId,

    [switch]$StopTargetProcess,

    [switch]$ScheduleOnReboot,

    [switch]$Confirmed,

    [string]$BaselinePath,

    [string[]]$IntegrityPaths = @(),

    [ValidateSet('Security', 'Services', 'Tasks', 'Startup', 'Files')]
    [string[]]$IntegritySections = @('Security', 'Services', 'Tasks', 'Startup', 'Files'),

    [switch]$NoHosts,

    [switch]$RebootAcknowledged,

    [string]$ReportPath,

    [ValidateSet('Json', 'Html', 'Both')]
    [string]$ReportFormat = 'Both',

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
    'VoidGuard.RulePacks.psm1',
    'VoidGuard.Scanner.psm1',
    'VoidGuard.System.psm1',
    'VoidGuard.Persistence.psm1',
    'VoidGuard.Remediation.psm1',
    'VoidGuard.Quarantine.psm1',
    'VoidGuard.IntegritySnapshot.psm1',
    'VoidGuard.IntegrityBaseline.psm1',
    'VoidGuard.DefenderOffline.psm1',
    'VoidGuard.Reporting.psm1',
    'VoidGuard.UI.psm1',
    'VoidGuard.ConsoleFix.psm1',
    'VoidGuard.Stability.psm1'
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
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) {
        if ($Json) {
            Write-Output '[]'
            return
        }
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $reportFiles = @(Export-VoidGuardReportBundle -InputObject $Value -Context $context -OutputPath $ReportPath -Format $ReportFormat)
        foreach ($reportFile in $reportFiles) { Write-Host "[OK] Report: $reportFile" -ForegroundColor Green }
    }

    if ($Json) {
        ConvertTo-Json -InputObject $Value -Depth 14
    } else {
        $Value
    }
}

try {
    switch ($Mode) {
        'Interactive' {
            if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
                throw 'Interactive mode requires a real console. Use a non-interactive -Mode value.'
            }
            if (-not $Professional -and -not $NoAnimation) { Show-VoidGuardBootSequence -RootPath $script:VoidGuardRoot }
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
                Path = $Path
                ProcessAction = $null
                Quarantine = $null
                RebootDeletion = $null
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
        'RulePacks' {
            Write-ResultOutput (Get-VoidGuardRulePackInventory -Context $context)
        }
        'Yara' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Yara requires -Path.' }
            $engine = Get-VoidGuardRuleEngineState -Context $context
            Write-ResultOutput (Invoke-VoidGuardYaraScan -Path $Path -Context $context -RuleFiles $engine.YaraRuleFiles)
        }
        'BaselineCreate' {
            Write-ResultOutput (New-VGIntegrityBaseline -BaselinePath $BaselinePath -SelectedPaths $IntegrityPaths -Sections $IntegritySections -IncludeHosts:(-not $NoHosts))
        }
        'BaselineDiff' {
            if ([string]::IsNullOrWhiteSpace($BaselinePath)) { throw 'BaselineDiff requires -BaselinePath.' }
            Write-ResultOutput (Compare-VGIntegrityBaseline -BaselinePath $BaselinePath)
        }
        'DefenderOffline' {
            if ($Confirmed -or $RebootAcknowledged -or $WhatIfPreference) {
                Write-ResultOutput (Invoke-VGDefenderOffline -Confirmed:$Confirmed -RebootAcknowledged:$RebootAcknowledged -WhatIf:$WhatIfPreference)
            } else {
                Write-ResultOutput (Get-VGDefenderOfflineReadiness)
            }
        }
        'Demo' {
            Show-VoidGuardVisualDemo -RootPath $script:VoidGuardRoot
        }
        'SelfTest' {
            Write-ResultOutput (Get-VoidGuardRuntimeHealth)
        }
    }
} catch {
    if ($Json) {
        [pscustomobject]@{
            success = $false
            error = $_.Exception.Message
            type = $_.Exception.GetType().FullName
            position = $_.InvocationInfo.PositionMessage
            stack = $_.ScriptStackTrace
        } | ConvertTo-Json -Depth 6
    } else {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        if ($_.InvocationInfo.PositionMessage) {
            Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkRed
        }
    }
    exit 1
}
