#requires -Version 5.1
Set-StrictMode -Version Latest

# Совместимость PowerShell 5.1 обеспечивается исходным кодом Scanner и UI.
# Модуль не изменяет функции других модулей во время загрузки.
function Show-VGLoadingBar {
    [CmdletBinding()]
    param([string]$Label = 'PROCESSING')
    Show-VGProgressSequence -Label $Label
}

function Get-VoidGuardRuntimeHealth {
    [CmdletBinding()]
    param()

    $requiredCommands = @(
        'Set-VoidGuardAnimationOptions',
        'Show-VoidGuardBootSequence',
        'Show-VGLoadingBar',
        'New-VoidGuardContext',
        'Start-VoidGuardConsole',
        'Invoke-VoidGuardQuickScan',
        'Invoke-VoidGuardPathScan',
        'Get-VoidGuardSecurityStatus',
        'Get-VoidGuardProcessFindings',
        'Get-VoidGuardPersistenceFindings',
        'Get-VoidGuardFileLockOwners',
        'Get-VoidGuardPendingRemediations',
        'Get-VoidGuardRulePackInventory',
        'Invoke-VoidGuardYaraScan',
        'Invoke-VoidGuardQuarantine'
    )

    $missing = @($requiredCommands | Where-Object {
        -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
    })

    [pscustomobject]@{
        Healthy = ($missing.Count -eq 0)
        PowerShell = $PSVersionTable.PSVersion.ToString()
        MissingCommands = $missing
        CheckedCommands = $requiredCommands.Count
        TimestampUtc = (Get-Date).ToUniversalTime()
    }
}


Export-ModuleMember -Function @('Show-VGLoadingBar', 'Get-VoidGuardRuntimeHealth')
