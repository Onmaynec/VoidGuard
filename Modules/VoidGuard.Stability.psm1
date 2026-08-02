#requires -Version 5.1
Set-StrictMode -Version Latest

function Repair-VoidGuardPowerShell51Runtime {
    [CmdletBinding()]
    param()

    $targetModules = @(
        'VoidGuard.Protection',
        'VoidGuard.RulePacks',
        'VoidGuard.Scanner',
        'VoidGuard.System',
        'VoidGuard.Persistence',
        'VoidGuard.Remediation',
        'VoidGuard.Quarantine',
        'VoidGuard.Reporting',
        'VoidGuard.UI',
        'VoidGuard.ConsoleFix'
    )

    foreach ($moduleName in $targetModules) {
        $module = Get-Module -Name $moduleName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $module) { continue }

        & $module {
            $commands = @(Get-ChildItem -Path Function:\ -ErrorAction SilentlyContinue)
            foreach ($command in $commands) {
                $scriptBlockProperty = $command.PSObject.Properties['ScriptBlock']
                if ($null -eq $scriptBlockProperty -or $null -eq $scriptBlockProperty.Value) { continue }

                $definition = $scriptBlockProperty.Value.ToString()
                $patched = $definition

                if ($definition -match 'System\.Collections\.Generic\.List') {
                    $listNames = @(
                        [regex]::Matches(
                            $definition,
                            '\$(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*New-Object\s+["'']?System\.Collections\.Generic\.List',
                            [Text.RegularExpressions.RegexOptions]::IgnoreCase
                        ) | ForEach-Object { $_.Groups['name'].Value } | Select-Object -Unique
                    )

                    foreach ($listName in $listNames) {
                        # Windows PowerShell 5.1 иногда падает с "Argument types do not match"
                        # при прямом преобразовании Generic.List через @($list).
                        $patched = $patched.Replace(
                            ('@($' + $listName + ')'),
                            ('$' + $listName + '.ToArray()')
                        )
                    }
                }

                # PowerShell разворачивает одноэлементный массив на выходе функции.
                # Без явного @() свойство Count отсутствует у единственного FileInfo.
                $patched = $patched.Replace(
                    '$candidates = Get-VoidGuardScanCandidates -Paths @($resolved) -MaxFiles $maxFiles',
                    '$candidates = @(Get-VoidGuardScanCandidates -Paths @($resolved) -MaxFiles $maxFiles)'
                )
                $patched = $patched.Replace(
                    '$scanCandidates = Get-VoidGuardScanCandidates -Paths @($paths) -MaxFiles $maxFiles',
                    '$scanCandidates = @(Get-VoidGuardScanCandidates -Paths @($paths) -MaxFiles $maxFiles)'
                )

                if ($patched -cne $definition) {
                    $implementation = [scriptblock]::Create($patched)
                    Set-Item -Path ('Function:script:' + $command.Name) -Value $implementation -Force
                }
            }
        }
    }
}

function Show-VGLoadingBar {
    [CmdletBinding()]
    param([string]$Label = 'PROCESSING')

    # Совместимое имя для старого вызова из TUI. Реализация анимации уже
    # находится в Show-VGProgressSequence.
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

Repair-VoidGuardPowerShell51Runtime

Export-ModuleMember -Function @(
    'Show-VGLoadingBar',
    'Get-VoidGuardRuntimeHealth'
)
