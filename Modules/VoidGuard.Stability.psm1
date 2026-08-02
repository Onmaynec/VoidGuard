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

                if ($patched -cne $definition) {
                    $implementation = [scriptblock]::Create($patched)
                    Set-Item -Path ('Function:script:' + $command.Name) -Value $implementation -Force
                }
            }
        }
    }
}

function Get-VoidGuardScannerModule {
    $module = Get-Module -Name 'VoidGuard.Scanner' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $module) {
        throw 'Модуль VoidGuard.Scanner не загружен.'
    }
    return $module
}

function Invoke-VoidGuardPathScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [switch]$ShowProgress
    )

    $scannerModule = Get-VoidGuardScannerModule
    & $scannerModule {
        param(
            [string]$RequestedPath,
            $ContextObject,
            [bool]$ProgressEnabled
        )

        $resolved = Get-VoidGuardCanonicalPath -Path $RequestedPath
        $started = Get-Date
        $maxFiles = [int]$ContextObject.Settings.maxFilesPerScan
        $candidates = @(Get-VoidGuardScanCandidates -Paths @($resolved) -MaxFiles $maxFiles)
        $knownBad = Get-VoidGuardKnownBadHashes -RootPath $ContextObject.RootPath
        $ruleEngine = Get-VoidGuardRuleEngineState -Context $ContextObject
        $findings = New-Object System.Collections.Generic.List[object]

        for ($index = 0; $index -lt $candidates.Count; $index++) {
            $candidate = $candidates[$index]
            if ($ProgressEnabled) {
                $percent = if ($candidates.Count -eq 0) { 100 } else { [int](($index / [double]$candidates.Count) * 100) }
                Write-Progress -Activity 'VoidGuard file analysis' -Status $candidate.FullName -PercentComplete $percent
            }
            try {
                $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $ContextObject -KnownBadHashes $knownBad -RuleEngine $ruleEngine
                if ($finding -and $finding.Score -ge [int]$ContextObject.Settings.minimumFindingScore) {
                    $findings.Add($finding)
                }
            } catch {
            }
        }

        if ($ProgressEnabled) { Write-Progress -Activity 'VoidGuard file analysis' -Completed }
        $completed = Get-Date
        New-VoidGuardScanResult `
            -Context $ContextObject `
            -Mode 'Custom' `
            -Paths @($resolved) `
            -Started $started `
            -Completed $completed `
            -FilesScanned $candidates.Count `
            -Findings $findings.ToArray() `
            -RuleEngine $ruleEngine
    } $Path $Context ([bool]$ShowProgress)
}

function Invoke-VoidGuardQuickScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [switch]$ShowProgress
    )

    $scannerModule = Get-VoidGuardScannerModule
    & $scannerModule {
        param(
            $ContextObject,
            [bool]$ProgressEnabled
        )

        $paths = New-Object System.Collections.Generic.List[string]
        $candidatesToAdd = New-Object System.Collections.Generic.List[string]
        foreach ($candidate in @($env:TEMP, $env:APPDATA)) {
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { $candidatesToAdd.Add($candidate) }
        }
        if ($env:USERPROFILE) {
            $candidatesToAdd.Add((Join-Path $env:USERPROFILE 'Downloads'))
            $candidatesToAdd.Add((Join-Path $env:USERPROFILE 'Desktop'))
        }
        if ($env:APPDATA) {
            $candidatesToAdd.Add((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'))
        }
        if ($env:ProgramData) {
            $candidatesToAdd.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))
        }
        foreach ($candidate in $candidatesToAdd) {
            if ((Test-Path -LiteralPath $candidate) -and -not $paths.Contains($candidate)) {
                $paths.Add($candidate)
            }
        }

        $started = Get-Date
        $maxFiles = [int]$ContextObject.Settings.maxFilesPerScan
        $scanCandidates = @(Get-VoidGuardScanCandidates -Paths $paths.ToArray() -MaxFiles $maxFiles)
        $knownBad = Get-VoidGuardKnownBadHashes -RootPath $ContextObject.RootPath
        $ruleEngine = Get-VoidGuardRuleEngineState -Context $ContextObject
        $findings = New-Object System.Collections.Generic.List[object]

        for ($index = 0; $index -lt $scanCandidates.Count; $index++) {
            $candidate = $scanCandidates[$index]
            if ($ProgressEnabled) {
                $percent = if ($scanCandidates.Count -eq 0) { 100 } else { [int](($index / [double]$scanCandidates.Count) * 100) }
                Write-Progress -Activity 'VoidGuard quick scan' -Status $candidate.FullName -PercentComplete $percent
            }
            try {
                $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $ContextObject -KnownBadHashes $knownBad -RuleEngine $ruleEngine
                if ($finding -and $finding.Score -ge [int]$ContextObject.Settings.minimumFindingScore) {
                    $findings.Add($finding)
                }
            } catch {
            }
        }

        if ($ProgressEnabled) { Write-Progress -Activity 'VoidGuard quick scan' -Completed }
        $completed = Get-Date
        New-VoidGuardScanResult `
            -Context $ContextObject `
            -Mode 'Quick' `
            -Paths $paths.ToArray() `
            -Started $started `
            -Completed $completed `
            -FilesScanned $scanCandidates.Count `
            -Findings $findings.ToArray() `
            -RuleEngine $ruleEngine
    } $Context ([bool]$ShowProgress)
}

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

function Install-VoidGuardSafeConsoleLoop {
    [CmdletBinding()]
    param()

    $uiModule = Get-Module -Name 'VoidGuard.UI' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $uiModule) {
        throw 'Модуль VoidGuard.UI не загружен.'
    }

    $definition = @'
[CmdletBinding()]
param([Parameter(Mandatory)]$Context)

if ($Context.Settings.verifyPendingOnStartup) {
    try {
        Get-VoidGuardPendingRemediations -Verify | Out-Null
    } catch {
        # Ошибка проверки ledger не должна блокировать запуск интерфейса.
    }
}

$menu = @(
    [pscustomobject]@{ Label = 'QUICK THREAT SCAN'; Action = 'QuickScan' },
    [pscustomobject]@{ Label = 'SCAN FILE OR DIRECTORY'; Action = 'CustomScan' },
    [pscustomobject]@{ Label = 'PROCESS ANALYZER'; Action = 'Processes' },
    [pscustomobject]@{ Label = 'PERSISTENCE MATRIX'; Action = 'Persistence' },
    [pscustomobject]@{ Label = 'LOCKED FILE / SAFE REMEDIATION'; Action = 'Remediation' },
    [pscustomobject]@{ Label = 'PENDING REMEDIATION LEDGER'; Action = 'Pending' },
    [pscustomobject]@{ Label = 'WINDOWS SECURITY STATUS'; Action = 'Status' },
    [pscustomobject]@{ Label = 'SECURE QUARANTINE'; Action = 'Quarantine' },
    [pscustomobject]@{ Label = 'SYSTEM SELF-TEST'; Action = 'SelfTest' },
    [pscustomobject]@{ Label = 'VISUAL EFFECTS DEMO'; Action = 'Demo' },
    [pscustomobject]@{ Label = 'EXIT'; Action = 'Exit' }
)

while ($true) {
    $choice = Read-VoidGuardMenu -Context $Context -Items $menu
    if (-not $choice -or $choice.Action -eq 'Exit') {
        Clear-Host
        Write-Host 'VOIDGUARD OFFLINE // STAY SAFE' -ForegroundColor DarkGreen
        return
    }

    try {
        switch ($choice.Action) {
            'QuickScan' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                Show-VGLoadingBar -Label 'THREAT MATRIX'
                $Context.LastScan = Invoke-VoidGuardQuickScan -Context $Context -ShowProgress
                Show-VoidGuardScanSummary -Context $Context -Result $Context.LastScan
            }
            'CustomScan' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                $path = Read-Host 'Путь к файлу или папке'
                if (-not [string]::IsNullOrWhiteSpace($path)) {
                    $Context.LastScan = Invoke-VoidGuardPathScan -Path $path -Context $Context -ShowProgress
                    Show-VoidGuardScanSummary -Context $Context -Result $Context.LastScan
                }
            }
            'Processes' { Show-VoidGuardProcessScreen -Context $Context }
            'Persistence' { Show-VoidGuardPersistenceScreen -Context $Context }
            'Remediation' { Show-VoidGuardRemediationScreen -Context $Context }
            'Pending' { Show-VoidGuardPendingScreen -Context $Context }
            'Status' { Show-VoidGuardSecurityScreen -Context $Context }
            'Quarantine' { Show-VoidGuardQuarantineScreen -Context $Context }
            'SelfTest' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                $health = Get-VoidGuardRuntimeHealth
                if ($health.Healthy) {
                    Write-Host '[OK] Все обязательные компоненты загружены.' -ForegroundColor Green
                } else {
                    Write-Host '[ERROR] Не загружены обязательные команды:' -ForegroundColor Red
                    foreach ($commandName in @($health.MissingCommands)) {
                        Write-Host "  - $commandName" -ForegroundColor Yellow
                    }
                }
                Write-Host "PowerShell: $($health.PowerShell)" -ForegroundColor Cyan
                Write-Host "Проверено команд: $($health.CheckedCommands)" -ForegroundColor DarkCyan
                Wait-VoidGuardKey
            }
            'Demo' {
                Show-VoidGuardVisualDemo -RootPath $Context.RootPath
                Wait-VoidGuardKey
            }
        }
    } catch {
        Clear-Host
        Show-VoidGuardHeader -Context $Context
        Write-Host '[ERROR] Операция завершилась ошибкой, но VoidGuard продолжает работу.' -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        if ($_.InvocationInfo.PositionMessage) {
            Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkRed
        }
        Wait-VoidGuardKey
    }
}
'@

    & $uiModule {
        param([string]$FunctionDefinition)
        $implementation = [scriptblock]::Create($FunctionDefinition)
        Set-Item -Path Function:script:Start-VoidGuardConsole -Value $implementation -Force
    } $definition
}

Repair-VoidGuardPowerShell51Runtime
Install-VoidGuardSafeConsoleLoop

Export-ModuleMember -Function @(
    'Invoke-VoidGuardPathScan',
    'Invoke-VoidGuardQuickScan',
    'Show-VGLoadingBar',
    'Get-VoidGuardRuntimeHealth'
)
