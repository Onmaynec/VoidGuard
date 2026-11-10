Set-StrictMode -Version Latest

function New-VoidGuardContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)]$Settings,
        [switch]$Professional,
        [switch]$NoAnimation
    )

    $versionPath = Join-Path $RootPath 'VERSION'
    $version = if (Test-Path -LiteralPath $versionPath) {
        (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
    } else { '0.0.0-dev' }

    return [pscustomobject]@{
        RootPath     = $RootPath
        Version      = $version
        Settings     = $Settings
        Professional = [bool]$Professional
        NoAnimation  = [bool]$NoAnimation
        LastScan     = $null
    }
}

function Write-VGStatusLine {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host ('{0,-26} {1}' -f $Label, $Value) -ForegroundColor $Color
}

function Wait-VoidGuardKey {
    param([string]$Message = 'Нажмите любую клавишу для возврата...')
    Write-Host
    Write-Host $Message -ForegroundColor DarkGray
    [Console]::ReadKey($true) | Out-Null
}

function Show-VoidGuardHeader {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $admin = Test-VoidGuardAdministrator
    $adminText = if ($admin) { 'ELEVATED' } else { 'STANDARD' }
    $adminColor = if ($admin) { 'Green' } else { 'Yellow' }
    $hostName = [string]$env:COMPUTERNAME
    if ($hostName.Length -gt 22) { $hostName = $hostName.Substring(0, 22) }

    Write-Host ('╔' + ('═' * 76) + '╗') -ForegroundColor DarkGreen
    Write-Host ('║ VOIDGUARD SECURITY CONSOLE  v{0,-10} HOST: {1,-23} ║' -f $Context.Version, $hostName) -ForegroundColor Green
    Write-Host ('║ USER: {0,-27} PRIVILEGES: ' -f [Environment]::UserName) -NoNewline -ForegroundColor DarkGreen
    Write-Host ('{0,-26}' -f $adminText) -NoNewline -ForegroundColor $adminColor
    Write-Host '║' -ForegroundColor DarkGreen
    Write-Host ('╠' + ('═' * 76) + '╣') -ForegroundColor DarkGreen
}

function Read-VoidGuardMenu {
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
}

function Get-VoidGuardRiskColor {
    param([string]$Risk)
    switch ($Risk) {
        'CRITICAL' { return 'Red' }
        'HIGH' { return 'Red' }
        'MEDIUM' { return 'Yellow' }
        default { return 'Gray' }
    }
}

function Show-VoidGuardScanSummary {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Result)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'SCAN COMPLETE' -ForegroundColor Green
    Write-VGStatusLine -Label 'Mode' -Value ([string]$Result.Mode) -Color Cyan
    Write-VGStatusLine -Label 'Files discovered' -Value ([string]$Result.FilesDiscovered)
    Write-VGStatusLine -Label 'Files scanned' -Value ([string]$Result.FilesScanned)
    Write-VGStatusLine -Label 'Files skipped' -Value ([string]$Result.FilesSkipped)
    Write-VGStatusLine -Label 'Files failed' -Value ([string]$Result.FilesFailed)
    Write-VGStatusLine -Label 'Scan status' -Value ([string]$Result.ScanStatus) -Color $(if ($Result.Complete) { 'Green' } else { 'Yellow' })
    Write-VGStatusLine -Label 'Findings' -Value ([string]$Result.Findings.Count) -Color $(if ($Result.Findings.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-VGStatusLine -Label 'Duration' -Value ([string]$Result.Duration)
    Write-Host

    if ($Result.Findings.Count -eq 0) {
        if ($Result.Complete) {
            Write-Host '[OK] На проверенных объектах находки выше порога не обнаружены.' -ForegroundColor Green
        } else {
            Write-Host '[WARN] Проверка неполная. Отсутствие находок не означает отсутствие угроз.' -ForegroundColor Yellow
        }
        Write-Host 'Это не гарантирует полное отсутствие вредоносного ПО.' -ForegroundColor DarkGray
    } else {
        Write-Host ('{0,-10} {1,-6} {2,-56}' -f 'RISK', 'SCORE', 'PATH') -ForegroundColor Cyan
        Write-Host ('-' * 76) -ForegroundColor DarkGreen
        $limit = [int]$Context.Settings.maximumDisplayedFindings
        foreach ($finding in @($Result.Findings | Select-Object -First $limit)) {
            $displayPath = [string]$finding.Path
            if ($displayPath.Length -gt 56) { $displayPath = '...' + $displayPath.Substring($displayPath.Length - 53) }
            Write-Host ('{0,-10} {1,-6} {2,-56}' -f $finding.Risk, $finding.Score, $displayPath) -ForegroundColor (Get-VoidGuardRiskColor $finding.Risk)
            foreach ($reason in @($finding.Reasons | Select-Object -First 3)) {
                Write-Host ("             └─ $reason") -ForegroundColor DarkGray
            }
        }
    }
    if (-not $Result.Complete) {
        Write-Host '[WARN] Часть проверки не завершена: проверьте ошибки, недоступные каталоги и лимит файлов.' -ForegroundColor Yellow
        if ($Result.ScanLimitReached) { Write-Host 'Достигнут лимит количества файлов для сканирования.' -ForegroundColor Yellow }
        if ($Result.EnumerationErrorCount -gt 0) { Write-Host "Ошибок перечисления: $($Result.EnumerationErrorCount)" -ForegroundColor Yellow }
        foreach ($fileError in @($Result.FileErrors | Select-Object -First 5)) {
            Write-Host ("[ERROR] {0}: {1}" -f $fileError.Path, $fileError.Error) -ForegroundColor DarkYellow
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardSecurityScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'WINDOWS SECURITY STATUS' -ForegroundColor Cyan
    $status = Get-VoidGuardSecurityStatus
    Write-VGStatusLine -Label 'Administrator' -Value ([string]$status.IsAdministrator) -Color $(if ($status.IsAdministrator) { 'Green' } else { 'Yellow' })
    Write-VGStatusLine -Label 'PowerShell' -Value $status.PowerShellVersion
    Write-VGStatusLine -Label 'Defender available' -Value ([string]$status.DefenderAvailable)
    Write-VGStatusLine -Label 'Defender enabled' -Value ([string]$status.DefenderEnabled) -Color $(if ($status.DefenderEnabled) { 'Green' } else { 'Yellow' })
    Write-VGStatusLine -Label 'Real-time protection' -Value ([string]$status.RealTimeProtection) -Color $(if ($status.RealTimeProtection) { 'Green' } else { 'Yellow' })
    Write-VGStatusLine -Label 'Signature age (days)' -Value ([string]$status.SignatureAgeDays)
    Write-VGStatusLine -Label 'UAC enabled' -Value ([string]$status.UacEnabled) -Color $(if ($status.UacEnabled) { 'Green' } else { 'Yellow' })
    if ($status.PSObject.Properties.Name -contains 'DefenderExclusions') {
        Write-VGStatusLine -Label 'Defender exclusions' -Value ([string]$status.DefenderExclusions.Count) -Color $(if ($status.DefenderExclusions.Count -gt 0) { 'Yellow' } else { 'Green' })
    }
    Write-Host
    if ($status.FirewallProfiles.Count -gt 0) { $status.FirewallProfiles | Format-Table -AutoSize | Out-Host }
    Wait-VoidGuardKey
}

function Show-VoidGuardProcessScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'PROCESS ANALYZER' -ForegroundColor Cyan
    Show-VGTreeAnimation -RootLabel 'PROCESS::ENUMERATION'
    $findings = @(Get-VoidGuardProcessFindings -Context $Context)
    if ($findings.Count -eq 0) {
        Write-Host '[OK] Подозрительные запущенные процессы выше порога не найдены.' -ForegroundColor Green
    } else {
        foreach ($finding in @($findings | Select-Object -First 30)) {
            Write-Host ("[{0}] PID {1} {2}" -f $finding.Risk, $finding.Id, $finding.Path) -ForegroundColor (Get-VoidGuardRiskColor $finding.Risk)
            foreach ($reason in @($finding.Reasons | Select-Object -First 3)) { Write-Host "    └─ $reason" -ForegroundColor DarkGray }
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardPersistenceScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'PERSISTENCE MATRIX' -ForegroundColor Cyan
    Show-VGTreeAnimation -RootLabel 'PERSISTENCE::GRAPH'
    $findings = @(Get-VoidGuardPersistenceFindings -Context $Context)
    if ($findings.Count -eq 0) {
        Write-Host '[OK] Подозрительные точки закрепления выше порога не обнаружены.' -ForegroundColor Green
    } else {
        foreach ($finding in @($findings | Select-Object -First 40)) {
            Write-Host ("[{0}] {1} :: {2}" -f $finding.Risk, $finding.Type, $finding.Name) -ForegroundColor (Get-VoidGuardRiskColor $finding.Risk)
            Write-Host "    $($finding.Command)" -ForegroundColor Gray
            foreach ($reason in @($finding.Reasons | Select-Object -First 3)) { Write-Host "    └─ $reason" -ForegroundColor DarkGray }
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardPendingScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'PENDING REMEDIATION LEDGER' -ForegroundColor Cyan
    $items = @(Get-VoidGuardPendingRemediations -Verify)
    if ($items.Count -eq 0) {
        Write-Host '[OK] Ожидающих операций после перезагрузки нет.' -ForegroundColor Green
    } else {
        $items | Select-Object Id, Status, Path, ScheduledUtc, VerifiedUtc | Format-Table -Wrap | Out-Host
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardRemediationScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'LOCKED FILE / SAFE REMEDIATION' -ForegroundColor Yellow
    Write-Host 'Системные, Microsoft-signed, WRP, TrustedInstaller и reparse-point цели блокируются.' -ForegroundColor Gray
    Write-Host
    $target = Read-Host 'Точный путь к файлу'
    if ([string]::IsNullOrWhiteSpace($target)) { return }

    $policy = Test-VoidGuardProtectedTarget -Path $target
    if (-not $policy.Allowed) {
        Write-Host '[BLOCK] Цель запрещена защитной политикой:' -ForegroundColor Red
        foreach ($reason in @($policy.Reasons)) { Write-Host "  - $reason" -ForegroundColor Yellow }
        Wait-VoidGuardKey
        return
    }

    Write-Host "[OK] Canonical path: $($policy.CanonicalPath)" -ForegroundColor Green
    foreach ($warning in @($policy.Warnings)) { Write-Host "[WARN] $warning" -ForegroundColor Yellow }
    $locks = @(Get-VoidGuardFileLockOwners -Path $policy.CanonicalPath)
    if ($locks.Count -eq 0) {
        Write-Host '[OK] Restart Manager не обнаружил блокирующих процессов.' -ForegroundColor Green
    } else {
        Write-Host '[WARN] Владельцы блокировки:' -ForegroundColor Yellow
        $locks | Select-Object Id, Name, Path, ServiceName, Type, Restartable | Format-Table -Wrap | Out-Host
    }

    $actions = @(
        [pscustomobject]@{ Label = 'ПОМЕСТИТЬ В КАРАНТИН СЕЙЧАС'; Action = 'Quarantine' },
        [pscustomobject]@{ Label = 'ОСТАНОВИТЬ ТОЧНЫЙ ПРОЦЕСС И КАРАНТИН'; Action = 'StopAndQuarantine' },
        [pscustomobject]@{ Label = 'УДАЛИТЬ ПРИ СЛЕДУЮЩЕЙ ЗАГРУЗКЕ'; Action = 'Schedule' },
        [pscustomobject]@{ Label = 'НАЗАД'; Action = 'Back' }
    )
    $choice = Read-VoidGuardMenu -Context $Context -Items $actions -Title 'CHOOSE REMEDIATION PATH'
    if (-not $choice -or $choice.Action -eq 'Back') { return }

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host "TARGET: $($policy.CanonicalPath)" -ForegroundColor Cyan

    switch ($choice.Action) {
        'Quarantine' {
            $confirmation = Read-Host 'Введите QUARANTINE'
            if ($confirmation -cne 'QUARANTINE') { Write-Host '[WAIT] Отменено.' -ForegroundColor DarkGray; Wait-VoidGuardKey; return }
            $result = Invoke-VoidGuardQuarantine -Path $policy.CanonicalPath -Confirmed
            Write-Host "[$($result.Status)] $($result.Path)" -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Red' })
            foreach ($reason in @($result.Reasons)) { Write-Host "  - $reason" -ForegroundColor Yellow }
        }
        'StopAndQuarantine' {
            $eligible = New-Object System.Collections.Generic.List[object]
            foreach ($lock in $locks) {
                $decision = Test-VoidGuardProcessSafeToStop -Id ([int]$lock.Id) -TargetPath $policy.CanonicalPath
                if ($decision.Allowed) { $eligible.Add($lock) }
            }
            if ($eligible.Count -eq 0) {
                Write-Host '[BLOCK] Нет процесса, исполняемый файл которого точно совпадает с целью.' -ForegroundColor Red
                Write-Host 'Для DLL или общей блокировки используйте удаление при перезагрузке.' -ForegroundColor Yellow
                Wait-VoidGuardKey
                return
            }
            $eligible | Format-Table Id, Name, Path -Wrap | Out-Host
            $pidText = Read-Host 'Введите PID из списка'
            [int]$selectedPid = 0
            if (-not [int]::TryParse($pidText, [ref]$selectedPid)) { Write-Host '[ERROR] Неверный PID.' -ForegroundColor Red; Wait-VoidGuardKey; return }
            $confirmation = Read-Host 'Введите TERMINATE'
            if ($confirmation -cne 'TERMINATE') { Write-Host '[WAIT] Отменено.' -ForegroundColor DarkGray; Wait-VoidGuardKey; return }
            $stop = Stop-VoidGuardTargetProcess -Id $selectedPid -TargetPath $policy.CanonicalPath -Confirmed
            Write-Host "[$($stop.Status)] PID $selectedPid" -ForegroundColor $(if ($stop.Success) { 'Green' } else { 'Red' })
            if ($stop.Success) {
                $result = Invoke-VoidGuardQuarantine -Path $policy.CanonicalPath -Confirmed
                Write-Host "[$($result.Status)] $($result.Path)" -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Red' })
            }
        }
        'Schedule' {
            $confirmation = Read-Host 'Введите DELETE-ON-REBOOT'
            if ($confirmation -cne 'DELETE-ON-REBOOT') { Write-Host '[WAIT] Отменено.' -ForegroundColor DarkGray; Wait-VoidGuardKey; return }
            $result = Register-VoidGuardDeleteOnReboot -Path $policy.CanonicalPath -Confirmed
            Write-Host "[$($result.Status)] $($result.Path)" -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Red' })
            if ($result.Success) { Write-Host '[NEXT] Перезагрузите Windows и откройте Pending Remediation Ledger.' -ForegroundColor Cyan }
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardQuarantineScreen {
    param([Parameter(Mandatory)]$Context)

    $items = @(
        [pscustomobject]@{ Label = 'ДОБАВИТЬ ПРОВЕРЕННЫЙ ФАЙЛ'; Action = 'Add' },
        [pscustomobject]@{ Label = 'ПОКАЗАТЬ ХРАНИЛИЩЕ'; Action = 'List' },
        [pscustomobject]@{ Label = 'ВОССТАНОВИТЬ ОБЪЕКТ'; Action = 'Restore' },
        [pscustomobject]@{ Label = 'НАЗАД'; Action = 'Back' }
    )

    while ($true) {
        $choice = Read-VoidGuardMenu -Context $Context -Items $items -Title 'SECURE QUARANTINE'
        if (-not $choice -or $choice.Action -eq 'Back') { return }
        switch ($choice.Action) {
            'Add' { Show-VoidGuardRemediationScreen -Context $Context }
            'List' {
                Clear-Host; Show-VoidGuardHeader -Context $Context
                $vault = @(Get-VoidGuardQuarantineItems)
                if ($vault.Count -eq 0) { Write-Host '[OK] Карантин пуст.' -ForegroundColor Green }
                else { $vault | Select-Object Id, OriginalName, OriginalPath, QuarantinedUtc, SHA256 | Format-Table -Wrap | Out-Host }
                Wait-VoidGuardKey
            }
            'Restore' {
                Clear-Host; Show-VoidGuardHeader -Context $Context
                $id = Read-Host 'Quarantine ID'
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ((Read-Host 'Введите RESTORE') -cne 'RESTORE') { continue }
                try {
                    $result = Restore-VoidGuardQuarantineItem -Id $id
                    Write-Host "[OK] Восстановлено: $($result.Path)" -ForegroundColor Green
                } catch { Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red }
                Wait-VoidGuardKey
            }
        }
    }
}

function Show-VGIntegrityScreen {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $menu=@(
        [pscustomobject]@{ Label='SAVE NEW SYSTEM BASELINE'; Action='Create' },
        [pscustomobject]@{ Label='COMPARE WITH EXISTING BASELINE'; Action='Compare' },
        [pscustomobject]@{ Label='BACK'; Action='Back' }
    )
    while ($true) {
        $choice=Read-VoidGuardMenu -Context $Context -Items $menu -Title 'SYSTEM INTEGRITY // BASELINE'
        if (-not $choice -or $choice.Action -eq 'Back') { return }
        Clear-Host
        Show-VoidGuardHeader -Context $Context
        try {
            if ($choice.Action -eq 'Create') {
                Write-Host 'SYSTEM INTEGRITY // SAVE BASELINE' -ForegroundColor Cyan
                Write-Host 'Снимок сохранит защитные настройки, службы, задачи, автозапуск и hosts.' -ForegroundColor Gray
                Write-Host 'Снимок может содержать чувствительные пути и команды запуска. Не публикуйте его.' -ForegroundColor Yellow
                $path=Read-Host 'Файл baseline (.json, Enter — локальный каталог VoidGuard)'
                $extra=Read-Host 'Дополнительный файл для проверки SHA-256 (Enter — без него)'
                $paths=if ($extra) { @($extra) } else { @() }
                $result=New-VGIntegrityBaseline -BaselinePath $path -SelectedPaths $paths
                Write-Host ("[{0}] {1}" -f $result.Status,$result.BaselinePath) -ForegroundColor $(if ($result.Status -eq 'COMPLETE') { 'Green' } else { 'Yellow' })
                Write-Host ("SHA-256: {0}" -f $result.SHA256) -ForegroundColor DarkGray
                foreach ($errorText in @($result.Errors | Select-Object -First 10)) {
                    Write-Host "[WARN] $errorText" -ForegroundColor Yellow
                }
            }
            if ($choice.Action -eq 'Compare') {
                Write-Host 'SYSTEM INTEGRITY // BASELINE DIFF' -ForegroundColor Cyan
                $path=Read-Host 'Полный путь к существующему baseline (.json)'
                if (-not [string]::IsNullOrWhiteSpace($path)) {
                    $result=Compare-VGIntegrityBaseline -BaselinePath $path
                    Write-Host ("[{0}] Changes: {1} | Added: {2} | Removed: {3} | Modified: {4}" -f $result.Status,$result.ChangesCount,$result.Added,$result.Removed,$result.Changed) -ForegroundColor $(if ($result.Complete) { 'Green' } else { 'Yellow' })
                    foreach ($item in @($result.Changes | Select-Object -First 35)) {
                        Write-Host ("[{0}] {1} :: {2}" -f $item.Kind,$item.Section,$item.Key) -ForegroundColor Yellow
                        if ($item.Kind -eq 'CHANGED') {
                            Write-Host ("  Было: {0}" -f $item.Before) -ForegroundColor DarkGray
                            Write-Host ("  Стало: {0}" -f $item.After) -ForegroundColor Gray
                        }
                    }
                    foreach ($problem in @($result.Issues)) { Write-Host "[WARN] $problem" -ForegroundColor Yellow }
                    foreach ($problem in @($result.CollectionErrors | Select-Object -First 10)) { Write-Host "[ERROR] $problem" -ForegroundColor Yellow }
                    if (-not $result.Complete) {
                        Write-Host 'Неполный раздел не сравнивается: отсутствие записи не считается удалением.' -ForegroundColor Yellow
                    }
                }
            }
        } catch {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
        Wait-VoidGuardKey
    }
}

function Show-VGDefenderOfflineScreen {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'MICROSOFT DEFENDER // OFFLINE CHECK' -ForegroundColor Cyan
    $state=Get-VGDefenderOfflineReadiness
    Write-Host ("Status: {0} | Defender: {1} | WinRE: {2} | BitLocker: {3}" -f $state.Status,$state.Defender,$state.WinRE,$state.BitLocker) -ForegroundColor $(if ($state.Ready) { 'Green' } else { 'Yellow' })
    foreach ($problem in @($state.Blocks)) { Write-Host "[BLOCK] $problem" -ForegroundColor Yellow }
    foreach ($message in @($state.Warnings)) { Write-Host "[WARN] $message" -ForegroundColor DarkYellow }
    Write-Host
    Write-Host 'Offline Scan может немедленно перезагрузить Windows. Результаты доступны в журнале Windows Security.' -ForegroundColor Yellow
    if (-not $state.Ready) {
        Write-Host 'Запуск заблокирован, пока не устранены перечисленные причины.' -ForegroundColor Gray
        Wait-VoidGuardKey
        return
    }
    $accept=Read-Host 'Сохраните документы. Введите OFFLINE для продолжения'
    if ($accept -cne 'OFFLINE') {
        Write-Host '[WAIT] Отменено.' -ForegroundColor Gray
        Wait-VoidGuardKey
        return
    }
    $restart=Read-Host 'Подтвердите немедленную перезагрузку словом RESTART'
    if ($restart -cne 'RESTART') {
        Write-Host '[WAIT] Отменено.' -ForegroundColor Gray
        Wait-VoidGuardKey
        return
    }
    $operation=Invoke-VGDefenderOffline -Confirmed -RebootAcknowledged
    Write-Host ("[{0}] {1}" -f $operation.Status,$operation.Message) -ForegroundColor $(if ($operation.Success) { 'Green' } else { 'Yellow' })
    Wait-VoidGuardKey
}

function Show-VGRuleIntelligenceScreen {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $menu=@(
        [pscustomobject]@{Label='INSTALLED RULE PACKS';Action='Inventory'},
        [pscustomobject]@{Label='PREVIEW SIGNED UPDATE';Action='Preview'},
        [pscustomobject]@{Label='INSTALL SIGNED UPDATE';Action='Install'},
        [pscustomobject]@{Label='VERSION HISTORY';Action='History'},
        [pscustomobject]@{Label='ROLL BACK SIGNED PACK';Action='Rollback'},
        [pscustomobject]@{Label='ENABLE / DISABLE PACK';Action='Activation'},
        [pscustomobject]@{Label='BACK';Action='Back'}
    )
    while ($true) {
        $choice=Read-VoidGuardMenu -Context $Context -Items $menu -Title 'THREAT INTELLIGENCE // RULE PACKS'
        if (-not $choice -or $choice.Action -eq 'Back') { return }
        Clear-Host; Show-VoidGuardHeader -Context $Context
        try {
            switch ($choice.Action) {
                'Inventory' {
                    $packs=@(Get-VoidGuardRulePackInventory -Context $Context)
                    if ($packs.Count -eq 0) { Write-Host 'Пакетов правил пока нет.' -ForegroundColor Gray }
                    else { $packs | Select-Object Id,Version,Publisher,Enabled,Trusted,IntegrityValid | Format-Table -Wrap | Out-Host }
                }
                'Preview' {
                    $path=Read-Host 'Путь к распакованному каталогу подписанного обновления'
                    if (-not $path) { continue }
                    $preview=Get-VGRuleUpdatePreview -SourcePath $path -Context $Context
                    Write-Host ("[{0}] {1} {2}" -f $preview.Status,$preview.PackId,$preview.Version) -ForegroundColor $(if ($preview.CanApply) { 'Green' } else { 'Yellow' })
                    if ($preview.CanApply) {
                        Write-Host ("Действие: {0} | Сейчас: {1} | Издатель: {2} | Key ID: {3}" -f $preview.Operation,$preview.CurrentVersion,$preview.Publisher,$preview.KeyId) -ForegroundColor Cyan
                        Write-Host ("Файлов: {0}; после установки включён: {1}" -f @($preview.Files).Count,$preview.WillBeEnabled) -ForegroundColor Gray
                    } else { Write-Host $preview.Reason -ForegroundColor Yellow }
                }
                'Install' {
                    Write-Host 'Только RSA-SHA256 signed pack. Доверенный ключ должен быть в trusted-publishers.json.' -ForegroundColor Yellow
                    Write-Host 'Никаких обновлений из интернета VoidGuard самостоятельно не скачивает.' -ForegroundColor DarkGray
                    $path=Read-Host 'Каталог локального обновления'
                    if (-not $path) { continue }
                    $preview=Get-VGRuleUpdatePreview -SourcePath $path -Context $Context
                    if (-not $preview.CanApply) { Write-Host "[BLOCK] $($preview.Reason)" -ForegroundColor Yellow; break }
                    Write-Host ("[{0}] {1}: {2} -> {3}" -f $preview.Operation,$preview.PackId,$preview.CurrentVersion,$preview.Version) -ForegroundColor Cyan
                    if ((Read-Host 'Введите INSTALL для записи файлов правил') -cne 'INSTALL') { Write-Host '[WAIT] Отменено.' -ForegroundColor Gray; break }
                    $result=Install-VGRulePackUpdate -SourcePath $path -Context $Context -Confirmed
                    Write-Host ("[{0}] {1}" -f $result.Status,$result.Message) -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Yellow' })
                    if ($result.Error) { Write-Host $result.Error -ForegroundColor Yellow }
                    if ($result.HistoryId) { Write-Host "Сохранённая версия: $($result.HistoryId)" -ForegroundColor Gray }
                }
                'History' {
                    $id=Read-Host 'ID пакета (Enter — вся история)'
                    $history=@(Get-VGRulePackUpdateHistory -Context $Context -PackId $id)
                    if ($history.Count -eq 0) { Write-Host 'Сохранённых версий нет.' -ForegroundColor Gray }
                    else { $history | Select-Object PackId,HistoryId,Version,Trusted,IntegrityValid | Format-Table -Wrap | Out-Host }
                }
                'Rollback' {
                    $id=Read-Host 'Pack ID'
                    $historyId=Read-Host 'History ID (из списка истории)'
                    if (-not $id -or -not $historyId) { continue }
                    $preview=Restore-VGRulePackVersion -PackId $id -HistoryId $historyId -Context $Context
                    Write-Host ("Возврат {0}: {1} -> {2}" -f $id,$preview.Preview.CurrentVersion,$preview.Preview.RestoreVersion) -ForegroundColor Cyan
                    if ((Read-Host 'Введите ROLLBACK для возврата подписанной версии') -cne 'ROLLBACK') { Write-Host '[WAIT] Отменено.' -ForegroundColor Gray; break }
                    $result=Restore-VGRulePackVersion -PackId $id -HistoryId $historyId -Context $Context -Confirmed
                    Write-Host ("[{0}] {1}" -f $result.Status,$result.Version) -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Yellow' })
                    if ($result.Error) { Write-Host $result.Error -ForegroundColor Yellow }
                }
                'Activation' {
                    $id=Read-Host 'Pack ID'
                    $action=Read-Host 'Введите ENABLE или DISABLE'
                    if (-not $id -or $action -cnotin @('ENABLE','DISABLE')) { continue }
                    $enabled=$action -ceq 'ENABLE'
                    $preview=Set-VGRulePackEnabled -PackId $id -Context $Context -Enabled:$enabled
                    Write-Host ("Правила после изменения: {0}" -f (@($preview.Preview.ActivePacks) -join ', ')) -ForegroundColor Gray
                    if ((Read-Host 'Введите CONFIRM, чтобы изменить настройки') -cne 'CONFIRM') { Write-Host '[WAIT] Отменено.' -ForegroundColor Gray; break }
                    $result=Set-VGRulePackEnabled -PackId $id -Context $Context -Enabled:$enabled -Confirmed
                    Write-Host ("[{0}] {1} Enabled={2}" -f $result.Status,$id,$enabled) -ForegroundColor $(if ($result.Success) { 'Green' } else { 'Yellow' })
                }
            }
        } catch { Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red }
        Wait-VoidGuardKey
    }
}

function Show-VGIncidentBundleScreen {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $menu=@(
        [pscustomobject]@{Label='PREVIEW LOCAL DIAGNOSTIC BUNDLE';Action='Preview'},
        [pscustomobject]@{Label='EXPORT INCIDENT BUNDLE ZIP';Action='Export'},
        [pscustomobject]@{Label='BACK';Action='Back'}
    )
    while ($true) {
        $choice=Read-VoidGuardMenu -Context $Context -Items $menu -Title 'THREAT INTELLIGENCE // INCIDENT BUNDLE'
        if (-not $choice -or $choice.Action -eq 'Back') { return }
        Clear-Host;Show-VoidGuardHeader -Context $Context
        Write-Host 'LOCAL ONLY: ZIP не загружается в интернет.' -ForegroundColor Cyan
        Write-Host 'По умолчанию сырые пути, команды и тексты событий исключены.' -ForegroundColor Gray
        try {
            $path=Read-Host 'Путь к ZIP (Enter — локальный каталог VoidGuard)'
            $scan=Read-Host 'Дополнительный файл или каталог для сканирования (Enter — пропустить)'
            $baseline=Read-Host 'Существующий System Baseline для сравнения (Enter — пропустить)'
            $events=(Read-Host 'Включить метаданные Windows Defender events? Введите EVENTS') -ceq 'EVENTS'
            $sensitive=(Read-Host 'Включить личные пути, команды и тексты событий? Введите SENSITIVE') -ceq 'SENSITIVE'
            $preview=Get-VGIncidentPreview -OutputPath $path -ScanPath $scan -BaselinePath $baseline -IncludeEventLogs:$events -IncludeSensitive:$sensitive
            Write-Host "Путь: $($preview.OutputPath)" -ForegroundColor Cyan
            foreach ($category in $preview.Categories) { Write-Host ("[DATA] {0}" -f $category) -ForegroundColor Gray }
            foreach ($warning in $preview.Warnings) { Write-Host ("[WARN] {0}" -f $warning) -ForegroundColor Yellow }
            if ($choice.Action -eq 'Export') {
                if ((Read-Host 'Проверьте состав. Введите EXPORT для создания ZIP') -cne 'EXPORT') {
                    Write-Host '[WAIT] Отменено.' -ForegroundColor Gray
                } else {
                    $bundle=Export-VGIncidentBundle -Context $Context -OutputPath $preview.OutputPath -ScanPath $scan -BaselinePath $baseline -IncludeEventLogs:$events -IncludeSensitive:$sensitive -Confirmed
                    Write-Host ("[{0}] {1}" -f $bundle.Status,$bundle.OutputPath) -ForegroundColor $(if ($bundle.Success) { 'Green' } else { 'Yellow' })
                    Write-Host ("SHA-256: {0}" -f $bundle.SHA256) -ForegroundColor DarkGray
                    foreach ($issue in @($bundle.CollectionIssues)) { Write-Host "[WARN] $issue" -ForegroundColor Yellow }
                }
            }
        } catch { Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red }
        Wait-VoidGuardKey
    }
}

function Start-VoidGuardConsole {
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
        [pscustomobject]@{ Label = 'SYSTEM INTEGRITY / BASELINES'; Action = 'Integrity' },
        [pscustomobject]@{ Label = 'MICROSOFT DEFENDER OFFLINE'; Action = 'DefenderOffline' },
        [pscustomobject]@{ Label = 'THREAT INTELLIGENCE / RULE PACKS'; Action = 'ThreatIntel' },
        [pscustomobject]@{ Label = 'INCIDENT BUNDLE / EVIDENCE'; Action = 'IncidentBundle' },
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
                'Integrity' { Show-VGIntegrityScreen -Context $Context }
                'DefenderOffline' { Show-VGDefenderOfflineScreen -Context $Context }
                'ThreatIntel' { Show-VGRuleIntelligenceScreen -Context $Context }
                'IncidentBundle' { Show-VGIncidentBundleScreen -Context $Context }
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
}

Export-ModuleMember -Function @(
    'New-VoidGuardContext',
    'Start-VoidGuardConsole',
    'Show-VoidGuardHeader',
    'Read-VoidGuardMenu'
)
