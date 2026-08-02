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
    } else {
        '0.0.0-dev'
    }

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
        [Parameter(Mandatory)][string]$Value,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host ('{0,-24} {1}' -f $Label, $Value) -ForegroundColor $Color
}

function Wait-VoidGuardKey {
    param([string]$Message = 'Press any key to return...')
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
    $width = 78

    Write-Host ('╔' + ('═' * ($width - 2)) + '╗') -ForegroundColor DarkGreen
    Write-Host ('║ VOIDGUARD SECURITY CONSOLE  v{0,-12} HOST: {1,-24} ║' -f $Context.Version, $env:COMPUTERNAME) -ForegroundColor Green
    Write-Host ('║ USER: {0,-25} PRIVILEGES: ' -f [Environment]::UserName) -NoNewline -ForegroundColor DarkGreen
    Write-Host ('{0,-29}' -f $adminText) -NoNewline -ForegroundColor $adminColor
    Write-Host '║' -ForegroundColor DarkGreen
    Write-Host ('╠' + ('═' * ($width - 2)) + '╣') -ForegroundColor DarkGreen
}

function Read-VoidGuardMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][object[]]$Items,
        [string]$Title = 'SELECT SECURITY OPERATION'
    )

    $selected = 0
    while ($true) {
        Clear-Host
        Show-VoidGuardHeader -Context $Context
        Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen
        Write-Host ('║' + $Title.PadLeft([int](($Title.Length + 76) / 2)).PadRight(76) + '║') -ForegroundColor Cyan
        Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen

        for ($index = 0; $index -lt $Items.Count; $index++) {
            $prefix = if ($index -eq $selected) { '▶' } else { ' ' }
            $line = '  {0} [{1:00}] {2}' -f $prefix, $index + 1, $Items[$index].Label
            $line = $line.PadRight(76)
            if ($index -eq $selected) {
                Write-Host ('║' + $line + '║') -ForegroundColor Black -BackgroundColor Green
            } else {
                Write-Host ('║' + $line + '║') -ForegroundColor Gray
            }
        }

        Write-Host ('║' + (' ' * 76) + '║') -ForegroundColor DarkGreen
        Write-Host ('╠' + ('═' * 76) + '╣') -ForegroundColor DarkGreen
        Write-Host ('║ ↑ ↓ Navigate    ENTER Select    ESC Back    F1 Help'.PadRight(77) + '║') -ForegroundColor DarkGray
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
                Write-Host 'Arrows select an operation. ENTER opens it. ESC returns.' -ForegroundColor Gray
                Write-Host 'Decorative [VISUAL] output is never evidence of a threat.' -ForegroundColor Yellow
                Write-Host 'Real actions use [SCAN], [OK], [WARN], [BLOCK], or [ERROR].' -ForegroundColor Yellow
                Wait-VoidGuardKey
            }
        }
    }
}

function Show-VoidGuardScanSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Result
    )

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'SCAN COMPLETE' -ForegroundColor Green
    Write-VGStatusLine -Label 'Mode' -Value ([string]$Result.Mode) -Color Cyan
    Write-VGStatusLine -Label 'Files scanned' -Value ([string]$Result.FilesScanned)
    Write-VGStatusLine -Label 'Findings' -Value ([string]$Result.Findings.Count) -Color $(if ($Result.Findings.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-VGStatusLine -Label 'Duration' -Value ([string]$Result.Duration)
    Write-Host

    if ($Result.Findings.Count -eq 0) {
        Write-Host '[OK] No heuristic findings crossed the configured threshold.' -ForegroundColor Green
        Write-Host 'This does not guarantee that the system is malware-free.' -ForegroundColor DarkGray
    } else {
        Write-Host ('{0,-10} {1,-6} {2,-56}' -f 'RISK', 'SCORE', 'PATH') -ForegroundColor Cyan
        Write-Host ('-' * 76) -ForegroundColor DarkGreen
        foreach ($finding in @($Result.Findings | Select-Object -First 18)) {
            $color = switch ($finding.Risk) {
                'CRITICAL' { 'Red' }
                'HIGH' { 'Red' }
                'MEDIUM' { 'Yellow' }
                default { 'Gray' }
            }
            $displayPath = [string]$finding.Path
            if ($displayPath.Length -gt 56) { $displayPath = '…' + $displayPath.Substring($displayPath.Length - 55) }
            Write-Host ('{0,-10} {1,-6} {2,-56}' -f $finding.Risk, $finding.Score, $displayPath) -ForegroundColor $color
            foreach ($reason in @($finding.Reasons | Select-Object -First 3)) {
                Write-Host ("             └─ $reason") -ForegroundColor DarkGray
            }
        }
        if ($Result.Findings.Count -gt 18) {
            Write-Host "... and $($Result.Findings.Count - 18) more findings." -ForegroundColor DarkGray
        }
    }

    Write-Host
    Write-Host '[INFO] Use the Quarantine menu only after reviewing the exact target.' -ForegroundColor Cyan
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
    Write-Host

    if ($status.FirewallProfiles.Count -gt 0) {
        Write-Host 'Firewall profiles:' -ForegroundColor Cyan
        $status.FirewallProfiles | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host '[WARN] Firewall status is unavailable in this host.' -ForegroundColor Yellow
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardStartupScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'STARTUP INSPECTOR' -ForegroundColor Cyan
    $entries = Get-VoidGuardStartupEntries
    if ($entries.Count -eq 0) {
        Write-Host '[OK] No startup entries were returned.' -ForegroundColor Green
    } else {
        foreach ($entry in @($entries | Select-Object -First 40)) {
            Write-Host ("[{0}] {1} :: {2}" -f $entry.Type, $entry.Name, $entry.Command) -ForegroundColor Gray
        }
        if ($entries.Count -gt 40) {
            Write-Host "... and $($entries.Count - 40) more entries." -ForegroundColor DarkGray
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardProcessScreen {
    param([Parameter(Mandatory)]$Context)

    Clear-Host
    Show-VoidGuardHeader -Context $Context
    Write-Host 'PROCESS ANALYZER' -ForegroundColor Cyan
    Show-VGTreeAnimation -RootLabel 'PROCESS::ENUMERATION'
    $findings = Get-VoidGuardProcessFindings -Context $Context
    if ($findings.Count -eq 0) {
        Write-Host '[OK] No running process crossed the heuristic threshold.' -ForegroundColor Green
    } else {
        foreach ($finding in @($findings | Select-Object -First 25)) {
            Write-Host ("[{0}] PID {1} {2}" -f $finding.Risk, $finding.Id, $finding.Path) -ForegroundColor $(if ($finding.Score -ge 45) { 'Red' } else { 'Yellow' })
            foreach ($reason in @($finding.Reasons | Select-Object -First 2)) {
                Write-Host ("    └─ $reason") -ForegroundColor DarkGray
            }
        }
    }
    Wait-VoidGuardKey
}

function Show-VoidGuardQuarantineScreen {
    param([Parameter(Mandatory)]$Context)

    $items = @(
        [pscustomobject]@{ Label = 'Quarantine a reviewed file'; Action = 'Add' },
        [pscustomobject]@{ Label = 'List quarantine vault'; Action = 'List' },
        [pscustomobject]@{ Label = 'Restore quarantine item'; Action = 'Restore' },
        [pscustomobject]@{ Label = 'Back'; Action = 'Back' }
    )

    while ($true) {
        $choice = Read-VoidGuardMenu -Context $Context -Items $items -Title 'SECURE QUARANTINE'
        if (-not $choice -or $choice.Action -eq 'Back') { return }

        switch ($choice.Action) {
            'Add' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                Write-Host 'SECURE QUARANTINE' -ForegroundColor Yellow
                Write-Host 'Directories, Windows files, Microsoft-signed files, reparse points,' -ForegroundColor Gray
                Write-Host 'and TrustedInstaller-owned targets are blocked by policy.' -ForegroundColor Gray
                Write-Host
                $target = Read-Host 'Exact file path'
                if ([string]::IsNullOrWhiteSpace($target)) { continue }

                $policy = Test-VoidGuardProtectedTarget -Path $target
                if (-not $policy.Allowed) {
                    Write-Host '[BLOCK] Protection policy denied this target:' -ForegroundColor Red
                    foreach ($reason in $policy.Reasons) { Write-Host "  - $reason" -ForegroundColor Yellow }
                    Wait-VoidGuardKey
                    continue
                }

                foreach ($warning in $policy.Warnings) { Write-Host "[WARN] $warning" -ForegroundColor Yellow }
                Write-Host "Target: $($policy.CanonicalPath)" -ForegroundColor Cyan
                $confirmation = Read-Host 'Type QUARANTINE to continue'
                if ($confirmation -cne 'QUARANTINE') {
                    Write-Host '[WAIT] Operation cancelled.' -ForegroundColor DarkGray
                    Wait-VoidGuardKey
                    continue
                }

                $result = Invoke-VoidGuardQuarantine -Path $policy.CanonicalPath -Confirmed
                $color = if ($result.Success) { 'Green' } else { 'Red' }
                Write-Host "[$($result.Status)] $($result.Path)" -ForegroundColor $color
                foreach ($reason in @($result.Reasons)) { Write-Host "  - $reason" -ForegroundColor Yellow }
                if ($result.PSObject.Properties.Name -contains 'Processes') {
                    $result.Processes | Format-Table -AutoSize | Out-Host
                }
                Wait-VoidGuardKey
            }
            'List' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                $vaultItems = Get-VoidGuardQuarantineItems
                if ($vaultItems.Count -eq 0) {
                    Write-Host '[OK] Quarantine vault is empty.' -ForegroundColor Green
                } else {
                    $vaultItems | Select-Object Id, OriginalName, OriginalPath, QuarantinedUtc, SHA256 | Format-Table -Wrap | Out-Host
                }
                Wait-VoidGuardKey
            }
            'Restore' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                $id = Read-Host 'Quarantine ID'
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                $confirmation = Read-Host 'Type RESTORE to continue'
                if ($confirmation -cne 'RESTORE') { continue }
                try {
                    $result = Restore-VoidGuardQuarantineItem -Id $id
                    Write-Host "[OK] Restored to $($result.Path)" -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                }
                Wait-VoidGuardKey
            }
        }
    }
}

function Start-VoidGuardConsole {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $menu = @(
        [pscustomobject]@{ Label = 'QUICK THREAT SCAN'; Action = 'QuickScan' },
        [pscustomobject]@{ Label = 'SCAN FILE OR DIRECTORY'; Action = 'CustomScan' },
        [pscustomobject]@{ Label = 'PROCESS ANALYZER'; Action = 'Processes' },
        [pscustomobject]@{ Label = 'STARTUP INSPECTOR'; Action = 'Startup' },
        [pscustomobject]@{ Label = 'WINDOWS SECURITY STATUS'; Action = 'Status' },
        [pscustomobject]@{ Label = 'SECURE QUARANTINE'; Action = 'Quarantine' },
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

        switch ($choice.Action) {
            'QuickScan' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                Show-VGGlitchText -Text 'QUICK SCAN CHANNEL OPEN' -Color Cyan
                $result = Invoke-VoidGuardQuickScan -Context $Context -ShowProgress
                $Context.LastScan = $result
                Show-VoidGuardScanSummary -Context $Context -Result $result
            }
            'CustomScan' {
                Clear-Host
                Show-VoidGuardHeader -Context $Context
                $target = Read-Host 'File or directory path'
                if ([string]::IsNullOrWhiteSpace($target)) { continue }
                try {
                    $result = Invoke-VoidGuardPathScan -Path $target -Context $Context -ShowProgress
                    $Context.LastScan = $result
                    Show-VoidGuardScanSummary -Context $Context -Result $result
                } catch {
                    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
                    Wait-VoidGuardKey
                }
            }
            'Processes' { Show-VoidGuardProcessScreen -Context $Context }
            'Startup' { Show-VoidGuardStartupScreen -Context $Context }
            'Status' { Show-VoidGuardSecurityScreen -Context $Context }
            'Quarantine' { Show-VoidGuardQuarantineScreen -Context $Context }
            'Demo' {
                Show-VoidGuardVisualDemo -RootPath $Context.RootPath
                Wait-VoidGuardKey
            }
        }
    }
}

Export-ModuleMember -Function @(
    'New-VoidGuardContext',
    'Start-VoidGuardConsole'
)
