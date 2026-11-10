#requires -Version 5.1
Set-StrictMode -Version Latest

function Get-VGDefenderOfflineReadiness {
    [CmdletBinding()]
    param()
    $blocks=New-Object 'System.Collections.Generic.List[string]'
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    $winre='UNKNOWN'
    $bitlocker='UNKNOWN'
    $defender='UNKNOWN'
    $admin=$false
    if (-not (Test-VoidGuardWindows)) { $blocks.Add('Windows is required.') }
    else {
        $admin=[bool](Test-VoidGuardAdministrator)
        if (-not $admin) { $blocks.Add('Administrator rights are required.') }
        if ($env:PROCESSOR_ARCHITECTURE -match '^ARM') { $blocks.Add('Windows on ARM is not supported by Defender Offline.') }
        try {
            $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            if ([int]$os.ProductType -ne 1) { $blocks.Add('Windows Server is not supported by Defender Offline.') }
        } catch { $blocks.Add('Cannot verify the Windows edition.') }

        if (-not (Get-Command Start-MpWDOScan -ErrorAction SilentlyContinue)) {
            $blocks.Add('Start-MpWDOScan is not installed.')
        }
        try {
            $status=Get-MpComputerStatus -ErrorAction Stop
            $defender=if ($status.AntivirusEnabled -and ([string]$status.AMRunningMode -ne 'Passive Mode')) { 'ACTIVE' } else { 'INACTIVE' }
            if ($defender -ne 'ACTIVE') { $blocks.Add('Microsoft Defender Antivirus must be active.') }
        } catch { $blocks.Add('Cannot verify Microsoft Defender Antivirus status.') }

        if (Get-Command reagentc.exe -ErrorAction SilentlyContinue) {
            try {
                $response=(& reagentc.exe /info 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw 'reagentc failed.' }
                $winre=if ($response -match '(?i)\bEnabled\b|Включено') { 'ENABLED' } else { 'UNKNOWN' }
                if ($winre -ne 'ENABLED') { $blocks.Add('Windows Recovery Environment could not be confirmed enabled.') }
            } catch { $blocks.Add('Could not verify Windows Recovery Environment.') }
        } else { $blocks.Add('reagentc.exe not found: WinRE cannot be verified.') }

        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            try {
                $volume=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                $bitlocker=[string]$volume.ProtectionStatus
                if ($bitlocker -eq 'On' -or $bitlocker -eq '1') {
                    $blocks.Add('BitLocker is active: save the recovery key and suspend protection manually before trying again.')
                } elseif ($bitlocker -notin @('Off','0')) {
                    $blocks.Add('BitLocker protection state is unknown.')
                }
            } catch { $blocks.Add('Cannot determine system drive BitLocker protection state.') }
        } else { $blocks.Add('BitLocker status cannot be checked on this system.') }
    }

    $warnings.Add('Starting Microsoft Defender Offline can restart this computer immediately.')
    $warnings.Add('Save your work and close applications before confirming.')
    $warnings.Add('Do not run with unsaved work. BitLocker recovery key may be required after boot.')
    [pscustomobject]@{
        Mode='DefenderOffline'
        Ready=($blocks.Count -eq 0)
        Status=if ($blocks.Count -eq 0) { 'READY' } else { 'BLOCKED' }
        IsAdministrator=$admin
        WinRE=$winre;BitLocker=$bitlocker;Defender=$defender
        Blocks=$blocks.ToArray();Warnings=$warnings.ToArray()
    }
}

function Get-VGDefenderOfflineDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Readiness,
        [switch]$Confirmed,
        [switch]$RebootAcknowledged
    )
    if (-not $Readiness.Ready) { return 'BLOCKED' }
    if (-not $Confirmed -or -not $RebootAcknowledged) { return 'CONFIRMATION_REQUIRED' }
    return 'READY_TO_LAUNCH'
}

function Invoke-VGDefenderOffline {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$Confirmed,[switch]$RebootAcknowledged)
    $readiness=Get-VGDefenderOfflineReadiness
    $decision=Get-VGDefenderOfflineDecision -Readiness $readiness -Confirmed:$Confirmed -RebootAcknowledged:$RebootAcknowledged
    if ($decision -ne 'READY_TO_LAUNCH') {
        return [pscustomobject]@{Success=$false;Status=$decision;Readiness=$readiness}
    }
    if (-not $PSCmdlet.ShouldProcess('Local Windows computer','Start Microsoft Defender Offline and initiate system restart')) {
        return [pscustomobject]@{Success=$false;Status='DRY_RUN';Readiness=$readiness}
    }
    try {
        # Команда Microsoft может перезагрузить ПК прежде, чем функция вернёт управление.
        Start-MpWDOScan -ErrorAction Stop
        return [pscustomobject]@{
            Success=$true
            Status='REQUESTED'
            Message='Microsoft Defender accepted the offline scan request. Results are available in Windows Security Protection history after reboot.'
        }
    } catch {
        return [pscustomobject]@{Success=$false;Status='REQUEST_FAILED';Error=$_.Exception.Message}
    }
}

Export-ModuleMember -Function @('Get-VGDefenderOfflineReadiness','Get-VGDefenderOfflineDecision','Invoke-VGDefenderOffline')
