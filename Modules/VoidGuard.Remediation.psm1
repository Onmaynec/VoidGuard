Set-StrictMode -Version Latest

$script:RemediationNativeLoaded = $false

function Initialize-VoidGuardRemediationNative {
    if ($script:RemediationNativeLoaded -or -not (Test-VoidGuardWindows)) { return }

    $source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class VoidGuardRemediationNative
{
    public const int CCH_RM_SESSION_KEY = 32;
    public const int CCH_RM_MAX_APP_NAME = 255;
    public const int CCH_RM_MAX_SVC_NAME = 63;
    public const int ERROR_MORE_DATA = 234;
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    public enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    public static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded,
        ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    public static extern int RmEndSession(uint pSessionHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
}
'@

    try {
        Add-Type -TypeDefinition $source -ErrorAction Stop
        $script:RemediationNativeLoaded = $true
    } catch {
        if ($_.Exception.Message -match 'already exists') {
            $script:RemediationNativeLoaded = $true
        } else { throw }
    }
}

function Get-VoidGuardLastBootTimeUtc {
    [CmdletBinding()]
    param()

    if (-not (Test-VoidGuardWindows)) { return $null }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1
        if ($os -and $os.LastBootUpTime) {
            return ([datetime]$os.LastBootUpTime).ToUniversalTime()
        }
    } catch {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1
            if ($os -and $os.LastBootUpTime) {
                return [Management.ManagementDateTimeConverter]::ToDateTime([string]$os.LastBootUpTime).ToUniversalTime()
            }
        } catch { }
    }
    return $null
}

function Get-VoidGuardPendingRecordState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        $CurrentBootUtc,
        [bool]$FileExists = $false,
        [string]$CurrentHash,
        [string]$HashError
    )

    if ($null -eq $CurrentBootUtc) {
        return [pscustomobject]@{ Status = 'VERIFICATION_UNAVAILABLE'; Reason = 'Не удалось установить время последней загрузки Windows.' }
    }
    $scheduled = ([datetime]$Record.ScheduledUtc).ToUniversalTime()
    $boot = ([datetime]$CurrentBootUtc).ToUniversalTime()
    if ($boot -le $scheduled) {
        return [pscustomobject]@{ Status = 'AWAITING_REBOOT'; Reason = 'После назначения операции Windows ещё не перезагружалась.' }
    }
    if (-not $FileExists) {
        return [pscustomobject]@{ Status = 'REMOVED_VERIFIED'; Reason = 'После подтверждённой перезагрузки файл отсутствует.' }
    }
    if (-not [string]::IsNullOrWhiteSpace($HashError) -or [string]::IsNullOrWhiteSpace($CurrentHash)) {
        return [pscustomobject]@{ Status = 'VERIFICATION_INCOMPLETE'; Reason = "Не удалось вычислить хеш: $HashError" }
    }
    if (-not [string]::Equals([string]$Record.SHA256, $CurrentHash, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Status = 'REPLACED_OR_RECREATED'; Reason = 'Файл существует, но SHA-256 изменился.' }
    }
    return [pscustomobject]@{ Status = 'STILL_PRESENT'; Reason = 'После перезагрузки исходный файл остаётся на месте.' }
}

function Get-VoidGuardPendingRoot {
    [CmdletBinding()]
    param()

    $root = if ((Test-VoidGuardAdministrator) -and $env:ProgramData) {
        Join-Path $env:ProgramData 'VoidGuard\Pending'
    } elseif ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'VoidGuard\Pending'
    } else {
        Join-Path $env:TEMP 'VoidGuard\Pending'
    }
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return $root
}

function Get-VoidGuardFileLockOwners {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-VoidGuardWindows)) { return @() }
    $canonical = Get-VoidGuardCanonicalPath -Path $Path
    Initialize-VoidGuardRemediationNative

    [uint32]$session = 0
    $key = [Text.StringBuilder]::new(33)
    $start = [VoidGuardRemediationNative]::RmStartSession([ref]$session, 0, $key)
    if ($start -ne 0) { return @(Get-VoidGuardLockingProcesses -Path $canonical) }

    try {
        [string[]]$files = @($canonical)
        $registered = [VoidGuardRemediationNative]::RmRegisterResources($session, 1, $files, 0, [IntPtr]::Zero, 0, $null)
        if ($registered -ne 0) { return @(Get-VoidGuardLockingProcesses -Path $canonical) }

        [uint32]$needed = 0
        [uint32]$count = 0
        [uint32]$rebootReasons = 0
        $result = [VoidGuardRemediationNative]::RmGetList($session, [ref]$needed, [ref]$count, $null, [ref]$rebootReasons)
        if ($result -eq 0 -and $needed -eq 0) { return @() }
        if ($result -ne [VoidGuardRemediationNative]::ERROR_MORE_DATA -or $needed -eq 0) {
            return @(Get-VoidGuardLockingProcesses -Path $canonical)
        }

        $items = [VoidGuardRemediationNative+RM_PROCESS_INFO[]]::new([int]$needed)
        $count = $needed
        $result = [VoidGuardRemediationNative]::RmGetList($session, [ref]$needed, [ref]$count, $items, [ref]$rebootReasons)
        if ($result -ne 0) { return @(Get-VoidGuardLockingProcesses -Path $canonical) }

        $owners = New-Object System.Collections.Generic.List[object]
        for ($index = 0; $index -lt $count; $index++) {
            $entry = $items[$index]
            $processPath = $null
            $processName = $entry.strAppName
            try {
                $process = Get-Process -Id $entry.Process.dwProcessId -ErrorAction Stop
                $processName = $process.ProcessName
                $processPath = $process.Path
            } catch { }
            $owners.Add([pscustomobject]@{
                Id          = [int]$entry.Process.dwProcessId
                Name        = [string]$processName
                Path        = $processPath
                ServiceName = [string]$entry.strServiceShortName
                Type        = [string]$entry.ApplicationType
                Restartable = [bool]$entry.bRestartable
                RebootReason = [uint32]$rebootReasons
            })
        }
        return @($owners | Sort-Object Id -Unique)
    } finally {
        [VoidGuardRemediationNative]::RmEndSession($session) | Out-Null
    }
}

function Test-VoidGuardProcessSafeToStop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][string]$TargetPath
    )

    $blockedNames = @('system','registry','smss','csrss','wininit','services','lsass','winlogon','fontdrvhost','dwm')
    try {
        $process = Get-Process -Id $Id -ErrorAction Stop
        $name = $process.ProcessName.ToLowerInvariant()
        if ($Id -le 4 -or $blockedNames -contains $name) {
            return [pscustomobject]@{ Allowed = $false; Reason = 'Critical Windows process.'; Process = $process }
        }
        if (-not $process.Path) {
            return [pscustomobject]@{ Allowed = $false; Reason = 'Executable path is unavailable.'; Process = $process }
        }
        $canonicalTarget = Get-VoidGuardCanonicalPath -Path $TargetPath
        if (-not [string]::Equals($process.Path, $canonicalTarget, [StringComparison]::OrdinalIgnoreCase)) {
            return [pscustomobject]@{ Allowed = $false; Reason = 'Process executable is not the remediation target.'; Process = $process }
        }
        $policy = Test-VoidGuardProtectedTarget -Path $process.Path
        if (-not $policy.Allowed) {
            return [pscustomobject]@{ Allowed = $false; Reason = 'Process executable is protected by policy.'; Process = $process }
        }
        return [pscustomobject]@{ Allowed = $true; Reason = 'Exact unprotected target process.'; Process = $process }
    } catch {
        return [pscustomobject]@{ Allowed = $false; Reason = $_.Exception.Message; Process = $null }
    }
}

function Stop-VoidGuardTargetProcess {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][string]$TargetPath,
        [switch]$Confirmed
    )

    if (-not $Confirmed) {
        return [pscustomobject]@{ Success = $false; Status = 'CONFIRMATION_REQUIRED'; Id = $Id }
    }
    $decision = Test-VoidGuardProcessSafeToStop -Id $Id -TargetPath $TargetPath
    if (-not $decision.Allowed) {
        return [pscustomobject]@{ Success = $false; Status = 'BLOCKED_PROCESS_POLICY'; Id = $Id; Reason = $decision.Reason }
    }

    if ($PSCmdlet.ShouldProcess("PID $Id", 'Stop exact target process')) {
        try {
            Stop-Process -Id $Id -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 350
            if (Get-Process -Id $Id -ErrorAction SilentlyContinue) {
                return [pscustomobject]@{ Success = $false; Status = 'PROCESS_STILL_RUNNING'; Id = $Id }
            }
            return [pscustomobject]@{ Success = $true; Status = 'PROCESS_STOPPED'; Id = $Id }
        } catch {
            return [pscustomobject]@{ Success = $false; Status = 'PROCESS_STOP_FAILED'; Id = $Id; Reason = $_.Exception.Message }
        }
    }
}

function Register-VoidGuardDeleteOnReboot {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Confirmed
    )

    if (-not (Test-VoidGuardAdministrator)) {
        return [pscustomobject]@{ Success = $false; Status = 'ADMIN_REQUIRED'; Path = $Path }
    }
    if (-not $Confirmed) {
        return [pscustomobject]@{ Success = $false; Status = 'CONFIRMATION_REQUIRED'; Path = $Path }
    }

    $policy = Test-VoidGuardProtectedTarget -Path $Path
    if (-not $policy.Allowed) {
        return [pscustomobject]@{ Success = $false; Status = 'BLOCKED_SYSTEM_POLICY'; Path = $Path; Reasons = $policy.Reasons }
    }

    Initialize-VoidGuardRemediationNative
    $canonical = $policy.CanonicalPath
    $hash = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256 -ErrorAction Stop).Hash
    $id = 'P-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), ([Guid]::NewGuid().ToString('N').Substring(0, 8).ToUpperInvariant())

    if (-not $PSCmdlet.ShouldProcess($canonical, 'Schedule file deletion during the next Windows boot')) {
        return [pscustomobject]@{ Success = $false; Status = 'DRY_RUN'; Path = $canonical }
    }
    $ok = [VoidGuardRemediationNative]::MoveFileEx($canonical, $null, [VoidGuardRemediationNative]::MOVEFILE_DELAY_UNTIL_REBOOT)
    if (-not $ok) {
        $win32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        return [pscustomobject]@{ Success = $false; Status = 'SCHEDULE_FAILED'; Path = $canonical; Win32Error = $win32 }
    }

    $record = [ordered]@{
        SchemaVersion  = 1
        Id             = $id
        Path           = $canonical
        SHA256         = $hash
        CurrentSHA256  = $null
        HashMatches    = $null
        ScheduledUtc   = (Get-Date).ToUniversalTime()
        BootTimeAtScheduleUtc = Get-VoidGuardLastBootTimeUtc
        VerifiedBootUtc = $null
        VerificationReason = $null
        Status         = 'PENDING_REBOOT'
        VerifiedUtc    = $null
        PolicyWarnings = @($policy.Warnings)
    }
    $recordPath = Join-Path (Get-VoidGuardPendingRoot) "$id.json"
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordPath -Encoding UTF8

    return [pscustomobject]@{ Success = $true; Status = 'DELETE_SCHEDULED'; Id = $id; Path = $canonical; SHA256 = $hash }
}

function Get-VoidGuardPendingRemediations {
    [CmdletBinding()]
    param([switch]$Verify)

    $records = New-Object 'System.Collections.Generic.List[object]'
    $boot = if ($Verify) { Get-VoidGuardLastBootTimeUtc } else { $null }
    foreach ($file in Get-ChildItem -LiteralPath (Get-VoidGuardPendingRoot) -Filter '*.json' -File -ErrorAction SilentlyContinue) {
        try {
            $record = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            if ($Verify) {
                $exists = $false
                $currentHash = $null
                $hashError = $null
                if ($null -ne $boot -and ([datetime]$boot).ToUniversalTime() -gt ([datetime]$record.ScheduledUtc).ToUniversalTime()) {
                    $exists = Test-Path -LiteralPath ([string]$record.Path) -PathType Leaf
                    if ($exists) {
                        try {
                            $currentHash = (Get-FileHash -LiteralPath ([string]$record.Path) -Algorithm SHA256 -ErrorAction Stop).Hash
                        } catch {
                            $hashError = $_.Exception.Message
                        }
                    }
                }
                $decision = Get-VoidGuardPendingRecordState -Record $record -CurrentBootUtc $boot -FileExists:$exists -CurrentHash $currentHash -HashError $hashError
                $record.Status = $decision.Status
                $record.CurrentSHA256 = $currentHash
                $record.HashMatches = if ($currentHash) { [string]::Equals([string]$record.SHA256, $currentHash, [StringComparison]::OrdinalIgnoreCase) } else { $null }
                $record.VerifiedUtc = (Get-Date).ToUniversalTime()
                # Совместимость со старыми ledger: поля могли отсутствовать в схеме v0.3.
                $record | Add-Member -NotePropertyName VerifiedBootUtc -NotePropertyValue $boot -Force
                $record | Add-Member -NotePropertyName VerificationReason -NotePropertyValue $decision.Reason -Force
                $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction Stop
            }
            $records.Add($record)
        } catch {
            $records.Add([pscustomobject]@{
                Id = $file.BaseName
                Status = 'LEDGER_READ_ERROR'
                Path = $file.FullName
                VerificationReason = $_.Exception.Message
            })
        }
    }
    return @($records.ToArray() | Sort-Object ScheduledUtc -Descending)
}

Export-ModuleMember -Function @(
    'Get-VoidGuardFileLockOwners',
    'Test-VoidGuardProcessSafeToStop',
    'Stop-VoidGuardTargetProcess',
    'Register-VoidGuardDeleteOnReboot',
    'Get-VoidGuardPendingRemediations',
    'Get-VoidGuardPendingRecordState'
)
