Set-StrictMode -Version Latest

function Test-VoidGuardAdministrator {
    if (-not (Test-VoidGuardWindows)) { return $false }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-VoidGuardSecurityStatus {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        ComputerName        = $env:COMPUTERNAME
        UserName            = [Environment]::UserName
        IsAdministrator     = Test-VoidGuardAdministrator
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        DefenderAvailable   = $false
        DefenderEnabled     = $null
        RealTimeProtection  = $null
        BehaviorMonitor     = $null
        IoavProtection      = $null
        SignatureAgeDays    = $null
        DefenderExclusions  = @()
        FirewallAvailable   = $false
        FirewallProfiles    = @()
        UacEnabled          = $null
        SmartScreenEnabled  = $null
        UserProxyEnabled    = $null
        HostsModifiedUtc    = $null
        TimestampUtc        = (Get-Date).ToUniversalTime()
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $result.DefenderAvailable = $true
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $result.DefenderEnabled = [bool]$defender.AntivirusEnabled
            $result.RealTimeProtection = [bool]$defender.RealTimeProtectionEnabled
            $result.BehaviorMonitor = [bool]$defender.BehaviorMonitorEnabled
            $result.IoavProtection = [bool]$defender.IoavProtectionEnabled
            if ($defender.AntivirusSignatureLastUpdated) {
                $result.SignatureAgeDays = [Math]::Round(((Get-Date) - $defender.AntivirusSignatureLastUpdated).TotalDays, 2)
            }
        } catch { }
        try {
            $preference = Get-MpPreference -ErrorAction Stop
            $exclusions = New-Object System.Collections.Generic.List[string]
            foreach ($value in @($preference.ExclusionPath)) { if ($value) { $exclusions.Add("Path: $value") } }
            foreach ($value in @($preference.ExclusionProcess)) { if ($value) { $exclusions.Add("Process: $value") } }
            foreach ($value in @($preference.ExclusionExtension)) { if ($value) { $exclusions.Add("Extension: $value") } }
            $result.DefenderExclusions = @($exclusions)
        } catch { }
    }

    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $result.FirewallAvailable = $true
        try {
            $result.FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        } catch { }
    }

    if (Test-VoidGuardWindows) {
        try {
            $uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
            $result.UacEnabled = [bool]$uac.EnableLUA
        } catch { }
        try {
            $smartScreen = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction Stop
            $result.SmartScreenEnabled = ([string]$smartScreen.SmartScreenEnabled -ne 'Off')
        } catch { }
        try {
            $proxy = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -ErrorAction Stop
            $result.UserProxyEnabled = [bool]$proxy.ProxyEnable
        } catch { }
        try {
            $hosts = Join-Path $env:windir 'System32\drivers\etc\hosts'
            if (Test-Path -LiteralPath $hosts) { $result.HostsModifiedUtc = (Get-Item -LiteralPath $hosts).LastWriteTimeUtc }
        } catch { }
    }

    return [pscustomobject]$result
}

function Get-VoidGuardStartupEntries {
    [CmdletBinding()]
    param()

    $entries = New-Object System.Collections.Generic.List[object]
    if (Test-VoidGuardWindows) {
        $registryLocations = @(
            @{ Scope = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
            @{ Scope = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
            @{ Scope = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' },
            @{ Scope = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
            @{ Scope = 'HKLM32'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
            @{ Scope = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' },
            @{ Scope = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' }
        )
        foreach ($location in $registryLocations) {
            if (-not (Test-Path -LiteralPath $location.Path)) { continue }
            try {
                $properties = Get-ItemProperty -LiteralPath $location.Path -ErrorAction Stop
                foreach ($property in $properties.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        $entries.Add([pscustomobject]@{
                            Type = 'Registry'; Scope = $location.Scope; Name = $property.Name
                            Command = [string]$property.Value; Location = $location.Path
                        })
                    }
                }
            } catch { }
        }
    }

    $startupFolders = @()
    if ($env:APPDATA) { $startupFolders += Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup' }
    if ($env:ProgramData) { $startupFolders += Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp' }
    foreach ($folder in $startupFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $entries.Add([pscustomobject]@{
                Type = 'StartupFolder'; Scope = if ($_.FullName -like "$env:APPDATA*") { 'User' } else { 'Machine' }
                Name = $_.Name; Command = $_.FullName; Location = $folder
            })
        }
    }
    return @($entries)
}

function Get-VoidGuardProcessFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $findings = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $cimMap = @{}
    $networkMap = @{}

    if (Test-VoidGuardWindows) {
        try {
            foreach ($row in Get-CimInstance -ClassName Win32_Process -ErrorAction Stop) { $cimMap[[int]$row.ProcessId] = $row }
        } catch { }
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            try {
                foreach ($connection in Get-NetTCPConnection -State Established -ErrorAction Stop) {
                    $pid = [int]$connection.OwningProcess
                    if (-not $networkMap.ContainsKey($pid)) { $networkMap[$pid] = New-Object System.Collections.Generic.List[string] }
                    $networkMap[$pid].Add("$($connection.RemoteAddress):$($connection.RemotePort)")
                }
            } catch { }
        }
    }

    foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
        try {
            if (-not $process.Path -or $seen.ContainsKey($process.Path)) { continue }
            $seen[$process.Path] = $true
            $fileFinding = Test-VoidGuardFile -Path $process.Path -Context $Context -KnownBadHashes @{}
            if (-not $fileFinding) { continue }

            $score = [int]$fileFinding.Score
            $reasons = New-Object System.Collections.Generic.List[string]
            foreach ($reason in @($fileFinding.Reasons)) { $reasons.Add($reason) }
            $commandLine = $null
            $parentId = $null
            if ($cimMap.ContainsKey([int]$process.Id)) {
                $commandLine = [string]$cimMap[[int]$process.Id].CommandLine
                $parentId = [int]$cimMap[[int]$process.Id].ParentProcessId
                if ($commandLine -match '(?i)(-enc|encodedcommand|windowstyle\s+hidden|frombase64string|downloadstring)') {
                    $score += 24
                    $reasons.Add('Suspicious encoded, hidden, or downloader command line.')
                }
            }
            $connections = if ($networkMap.ContainsKey([int]$process.Id)) { @($networkMap[[int]$process.Id] | Select-Object -Unique) } else { @() }
            if ($connections.Count -gt 0 -and $fileFinding.SignatureStatus -ne 'Valid') {
                $score += 10
                $reasons.Add('Unsigned or untrusted process has established network connections.')
            }

            if ($score -ge [int]$Context.Settings.minimumFindingScore) {
                $findings.Add([pscustomobject]@{
                    Id = $process.Id; ParentId = $parentId; ProcessName = $process.ProcessName
                    Path = $process.Path; CommandLine = $commandLine; Connections = $connections
                    Score = $score; Risk = Get-VoidGuardRiskLevel -Score $score
                    SignatureStatus = $fileFinding.SignatureStatus; Reasons = @($reasons | Select-Object -Unique)
                })
            }
        } catch { }
    }
    return @($findings | Sort-Object Score -Descending)
}

Export-ModuleMember -Function @(
    'Test-VoidGuardAdministrator',
    'Get-VoidGuardSecurityStatus',
    'Get-VoidGuardStartupEntries',
    'Get-VoidGuardProcessFindings'
)
