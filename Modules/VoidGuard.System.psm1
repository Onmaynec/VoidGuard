Set-StrictMode -Version Latest

function Test-VoidGuardAdministrator {
    if (-not (Test-VoidGuardWindows)) {
        return $false
    }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-VoidGuardSecurityStatus {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        ComputerName       = $env:COMPUTERNAME
        UserName           = [Environment]::UserName
        IsAdministrator    = Test-VoidGuardAdministrator
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        DefenderAvailable  = $false
        DefenderEnabled    = $null
        RealTimeProtection = $null
        SignatureAgeDays   = $null
        FirewallAvailable  = $false
        FirewallProfiles   = @()
        UacEnabled         = $null
        TimestampUtc       = (Get-Date).ToUniversalTime()
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $result.DefenderAvailable = $true
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $result.DefenderEnabled = [bool]$defender.AntivirusEnabled
            $result.RealTimeProtection = [bool]$defender.RealTimeProtectionEnabled
            if ($defender.AntivirusSignatureLastUpdated) {
                $result.SignatureAgeDays = [Math]::Round(((Get-Date) - $defender.AntivirusSignatureLastUpdated).TotalDays, 2)
            }
        } catch {
        }
    }

    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $result.FirewallAvailable = $true
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
            $result.FirewallProfiles = @($profiles)
        } catch {
        }
    }

    if (Test-VoidGuardWindows) {
        try {
            $uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
            $result.UacEnabled = [bool]$uac.EnableLUA
        } catch {
        }
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
            @{ Scope = 'HKLM32'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
        )

        foreach ($location in $registryLocations) {
            if (-not (Test-Path -LiteralPath $location.Path)) { continue }
            try {
                $properties = Get-ItemProperty -LiteralPath $location.Path -ErrorAction Stop
                foreach ($property in $properties.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        $entries.Add([pscustomobject]@{
                            Type     = 'Registry'
                            Scope    = $location.Scope
                            Name     = $property.Name
                            Command  = [string]$property.Value
                            Location = $location.Path
                        })
                    }
                }
            } catch {
            }
        }
    }

    $startupFolders = @()
    if ($env:APPDATA) {
        $startupFolders += Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
    }
    if ($env:ProgramData) {
        $startupFolders += Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    }

    foreach ($folder in $startupFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $entries.Add([pscustomobject]@{
                Type     = 'StartupFolder'
                Scope    = if ($_.FullName -like "$env:APPDATA*") { 'User' } else { 'Machine' }
                Name     = $_.Name
                Command  = $_.FullName
                Location = $folder
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
    $knownBad = @{}

    foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
        try {
            if (-not $process.Path -or $seen.ContainsKey($process.Path)) { continue }
            $seen[$process.Path] = $true
            $fileFinding = Test-VoidGuardFile -Path $process.Path -Context $Context -KnownBadHashes $knownBad
            if ($fileFinding -and $fileFinding.Score -ge [int]$Context.Settings.minimumFindingScore) {
                $findings.Add([pscustomobject]@{
                    Id              = $process.Id
                    ProcessName     = $process.ProcessName
                    Path            = $process.Path
                    Score           = $fileFinding.Score
                    Risk            = $fileFinding.Risk
                    SignatureStatus = $fileFinding.SignatureStatus
                    Reasons         = $fileFinding.Reasons
                })
            }
        } catch {
            # Protected processes may deny access to Path.
        }
    }

    return @($findings | Sort-Object Score -Descending)
}

Export-ModuleMember -Function @(
    'Test-VoidGuardAdministrator',
    'Get-VoidGuardSecurityStatus',
    'Get-VoidGuardStartupEntries',
    'Get-VoidGuardProcessFindings'
)
