Set-StrictMode -Version Latest

function Resolve-VoidGuardCommandTarget {
    [CmdletBinding()]
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $candidate = $null

    if ($expanded.StartsWith('"')) {
        $end = $expanded.IndexOf('"', 1)
        if ($end -gt 1) { $candidate = $expanded.Substring(1, $end - 1) }
    } elseif ($expanded -match '^([^\s]+\.(exe|com|bat|cmd|ps1|vbs|js|hta|dll))\b') {
        $candidate = $matches[1]
    }

    if (-not $candidate) { return $null }
    try {
        if (Test-Path -LiteralPath $candidate) {
            return (Get-Item -LiteralPath $candidate -Force -ErrorAction Stop).FullName
        }
    } catch {
    }
    return $candidate
}

function Get-VoidGuardPersistenceScore {
    [CmdletBinding()]
    param(
        [string]$Command,
        [string]$TargetPath,
        [Parameter(Mandatory)]$Context
    )

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $text = [string]$Command
    $lower = $text.ToLowerInvariant()

    if ($lower -match '\\appdata\\|\\temp\\|\\downloads\\|\\public\\') {
        $score += 22
        $reasons.Add('Persistence launches content from a commonly abused user-writable location.')
    }
    if ($lower -match 'powershell(\.exe)?\s+.*(-enc|encodedcommand|hidden|windowstyle\s+hidden|iex\b)') {
        $score += 32
        $reasons.Add('Obfuscated or hidden PowerShell execution pattern.')
    }
    if ($lower -match '\b(mshta|regsvr32|rundll32|wscript|cscript|certutil|bitsadmin)\.exe\b') {
        $score += 18
        $reasons.Add('Living-off-the-land executable used by persistence entry.')
    }
    if ($lower -match 'https?://|downloadstring|invoke-webrequest|frombase64string') {
        $score += 25
        $reasons.Add('Network retrieval or encoded payload behavior appears in the command.')
    }

    if ($TargetPath) {
        if (Test-Path -LiteralPath $TargetPath) {
            try {
                $fileFinding = Test-VoidGuardFile -Path $TargetPath -Context $Context -KnownBadHashes @{}
                if ($fileFinding) {
                    $score += [Math]::Min([int]$fileFinding.Score, 55)
                    foreach ($reason in @($fileFinding.Reasons | Select-Object -First 4)) {
                        $reasons.Add($reason)
                    }
                }
            } catch {
                $reasons.Add('Target file could not be inspected.')
            }
        } else {
            $score += 12
            $reasons.Add('Referenced target does not currently exist.')
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($Command)) {
        $score += 6
        $reasons.Add('Executable target could not be resolved from the command.')
    }

    return [pscustomobject]@{
        Score   = [int]$score
        Risk    = Get-VoidGuardRiskLevel -Score $score
        Reasons = @($reasons | Select-Object -Unique)
    }
}

function New-VoidGuardPersistenceFinding {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Name,
        [string]$Command,
        [string]$Location,
        [string]$Scope,
        [Parameter(Mandatory)]$Context,
        [hashtable]$Extra
    )

    $target = Resolve-VoidGuardCommandTarget -Command $Command
    $assessment = Get-VoidGuardPersistenceScore -Command $Command -TargetPath $target -Context $Context
    $data = [ordered]@{
        Type       = $Type
        Name       = $Name
        Scope      = $Scope
        Command    = $Command
        TargetPath = $target
        Location   = $Location
        Score      = $assessment.Score
        Risk       = $assessment.Risk
        Reasons    = $assessment.Reasons
    }
    if ($Extra) {
        foreach ($key in $Extra.Keys) { $data[$key] = $Extra[$key] }
    }
    return [pscustomobject]$data
}

function Get-VoidGuardServicePersistence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Test-VoidGuardWindows)) { return @() }
    try {
        foreach ($service in Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) {
            if ($service.StartMode -notin @('Auto', 'Manual')) { continue }
            $finding = New-VoidGuardPersistenceFinding -Type 'Service' -Name ([string]$service.Name) -Command ([string]$service.PathName) -Location 'Service Control Manager' -Scope 'Machine' -Context $Context -Extra @{
                StartMode   = [string]$service.StartMode
                State       = [string]$service.State
                DisplayName = [string]$service.DisplayName
            }
            if ($finding.Score -ge [int]$Context.Settings.minimumPersistenceScore) { $items.Add($finding) }
        }
    } catch {
    }
    return $items.ToArray()
}

function Get-VoidGuardScheduledTaskPersistence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return @() }
    try {
        foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
            foreach ($action in @($task.Actions)) {
                $command = (([string]$action.Execute) + ' ' + ([string]$action.Arguments)).Trim()
                if ([string]::IsNullOrWhiteSpace($command)) { continue }
                $finding = New-VoidGuardPersistenceFinding -Type 'ScheduledTask' -Name ([string]$task.TaskName) -Command $command -Location ([string]$task.TaskPath) -Scope 'Machine/User' -Context $Context -Extra @{
                    State = [string]$task.State
                }
                if ($finding.Score -ge [int]$Context.Settings.minimumPersistenceScore) { $items.Add($finding) }
            }
        }
    } catch {
    }
    return $items.ToArray()
}

function Get-VoidGuardWmiPersistence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Test-VoidGuardWindows)) { return @() }
    try {
        $namespace = 'root/subscription'
        $consumers = @{}
        foreach ($consumer in Get-CimInstance -Namespace $namespace -ClassName __EventConsumer -ErrorAction Stop) {
            $name = [string]$consumer.Name
            $command = $null
            if ($consumer.PSObject.Properties.Name -contains 'CommandLineTemplate') { $command = [string]$consumer.CommandLineTemplate }
            if (-not $command -and $consumer.PSObject.Properties.Name -contains 'ScriptText') { $command = [string]$consumer.ScriptText }
            $consumers[$name] = $command
        }
        foreach ($binding in Get-CimInstance -Namespace $namespace -ClassName __FilterToConsumerBinding -ErrorAction Stop) {
            $consumerName = [regex]::Match([string]$binding.Consumer, 'Name="([^"]+)"').Groups[1].Value
            $command = if ($consumers.ContainsKey($consumerName)) { [string]$consumers[$consumerName] } else { [string]$binding.Consumer }
            $finding = New-VoidGuardPersistenceFinding -Type 'WMI' -Name $consumerName -Command $command -Location $namespace -Scope 'Machine' -Context $Context -Extra @{}
            $finding.Score = [int]$finding.Score + 18
            $finding.Risk = Get-VoidGuardRiskLevel -Score $finding.Score
            $finding.Reasons = @('Permanent WMI event subscription detected.') + @($finding.Reasons)
            if ($finding.Score -ge [int]$Context.Settings.minimumPersistenceScore) { $items.Add($finding) }
        }
    } catch {
    }
    return $items.ToArray()
}

function Get-VoidGuardPersistenceFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($entry in Get-VoidGuardStartupEntries) {
        $finding = New-VoidGuardPersistenceFinding -Type ([string]$entry.Type) -Name ([string]$entry.Name) -Command ([string]$entry.Command) -Location ([string]$entry.Location) -Scope ([string]$entry.Scope) -Context $Context -Extra @{}
        if ($finding.Score -ge [int]$Context.Settings.minimumPersistenceScore) { $findings.Add($finding) }
    }
    foreach ($item in Get-VoidGuardServicePersistence -Context $Context) { $findings.Add($item) }
    foreach ($item in Get-VoidGuardScheduledTaskPersistence -Context $Context) { $findings.Add($item) }
    foreach ($item in Get-VoidGuardWmiPersistence -Context $Context) { $findings.Add($item) }

    return @($findings.ToArray() | Sort-Object Score -Descending)
}

Export-ModuleMember -Function @(
    'Resolve-VoidGuardCommandTarget',
    'Get-VoidGuardPersistenceFindings',
    'Get-VoidGuardServicePersistence',
    'Get-VoidGuardScheduledTaskPersistence',
    'Get-VoidGuardWmiPersistence'
)
