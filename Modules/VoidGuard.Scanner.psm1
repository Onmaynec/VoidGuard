Set-StrictMode -Version Latest

function Get-VoidGuardScannerSetting {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Name,
        $DefaultValue
    )
    $property = $Settings.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $DefaultValue
}

function Get-VoidGuardRiskLevel {
    param([int]$Score)
    if ($Score -ge 70) { return 'CRITICAL' }
    if ($Score -ge 45) { return 'HIGH' }
    if ($Score -ge 20) { return 'MEDIUM' }
    return 'LOW'
}

function Get-VoidGuardKnownBadHashes {
    param([Parameter(Mandatory)][string]$RootPath)

    $path = Join-Path $RootPath 'Rules\known-bad-hashes.json'
    if (-not (Test-Path -LiteralPath $path)) { return @{} }

    $table = @{}
    try {
        $entries = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in @($entries)) {
            if ($entry.sha256) { $table[[string]$entry.sha256.ToUpperInvariant()] = [string]$entry.name }
        }
    } catch {
    }
    return $table
}

function Get-VoidGuardFileEntropy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaximumBytes = 1048576
    )

    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $length = [int][Math]::Min([long][Math]::Max(1, $MaximumBytes), $stream.Length)
        if ($length -le 0) { return 0.0 }
        $buffer = New-Object byte[] $length
        $read = $stream.Read($buffer, 0, $length)
        if ($read -le 0) { return 0.0 }

        $counts = New-Object int[] 256
        for ($i = 0; $i -lt $read; $i++) { $counts[[int]$buffer[$i]]++ }
        $entropy = 0.0
        foreach ($count in $counts) {
            if ($count -le 0) { continue }
            $p = $count / [double]$read
            $entropy -= $p * ([Math]::Log($p, 2))
        }
        return [Math]::Round($entropy, 4)
    } catch {
        return $null
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Get-VoidGuardPeInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $result = [ordered]@{
        IsPE = $false
        Machine = $null
        Architecture = $null
        Sections = $null
        CompileTimeUtc = $null
        Characteristics = $null
        OptionalHeaderMagic = $null
    }

    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        if ($stream.Length -lt 128) { return [pscustomobject]$result }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return [pscustomobject]$result }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 24)) { return [pscustomobject]$result }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return [pscustomobject]$result }

        $machine = $reader.ReadUInt16()
        $sections = $reader.ReadUInt16()
        $timestamp = $reader.ReadUInt32()
        $null = $reader.ReadUInt32()
        $null = $reader.ReadUInt32()
        $optionalSize = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        $optionalMagic = if ($optionalSize -ge 2) { $reader.ReadUInt16() } else { $null }

        $architecture = switch ($machine) {
            0x014c { 'x86' }
            0x8664 { 'x64' }
            0x01c0 { 'ARM' }
            0xaa64 { 'ARM64' }
            default { ('0x{0:X4}' -f $machine) }
        }
        $compileTime = $null
        if ($timestamp -gt 0) {
            try { $compileTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$timestamp).UtcDateTime } catch { }
        }

        $result.IsPE = $true
        $result.Machine = ('0x{0:X4}' -f $machine)
        $result.Architecture = $architecture
        $result.Sections = [int]$sections
        $result.CompileTimeUtc = $compileTime
        $result.Characteristics = ('0x{0:X4}' -f $characteristics)
        $result.OptionalHeaderMagic = if ($null -ne $optionalMagic) { ('0x{0:X4}' -f $optionalMagic) } else { $null }
        return [pscustomobject]$result
    } catch {
        return [pscustomobject]$result
    } finally {
        if ($reader) { $reader.Dispose() } elseif ($stream) { $stream.Dispose() }
    }
}

function Get-VoidGuardTextSample {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaximumCharacters = 1048576
    )

    $reader = $null
    try {
        $reader = New-Object IO.StreamReader($Path, $true)
        $buffer = New-Object char[] ([Math]::Max(1, $MaximumCharacters))
        $read = $reader.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return '' }
        return New-Object string($buffer, 0, $read)
    } catch {
        return $null
    } finally {
        if ($reader) { $reader.Dispose() }
    }
}

function Test-VoidGuardFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [hashtable]$KnownBadHashes,
        $RuleEngine
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { return $null }
    if (-not $RuleEngine) { $RuleEngine = Get-VoidGuardRuleEngineState -Context $Context }

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $ruleMatches = New-Object System.Collections.Generic.List[object]
    $yaraMatches = New-Object System.Collections.Generic.List[object]
    $extension = $item.Extension.ToLowerInvariant()
    $activeExtensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.cpl', '.ocx', '.sys', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk')
    $executableExtensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.ocx', '.sys')
    $scriptExtensions = @('.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta')

    if ($activeExtensions -contains $extension) {
        $score += 4
        $reasons.Add("Active content type: $extension")
    }
    if ($item.Name -match '\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|txt|zip|rar)\.(exe|scr|com|pif|bat|cmd|js|vbs)$') {
        $score += 32
        $reasons.Add('Double extension masquerading as a document or archive.')
    }

    $lowerPath = $item.FullName.ToLowerInvariant()
    $suspiciousLocations = @('\appdata\roaming\', '\appdata\local\temp\', '\windows\temp\', '\downloads\')
    if (($activeExtensions -contains $extension) -and ($suspiciousLocations | Where-Object { $lowerPath.Contains($_) })) {
        $score += 16
        $reasons.Add('Active file located in a commonly abused user or temporary directory.')
    }
    if ($lowerPath -match '\\start menu\\programs\\startup\\') {
        $score += 28
        $reasons.Add('Active file is placed in a Startup folder.')
    }
    if (($item.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) {
        $score += 8
        $reasons.Add('Hidden file attribute is set.')
    }
    if (($item.Attributes -band [IO.FileAttributes]::System) -ne 0 -and $lowerPath -notmatch '\\windows\\') {
        $score += 12
        $reasons.Add('System attribute is set outside the Windows directory.')
    }

    $systemNames = @('svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'winlogon.exe', 'explorer.exe', 'smss.exe')
    if (($systemNames -contains $item.Name.ToLowerInvariant()) -and $lowerPath -notmatch '\\windows\\(system32|syswow64)\\') {
        $score += 38
        $reasons.Add('Filename imitates a Windows component outside its expected directory.')
    }

    $signature = Get-VoidGuardSignatureInfo -Path $item.FullName
    if ($executableExtensions -contains $extension) {
        switch ($signature.Status) {
            'Valid' {
                if ($signature.IsMicrosoft) {
                    $score = [Math]::Max(0, $score - 12)
                    $reasons.Add('Valid Microsoft signature lowers the risk score.')
                }
            }
            'NotSigned' { $score += 14; $reasons.Add('Executable is not digitally signed.') }
            'HashMismatch' { $score += 40; $reasons.Add('Authenticode hash mismatch detected.') }
            'NotTrusted' { $score += 24; $reasons.Add('Digital signature is not trusted.') }
        }
    }

    $pe = Get-VoidGuardPeInfo -Path $item.FullName
    $entropyBytes = [int](Get-VoidGuardScannerSetting -Settings $Context.Settings -Name 'entropySampleBytes' -DefaultValue 1048576)
    $entropy = Get-VoidGuardFileEntropy -Path $item.FullName -MaximumBytes $entropyBytes
    if ($pe.IsPE -and $executableExtensions -notcontains $extension) {
        $score += 34
        $reasons.Add('PE executable content does not match the filename extension.')
    }
    if ($null -ne $entropy -and $item.Length -ge 4096 -and $entropy -ge 7.35) {
        $score += 12
        $reasons.Add("High byte entropy detected: $entropy")
    }
    if ($pe.IsPE) {
        if ($null -eq $pe.CompileTimeUtc) {
            $score += 5
            $reasons.Add('PE compile timestamp is missing or zero.')
        } elseif ($pe.CompileTimeUtc -gt (Get-Date).ToUniversalTime().AddDays(30)) {
            $score += 10
            $reasons.Add('PE compile timestamp is unexpectedly in the future.')
        }
    }

    $maximumPatternBytes = 1048576
    foreach ($rule in @($RuleEngine.Patterns)) {
        if ($rule.Extensions.Count -eq 0 -or $rule.Extensions -contains $extension) {
            $maximumPatternBytes = [Math]::Max($maximumPatternBytes, [int]$rule.MaxBytes)
        }
    }
    $textSample = if (($scriptExtensions -contains $extension) -or $RuleEngine.Patterns.Count -gt 0) {
        Get-VoidGuardTextSample -Path $item.FullName -MaximumCharacters $maximumPatternBytes
    } else { $null }

    if ($scriptExtensions -contains $extension -and $null -ne $textSample) {
        $patterns = @(
            @{ Pattern = 'FromBase64String'; Score = 12; Reason = 'Base64 decoding behavior detected.' },
            @{ Pattern = 'Invoke-Expression|\bIEX\b'; Score = 18; Reason = 'Dynamic PowerShell execution pattern detected.' },
            @{ Pattern = 'DownloadString|Net\.WebClient|Invoke-WebRequest'; Score = 14; Reason = 'Network download behavior detected.' },
            @{ Pattern = 'EncodedCommand|-enc\s'; Score = 18; Reason = 'Encoded command execution pattern detected.' },
            @{ Pattern = 'Add-MpPreference|Set-MpPreference'; Score = 25; Reason = 'Microsoft Defender configuration modification detected.' }
        )
        foreach ($rule in $patterns) {
            if ($textSample -match $rule.Pattern) { $score += $rule.Score; $reasons.Add($rule.Reason) }
        }
    }

    if ($null -ne $textSample) {
        foreach ($rule in @($RuleEngine.Patterns)) {
            if ($rule.Extensions.Count -gt 0 -and $rule.Extensions -notcontains $extension) { continue }
            try {
                if ($rule.Regex.IsMatch($textSample)) {
                    $score += [int]$rule.Score
                    $reasons.Add("Rule $($rule.Id): $($rule.Reason)")
                    $ruleMatches.Add([pscustomobject]@{ PackId = $rule.PackId; Rule = $rule.Id; Score = $rule.Score; Reason = $rule.Reason })
                }
            } catch {
            }
        }
    }

    $yaraLimit = [long](Get-VoidGuardScannerSetting -Settings $Context.Settings -Name 'yaraMaxFileSizeBytes' -DefaultValue 67108864)
    if ($RuleEngine.Yara.Available -and $RuleEngine.YaraRuleFiles.Count -gt 0 -and $item.Length -le $yaraLimit) {
        $yaraResult = Invoke-VoidGuardYaraScan -Path $item.FullName -Context $Context -RuleFiles $RuleEngine.YaraRuleFiles
        foreach ($match in @($yaraResult.Matches)) { $yaraMatches.Add($match) }
        if ($yaraMatches.Count -gt 0) {
            $yaraScore = [Math]::Min(115, 55 + (($yaraMatches.Count - 1) * 20))
            $score += $yaraScore
            foreach ($match in @($yaraMatches)) { $reasons.Add("YARA match: $($match.Rule)") }
        }
        if ($yaraResult.TimedOut) { $reasons.Add('YARA scan reached its configured timeout.') }
    }

    $hash = $null
    try {
        $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($KnownBadHashes -and $KnownBadHashes.ContainsKey($hash.ToUpperInvariant())) {
            $score += 100
            $reasons.Add("Known malicious hash: $($KnownBadHashes[$hash.ToUpperInvariant()])")
        }
    } catch {
        $reasons.Add('SHA-256 could not be calculated.')
    }

    return [pscustomobject]@{
        Path = $item.FullName
        Name = $item.Name
        Extension = $extension
        Size = [long]$item.Length
        ModifiedUtc = $item.LastWriteTimeUtc
        SHA256 = $hash
        SignatureStatus = $signature.Status
        Publisher = $signature.Subject
        IsPE = [bool]$pe.IsPE
        PEArchitecture = $pe.Architecture
        PESections = $pe.Sections
        PECompileTimeUtc = $pe.CompileTimeUtc
        Entropy = $entropy
        RuleMatches = @($ruleMatches)
        YaraMatches = @($yaraMatches)
        Score = [int]$score
        Risk = Get-VoidGuardRiskLevel -Score $score
        Reasons = @($reasons)
    }
}

function Test-VoidGuardScanCandidate {
    param([Parameter(Mandatory)]$Item)
    $extensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.cpl', '.ocx', '.sys', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk')
    $extension = $Item.Extension.ToLowerInvariant()
    return ($extensions -contains $extension) -or ([string]::IsNullOrWhiteSpace($extension) -and $Item.Length -le 67108864)
}

function Get-VoidGuardScanCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [int]$MaxFiles = 2500
    )

    $seen = @{}
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($scanPath in $Paths) {
        if ([string]::IsNullOrWhiteSpace($scanPath) -or -not (Test-Path -LiteralPath $scanPath)) { continue }
        $target = Get-Item -LiteralPath $scanPath -Force -ErrorAction SilentlyContinue
        if (-not $target) { continue }

        if (-not $target.PSIsContainer) {
            if (-not $seen.ContainsKey($target.FullName)) { $files.Add($target); $seen[$target.FullName] = $true }
            continue
        }

        Get-ChildItem -LiteralPath $target.FullName -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            if ($files.Count -ge $MaxFiles) { return }
            if ((Test-VoidGuardScanCandidate -Item $_) -and -not $seen.ContainsKey($_.FullName)) {
                $files.Add($_)
                $seen[$_.FullName] = $true
            }
        }
        if ($files.Count -ge $MaxFiles) { break }
    }
    return @($files)
}

function New-VoidGuardScanResult {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)]$Started,
        [Parameter(Mandatory)]$Completed,
        [Parameter(Mandatory)][int]$FilesScanned,
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$RuleEngine
    )

    return [pscustomobject]@{
        Version = $Context.Version
        Mode = $Mode
        Paths = @($Paths)
        StartedUtc = $Started.ToUniversalTime()
        CompletedUtc = $Completed.ToUniversalTime()
        Duration = ($Completed - $Started).ToString()
        FilesScanned = $FilesScanned
        Findings = @($Findings | Sort-Object Score -Descending)
        RulePacks = @($RuleEngine.Inventory | Select-Object Id, Name, Version, Enabled, Trusted, IntegrityValid, TrustReason, Errors)
        Yara = $RuleEngine.Yara
    }
}

function Invoke-VoidGuardPathScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [switch]$ShowProgress
    )

    $resolved = Get-VoidGuardCanonicalPath -Path $Path
    $started = Get-Date
    $maxFiles = [int]$Context.Settings.maxFilesPerScan
    $candidates = Get-VoidGuardScanCandidates -Paths @($resolved) -MaxFiles $maxFiles
    $knownBad = Get-VoidGuardKnownBadHashes -RootPath $Context.RootPath
    $ruleEngine = Get-VoidGuardRuleEngineState -Context $Context
    $findings = New-Object System.Collections.Generic.List[object]

    for ($index = 0; $index -lt $candidates.Count; $index++) {
        $candidate = $candidates[$index]
        if ($ShowProgress) {
            $percent = if ($candidates.Count -eq 0) { 100 } else { [int](($index / [double]$candidates.Count) * 100) }
            Write-Progress -Activity 'VoidGuard file analysis' -Status $candidate.FullName -PercentComplete $percent
        }
        try {
            $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $Context -KnownBadHashes $knownBad -RuleEngine $ruleEngine
            if ($finding -and $finding.Score -ge [int]$Context.Settings.minimumFindingScore) { $findings.Add($finding) }
        } catch {
        }
    }
    if ($ShowProgress) { Write-Progress -Activity 'VoidGuard file analysis' -Completed }
    $completed = Get-Date
    return New-VoidGuardScanResult -Context $Context -Mode 'Custom' -Paths @($resolved) -Started $started -Completed $completed -FilesScanned $candidates.Count -Findings @($findings) -RuleEngine $ruleEngine
}

function Invoke-VoidGuardQuickScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [switch]$ShowProgress
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
    if ($env:APPDATA) { $candidatesToAdd.Add((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')) }
    if ($env:ProgramData) { $candidatesToAdd.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')) }
    foreach ($candidate in $candidatesToAdd) {
        if ((Test-Path -LiteralPath $candidate) -and -not $paths.Contains($candidate)) { $paths.Add($candidate) }
    }

    $started = Get-Date
    $maxFiles = [int]$Context.Settings.maxFilesPerScan
    $scanCandidates = Get-VoidGuardScanCandidates -Paths @($paths) -MaxFiles $maxFiles
    $knownBad = Get-VoidGuardKnownBadHashes -RootPath $Context.RootPath
    $ruleEngine = Get-VoidGuardRuleEngineState -Context $Context
    $findings = New-Object System.Collections.Generic.List[object]

    for ($index = 0; $index -lt $scanCandidates.Count; $index++) {
        $candidate = $scanCandidates[$index]
        if ($ShowProgress) {
            $percent = if ($scanCandidates.Count -eq 0) { 100 } else { [int](($index / [double]$scanCandidates.Count) * 100) }
            Write-Progress -Activity 'VoidGuard quick scan' -Status $candidate.FullName -PercentComplete $percent
        }
        try {
            $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $Context -KnownBadHashes $knownBad -RuleEngine $ruleEngine
            if ($finding -and $finding.Score -ge [int]$Context.Settings.minimumFindingScore) { $findings.Add($finding) }
        } catch {
        }
    }
    if ($ShowProgress) { Write-Progress -Activity 'VoidGuard quick scan' -Completed }
    $completed = Get-Date
    return New-VoidGuardScanResult -Context $Context -Mode 'Quick' -Paths @($paths) -Started $started -Completed $completed -FilesScanned $scanCandidates.Count -Findings @($findings) -RuleEngine $ruleEngine
}

Export-ModuleMember -Function @(
    'Get-VoidGuardRiskLevel',
    'Get-VoidGuardFileEntropy',
    'Get-VoidGuardPeInfo',
    'Test-VoidGuardFile',
    'Invoke-VoidGuardPathScan',
    'Invoke-VoidGuardQuickScan'
)
