Set-StrictMode -Version Latest

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
    if (-not (Test-Path -LiteralPath $path)) {
        return @{}
    }

    $table = @{}
    try {
        $entries = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in @($entries)) {
            if ($entry.sha256) {
                $table[[string]$entry.sha256.ToUpperInvariant()] = [string]$entry.name
            }
        }
    } catch {
        # A malformed optional rules file should not stop the scan.
    }
    return $table
}

function Test-VoidGuardFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [hashtable]$KnownBadHashes
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        return $null
    }

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $extension = $item.Extension.ToLowerInvariant()
    $activeExtensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk')
    $executableExtensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.msi')
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
            'NotSigned' {
                $score += 14
                $reasons.Add('Executable is not digitally signed.')
            }
            'HashMismatch' {
                $score += 40
                $reasons.Add('Authenticode hash mismatch detected.')
            }
            'NotTrusted' {
                $score += 24
                $reasons.Add('Digital signature is not trusted.')
            }
        }
    }

    if ($scriptExtensions -contains $extension) {
        try {
            $sample = Get-Content -LiteralPath $item.FullName -Raw -ErrorAction Stop
            $patterns = @(
                @{ Pattern = 'FromBase64String'; Score = 12; Reason = 'Base64 decoding behavior detected.' },
                @{ Pattern = 'Invoke-Expression|\bIEX\b'; Score = 18; Reason = 'Dynamic PowerShell execution pattern detected.' },
                @{ Pattern = 'DownloadString|Net\.WebClient|Invoke-WebRequest'; Score = 14; Reason = 'Network download behavior detected.' },
                @{ Pattern = 'EncodedCommand|-enc\s'; Score = 18; Reason = 'Encoded command execution pattern detected.' },
                @{ Pattern = 'Add-MpPreference|Set-MpPreference'; Score = 25; Reason = 'Microsoft Defender configuration modification detected.' }
            )
            foreach ($rule in $patterns) {
                if ($sample -match $rule.Pattern) {
                    $score += $rule.Score
                    $reasons.Add($rule.Reason)
                }
            }
        } catch {
            # Binary, locked, or inaccessible content is handled by metadata-only checks.
        }
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
        Path            = $item.FullName
        Name            = $item.Name
        Extension       = $extension
        Size            = [long]$item.Length
        ModifiedUtc     = $item.LastWriteTimeUtc
        SHA256          = $hash
        SignatureStatus = $signature.Status
        Publisher       = $signature.Subject
        Score           = [int]$score
        Risk            = Get-VoidGuardRiskLevel -Score $score
        Reasons         = @($reasons)
    }
}

function Get-VoidGuardScanCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [int]$MaxFiles = 2500
    )

    $extensions = @('.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk')
    $seen = @{}
    $files = New-Object System.Collections.Generic.List[object]

    foreach ($scanPath in $Paths) {
        if ([string]::IsNullOrWhiteSpace($scanPath) -or -not (Test-Path -LiteralPath $scanPath)) {
            continue
        }

        $target = Get-Item -LiteralPath $scanPath -Force -ErrorAction SilentlyContinue
        if (-not $target) { continue }

        if (-not $target.PSIsContainer) {
            if (-not $seen.ContainsKey($target.FullName)) {
                $files.Add($target)
                $seen[$target.FullName] = $true
            }
            continue
        }

        Get-ChildItem -LiteralPath $target.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } |
            ForEach-Object {
                if ($files.Count -ge $MaxFiles) { return }
                if (-not $seen.ContainsKey($_.FullName)) {
                    $files.Add($_)
                    $seen[$_.FullName] = $true
                }
            }

        if ($files.Count -ge $MaxFiles) { break }
    }

    return @($files)
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
    $findings = New-Object System.Collections.Generic.List[object]
    $count = $candidates.Count

    for ($index = 0; $index -lt $count; $index++) {
        $candidate = $candidates[$index]
        if ($ShowProgress) {
            $percent = if ($count -eq 0) { 100 } else { [int](($index / [double]$count) * 100) }
            Write-Progress -Activity 'VoidGuard file analysis' -Status $candidate.FullName -PercentComplete $percent
        }

        try {
            $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $Context -KnownBadHashes $knownBad
            if ($finding -and $finding.Score -ge [int]$Context.Settings.minimumFindingScore) {
                $findings.Add($finding)
            }
        } catch {
            # Individual file failures must not terminate the whole scan.
        }
    }

    if ($ShowProgress) {
        Write-Progress -Activity 'VoidGuard file analysis' -Completed
    }

    $completed = Get-Date
    return [pscustomobject]@{
        Version      = $Context.Version
        Mode         = 'Custom'
        Paths        = @($resolved)
        StartedUtc   = $started.ToUniversalTime()
        CompletedUtc = $completed.ToUniversalTime()
        Duration     = ($completed - $started).ToString()
        FilesScanned = $count
        Findings     = @($findings | Sort-Object Score -Descending)
    }
}

function Invoke-VoidGuardQuickScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [switch]$ShowProgress
    )

    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @(
        $env:TEMP,
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        $env:APPDATA,
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            $paths.Add($candidate)
        }
    }

    $started = Get-Date
    $maxFiles = [int]$Context.Settings.maxFilesPerScan
    $candidates = Get-VoidGuardScanCandidates -Paths @($paths) -MaxFiles $maxFiles
    $knownBad = Get-VoidGuardKnownBadHashes -RootPath $Context.RootPath
    $findings = New-Object System.Collections.Generic.List[object]

    for ($index = 0; $index -lt $candidates.Count; $index++) {
        $candidate = $candidates[$index]
        if ($ShowProgress) {
            $percent = if ($candidates.Count -eq 0) { 100 } else { [int](($index / [double]$candidates.Count) * 100) }
            Write-Progress -Activity 'VoidGuard quick scan' -Status $candidate.FullName -PercentComplete $percent
        }
        try {
            $finding = Test-VoidGuardFile -Path $candidate.FullName -Context $Context -KnownBadHashes $knownBad
            if ($finding -and $finding.Score -ge [int]$Context.Settings.minimumFindingScore) {
                $findings.Add($finding)
            }
        } catch {
        }
    }

    if ($ShowProgress) {
        Write-Progress -Activity 'VoidGuard quick scan' -Completed
    }

    $completed = Get-Date
    return [pscustomobject]@{
        Version      = $Context.Version
        Mode         = 'Quick'
        Paths        = @($paths)
        StartedUtc   = $started.ToUniversalTime()
        CompletedUtc = $completed.ToUniversalTime()
        Duration     = ($completed - $started).ToString()
        FilesScanned = $candidates.Count
        Findings     = @($findings | Sort-Object Score -Descending)
    }
}

Export-ModuleMember -Function @(
    'Get-VoidGuardRiskLevel',
    'Test-VoidGuardFile',
    'Invoke-VoidGuardPathScan',
    'Invoke-VoidGuardQuickScan'
)
