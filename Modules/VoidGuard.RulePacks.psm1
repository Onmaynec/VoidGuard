Set-StrictMode -Version Latest

function Get-VoidGuardRuleSetting {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Name,
        $DefaultValue
    )

    $property = $Settings.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $DefaultValue
}

function Get-VoidGuardTrustedPublishers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RootPath)

    $path = Join-Path $RootPath 'Rules\trusted-publishers.json'
    $table = @{}
    if (-not (Test-Path -LiteralPath $path)) { return $table }

    try {
        $entries = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in @($entries)) {
            if ($entry.keyId -and $entry.rsaXml) {
                $table[[string]$entry.keyId] = $entry
            }
        }
    } catch {
    }
    return $table
}

function ConvertTo-VoidGuardRulePackPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Manifest)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("schemaVersion=$([int]$Manifest.schemaVersion)")
    $lines.Add("id=$([string]$Manifest.id)")
    $lines.Add("name=$([string]$Manifest.name)")
    $lines.Add("version=$([string]$Manifest.version)")
    $lines.Add("publisher=$([string]$Manifest.publisher)")
    $lines.Add("trustMode=$([string]$Manifest.trustMode)")
    $lines.Add("minimumVoidGuardVersion=$([string]$Manifest.minimumVoidGuardVersion)")

    foreach ($file in @($Manifest.files | Sort-Object path)) {
        $lines.Add("file=$([string]$file.path)|$([string]$file.sha256)|$([string]$file.type)")
    }
    return ($lines -join "`n")
}

function Test-VoidGuardRulePack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PackPath,
        [Parameter(Mandatory)]$Context
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $verifiedFiles = New-Object System.Collections.Generic.List[object]
    $manifest = $null
    $canonicalPack = $null

    try {
        $canonicalPack = (Get-Item -LiteralPath $PackPath -Force -ErrorAction Stop).FullName
        $manifestPath = Join-Path $canonicalPack 'manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    } catch {
        $errors.Add("Manifest cannot be loaded: $($_.Exception.Message)")
    }

    if ($manifest) {
        if ([int]$manifest.schemaVersion -ne 1) { $errors.Add('Unsupported rule-pack schema version.') }
        if ([string]$manifest.id -notmatch '^[a-z0-9][a-z0-9._-]{2,79}$') { $errors.Add('Invalid rule-pack id.') }
        try { $null = [version]([string]$manifest.version) } catch { $errors.Add('Invalid rule-pack version.') }

        $trustMode = [string]$manifest.trustMode
        if ($trustMode -notin @('bundled', 'signed', 'local')) { $errors.Add('Invalid trustMode.') }

        $packRoot = [IO.Path]::GetFullPath($canonicalPack).TrimEnd('\') + '\'
        foreach ($entry in @($manifest.files)) {
            $relative = [string]$entry.path
            if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
                $errors.Add("Unsafe rule-pack file path: $relative")
                continue
            }

            try {
                $fullPath = [IO.Path]::GetFullPath((Join-Path $canonicalPack $relative))
                if (-not $fullPath.StartsWith($packRoot, [StringComparison]::OrdinalIgnoreCase)) {
                    $errors.Add("Rule-pack file escapes pack root: $relative")
                    continue
                }
                if ([IO.Path]::GetExtension($fullPath).ToLowerInvariant() -notin @('.json', '.yar', '.yara')) {
                    $errors.Add("Unsupported rule-pack file type: $relative")
                    continue
                }
                if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                    $errors.Add("Rule-pack file is missing: $relative")
                    continue
                }

                $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
                $expectedHash = ([string]$entry.sha256).ToUpperInvariant()
                if ($actualHash -ne $expectedHash) {
                    $errors.Add("SHA-256 mismatch: $relative")
                    continue
                }
                $verifiedFiles.Add([pscustomobject]@{
                    Path = $fullPath
                    RelativePath = $relative
                    Type = [string]$entry.type
                    SHA256 = $actualHash
                })
            } catch {
                $errors.Add("Rule-pack file validation failed for ${relative}: $($_.Exception.Message)")
            }
        }
    }

    $signatureValid = $false
    $trustReason = 'Untrusted'
    if ($manifest -and $errors.Count -eq 0) {
        switch ([string]$manifest.trustMode) {
            'bundled' {
                $expectedRoot = [IO.Path]::GetFullPath((Join-Path $Context.RootPath 'Rules\Packs')).TrimEnd('\') + '\'
                if ($canonicalPack.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
                    $signatureValid = $true
                    $trustReason = 'Bundled release pack with verified file hashes.'
                } else {
                    $errors.Add('Bundled trustMode is allowed only inside the application Rules\Packs directory.')
                }
            }
            'signed' {
                try {
                    if (-not $manifest.signature -or -not $manifest.signature.keyId -or -not $manifest.signature.value) {
                        throw 'Detached signature metadata is missing.'
                    }
                    $publishers = Get-VoidGuardTrustedPublishers -RootPath $Context.RootPath
                    $keyId = [string]$manifest.signature.keyId
                    if (-not $publishers.ContainsKey($keyId)) { throw "Publisher key is not trusted: $keyId" }
                    if ([string]$manifest.signature.algorithm -ne 'RSA-SHA256') { throw 'Unsupported signature algorithm.' }

                    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
                    try {
                        $rsa.FromXmlString([string]$publishers[$keyId].rsaXml)
                        $payload = ConvertTo-VoidGuardRulePackPayload -Manifest $manifest
                        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
                        $signature = [Convert]::FromBase64String([string]$manifest.signature.value)
                        $oid = [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')
                        $signatureValid = $rsa.VerifyData($bytes, $oid, $signature)
                    } finally {
                        $rsa.Dispose()
                    }
                    if (-not $signatureValid) { throw 'RSA signature verification failed.' }
                    $trustReason = "Signed by trusted key $keyId."
                } catch {
                    $errors.Add($_.Exception.Message)
                }
            }
            'local' {
                $allowLocal = [bool](Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'allowUnsignedLocalRulePacks' -DefaultValue $false)
                if ($allowLocal) {
                    $signatureValid = $true
                    $trustReason = 'Unsigned local pack allowed by explicit configuration.'
                    $warnings.Add('Unsigned local rule packs can change detection behavior.')
                } else {
                    $errors.Add('Unsigned local rule packs are disabled.')
                }
            }
        }
    }

    $enabledIds = @((Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'enabledRulePacks' -DefaultValue @()))
    $enabled = $manifest -and ($enabledIds.Count -eq 0 -or $enabledIds -contains [string]$manifest.id)

    return [pscustomobject]@{
        Id = if ($manifest) { [string]$manifest.id } else { Split-Path -Leaf $PackPath }
        Name = if ($manifest) { [string]$manifest.name } else { $null }
        Version = if ($manifest) { [string]$manifest.version } else { $null }
        Publisher = if ($manifest) { [string]$manifest.publisher } else { $null }
        PackPath = $canonicalPack
        Enabled = [bool]$enabled
        IntegrityValid = ($errors.Count -eq 0)
        Trusted = ($errors.Count -eq 0 -and $signatureValid)
        TrustReason = $trustReason
        Errors = @($errors)
        Warnings = @($warnings)
        Files = @($verifiedFiles)
        Manifest = $manifest
    }
}

function Get-VoidGuardRulePackInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $root = Join-Path $Context.RootPath 'Rules\Packs'
    if (-not (Test-Path -LiteralPath $root)) { return @() }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($directory in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
        $items.Add((Test-VoidGuardRulePack -PackPath $directory.FullName -Context $Context))
    }
    return @($items | Sort-Object Id)
}

function Get-VoidGuardRuleEngineState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $inventory = @(Get-VoidGuardRulePackInventory -Context $Context)
    $patterns = New-Object System.Collections.Generic.List[object]
    $yaraFiles = New-Object System.Collections.Generic.List[string]

    foreach ($pack in @($inventory | Where-Object { $_.Enabled -and $_.Trusted -and $_.IntegrityValid })) {
        foreach ($file in @($pack.Files)) {
            switch ($file.Type) {
                'pattern' {
                    try {
                        $rules = Get-Content -LiteralPath $file.Path -Raw -Encoding UTF8 | ConvertFrom-Json
                        foreach ($rule in @($rules)) {
                            $regex = New-Object Text.RegularExpressions.Regex(
                                [string]$rule.pattern,
                                [Text.RegularExpressions.RegexOptions]::CultureInvariant,
                                [TimeSpan]::FromMilliseconds(300)
                            )
                            $patterns.Add([pscustomobject]@{
                                PackId = $pack.Id
                                Id = [string]$rule.id
                                Extensions = @($rule.extensions | ForEach-Object { ([string]$_).ToLowerInvariant() })
                                Regex = $regex
                                Score = [int]$rule.score
                                Reason = [string]$rule.reason
                                MaxBytes = if ($rule.maxBytes) { [int]$rule.maxBytes } else { 1048576 }
                            })
                        }
                    } catch {
                    }
                }
                'yara' { $yaraFiles.Add([string]$file.Path) }
            }
        }
    }

    return [pscustomobject]@{
        Inventory = $inventory
        Patterns = @($patterns)
        YaraRuleFiles = @($yaraFiles)
        Yara = Get-VoidGuardYaraStatus -Context $Context
    }
}

function Get-VoidGuardYaraExecutable {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $configured = [string](Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'yaraExecutable' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        $expanded = [Environment]::ExpandEnvironmentVariables($configured)
        if (Test-Path -LiteralPath $expanded -PathType Leaf) { return (Get-Item -LiteralPath $expanded).FullName }
    }

    foreach ($name in @('yara64.exe', 'yara.exe', 'yara64', 'yara')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { return [string]$command.Source }
    }
    return $null
}

function Invoke-VoidGuardYaraProcess {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Arguments,
        [int]$TimeoutSeconds = 15
    )

    $process = New-Object Diagnostics.Process
    $process.StartInfo = New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = $Executable
    $process.StartInfo.Arguments = $Arguments
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true

    try {
        if (-not $process.Start()) { throw 'YARA process did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
            try { $process.Kill() } catch { }
            return [pscustomobject]@{ Success = $false; TimedOut = $true; ExitCode = $null; Output = ''; Error = 'YARA timeout.' }
        }
        return [pscustomobject]@{
            Success = ($process.ExitCode -in @(0, 1))
            TimedOut = $false
            ExitCode = $process.ExitCode
            Output = $stdoutTask.Result
            Error = $stderrTask.Result
        }
    } catch {
        return [pscustomobject]@{ Success = $false; TimedOut = $false; ExitCode = $null; Output = ''; Error = $_.Exception.Message }
    } finally {
        $process.Dispose()
    }
}

function Get-VoidGuardYaraStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $executable = Get-VoidGuardYaraExecutable -Context $Context
    if (-not $executable) {
        return [pscustomobject]@{ Available = $false; Executable = $null; Version = $null; Error = 'YARA CLI not found.' }
    }

    $result = Invoke-VoidGuardYaraProcess -Executable $executable -Arguments '--version' -TimeoutSeconds 5
    return [pscustomobject]@{
        Available = [bool]$result.Success
        Executable = $executable
        Version = if ($result.Success) { ([string]$result.Output).Trim() } else { $null }
        Error = if ($result.Success) { $null } else { [string]$result.Error }
    }
}

function Invoke-VoidGuardYaraScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [string[]]$RuleFiles
    )

    $canonical = Get-VoidGuardCanonicalPath -Path $Path
    $status = Get-VoidGuardYaraStatus -Context $Context
    $matches = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    if (-not $status.Available) {
        return [pscustomobject]@{ Available = $false; Executable = $status.Executable; Matches = @(); Errors = @($status.Error); TimedOut = $false }
    }

    $timeout = [int](Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'yaraTimeoutSeconds' -DefaultValue 15)
    $timedOut = $false
    foreach ($ruleFile in @($RuleFiles)) {
        if (-not (Test-Path -LiteralPath $ruleFile -PathType Leaf)) { continue }
        $safeRule = $ruleFile.Replace('"', '')
        $safeTarget = $canonical.Replace('"', '')
        $arguments = '-w "{0}" "{1}"' -f $safeRule, $safeTarget
        $result = Invoke-VoidGuardYaraProcess -Executable $status.Executable -Arguments $arguments -TimeoutSeconds $timeout
        if ($result.TimedOut) { $timedOut = $true }
        if (-not $result.Success) {
            if ($result.Error) { $errors.Add([string]$result.Error) }
            continue
        }

        foreach ($line in @(([string]$result.Output) -split "`r?`n")) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            $parts = $trimmed -split '\s+', 2
            $matches.Add([pscustomobject]@{
                Rule = $parts[0]
                RuleFile = $ruleFile
                Output = $trimmed
            })
        }
    }

    return [pscustomobject]@{
        Available = $true
        Executable = $status.Executable
        Matches = @($matches | Sort-Object Rule -Unique)
        Errors = @($errors)
        TimedOut = $timedOut
    }
}

Export-ModuleMember -Function @(
    'Test-VoidGuardRulePack',
    'Get-VoidGuardRulePackInventory',
    'Get-VoidGuardRuleEngineState',
    'Get-VoidGuardYaraStatus',
    'Invoke-VoidGuardYaraScan'
)
