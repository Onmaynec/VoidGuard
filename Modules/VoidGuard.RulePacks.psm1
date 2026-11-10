Set-StrictMode -Version Latest

function Get-VoidGuardPropertyValue {
    param(
        $InputObject,
        [Parameter(Mandatory)][string]$Name,
        $DefaultValue = $null
    )

    if ($null -eq $InputObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $DefaultValue
}

function Get-VoidGuardRuleSetting {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Name,
        $DefaultValue
    )
    return Get-VoidGuardPropertyValue -InputObject $Settings -Name $Name -DefaultValue $DefaultValue
}

function Get-VoidGuardTrustedPublishers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RootPath)

    $path = Join-Path $RootPath 'Rules\trusted-publishers.json'
    $table = @{}
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $table }

    try {
        $entries = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in @($entries)) {
            $keyId = [string](Get-VoidGuardPropertyValue $entry 'keyId' '')
            $rsaXml = [string](Get-VoidGuardPropertyValue $entry 'rsaXml' '')
            if (-not [string]::IsNullOrWhiteSpace($keyId) -and -not [string]::IsNullOrWhiteSpace($rsaXml)) {
                $table[$keyId] = $entry
            }
        }
    } catch {
    }
    return $table
}

function ConvertTo-VoidGuardRulePackPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Manifest)

    $lines = @(
        "schemaVersion=$([int](Get-VoidGuardPropertyValue $Manifest 'schemaVersion' 0))",
        "id=$([string](Get-VoidGuardPropertyValue $Manifest 'id' ''))",
        "name=$([string](Get-VoidGuardPropertyValue $Manifest 'name' ''))",
        "version=$([string](Get-VoidGuardPropertyValue $Manifest 'version' ''))",
        "publisher=$([string](Get-VoidGuardPropertyValue $Manifest 'publisher' ''))",
        "trustMode=$([string](Get-VoidGuardPropertyValue $Manifest 'trustMode' ''))",
        "minimumVoidGuardVersion=$([string](Get-VoidGuardPropertyValue $Manifest 'minimumVoidGuardVersion' ''))"
    )

    $manifestFiles = @(Get-VoidGuardPropertyValue $Manifest 'files' @())
    foreach ($file in @($manifestFiles | Sort-Object { [string](Get-VoidGuardPropertyValue $_ 'path' '') })) {
        $path = [string](Get-VoidGuardPropertyValue $file 'path' '')
        $hash = [string](Get-VoidGuardPropertyValue $file 'sha256' '')
        $type = [string](Get-VoidGuardPropertyValue $file 'type' '')
        $lines += "file=$path|$hash|$type"
    }
    return ($lines -join "`n")
}

function Import-VoidGuardRsaPublicKey {
    param(
        [Parameter(Mandatory)][Security.Cryptography.RSA]$Rsa,
        [Parameter(Mandatory)][string]$RsaXml
    )

    [xml]$document = $RsaXml
    $root = $document.RSAKeyValue
    if (-not $root -or -not $root.Modulus -or -not $root.Exponent) {
        throw 'Trusted RSA key XML is invalid.'
    }
    $parameters = New-Object Security.Cryptography.RSAParameters
    $parameters.Modulus = [Convert]::FromBase64String([string]$root.Modulus)
    $parameters.Exponent = [Convert]::FromBase64String([string]$root.Exponent)
    if ($null -eq $parameters.Modulus -or $parameters.Modulus.Length -lt 256) {
        throw 'RSA rule-pack trust key must contain at least 2048 bits.'
    }
    $Rsa.ImportParameters($parameters)
}

function Assert-VoidGuardBundledPackIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$CanonicalPack,
        [Parameter(Mandatory)]$Context
    )

    # Изменение этого каталога требует отдельного обновления доверенного набора в коде.
    # Manifest сам по себе не может выдавать произвольному пакету статус bundled.
    $pinned = @{
        'detections.json' = @{ Hash = '274C32D1A8A952000F70E58FC92017EE691755D2706C3B6EEC910AD69C454478'; Type = 'pattern' }
        'core.yar' = @{ Hash = 'CCCF10365CA77BDFC4F9CD81C310C5FF27F26C7204916AF83FEBEE859701A394'; Type = 'yara' }
    }
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $Context.RootPath 'Rules\Packs\core')).TrimEnd('\')
    if (-not [string]::Equals([IO.Path]::GetFullPath($CanonicalPack).TrimEnd('\'), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unknown bundled pack: only the pinned core directory is accepted.'
    }
    if ([string](Get-VoidGuardPropertyValue $Manifest 'id' '') -cne 'voidguard.core' -or
        [string](Get-VoidGuardPropertyValue $Manifest 'name' '') -cne 'VoidGuard Core Defensive Rules' -or
        [string](Get-VoidGuardPropertyValue $Manifest 'version' '') -cne '1.0.0' -or
        [string](Get-VoidGuardPropertyValue $Manifest 'publisher' '') -cne 'VoidGuard Project' -or
        [string](Get-VoidGuardPropertyValue $Manifest 'minimumVoidGuardVersion' '') -cne '0.3.0' -or
        [string](Get-VoidGuardPropertyValue $Manifest 'trustMode' '') -cne 'bundled') {
        throw 'Bundled core metadata differs from the pinned release identity.'
    }
    if ($null -ne (Get-VoidGuardPropertyValue $Manifest 'signature' $null)) {
        throw 'Bundled core must not contain an external signature.'
    }
    $entries = @(Get-VoidGuardPropertyValue $Manifest 'files' @())
    if ($entries.Count -ne $pinned.Count) { throw 'Bundled core file inventory differs from the trusted inventory.' }
    $seen = @{}
    foreach ($entry in $entries) {
        $path = [string](Get-VoidGuardPropertyValue $entry 'path' '')
        if ($seen.ContainsKey($path) -or -not $pinned.ContainsKey($path)) {
            throw "Unexpected or duplicate bundled rule file: $path"
        }
        $seen[$path] = $true
        $hash = [string](Get-VoidGuardPropertyValue $entry 'sha256' '')
        $type = [string](Get-VoidGuardPropertyValue $entry 'type' '')
        if ($hash -cne $pinned[$path].Hash -or $type -cne $pinned[$path].Type) {
            throw "Bundled core file is not pinned: $path"
        }
    }
}

function Test-VoidGuardRulePack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PackPath,
        [Parameter(Mandatory)]$Context
    )

    $errors = @()
    $warnings = @()
    $verifiedFiles = @()
    $manifest = $null
    $canonicalPack = $null

    try {
        $packItem = Get-Item -LiteralPath $PackPath -Force -ErrorAction Stop
        if (-not $packItem.PSIsContainer) { throw 'Rule-pack path is not a directory.' }
        $canonicalPack = $packItem.FullName
        if (Get-VoidGuardPathReparseAncestor -Path $canonicalPack) {
            throw 'Rule-pack directory contains a reparse point.'
        }
        $manifestPath = Join-Path $canonicalPack 'manifest.json'
        if (Get-VoidGuardPathReparseAncestor -Path $manifestPath) {
            throw 'Rule-pack manifest contains a reparse point.'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    } catch {
        $errors += "Manifest cannot be loaded: $($_.Exception.Message)"
    }

    $packId = if ($manifest) { [string](Get-VoidGuardPropertyValue $manifest 'id' '') } else { Split-Path -Leaf $PackPath }
    $packName = if ($manifest) { [string](Get-VoidGuardPropertyValue $manifest 'name' '') } else { $null }
    $packVersion = if ($manifest) { [string](Get-VoidGuardPropertyValue $manifest 'version' '') } else { $null }
    $publisher = if ($manifest) { [string](Get-VoidGuardPropertyValue $manifest 'publisher' '') } else { $null }
    $trustMode = if ($manifest) { [string](Get-VoidGuardPropertyValue $manifest 'trustMode' '') } else { '' }

    if ($manifest) {
        if ([int](Get-VoidGuardPropertyValue $manifest 'schemaVersion' 0) -ne 1) { $errors += 'Unsupported rule-pack schema version.' }
        if ($packId -notmatch '^[a-z0-9][a-z0-9._-]{2,79}$') { $errors += 'Invalid rule-pack id.' }
        try { $null = [version]$packVersion } catch { $errors += 'Invalid rule-pack version.' }
        if ($trustMode -notin @('bundled', 'signed', 'local')) { $errors += 'Invalid trustMode.' }

        $minimum = [string](Get-VoidGuardPropertyValue $manifest 'minimumVoidGuardVersion' '0.0.0')
        try {
            if ([version]$Context.Version -lt [version]$minimum) {
                $errors += "Rule pack requires VoidGuard $minimum or newer."
            }
        } catch {
            $errors += 'Invalid minimumVoidGuardVersion.'
        }

        $packRoot = [IO.Path]::GetFullPath($canonicalPack).TrimEnd('\') + '\'
        $manifestFiles = @(Get-VoidGuardPropertyValue $manifest 'files' @())
        if ($manifestFiles.Count -eq 0) { $errors += 'Rule pack contains no files.' }

        foreach ($entry in $manifestFiles) {
            $relative = [string](Get-VoidGuardPropertyValue $entry 'path' '')
            $expectedHash = ([string](Get-VoidGuardPropertyValue $entry 'sha256' '')).ToUpperInvariant()
            $fileType = [string](Get-VoidGuardPropertyValue $entry 'type' '')

            if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
                $errors += "Unsafe rule-pack file path: $relative"
                continue
            }
            if ($expectedHash -notmatch '^[A-F0-9]{64}$') {
                $errors += "Invalid SHA-256 in manifest: $relative"
                continue
            }
            if ($fileType -notin @('pattern', 'yara')) {
                $errors += "Unsupported rule-pack file role: $relative"
                continue
            }

            try {
                $fullPath = [IO.Path]::GetFullPath((Join-Path $canonicalPack $relative))
                if (-not $fullPath.StartsWith($packRoot, [StringComparison]::OrdinalIgnoreCase)) {
                    $errors += "Rule-pack file escapes pack root: $relative"
                    continue
                }
                if ([IO.Path]::GetExtension($fullPath).ToLowerInvariant() -notin @('.json', '.yar', '.yara')) {
                    $errors += "Unsupported rule-pack file extension: $relative"
                    continue
                }
                if (Get-VoidGuardPathReparseAncestor -Path $fullPath) {
                    $errors += "Rule-pack file contains a reparse point: $relative"
                    continue
                }
                if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                    $errors += "Rule-pack file is missing: $relative"
                    continue
                }

                $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
                if ($actualHash -ne $expectedHash) {
                    $errors += "SHA-256 mismatch: $relative"
                    continue
                }
                $verifiedFiles += [pscustomobject]@{
                    Path = $fullPath
                    RelativePath = $relative
                    Type = $fileType
                    SHA256 = $actualHash
                }
            } catch {
                $errors += "Rule-pack file validation failed for ${relative}: $($_.Exception.Message)"
            }
        }
    }

    $trusted = $false
    $trustReason = 'Untrusted'
    if ($manifest -and $errors.Count -eq 0) {
        switch ($trustMode) {
            'bundled' {
                try {
                    Assert-VoidGuardBundledPackIdentity -Manifest $manifest -CanonicalPack $canonicalPack -Context $Context
                    $trusted = $true
                    $trustReason = 'Bundled core pinned to the release code and verified file hashes.'
                } catch {
                    $errors += $_.Exception.Message
                }
            }
            'signed' {
                try {
                    $signatureObject = Get-VoidGuardPropertyValue $manifest 'signature' $null
                    $keyId = [string](Get-VoidGuardPropertyValue $signatureObject 'keyId' '')
                    $algorithm = [string](Get-VoidGuardPropertyValue $signatureObject 'algorithm' '')
                    $signatureValue = [string](Get-VoidGuardPropertyValue $signatureObject 'value' '')
                    if ([string]::IsNullOrWhiteSpace($keyId) -or [string]::IsNullOrWhiteSpace($signatureValue)) {
                        throw 'Detached signature metadata is missing.'
                    }
                    if ($algorithm -ne 'RSA-SHA256') { throw 'Unsupported signature algorithm.' }

                    $publishers = Get-VoidGuardTrustedPublishers -RootPath $Context.RootPath
                    if (-not $publishers.ContainsKey($keyId)) { throw "Publisher key is not trusted: $keyId" }
                    $rsaXml = [string](Get-VoidGuardPropertyValue $publishers[$keyId] 'rsaXml' '')
                    $rsa = [Security.Cryptography.RSA]::Create()
                    try {
                        Import-VoidGuardRsaPublicKey -Rsa $rsa -RsaXml $rsaXml
                        $payload = ConvertTo-VoidGuardRulePackPayload -Manifest $manifest
                        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
                        $signature = [Convert]::FromBase64String($signatureValue)
                        $trusted = $rsa.VerifyData(
                            $bytes,
                            $signature,
                            [Security.Cryptography.HashAlgorithmName]::SHA256,
                            [Security.Cryptography.RSASignaturePadding]::Pkcs1
                        )
                    } finally {
                        $rsa.Dispose()
                    }
                    if (-not $trusted) { throw 'RSA signature verification failed.' }
                    $trustReason = "Signed by trusted key $keyId."
                } catch {
                    $errors += $_.Exception.Message
                    $trusted = $false
                }
            }
            'local' {
                $allowLocal = [bool](Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'allowUnsignedLocalRulePacks' -DefaultValue $false)
                if ($allowLocal) {
                    $trusted = $true
                    $trustReason = 'Unsigned local pack allowed by explicit configuration.'
                    $warnings += 'Unsigned local rule packs can change detection behavior.'
                } else {
                    $errors += 'Unsigned local rule packs are disabled.'
                }
            }
        }
    }

    $enabledIds = @(Get-VoidGuardRuleSetting -Settings $Context.Settings -Name 'enabledRulePacks' -DefaultValue @())
    $enabled = $manifest -and ($enabledIds.Count -eq 0 -or $enabledIds -contains $packId)

    return [pscustomobject]@{
        Id = $packId
        Name = $packName
        Version = $packVersion
        Publisher = $publisher
        PackPath = $canonicalPack
        Enabled = [bool]$enabled
        IntegrityValid = ($errors.Count -eq 0)
        Trusted = ($errors.Count -eq 0 -and $trusted)
        TrustReason = $trustReason
        Errors = $errors
        Warnings = $warnings
        Files = $verifiedFiles
        Manifest = $manifest
    }
}

function Get-VoidGuardRulePackInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $root = Join-Path $Context.RootPath 'Rules\Packs'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $items = @()
    foreach ($directory in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
        $items += Test-VoidGuardRulePack -PackPath $directory.FullName -Context $Context
    }
    return $items | Sort-Object Id
}

function Get-VoidGuardRuleEngineState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $inventory = @(Get-VoidGuardRulePackInventory -Context $Context)
    $patterns = @()
    $yaraFiles = @()

    foreach ($pack in @($inventory | Where-Object { $_.Enabled -and $_.Trusted -and $_.IntegrityValid })) {
        foreach ($file in @($pack.Files)) {
            switch ([string]$file.Type) {
                'pattern' {
                    try {
                        $rules = Get-Content -LiteralPath $file.Path -Raw -Encoding UTF8 | ConvertFrom-Json
                        foreach ($rule in @($rules)) {
                            $pattern = [string](Get-VoidGuardPropertyValue $rule 'pattern' '')
                            $regex = [regex]::new(
                                $pattern,
                                [Text.RegularExpressions.RegexOptions]::CultureInvariant,
                                [TimeSpan]::FromMilliseconds(300)
                            )
                            $extensions = @((Get-VoidGuardPropertyValue $rule 'extensions' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })
                            $patterns += [pscustomobject]@{
                                PackId = $pack.Id
                                Id = [string](Get-VoidGuardPropertyValue $rule 'id' '')
                                Extensions = $extensions
                                Regex = $regex
                                Score = [int](Get-VoidGuardPropertyValue $rule 'score' 0)
                                Reason = [string](Get-VoidGuardPropertyValue $rule 'reason' '')
                                MaxBytes = [int](Get-VoidGuardPropertyValue $rule 'maxBytes' 1048576)
                            }
                        }
                    } catch {
                    }
                }
                'yara' { $yaraFiles += [string]$file.Path }
            }
        }
    }

    return [pscustomobject]@{
        Inventory = $inventory
        Patterns = $patterns
        YaraRuleFiles = $yaraFiles
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
    $matches = @()
    $errors = @()
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
            if ($result.Error) { $errors += [string]$result.Error }
            continue
        }

        foreach ($line in @(([string]$result.Output) -split "`r?`n")) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            $parts = $trimmed -split '\s+', 2
            $matches += [pscustomobject]@{
                Rule = $parts[0]
                RuleFile = $ruleFile
                Output = $trimmed
            }
        }
    }

    return [pscustomobject]@{
        Available = $true
        Executable = $status.Executable
        Matches = @($matches | Sort-Object Rule -Unique)
        Errors = $errors
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
