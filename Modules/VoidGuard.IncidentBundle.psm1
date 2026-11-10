#requires -Version 5.1
Set-StrictMode -Version Latest

function Assert-VGIncidentDestination {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputPath)
    $full=[IO.Path]::GetFullPath($OutputPath)
    if ($full -notmatch '^[a-zA-Z]:\\' -or [IO.Path]::GetExtension($full).ToLowerInvariant() -ne '.zip') {
        throw 'Incident bundle requires a local, absolute .zip path.'
    }
    if (Get-VoidGuardPathReparseAncestor -Path $full) { throw 'Incident output path contains a reparse point.' }
    foreach ($candidate in @($env:windir,$env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if (-not $candidate) { continue }
        $protected=[IO.Path]::GetFullPath($candidate).TrimEnd('\')
        if ($full.StartsWith($protected+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Incident bundle cannot be written to a protected system directory.'
        }
    }
    return $full
}

function Get-VGIncidentDefaultPath {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is unavailable; specify -IncidentPath.' }
    $name='incident-{0}-{1}.zip' -f @((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    return Join-Path (Join-Path $env:LOCALAPPDATA 'VoidGuard\Incidents') $name
}

function Get-VGIncidentPreview {
    [CmdletBinding()]
    param(
        [string]$OutputPath,[string]$ScanPath,[string]$BaselinePath,
        [switch]$IncludeEventLogs,[switch]$IncludeSensitive
    )
    if (-not $OutputPath) { $OutputPath=Get-VGIncidentDefaultPath }
    $path=Assert-VGIncidentDestination -OutputPath $OutputPath
    $sections=New-Object 'System.Collections.Generic.List[string]'
    foreach ($value in @('Windows security summary','Rule-pack inventory','Process findings','Persistence findings','Pending remediation statuses')) {
        $sections.Add($value)
    }
    if ($ScanPath) { $sections.Add('Selected file or directory scan (bounded by maxFilesPerScan)') }
    if ($BaselinePath) { $sections.Add('System integrity baseline diff') }
    if ($IncludeEventLogs) { $sections.Add('Defender operational event metadata (100 events, last 7 days)') }
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    $warnings.Add('No files or logs are uploaded. The ZIP remains on the local computer.')
    $warnings.Add('This is a collection preview, not a completed diagnostic scan.')
    if ($IncludeSensitive) {
        $warnings.Add('Sensitive mode includes raw paths, commands, exclusion details, addresses and optional event messages.')
        $warnings.Add('Review the resulting archive before sharing it with anyone.')
    } else {
        $warnings.Add('Default export omits raw process paths, commands, user/computer name and event messages.')
    }
    return [pscustomobject]@{
        Mode='IncidentPreview';Status='READY';OutputPath=$path
        Categories=$sections.ToArray()
        IncludeEventLogs=[bool]$IncludeEventLogs
        IncludeSensitive=[bool]$IncludeSensitive
        ScanRequested= -not [string]::IsNullOrWhiteSpace($ScanPath)
        BaselineRequested= -not [string]::IsNullOrWhiteSpace($BaselinePath)
        Warnings=$warnings.ToArray()
        RequiresConfirmation=$true
    }
}

function New-VGIncidentFindingSummary {
    param($Finding,[bool]$Sensitive=$false)
    $r=[ordered]@{}
    foreach ($key in @('Score','Risk','SignatureStatus','ProcessName','Type','SHA256','Id')) {
        $property=$Finding.PSObject.Properties[$key]
        if ($property -and $null -ne $property.Value) { $r[$key]=$property.Value }
    }
    if ($Sensitive) {
        foreach ($key in @('Path','Command','CommandLine','TargetPath','Location','Name','Scope','Connections','Reasons','RuleMatches','YaraMatches','ParentId')) {
            $property=$Finding.PSObject.Properties[$key]
            if ($property) { $r[$key]=$property.Value }
        }
    }
    [pscustomobject]$r
}

function Get-VGIncidentData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,[string]$ScanPath,[string]$BaselinePath,
        [switch]$IncludeEventLogs,[switch]$IncludeSensitive
    )
    if (-not (Test-VoidGuardWindows)) { throw 'Incident Bundle is supported only on Windows.' }
    $errors=New-Object 'System.Collections.Generic.List[string]'
    $collection=[ordered]@{}
    $status=[ordered]@{}
    function Add-IncidentCollection {
        param([string]$Name,$Value)
        $collection[$Name]=$Value
        $status[$Name]='COMPLETE'
    }
    function Add-IncidentFailure {
        param([string]$Name,[string]$Problem)
        $status[$Name]='PARTIAL'
        $errors.Add($(if ($IncludeSensitive) { "$Name : $Problem" } else { "$Name : collection unavailable or incomplete" }))
    }

    try {
        $s=Get-VoidGuardSecurityStatus
        $security=[ordered]@{
            DefenderAvailable=$s.DefenderAvailable
            DefenderEnabled=$s.DefenderEnabled
            RealTimeProtection=$s.RealTimeProtection
            FirewallAvailable=$s.FirewallAvailable
            FirewallProfiles=@($s.FirewallProfiles | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
            UacEnabled=$s.UacEnabled
            SmartScreenEnabled=$s.SmartScreenEnabled
            DefenderExclusionCount=@($s.DefenderExclusions).Count
        }
        if ($IncludeSensitive) { $security.DefenderExclusions=@($s.DefenderExclusions) }
        Add-IncidentCollection 'Security' ([pscustomobject]$security)
    } catch { Add-IncidentFailure 'Security' $_.Exception.Message }

    try {
        $packs=@(Get-VoidGuardRulePackInventory -Context $Context)
        $records=@($packs | ForEach-Object {
            [pscustomobject]@{
                Id=$_.Id;Version=$_.Version;Publisher=$_.Publisher
                Trusted=$_.Trusted;Enabled=$_.Enabled;IntegrityValid=$_.IntegrityValid
            }
        })
        Add-IncidentCollection 'RulePacks' $records
    } catch { Add-IncidentFailure 'RulePacks' $_.Exception.Message }

    try {
        $processes=@(Get-VoidGuardProcessFindings -Context $Context)
        $items=@($processes | Select-Object -First 100 | ForEach-Object { New-VGIncidentFindingSummary -Finding $_ -Sensitive:$IncludeSensitive })
        Add-IncidentCollection 'Processes' ([pscustomobject]@{Total=$processes.Count;Included=$items.Count;Findings=$items})
        if ($processes.Count -gt 100) { Add-IncidentFailure 'Processes' 'Only the first 100 process findings were included.' }
    } catch { Add-IncidentFailure 'Processes' $_.Exception.Message }

    try {
        $persistence=@(Get-VoidGuardPersistenceFindings -Context $Context)
        $items=@($persistence | Select-Object -First 100 | ForEach-Object { New-VGIncidentFindingSummary -Finding $_ -Sensitive:$IncludeSensitive })
        Add-IncidentCollection 'Persistence' ([pscustomobject]@{Total=$persistence.Count;Included=$items.Count;Findings=$items})
        if ($persistence.Count -gt 100) { Add-IncidentFailure 'Persistence' 'Only the first 100 persistence findings were included.' }
    } catch { Add-IncidentFailure 'Persistence' $_.Exception.Message }

    try {
        # Read-only: -Verify would modify the pending ledger.
        $pending=@(Get-VoidGuardPendingRemediations)
        $entries=@($pending | Select-Object -First 100 | ForEach-Object {
            $item=[ordered]@{Status=$_.Status}
            if ($IncludeSensitive) {
                foreach ($field in @('Id','Path','SHA256','VerificationReason')) {
                    $prop=$_.PSObject.Properties[$field]
                    if ($prop) { $item[$field]=$prop.Value }
                }
            }
            [pscustomobject]$item
        })
        Add-IncidentCollection 'Pending' ([pscustomobject]@{Total=$pending.Count;Included=$entries.Count;Records=$entries})
        if ($pending.Count -gt 100) { Add-IncidentFailure 'Pending' 'Only first 100 records included.' }
    } catch { Add-IncidentFailure 'Pending' $_.Exception.Message }

    if ($ScanPath) {
        try {
            $canonical=[IO.Path]::GetFullPath($ScanPath)
            if ($canonical -notmatch '^[a-zA-Z]:\\' -or (Get-VoidGuardPathReparseAncestor -Path $canonical)) {
                throw 'Only local scan paths without reparse points are allowed.'
            }
            $scan=Invoke-VoidGuardPathScan -Path $canonical -Context $Context
            $entries=@($scan.Findings | Select-Object -First 100 | ForEach-Object { New-VGIncidentFindingSummary -Finding $_ -Sensitive:$IncludeSensitive })
            Add-IncidentCollection 'Scan' ([pscustomobject]@{
                Status=$scan.ScanStatus;Complete=$scan.Complete
                FilesDiscovered=$scan.FilesDiscovered;FilesScanned=$scan.FilesScanned
                FilesSkipped=$scan.FilesSkipped;FilesFailed=$scan.FilesFailed
                Included=$entries.Count;Findings=$entries
            })
            if (-not $scan.Complete -or @($scan.Findings).Count -gt 100) { Add-IncidentFailure 'Scan' 'Incomplete scan or findings truncated.' }
        } catch { Add-IncidentFailure 'Scan' $_.Exception.Message }
    }

    if ($BaselinePath) {
        try {
            $diff=Compare-VGIntegrityBaseline -BaselinePath $BaselinePath
            $data=[ordered]@{
                Status=$diff.Status;Complete=$diff.Complete
                Added=$diff.Added;Removed=$diff.Removed;Changed=$diff.Changed
                ChangesCount=$diff.ChangesCount
            }
            if ($IncludeSensitive) {
                $data.Changes=@($diff.Changes | Select-Object -First 100)
            }
            Add-IncidentCollection 'BaselineDiff' ([pscustomobject]$data)
            if (-not $diff.Complete -or ($IncludeSensitive -and @($diff.Changes).Count -gt 100)) {
                Add-IncidentFailure 'BaselineDiff' 'Incomplete or truncated baseline comparison.'
            }
        } catch { Add-IncidentFailure 'BaselineDiff' $_.Exception.Message }
    }

    if ($IncludeEventLogs) {
        try {
            $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction Stop)
            $entries=@($events | ForEach-Object {
                $ev=[ordered]@{Id=$_.Id;Level=[string]$_.LevelDisplayName;TimeUtc=$_.TimeCreated.ToUniversalTime().ToString('o')}
                if ($IncludeSensitive) { $ev.Message=[string]$_.Message }
                [pscustomobject]$ev
            })
            Add-IncidentCollection 'DefenderEvents' $entries
        } catch { Add-IncidentFailure 'DefenderEvents' $_.Exception.Message }
    }

    return [pscustomobject]@{
        SchemaVersion=1;Kind='VoidGuard.IncidentBundle'
        CreatedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Version=[string]$Context.Version
        ComputerName=if ($IncludeSensitive) { [string]$env:COMPUTERNAME } else { '[REDACTED]' }
        ContainsSensitiveData=[bool]$IncludeSensitive
        Status=if ($errors.Count) { 'PARTIAL' } else { 'COMPLETE' }
        Sections=[pscustomobject]$collection
        SectionStatus=[pscustomobject]$status
        Errors=$errors.ToArray()
    }
}

function Export-VGIncidentBundle {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Context,[string]$OutputPath,[string]$ScanPath,[string]$BaselinePath,
        [switch]$IncludeEventLogs,[switch]$IncludeSensitive,[switch]$Confirmed
    )
    $preview=Get-VGIncidentPreview -OutputPath $OutputPath -ScanPath $ScanPath -BaselinePath $BaselinePath -IncludeEventLogs:$IncludeEventLogs -IncludeSensitive:$IncludeSensitive
    if (-not $Confirmed) { return [pscustomobject]@{Success=$false;Status='CONFIRMATION_REQUIRED';Preview=$preview} }
    if (-not $PSCmdlet.ShouldProcess($preview.OutputPath,'Collect local diagnostics and create ZIP archive')) {
        return [pscustomobject]@{Success=$false;Status='DRY_RUN';Preview=$preview}
    }

    $target=$preview.OutputPath
    if (Test-Path -LiteralPath $target) { throw 'Incident destination exists; overwrite is disabled.' }
    $parent=Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
    $null=Assert-VGIncidentDestination -OutputPath $target
    if (-not $env:TEMP) { throw 'TEMP is required for incident staging.' }
    $staging=Join-Path $env:TEMP ('VoidGuard-Incident-'+[guid]::NewGuid().ToString('N'))
    $tempArchive=$target+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $payload=Get-VGIncidentData -Context $Context -ScanPath $ScanPath -BaselinePath $BaselinePath -IncludeEventLogs:$IncludeEventLogs -IncludeSensitive:$IncludeSensitive
        $jsonPath=Join-Path $staging 'diagnostics.json'
        $manifestPath=Join-Path $staging 'manifest.json'
        $sums=Join-Path $staging 'SHA256SUMS.txt'
        $encoding=New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($jsonPath,(ConvertTo-Json -InputObject $payload -Depth 15),$encoding)
        $manifest=[ordered]@{
            SchemaVersion=1;Name='VoidGuard Incident Bundle'
            CreatedUtc=$payload.CreatedUtc;Version=$payload.Version
            Status=$payload.Status
            ContainsSensitiveData=$payload.ContainsSensitiveData
            Sections=@($payload.SectionStatus.PSObject.Properties.Name)
            Note='Inspect diagnostics.json before sharing this archive. No files or logs were uploaded.'
        }
        [IO.File]::WriteAllText($manifestPath,(ConvertTo-Json -InputObject $manifest -Depth 10),$encoding)
        $digests=@(
            ((Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash+'  diagnostics.json'),
            ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash+'  manifest.json')
        )
        [IO.File]::WriteAllText($sums,($digests -join [Environment]::NewLine),$encoding)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($staging,$tempArchive,[IO.Compression.CompressionLevel]::Optimal,$false)
        if ((Get-Item -LiteralPath $tempArchive).Length -gt 26214400) { throw 'Incident ZIP exceeds 25 MiB limit.' }
        if (Test-Path -LiteralPath $target) { throw 'Incident destination appeared during collection.' }
        $null=Assert-VGIncidentDestination -OutputPath $target
        Move-Item -LiteralPath $tempArchive -Destination $target -ErrorAction Stop
        return [pscustomobject]@{
            Success=$true;Status=$payload.Status;OutputPath=$target
            SHA256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
            ContainsSensitiveData=$payload.ContainsSensitiveData
            CollectionIssues=$payload.Errors
            SizeBytes=(Get-Item -LiteralPath $target).Length
            Files=@('diagnostics.json','manifest.json','SHA256SUMS.txt')
        }
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tempArchive) { Remove-Item -LiteralPath $tempArchive -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function @('Get-VGIncidentPreview','Get-VGIncidentData','Export-VGIncidentBundle')
