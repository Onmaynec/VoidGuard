#requires -Version 5.1
Set-StrictMode -Version Latest

$script:VGAllowedSections=@('Security','Services','Tasks','Startup','Files')

function Assert-VGIntegritySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)
    if ($null -eq $Snapshot -or [string]$Snapshot.Kind -cne 'VoidGuard.SystemIntegrity' -or [int]$Snapshot.SchemaVersion -ne 1) {
        throw 'Unsupported System Integrity baseline schema.'
    }
    if (-not [string]$Snapshot.ComputerName) { throw 'Computer name is missing.' }
    $scope=@($Snapshot.SectionsRequested)
    if ($scope.Count -lt 1 -or $scope.Count -gt 5) { throw 'Invalid section scope.' }
    $unique=@{}
    foreach ($name in $scope) {
        if ($script:VGAllowedSections -notcontains $name -or $unique.ContainsKey([string]$name)) { throw 'Invalid or duplicated section.' }
        $unique[[string]$name]=$true
        $property=$Snapshot.Sections.PSObject.Properties[[string]$name]
        if (-not $property) { throw "Missing section: $name" }
        $section=$property.Value
        if ([string]$section.State -notin @('COMPLETE','PARTIAL')) { throw "Invalid section state: $name" }
        if ($null -eq $section.Records -or @($section.Records).Count -gt 10000) { throw 'Invalid record inventory.' }
        $keys=@{}
        foreach ($record in @($section.Records)) {
            if (-not $record -or -not $record.PSObject.Properties['Key'] -or -not $record.PSObject.Properties['Value']) {
                throw "Malformed record in $name"
            }
            $key=[string]$record.Key
            if (-not $key -or $key.Length -gt 4096 -or ([string]$record.Value).Length -gt 65536 -or $keys.ContainsKey($key)) {
                throw "Invalid or duplicated record in $name"
            }
            $keys[$key]=$true
        }
    }
    if (@($Snapshot.SelectedPaths).Count -gt 128) { throw 'Too many paths.' }
}

function Compare-VGIntegritySnapshots {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Baseline,[Parameter(Mandatory)]$Current)
    Assert-VGIntegritySnapshot -Snapshot $Baseline
    Assert-VGIntegritySnapshot -Snapshot $Current
    if (-not [string]::Equals([string]$Baseline.ComputerName,[string]$Current.ComputerName,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing snapshots from different computers.'
    }
    if ((@($Baseline.SectionsRequested | Sort-Object -Unique) -join ',') -cne (@($Current.SectionsRequested | Sort-Object -Unique) -join ',')) {
        throw 'Snapshot sections differ.'
    }
    $changes=New-Object 'System.Collections.Generic.List[object]'
    $issues=New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @($Baseline.SectionsRequested | Sort-Object -Unique)) {
        $left=$Baseline.Sections.PSObject.Properties[[string]$name].Value
        $right=$Current.Sections.PSObject.Properties[[string]$name].Value
        if ($left.State -ne 'COMPLETE' -or $right.State -ne 'COMPLETE') {
            $issues.Add("Incomplete section: $name")
            continue
        }
        $a=@{}; $b=@{}
        foreach ($record in @($left.Records)) { $a[[string]$record.Key]=[string]$record.Value }
        foreach ($record in @($right.Records)) { $b[[string]$record.Key]=[string]$record.Value }
        $all=@(@($a.Keys)+@($b.Keys) | Sort-Object -Unique)
        foreach ($key in $all) {
            $kind=$null
            if (-not $a.ContainsKey($key)) { $kind='ADDED' }
            elseif (-not $b.ContainsKey($key)) { $kind='REMOVED' }
            elseif ($a[$key] -cne $b[$key]) { $kind='CHANGED' }
            if ($kind) {
                $changes.Add([pscustomobject]@{
                    Section=$name;Kind=$kind;Key=$key
                    Before=if ($a.ContainsKey($key)) { $a[$key] } else { $null }
                    After=if ($b.ContainsKey($key)) { $b[$key] } else { $null }
                })
            }
        }
    }
    [pscustomobject]@{
        Mode='BaselineDiff'
        Status=if ($issues.Count) { 'PARTIAL' } elseif ($changes.Count) { 'CHANGED' } else { 'UNCHANGED' }
        Complete=($issues.Count -eq 0)
        ComputerName=$Current.ComputerName;BaselineCapturedUtc=$Baseline.CapturedUtc;CurrentCapturedUtc=$Current.CapturedUtc
        ChangesCount=$changes.Count
        Added=@($changes.ToArray() | Where-Object Kind -eq 'ADDED').Count
        Removed=@($changes.ToArray() | Where-Object Kind -eq 'REMOVED').Count
        Changed=@($changes.ToArray() | Where-Object Kind -eq 'CHANGED').Count
        Changes=$changes.ToArray();Issues=$issues.ToArray();CollectionErrors=@($Current.Errors)
    }
}

function Assert-VGBaselinePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[a-zA-Z]:\\' -or $full -match '^\\' -or [IO.Path]::GetExtension($full).ToLowerInvariant() -ne '.json') {
        throw 'Baseline must use an absolute local .json path.'
    }
    if (Get-VoidGuardPathReparseAncestor -Path $full) { throw 'Baseline path contains a reparse point.' }
    foreach ($candidate in @($env:windir,$env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if (-not $candidate) { continue }
        $root=[IO.Path]::GetFullPath($candidate).TrimEnd('\')
        if ($full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Baseline cannot be placed inside a protected directory.'
        }
    }
    $full
}

function New-VGIntegrityBaseline {
    [CmdletBinding()]
    param(
        [string]$BaselinePath,
        [string[]]$SelectedPaths=@(),
        [ValidateSet('Security','Services','Tasks','Startup','Files')][string[]]$Sections=@('Security','Services','Tasks','Startup','Files'),
        [bool]$IncludeHosts=$true
    )
    if (-not $BaselinePath) {
        if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA unavailable; specify -BaselinePath.' }
        $filename='integrity-{0}-{1}.json' -f @((Get-Date -Format 'yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
        $BaselinePath=Join-Path (Join-Path $env:LOCALAPPDATA 'VoidGuard\Baselines') $filename
    }
    $target=Assert-VGBaselinePath -Path $BaselinePath
    if (Test-Path -LiteralPath $target) { throw 'Baseline already exists; overwrite is disabled.' }
    $snapshot=Get-VGIntegritySnapshot -SelectedPaths $SelectedPaths -Sections $Sections -IncludeHosts:$IncludeHosts
    Assert-VGIntegritySnapshot -Snapshot $snapshot
    $parent=Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }
    $null=Assert-VGBaselinePath -Path $target
    $tmp=$target+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        $json=ConvertTo-Json -InputObject $snapshot -Depth 12
        [IO.File]::WriteAllText($tmp,$json,(New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $target) { throw 'Baseline path appeared during creation.' }
        Move-Item -LiteralPath $tmp -Destination $target -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{
        Mode='BaselineCreate';Status=if ($snapshot.Complete) { 'COMPLETE' } else { 'PARTIAL' }
        BaselinePath=$target;SHA256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        CapturedUtc=$snapshot.CapturedUtc;Sections=$snapshot.SectionsRequested;Errors=$snapshot.Errors
    }
}

function Compare-VGIntegrityBaseline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BaselinePath)
    $target=Assert-VGBaselinePath -Path $BaselinePath
    $file=Get-Item -LiteralPath $target -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 10485760) { throw 'Baseline is not a file or exceeds 10 MiB.' }
    $baseline=Get-Content -LiteralPath $target -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Assert-VGIntegritySnapshot -Snapshot $baseline
    $current=Get-VGIntegritySnapshot -SelectedPaths @($baseline.SelectedPaths) -Sections @($baseline.SectionsRequested) -IncludeHosts:([bool]$baseline.IncludeHosts)
    $diff=Compare-VGIntegritySnapshots -Baseline $baseline -Current $current
    $diff | Add-Member -NotePropertyName BaselinePath -NotePropertyValue $target
    $diff | Add-Member -NotePropertyName BaselineSHA256 -NotePropertyValue ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)
    $diff
}

Export-ModuleMember -Function @('Assert-VGIntegritySnapshot','Compare-VGIntegritySnapshots','New-VGIntegrityBaseline','Compare-VGIntegrityBaseline')
