#requires -Version 5.1
Set-StrictMode -Version Latest

function Assert-VGRuleUpdateId {
    param([Parameter(Mandatory)][string]$Id)
    if ($Id -notmatch '^[a-z0-9][a-z0-9._-]{2,79}$' -or $Id -eq 'voidguard.core') {
        throw 'Invalid signed pack id. The bundled core pack cannot be replaced.'
    }
    return $Id
}

function Assert-VGRuleUpdatePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[a-zA-Z]:\\' -or $full -match '^\\') {
        throw 'Rule updates and history require local Windows drive paths. UNC/network paths are blocked.'
    }
    if (Get-VoidGuardPathReparseAncestor -Path $full) { throw "Reparse point in update path: $full" }
    return $full
}

function Assert-VGRuleUpdateSource {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)]$Context)
    $source = Assert-VGRuleUpdatePath -Path $SourcePath
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Source must be an extracted local directory.' }
    $pack = Test-VoidGuardRulePack -PackPath $source -Context $Context
    if (-not $pack.Trusted -or -not $pack.IntegrityValid -or [string]$pack.Manifest.trustMode -cne 'signed') {
        throw ('Only a verified RSA-signed pack can be installed: ' + (@($pack.Errors) -join '; '))
    }
    $null = Assert-VGRuleUpdateId -Id ([string]$pack.Id)
    $files = @($pack.Manifest.files)
    if ($files.Count -lt 1 -or $files.Count -gt 16) { throw 'Signed pack must contain 1–16 declared files.' }
    $expected = @{'manifest.json'=$true}
    foreach ($entry in $files) {
        $name = [string]$entry.path
        if ($name -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$' -or $expected.ContainsKey($name)) {
            throw "Nested, duplicate, or unsafe rule file: $name"
        }
        $expected[$name]=$true
    }
    $total = [long]0
    $present=@{}
    foreach ($item in @(Get-ChildItem -LiteralPath $source -Force -ErrorAction Stop)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Directories, links and reparse points inside an update are forbidden.'
        }
        if (-not $expected.ContainsKey([string]$item.Name) -or $present.ContainsKey([string]$item.Name)) {
            throw "Undeclared update file: $($item.Name)"
        }
        if ([long]$item.Length -gt 10485760) { throw 'Single rule file exceeds 10 MiB.' }
        $total += [long]$item.Length
        $present[[string]$item.Name]=$true
    }
    if ($total -gt 26214400 -or $present.Count -ne $expected.Count) {
        throw 'Update exceeds size limit or its file inventory is incomplete.'
    }
    return [pscustomobject]@{
        SourcePath=$source;Pack=$pack;FileNames=@($expected.Keys | Sort-Object)
        TotalBytes=$total
    }
}

function Get-VGRuleUpdatePreview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)]$Context)
    try {
        $candidate=Assert-VGRuleUpdateSource -SourcePath $SourcePath -Context $Context
        $pack=$candidate.Pack
        $root=Assert-VGRuleUpdatePath -Path (Join-Path $Context.RootPath 'Rules\Packs')
        $id=[string]$pack.Id
        $destination=Join-Path $root $id
        $current=$null
        if (Test-Path -LiteralPath $destination) {
            if (-not (Test-Path -LiteralPath $destination -PathType Container)) { throw 'Destination is not a directory.' }
            $current=Test-VoidGuardRulePack -PackPath $destination -Context $Context
            if (-not $current.Trusted -or -not $current.IntegrityValid -or [string]$current.Manifest.trustMode -cne 'signed') {
                throw 'Refusing to replace a non-signed or invalid installed pack.'
            }
            if ([string]$current.Id -cne $id -or [string]$current.Publisher -cne [string]$pack.Publisher -or
                [string]$current.Manifest.signature.keyId -cne [string]$pack.Manifest.signature.keyId) {
                throw 'Update publisher or signing-key identity differs from the installed pack.'
            }
            if ([version]$pack.Version -le [version]$current.Version) {
                throw 'The candidate version must be newer than the installed version.'
            }
        }
        $enabled=@($Context.Settings.enabledRulePacks) -contains $id
        return [pscustomobject]@{
            Status='READY';CanApply=$true;PackId=$id
            Version=[string]$pack.Version
            CurrentVersion=if ($current) { [string]$current.Version } else { $null }
            Publisher=[string]$pack.Publisher
            KeyId=[string]$pack.Manifest.signature.keyId
            Operation=if ($current) { 'UPGRADE' } else { 'INSTALL' }
            WillBeEnabled=$enabled
            SourcePath=$candidate.SourcePath;Files=$candidate.FileNames
            TotalBytes=$candidate.TotalBytes;Reason=$null
        }
    } catch {
        return [pscustomobject]@{
            Status='BLOCKED';CanApply=$false;PackId=$null
            SourcePath=$SourcePath;Reason=$_.Exception.Message
        }
    }
}

function Get-VGRulePackUpdateHistory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context,[string]$PackId)
    $root=Join-Path $Context.RootPath 'Rules\History'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $null=Assert-VGRuleUpdatePath -Path $root
    $list=New-Object 'System.Collections.Generic.List[object]'
    $dirs=if ($PackId) {
        $null=Assert-VGRuleUpdateId $PackId
        @(Get-Item -LiteralPath (Join-Path $root $PackId) -ErrorAction SilentlyContinue)
    } else {
        @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)
    }
    foreach ($group in $dirs) {
        if (-not $group -or -not $group.PSIsContainer -or $group.Name -notmatch '^[a-z0-9][a-z0-9._-]{2,79}$') { continue }
        foreach ($folder in @(Get-ChildItem -LiteralPath $group.FullName -Directory -Force -ErrorAction Stop)) {
            if ($folder.Name -notmatch '^h-[0-9]{14}-[a-f0-9]{12}$') { continue }
            $verified=Test-VoidGuardRulePack -PackPath $folder.FullName -Context $Context
            $list.Add([pscustomobject]@{
                PackId=[string]$group.Name;HistoryId=[string]$folder.Name
                Version=[string]$verified.Version;Trusted=[bool]$verified.Trusted
                IntegrityValid=[bool]$verified.IntegrityValid
                SigningKey=if ($verified.Manifest) { [string]$verified.Manifest.signature.keyId } else { $null }
                Errors=@($verified.Errors)
            })
        }
    }
    return @($list.ToArray() | Sort-Object HistoryId -Descending)
}

function New-VGRuleHistoryName {
    return ('h-{0}-{1}' -f @((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'),[guid]::NewGuid().ToString('N').Substring(0,12)))
}

function Install-VGRulePackUpdate {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)]$Context,[switch]$Confirmed)
    $preview=Get-VGRuleUpdatePreview -SourcePath $SourcePath -Context $Context
    if (-not $preview.CanApply) { return [pscustomobject]@{Success=$false;Status='BLOCKED';Preview=$preview} }
    if (-not $Confirmed) { return [pscustomobject]@{Success=$false;Status='CONFIRMATION_REQUIRED';Preview=$preview} }
    if (-not $PSCmdlet.ShouldProcess($preview.PackId,'Install verified signed rule pack')) {
        return [pscustomobject]@{Success=$false;Status='DRY_RUN';Preview=$preview}
    }

    $packs=Join-Path $Context.RootPath 'Rules\Packs'
    $rules=Join-Path $Context.RootPath 'Rules'
    $stagingRoot=Join-Path $rules '.update-staging'
    $historyRoot=Join-Path (Join-Path $rules 'History') $preview.PackId
    foreach ($path in @($packs,$rules,$stagingRoot,$historyRoot)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null }
        $null=Assert-VGRuleUpdatePath -Path $path
    }

    $stage=Join-Path $stagingRoot ([guid]::NewGuid().ToString('N'))
    $destination=Join-Path $packs $preview.PackId
    $backup=Join-Path $historyRoot (New-VGRuleHistoryName)
    $oldMoved=$false
    $newMoved=$false
    try {
        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
        foreach ($filename in @($preview.Files)) {
            Copy-Item -LiteralPath (Join-Path $preview.SourcePath $filename) -Destination (Join-Path $stage $filename) -ErrorAction Stop
        }
        # Подпись и хеши проверяются повторно уже по скопированным файлам.
        $stagePack=Assert-VGRuleUpdateSource -SourcePath $stage -Context $Context
        if ([string]$stagePack.Pack.Id -cne $preview.PackId -or [string]$stagePack.Pack.Version -cne $preview.Version) {
            throw 'Update source changed during staging.'
        }
        # Повторная проверка версии/издателя в момент замены.
        $fresh=Get-VGRuleUpdatePreview -SourcePath $stage -Context $Context
        if (-not $fresh.CanApply) { throw "Pack changed before installation: $($fresh.Reason)" }
        if (Test-Path -LiteralPath $destination) {
            $null=Assert-VGRuleUpdatePath -Path $destination
            Move-Item -LiteralPath $destination -Destination $backup -ErrorAction Stop
            $oldMoved=$true
        }
        Move-Item -LiteralPath $stage -Destination $destination -ErrorAction Stop
        $newMoved=$true
        $installed=Test-VoidGuardRulePack -PackPath $destination -Context $Context
        if (-not $installed.Trusted -or [string]$installed.Version -cne $preview.Version) {
            throw 'Installed pack failed post-commit trust verification.'
        }
        return [pscustomobject]@{
            Success=$true;Status=if ($oldMoved) { 'UPGRADED' } else { 'INSTALLED' }
            PackId=$preview.PackId;Version=$preview.Version
            PreviousVersion=$preview.CurrentVersion
            HistoryId=if ($oldMoved) { Split-Path -Leaf $backup } else { $null }
            Enabled=$preview.WillBeEnabled
            Message=if ($preview.WillBeEnabled) { 'Rules active on next scan.' } else { 'Enable this pack explicitly before it participates in scanning.' }
        }
    } catch {
        $problem=$_.Exception.Message
        if ($newMoved -and (Test-Path -LiteralPath $destination)) {
            $failed=Join-Path $stagingRoot ('failed-'+[guid]::NewGuid().ToString('N'))
            try {
                Move-Item -LiteralPath $destination -Destination $failed -ErrorAction Stop
            } catch {
                return [pscustomobject]@{
                    Success=$false;Status='CLEANUP_FAILED'
                    Error=$problem;RecoveryPath=$destination
                    PreviousVersionPath=if ($oldMoved) { $backup } else { $null }
                }
            }
        }
        if ($oldMoved -and -not (Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $backup)) {
            try { Move-Item -LiteralPath $backup -Destination $destination -ErrorAction Stop }
            catch { return [pscustomobject]@{Success=$false;Status='ROLLBACK_FAILED';Error=$problem;RecoveryPath=$backup;Destination=$destination} }
        }
        return [pscustomobject]@{Success=$false;Status='INSTALL_FAILED';Error=$problem}
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Restore-VGRulePackVersion {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$PackId,[Parameter(Mandatory)][string]$HistoryId,
        [Parameter(Mandatory)]$Context,[switch]$Confirmed
    )
    $null=Assert-VGRuleUpdateId $PackId
    if ($HistoryId -cnotmatch '^h-[0-9]{14}-[a-f0-9]{12}$') { throw 'Invalid history id.' }
    $root=Join-Path $Context.RootPath 'Rules'
    $active=Join-Path (Join-Path $root 'Packs') $PackId
    $historyRoot=Join-Path (Join-Path $root 'History') $PackId
    $source=Join-Path $historyRoot $HistoryId
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'History entry not found.' }
    if (-not (Test-Path -LiteralPath $active -PathType Container)) { throw 'Installed signed pack not found.' }
    $null=Assert-VGRuleUpdatePath $source
    $null=Assert-VGRuleUpdatePath $active
    $old=Assert-VGRuleUpdateSource -SourcePath $source -Context $Context
    $current=Assert-VGRuleUpdateSource -SourcePath $active -Context $Context
    if ([string]$old.Pack.Id -cne $PackId -or [string]$current.Pack.Id -cne $PackId -or
        [string]$old.Pack.Publisher -cne [string]$current.Pack.Publisher -or
        [string]$old.Pack.Manifest.signature.keyId -cne [string]$current.Pack.Manifest.signature.keyId) {
        throw 'Rollback identity or signing key differs from active pack.'
    }
    $preview=[pscustomobject]@{
        PackId=$PackId;CurrentVersion=$current.Pack.Version;RestoreVersion=$old.Pack.Version
        HistoryId=$HistoryId;Status='READY'
    }
    if (-not $Confirmed) { return [pscustomobject]@{Success=$false;Status='CONFIRMATION_REQUIRED';Preview=$preview} }
    if (-not $PSCmdlet.ShouldProcess($PackId,'Restore previously signed version')) {
        return [pscustomobject]@{Success=$false;Status='DRY_RUN';Preview=$preview}
    }
    $archive=Join-Path $historyRoot (New-VGRuleHistoryName)
    $movedOld=$false
    try {
        Move-Item -LiteralPath $active -Destination $archive -ErrorAction Stop
        $movedOld=$true
        Move-Item -LiteralPath $source -Destination $active -ErrorAction Stop
        $restored=Assert-VGRuleUpdateSource -SourcePath $active -Context $Context
        if ([string]$restored.Pack.Version -cne [string]$preview.RestoreVersion) { throw 'Rollback verification failed.' }
        return [pscustomobject]@{Success=$true;Status='RESTORED';PackId=$PackId;Version=$preview.RestoreVersion;ArchivedVersion=$preview.CurrentVersion;HistoryId=(Split-Path -Leaf $archive)}
    } catch {
        $reason=$_.Exception.Message
        if ($movedOld -and (Test-Path -LiteralPath $archive)) {
            if (Test-Path -LiteralPath $active) {
                $failed=Join-Path $historyRoot (New-VGRuleHistoryName)
                try { Move-Item -LiteralPath $active -Destination $failed -ErrorAction Stop } catch { }
            }
            if (-not (Test-Path -LiteralPath $active)) {
                try { Move-Item -LiteralPath $archive -Destination $active -ErrorAction Stop }
                catch { return [pscustomobject]@{Success=$false;Status='ROLLBACK_FAILED';Error=$reason;RecoveryPath=$archive} }
            }
        }
        return [pscustomobject]@{Success=$false;Status='RESTORE_FAILED';Error=$reason}
    }
}

function Set-VGRulePackEnabled {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$PackId,[Parameter(Mandatory)]$Context,[bool]$Enabled=$true,[switch]$Confirmed)
    if ($PackId -notmatch '^[a-z0-9][a-z0-9._-]{2,79}$') { throw 'Invalid pack id.' }
    $packPath=Join-Path (Join-Path $Context.RootPath 'Rules\Packs') $PackId
    if (-not (Test-Path -LiteralPath $packPath -PathType Container)) { throw 'Pack not installed.' }
    $pack=Test-VoidGuardRulePack -PackPath $packPath -Context $Context
    if (-not $pack.Trusted -or -not $pack.IntegrityValid -or [string]$pack.Id -cne $PackId) {
        throw 'Pack is not trusted or its directory does not match its id.'
    }
    $config=Join-Path $Context.RootPath 'Config\settings.json'
    $null=Assert-VGRuleUpdatePath $config
    $settings=Get-Content -LiteralPath $config -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $list=New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in @($settings.enabledRulePacks)) {
        if ($id -and -not $list.Contains([string]$id)) { $list.Add([string]$id) }
    }
    if ($Enabled -and -not $list.Contains($PackId)) { $list.Add($PackId) }
    if (-not $Enabled -and $list.Contains($PackId)) { $null=$list.Remove($PackId) }
    if ($list.Count -eq 0) {
        # Пустой список означает «все включены» в существующем engine.
        throw 'At least one pack must remain explicitly enabled.'
    }
    $preview=[pscustomobject]@{PackId=$PackId;Enabled=$Enabled;ActivePacks=$list.ToArray()}
    if (-not $Confirmed) { return [pscustomobject]@{Success=$false;Status='CONFIRMATION_REQUIRED';Preview=$preview} }
    if (-not $PSCmdlet.ShouldProcess($PackId,'Change rule-pack activation')) {
        return [pscustomobject]@{Success=$false;Status='DRY_RUN';Preview=$preview}
    }
    $settings.enabledRulePacks=$list.ToArray()
    $tmp=$config+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    $backup=$config+'.backup'
    try {
        [IO.File]::WriteAllText($tmp,(ConvertTo-Json -InputObject $settings -Depth 12),(New-Object Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction Stop }
        [IO.File]::Replace($tmp,$config,$backup)
        $Context.Settings.enabledRulePacks=$list.ToArray()
        return [pscustomobject]@{Success=$true;Status='UPDATED';PackId=$PackId;Enabled=$Enabled;ActivePacks=$list.ToArray()}
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function @(
    'Assert-VGRuleUpdateSource','Get-VGRuleUpdatePreview','Install-VGRulePackUpdate',
    'Get-VGRulePackUpdateHistory','Restore-VGRulePackVersion','Set-VGRulePackEnabled'
)
