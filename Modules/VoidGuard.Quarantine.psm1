Set-StrictMode -Version Latest

function Get-VoidGuardQuarantineRoot {
    [CmdletBinding()]
    param()

    $basePath = if ((Test-VoidGuardAdministrator) -and $env:ProgramData) {
        Join-Path $env:ProgramData 'VoidGuard\Quarantine'
    } elseif ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'VoidGuard\Quarantine'
    } else {
        Join-Path $env:TEMP 'VoidGuard\Quarantine'
    }

    if (-not (Test-Path -LiteralPath $basePath)) {
        New-Item -ItemType Directory -Path $basePath -Force | Out-Null
    }
    return $basePath
}

function Get-VoidGuardQuarantineItems {
    [CmdletBinding()]
    param()

    $root = Get-VoidGuardQuarantineRoot
    $items = New-Object System.Collections.Generic.List[object]
    Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $metadataPath = Join-Path $_.FullName 'metadata.json'
        if (Test-Path -LiteralPath $metadataPath) {
            try { $items.Add((Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json)) } catch { }
        }
    }
    return @($items | Sort-Object QuarantinedUtc -Descending)
}

function Invoke-VoidGuardQuarantine {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Confirmed
    )

    $policy = Test-VoidGuardProtectedTarget -Path $Path
    if (-not $policy.Allowed) {
        return [pscustomobject]@{
            Success = $false; Status = 'BLOCKED_SYSTEM_POLICY'; Path = $Path
            Reasons = $policy.Reasons; Warnings = $policy.Warnings
        }
    }
    if (-not $Confirmed) {
        return [pscustomobject]@{
            Success = $false; Status = 'CONFIRMATION_REQUIRED'; Path = $policy.CanonicalPath
            Reasons = @('Every quarantine operation requires explicit confirmation.'); Warnings = $policy.Warnings
        }
    }

    $reparse = Get-VoidGuardPathReparseAncestor -Path $policy.CanonicalPath
    if ($reparse) {
        return [pscustomobject]@{
            Success = $false; Status = 'BLOCKED_SYSTEM_POLICY'; Path = $policy.CanonicalPath
            Reasons = @("Reparse point in target path: $reparse"); Warnings = $policy.Warnings
        }
    }
    $locking = @(Get-VoidGuardFileLockOwners -Path $policy.CanonicalPath)
    if ($locking.Count -gt 0) {
        return [pscustomobject]@{
            Success   = $false
            Status    = 'LOCKED_BY_PROCESS'
            Path      = $policy.CanonicalPath
            Processes = $locking
            Reasons   = @('File is in use. Stop only an exact target process or schedule deletion for the next boot.')
            Warnings  = $policy.Warnings
        }
    }

    $item = Get-Item -LiteralPath $policy.CanonicalPath -Force -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    $id = 'Q-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), ([Guid]::NewGuid().ToString('N').Substring(0, 8).ToUpperInvariant())
    $container = Join-Path (Get-VoidGuardQuarantineRoot) $id
    New-Item -ItemType Directory -Path $container -Force | Out-Null

    $payloadPath = Join-Path $container 'payload.vgq'
    $metadataPath = Join-Path $container 'metadata.json'
    if ($PSCmdlet.ShouldProcess($item.FullName, 'Move file into VoidGuard quarantine')) {
        try {
            Move-Item -LiteralPath $item.FullName -Destination $payloadPath -Force -ErrorAction Stop
        } catch {
            Remove-Item -LiteralPath $container -Recurse -Force -ErrorAction SilentlyContinue
            return [pscustomobject]@{
                Success = $false; Status = 'MOVE_FAILED'; Path = $item.FullName
                Reasons = @($_.Exception.Message); Warnings = $policy.Warnings
            }
        }
    }

    $metadata = [ordered]@{
        SchemaVersion   = 2
        Id              = $id
        OriginalPath    = $item.FullName
        PayloadPath     = $payloadPath
        OriginalName    = $item.Name
        Size            = [long]$item.Length
        SHA256          = $hash
        QuarantinedUtc  = (Get-Date).ToUniversalTime()
        Restorable      = $true
        PolicyWarnings  = @($policy.Warnings)
    }
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8

    if (Test-VoidGuardWindows) {
        try {
            & icacls.exe $container /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" /c /q | Out-Null
            attrib.exe +h $container 2>$null
        } catch { }
    }

    return [pscustomobject]@{
        Success = $true; Status = 'QUARANTINED'; Id = $id; Path = $item.FullName
        SHA256 = $hash; Vault = $container; Reasons = @(); Warnings = $policy.Warnings
    }
}

function Test-VoidGuardRestoreDestination {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -notmatch '^[a-zA-Z]:\\' -or $Path -match '^[\\]{2}') {
        throw 'Восстановление разрешено только в обычный локальный путь диска Windows.'
    }
    $destination = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($destination, $Path, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Путь назначения должен быть каноническим.'
    }
    $root = [IO.Path]::GetPathRoot($destination)
    if ([string]::Equals($root.TrimEnd('\'), $destination.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Нельзя восстанавливать файл в корень тома как в файл назначения.'
    }
    $reparse = Get-VoidGuardPathReparseAncestor -Path $destination
    if ($reparse) { throw "Путь назначения содержит reparse point: $reparse" }

    foreach ($candidate in @($env:windir, $env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $protected = [IO.Path]::GetFullPath($candidate).TrimEnd('\')
        if ($destination.StartsWith($protected + '\', [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($destination, $protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Восстановление в защищённый системный каталог запрещено: $protected"
        }
    }

    if (Test-Path -LiteralPath $destination) {
        $policy = Test-VoidGuardProtectedTarget -Path $destination
        if (-not $policy.Allowed) {
            throw "Файл назначения защищён политикой: $($policy.Reasons -join '; ')"
        }
    }
    return $destination
}

function Restore-VoidGuardQuarantineItem {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Id,
        [switch]$Overwrite
    )

    if ($Id -cnotmatch '^Q-[0-9]{14}-[A-F0-9]{8}$') {
        throw 'Некорректный идентификатор карантина.'
    }
    $container = Join-Path (Get-VoidGuardQuarantineRoot) $Id
    $metadataPath = Join-Path $container 'metadata.json'
    $payloadPath = Join-Path $container 'payload.vgq'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or -not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) {
        throw "Quarantine item not found: $Id"
    }
    if (Get-VoidGuardPathReparseAncestor -Path $metadataPath) { throw 'Metadata path contains reparse point.' }
    if (Get-VoidGuardPathReparseAncestor -Path $payloadPath) { throw 'Quarantine payload path contains reparse point.' }

    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    if ([string]$metadata.Id -cne $Id -or [int]$metadata.SchemaVersion -ne 2) {
        throw 'Quarantine metadata identity or schema mismatch.'
    }
    $expectedHash = [string]$metadata.SHA256
    if ($expectedHash -notmatch '^[a-fA-F0-9]{64}$') { throw 'Quarantine metadata contains an invalid SHA-256.' }
    $payload = Get-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
    if ($payload.PSIsContainer -or [long]$payload.Length -ne [long]$metadata.Size) {
        throw 'Quarantine payload type or size mismatch.'
    }
    $actualHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not [string]::Equals($expectedHash, $actualHash, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Quarantine payload SHA-256 mismatch. Restoration has been blocked.'
    }

    $destination = Test-VoidGuardRestoreDestination -Path ([string]$metadata.OriginalPath)
    if ((Test-Path -LiteralPath $destination) -and -not $Overwrite) {
        throw "Destination already exists: $destination"
    }
    $parent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $parent)) {
        if ($PSCmdlet.ShouldProcess($parent, 'Create restore destination directory')) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        } else {
            return [pscustomobject]@{ Success = $false; Status = 'DRY_RUN'; Id = $Id; Path = $destination }
        }
    }

    # Проверка повторяется после создания каталогов непосредственно перед перемещением.
    $destination = Test-VoidGuardRestoreDestination -Path $destination
    if ($PSCmdlet.ShouldProcess($destination, 'Restore verified quarantined file')) {
        Move-Item -LiteralPath $payloadPath -Destination $destination -Force:$Overwrite -ErrorAction Stop
        Remove-Item -LiteralPath $container -Recurse -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ Success = $true; Status = 'RESTORED'; Id = $Id; Path = $destination; SHA256 = $actualHash }
    }
    return [pscustomobject]@{ Success = $false; Status = 'DRY_RUN'; Id = $Id; Path = $destination }
}

Export-ModuleMember -Function @(
    'Get-VoidGuardQuarantineRoot',
    'Get-VoidGuardQuarantineItems',
    'Invoke-VoidGuardQuarantine',
    'Restore-VoidGuardQuarantineItem'
)
