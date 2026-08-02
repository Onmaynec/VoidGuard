#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RootPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RootPath).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') {
    throw "Invalid version: $Version"
}

function Set-VGPowerShellUtf8Bom {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Directory)

    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $utf8Reader = New-Object System.Text.UTF8Encoding($false, $true)

    Get-ChildItem -LiteralPath $Directory -Recurse -File -ErrorAction Stop |
        Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') } |
        ForEach-Object {
            $text = [IO.File]::ReadAllText($_.FullName, $utf8Reader)
            [IO.File]::WriteAllText($_.FullName, $text, $utf8Bom)
        }
}

function Copy-VGTrackedSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $trackedFiles = @(& git -C $RepositoryRoot ls-files)
    if ($LASTEXITCODE -ne 0) {
        throw 'git ls-files failed.'
    }

    foreach ($relativePath in $trackedFiles) {
        if ([string]::IsNullOrWhiteSpace($relativePath)) { continue }

        $sourcePath = Join-Path $RepositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { continue }

        $destinationPath = Join-Path $DestinationRoot $relativePath
        $destinationDirectory = Split-Path -Parent $destinationPath
        if (-not (Test-Path -LiteralPath $destinationDirectory)) {
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
        }
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
    }
}

function New-VGZipArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $SourceDirectory,
        $ArchivePath,
        [IO.Compression.CompressionLevel]::Optimal,
        $false
    )
}

New-Item -ItemType Directory -Path $output -Force | Out-Null

$portableRoot = Join-Path $output "VoidGuard-v$Version"
$sourceRoot = Join-Path $output "VoidGuard-v$Version-Source"
foreach ($directory in @($portableRoot, $sourceRoot)) {
    if (Test-Path -LiteralPath $directory) {
        Remove-Item -LiteralPath $directory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$portableItems = @(
    'VoidGuard.ps1',
    'VoidGuard.cmd',
    'VERSION',
    'LICENSE',
    'README.md',
    'CHANGELOG.md',
    'SECURITY.md',
    'Modules',
    'Assets',
    'Config',
    'Rules',
    'docs'
)

foreach ($item in $portableItems) {
    $sourcePath = Join-Path $root $item
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Required release item is missing: $item"
    }
    Copy-Item -LiteralPath $sourcePath -Destination $portableRoot -Recurse -Force
}

Copy-VGTrackedSource -RepositoryRoot $root -DestinationRoot $sourceRoot

# Windows PowerShell 5.1 requires a BOM to reliably recognize UTF-8 source files.
Set-VGPowerShellUtf8Bom -Directory $portableRoot
Set-VGPowerShellUtf8Bom -Directory $sourceRoot

$portableZip = Join-Path $output "VoidGuard-v$Version-Portable.zip"
$sourceZip = Join-Path $output "VoidGuard-v$Version-Source.zip"
New-VGZipArchive -SourceDirectory $portableRoot -ArchivePath $portableZip
New-VGZipArchive -SourceDirectory $sourceRoot -ArchivePath $sourceZip

[pscustomobject]@{
    PortableZip = $portableZip
    SourceZip = $sourceZip
    PortableRoot = $portableRoot
    SourceRoot = $sourceRoot
}
