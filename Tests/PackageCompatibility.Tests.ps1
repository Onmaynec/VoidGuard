#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-Package-Test-' + [Guid]::NewGuid().ToString('N'))
$dist = Join-Path $tempRoot 'dist'

function Test-VGUtf8Bom {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    return $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
}

function Test-VGStatusCommand {
    param([Parameter(Mandatory = $true)][string]$EntryPoint)

    $output = & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $EntryPoint `
        -Mode Status -Professional -NoAnimation -Json 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    if ($exitCode -ne 0) {
        throw "Windows PowerShell 5.1 launch failed for ${EntryPoint}:`n$text"
    }

    $status = $text | ConvertFrom-Json
    if ($status.PSObject.Properties.Name -notcontains 'IsAdministrator') {
        throw "Status contract is incomplete for $EntryPoint"
    }
}

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    # The repository checkout itself must remain compatible with Windows PowerShell 5.1.
    $repositoryScripts = @(
        Get-ChildItem -LiteralPath $root -Recurse -File |
            Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') }
    )
    foreach ($scriptFile in $repositoryScripts) {
        if (-not (Test-VGUtf8Bom -Path $scriptFile.FullName)) {
            throw "PowerShell source is missing UTF-8 BOM: $($scriptFile.FullName)"
        }
    }
    Test-VGStatusCommand -EntryPoint (Join-Path $root 'VoidGuard.ps1')

    $buildScript = Join-Path $root 'Build\Build-Release.ps1'
    $buildResult = & $buildScript -RootPath $root -OutputDirectory $dist -Version $version
    if (-not $buildResult) { throw 'Release builder returned no result.' }

    $archives = @(
        [pscustomobject]@{ Name = 'Portable'; Path = $buildResult.PortableZip },
        [pscustomobject]@{ Name = 'Source'; Path = $buildResult.SourceZip }
    )

    foreach ($archive in $archives) {
        if (-not (Test-Path -LiteralPath $archive.Path -PathType Leaf)) {
            throw "$($archive.Name) archive was not created: $($archive.Path)"
        }

        $extractRoot = Join-Path $tempRoot ('extract-' + $archive.Name)
        Expand-Archive -LiteralPath $archive.Path -DestinationPath $extractRoot -Force

        $entryPoint = Get-ChildItem -LiteralPath $extractRoot -Recurse -File -Filter 'VoidGuard.ps1' |
            Select-Object -First 1 -ExpandProperty FullName
        if (-not $entryPoint) {
            throw "$($archive.Name) archive does not contain VoidGuard.ps1"
        }

        $packagedScripts = @(
            Get-ChildItem -LiteralPath $extractRoot -Recurse -File |
                Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') }
        )
        if ($packagedScripts.Count -lt 2) {
            throw "$($archive.Name) archive contains too few PowerShell files."
        }
        foreach ($scriptFile in $packagedScripts) {
            if (-not (Test-VGUtf8Bom -Path $scriptFile.FullName)) {
                throw "$($archive.Name) archive contains a PowerShell file without UTF-8 BOM: $($scriptFile.FullName)"
            }
        }

        Test-VGStatusCommand -EntryPoint $entryPoint
    }

    Write-Host 'VoidGuard package compatibility tests passed on Windows PowerShell 5.1.' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
