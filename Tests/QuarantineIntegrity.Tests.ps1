#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
foreach ($name in @('VoidGuard.Protection','VoidGuard.System','VoidGuard.Remediation','VoidGuard.Quarantine')) {
    Import-Module (Join-Path $root "Modules\$name.psm1") -Force -DisableNameChecking
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-QuarantineIntegrity-' + [guid]::NewGuid().ToString('N'))
$oldProgramData = $env:ProgramData
$oldLocalAppData = $env:LOCALAPPDATA
$oldTemp = $env:TEMP
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    # Тестовый vault должен находиться только внутри временной папки.
    $env:ProgramData = $tempRoot
    $env:LOCALAPPDATA = $tempRoot
    $env:TEMP = $tempRoot
    $vault = Get-VoidGuardQuarantineRoot
    $id = 'Q-20260105100000-ABCDEF12'
    $container = Join-Path $vault $id
    New-Item -ItemType Directory -Path $container -Force | Out-Null
    $payload = Join-Path $container 'payload.vgq'
    $metadataPath = Join-Path $container 'metadata.json'
    $destination = Join-Path $tempRoot 'restored.cmd'
    $bytes = [Text.Encoding]::UTF8.GetBytes('@echo off')
    [IO.File]::WriteAllBytes($payload, $bytes)
    $hash = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash
    [pscustomobject]@{
        SchemaVersion = 2
        Id = $id
        OriginalPath = $destination
        PayloadPath = $payload
        OriginalName = 'restored.cmd'
        Size = $bytes.Length
        SHA256 = $hash
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8

    $tamperedBytes = [byte[]]$bytes.Clone()
    $tamperedBytes[0] = [byte]($tamperedBytes[0] + 1)
    [IO.File]::WriteAllBytes($payload, $tamperedBytes)
    $blocked = $false
    try { $null = Restore-VoidGuardQuarantineItem -Id $id }
    catch {
        if ($_.Exception.Message -like '*SHA-256 mismatch*') { $blocked = $true }
        else { throw }
    }
    if (-not $blocked -or -not (Test-Path -LiteralPath $payload)) {
        throw 'Повреждённый payload был восстановлен или удалён.'
    }

    [IO.File]::WriteAllBytes($payload, $bytes)
    'existing file' | Set-Content -LiteralPath $destination -Encoding ASCII
    $blocked = $false
    try { $null = Restore-VoidGuardQuarantineItem -Id $id }
    catch {
        if ($_.Exception.Message -like '*Destination already exists*') { $blocked = $true }
        else { throw }
    }
    if (-not $blocked -or -not (Test-Path -LiteralPath $payload)) {
        throw 'Восстановление перезаписало существующий файл без разрешения.'
    }
    Remove-Item -LiteralPath $destination -Force

    $restored = Restore-VoidGuardQuarantineItem -Id $id
    if (-not $restored.Success -or $restored.Status -ne 'RESTORED' -or -not (Test-Path -LiteralPath $destination)) {
        throw 'Проверенный payload не удалось восстановить.'
    }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $hash) {
        throw 'Контрольная сумма после восстановления отличается.'
    }
    if (Test-Path -LiteralPath $container) { throw 'Успешно восстановленный объект остался в карантине.' }

    $blocked = $false
    try { $null = Restore-VoidGuardQuarantineItem -Id '..\escape' }
    catch { $blocked = $true }
    if (-not $blocked) { throw 'Небезопасный идентификатор карантина был принят.' }
    Write-Host '[OK] SHA-256, конфликты, восстановление и ID карантина проверены.' -ForegroundColor Green
} finally {
    $env:ProgramData = $oldProgramData
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:TEMP = $oldTemp
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
