#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $sourceRoot 'Modules\VoidGuard.Protection.psm1') -Force
Import-Module (Join-Path $sourceRoot 'Modules\VoidGuard.RulePacks.psm1') -Force
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-PackTrust-' + [guid]::NewGuid().ToString('N'))
$coreSource = Join-Path $sourceRoot 'Rules\Packs\core'
$core = Join-Path $tempRoot 'Rules\Packs\core'
New-Item -ItemType Directory -Path (Split-Path -Parent $core) -Force | Out-Null
try {
    Copy-Item -LiteralPath $coreSource -Destination $core -Recurse -Force
    $settings = Get-Content -LiteralPath (Join-Path $sourceRoot 'Config\settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $context = [pscustomobject]@{ RootPath = $tempRoot; Settings = $settings; Version = '0.3.4' }
    $good = Test-VoidGuardRulePack -PackPath $core -Context $context
    if (-not $good.Trusted -or -not $good.IntegrityValid) {
        throw "Официальный core pack был отклонён: $($good.Errors -join '; ')"
    }

    $manifestPath = Join-Path $core 'manifest.json'
    $original = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $manifest = $original | ConvertFrom-Json
    $manifest.version = '1.0.1'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $tampered = Test-VoidGuardRulePack -PackPath $core -Context $context
    if ($tampered.Trusted) { throw 'Изменённый manifest принят как официальный.' }
    [IO.File]::WriteAllText($manifestPath, $original, [Text.Encoding]::UTF8)

    $manifest = $original | ConvertFrom-Json
    $manifest.files[0].path = '../detections.json'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $unsafe = Test-VoidGuardRulePack -PackPath $core -Context $context
    if ($unsafe.Trusted -or $unsafe.IntegrityValid) { throw 'Небезопасный относительный путь не был отклонён.' }
    [IO.File]::WriteAllText($manifestPath, $original, [Text.Encoding]::UTF8)

    $fake = Join-Path $tempRoot 'Rules\Packs\rogue'
    Copy-Item -LiteralPath $core -Destination $fake -Recurse -Force
    $unknown = Test-VoidGuardRulePack -PackPath $fake -Context $context
    if ($unknown.Trusted) { throw 'Неизвестный bundled pack принят по признаку расположения.' }

    $signed = Join-Path $tempRoot 'Rules\Packs\signed'
    Copy-Item -LiteralPath $core -Destination $signed -Recurse -Force
    $signedManifestPath = Join-Path $signed 'manifest.json'
    $signedManifest = Get-Content -LiteralPath $signedManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $signedManifest.id = 'voidguard.test-signed'
    $signedManifest.trustMode = 'signed'
    $signedManifest.signature = [pscustomobject]@{
        keyId = 'test-key'; algorithm = 'RSA-SHA256'
        value = [Convert]::ToBase64String((New-Object byte[] 256))
    }
    $signedManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $signedManifestPath -Encoding UTF8
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048
    try {
        $key = @([pscustomobject]@{ keyId = 'test-key'; publisher = 'Test'; rsaXml = $rsa.ToXmlString($false) })
        $trustPath = Join-Path $tempRoot 'Rules\trusted-publishers.json'
        $key | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $trustPath -Encoding UTF8
        $invalid = Test-VoidGuardRulePack -PackPath $signed -Context $context
        if ($invalid.Trusted -or -not ($invalid.Errors -join ' ').Contains('RSA signature verification failed')) {
            throw 'Некорректная RSA-подпись не была отклонена.'
        }
    } finally {
        $rsa.Dispose()
    }
    Write-Host '[OK] Pinned bundled pack, path traversal и недействительные подписи отклоняются.' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
