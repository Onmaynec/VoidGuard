#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root=Split-Path -Parent $PSScriptRoot
foreach ($module in @('VoidGuard.Protection','VoidGuard.RulePacks','VoidGuard.RuleUpdates')) {
    Import-Module (Join-Path $root "Modules\$module.psm1") -Force -DisableNameChecking
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('VoidGuard-RuleUpdate-'+[guid]::NewGuid().ToString('N'))
$rules=Join-Path $temp 'Rules'
$downloads=Join-Path $temp 'downloads'
$null=New-Item -ItemType Directory -Path $rules -Force
$null=New-Item -ItemType Directory -Path $downloads -Force
$null=New-Item -ItemType Directory -Path (Join-Path $temp 'Config') -Force
$rsa=New-Object Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048
try {
    @([pscustomobject]@{keyId='test-key';publisher='Test Publisher';rsaXml=$rsa.ToXmlString($false)}) |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $rules 'trusted-publishers.json') -Encoding UTF8

    $settings=[pscustomobject]@{
        enabledRulePacks=@('voidguard.core')
        allowUnsignedLocalRulePacks=$false
    }
    $settings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $temp 'Config\settings.json') -Encoding UTF8
    $ctx=[pscustomobject]@{RootPath=$temp;Settings=$settings;Version='0.5.0'}

    function New-TestSignedPack {
        param([string]$Name,[string]$Version,[string]$Content)
        $folder=Join-Path $downloads $Name
        $null=New-Item -ItemType Directory -Path $folder -Force
        $rule=Join-Path $folder 'detections.json'
        [IO.File]::WriteAllText($rule,$Content,(New-Object Text.UTF8Encoding($false)))
        $manifest=[pscustomobject]@{
            schemaVersion=1
            id='example.rules'
            name='Example defensive rules'
            version=$Version
            publisher='Test Publisher'
            trustMode='signed'
            minimumVoidGuardVersion='0.3.0'
            files=@([pscustomobject]@{
                path='detections.json'
                type='pattern'
                sha256=(Get-FileHash -LiteralPath $rule -Algorithm SHA256).Hash
            })
            signature=[pscustomobject]@{
                keyId='test-key'
                algorithm='RSA-SHA256'
                value=''
            }
        }
        $engine=Get-Module VoidGuard.RulePacks
        $payload=& $engine {param($InputManifest) ConvertTo-VoidGuardRulePackPayload -Manifest $InputManifest } $manifest
        $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($payload),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $manifest.signature.value=[Convert]::ToBase64String($sig)
        $manifest | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $folder 'manifest.json') -Encoding UTF8
        return $folder
    }

    $one=New-TestSignedPack -Name 'source-100' -Version '1.0.0' -Content '[]'
    $preview=Get-VGRuleUpdatePreview -SourcePath $one -Context $ctx
    if (-not $preview.CanApply -or $preview.Operation -ne 'INSTALL') { throw "Signed fixture failed: $($preview.Reason)" }
    $before=Install-VGRulePackUpdate -SourcePath $one -Context $ctx
    if ($before.Status -ne 'CONFIRMATION_REQUIRED') { throw 'Rule installation must require explicit confirmation.' }
    $dry=Install-VGRulePackUpdate -SourcePath $one -Context $ctx -Confirmed -WhatIf
    if ($dry.Status -ne 'DRY_RUN') { throw 'WhatIf did not prevent installation.' }
    $dest=Join-Path $temp 'Rules\Packs\example.rules'
    if (Test-Path -LiteralPath $dest) { throw 'WhatIf modified the installed packs.' }

    $installed=Install-VGRulePackUpdate -SourcePath $one -Context $ctx -Confirmed
    if (-not $installed.Success -or $installed.Status -ne 'INSTALLED' -or -not (Test-Path -LiteralPath $dest)) {
        throw "Signed pack install failed: $($installed.Error)"
    }

    $v2=New-TestSignedPack -Name 'source-110' -Version '1.1.0' -Content '[{"id":"TEST-01","pattern":"example","type":"pattern"}]'
    $update=Install-VGRulePackUpdate -SourcePath $v2 -Context $ctx -Confirmed
    if (-not $update.Success -or $update.Status -ne 'UPGRADED' -or -not $update.HistoryId) {
        throw "Signed update and version history failed: $($update.Error)"
    }
    $history=@(Get-VGRulePackUpdateHistory -Context $ctx -PackId 'example.rules')
    if ($history.Count -ne 1 -or -not $history[0].Trusted -or $history[0].Version -ne '1.0.0') {
        throw 'Signed history must contain the verified previous version.'
    }

    $rollbackPreview=Restore-VGRulePackVersion -PackId 'example.rules' -HistoryId $update.HistoryId -Context $ctx
    if ($rollbackPreview.Status -ne 'CONFIRMATION_REQUIRED') { throw 'Rollback requires confirmation.' }
    $rolledBack=Restore-VGRulePackVersion -PackId 'example.rules' -HistoryId $update.HistoryId -Context $ctx -Confirmed
    if (-not $rolledBack.Success -or $rolledBack.Version -ne '1.0.0') {
        throw 'Verified rollback did not restore version 1.0.0.'
    }

    $activationPreview=Set-VGRulePackEnabled -PackId 'example.rules' -Context $ctx -Enabled:$true
    if ($activationPreview.Status -ne 'CONFIRMATION_REQUIRED') { throw 'Rule activation requires confirmation.' }
    $activated=Set-VGRulePackEnabled -PackId 'example.rules' -Context $ctx -Enabled:$true -Confirmed
    if (-not $activated.Success -or -not (@($ctx.Settings.enabledRulePacks) -contains 'example.rules')) {
        throw 'Signed rule pack was not activated.'
    }
    $disk=Get-Content -LiteralPath (Join-Path $temp 'Config\settings.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (@($disk.enabledRulePacks) -contains 'example.rules')) { throw 'Activation was not persisted.' }
    $disabled=Set-VGRulePackEnabled -PackId 'example.rules' -Context $ctx -Enabled:$false -Confirmed
    if (-not $disabled.Success -or (@($ctx.Settings.enabledRulePacks) -contains 'example.rules')) {
        throw 'Deactivation did not persist.'
    }

    # Нельзя принять испорченные файлы или лишние файлы внутри каталога обновления.
    $bad=New-TestSignedPack -Name 'tampered' -Version '2.0.0' -Content '[]'
    'modified' | Set-Content -LiteralPath (Join-Path $bad 'detections.json') -Encoding ASCII
    if ((Get-VGRuleUpdatePreview -SourcePath $bad -Context $ctx).CanApply) {
        throw 'Tampered signed update was accepted.'
    }
    $extra=New-TestSignedPack -Name 'extra' -Version '2.0.0' -Content '[]'
    'unexpected' | Set-Content -LiteralPath (Join-Path $extra 'unexpected.bin') -Encoding ASCII
    if ((Get-VGRuleUpdatePreview -SourcePath $extra -Context $ctx).CanApply) {
        throw 'Undeclared files were accepted.'
    }
    $wrong=New-TestSignedPack -Name 'wrong-sig' -Version '2.0.0' -Content '[]'
    $manifestPath=Join-Path $wrong 'manifest.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifest.signature.value=[Convert]::ToBase64String((New-Object byte[] 256))
    $manifest | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    if ((Get-VGRuleUpdatePreview -SourcePath $wrong -Context $ctx).CanApply) {
        throw 'Invalid RSA signature was accepted.'
    }

    $uncPreview=Get-VGRuleUpdatePreview -SourcePath '\\example.invalid\share\pack' -Context $ctx
    if ($uncPreview.CanApply -or $uncPreview.Status -ne 'BLOCKED') {
        throw 'UNC/network source path was accepted.'
    }

    $coreDenied=$false
    try { $null=Assert-VGRuleUpdateId 'voidguard.core' } catch { $coreDenied=$true }
    if (-not $coreDenied) { throw 'Bundled core was not protected.' }

    Write-Host '[OK] Signed update: preview, WhatIf, install, version history, rollback, activation and hostile fixtures.' -ForegroundColor Green
} finally {
    $rsa.Dispose()
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
