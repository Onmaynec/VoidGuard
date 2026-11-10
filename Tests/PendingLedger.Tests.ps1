#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\VoidGuard.Protection.psm1') -Force
Import-Module (Join-Path $root 'Modules\VoidGuard.System.psm1') -Force
Import-Module (Join-Path $root 'Modules\VoidGuard.Remediation.psm1') -Force

$scheduled = [datetime]'2026-01-05T10:00:00Z'
$beforeBoot = [datetime]'2026-01-05T08:00:00Z'
$afterBoot = [datetime]'2026-01-05T11:00:00Z'
$record = [pscustomobject]@{ ScheduledUtc = $scheduled; SHA256 = 'A' * 64 }
$cases = @(
    @{ Name = 'No boot time'; Boot = $null; Exists = $false; Hash = $null; Error = $null; Expected = 'VERIFICATION_UNAVAILABLE' },
    @{ Name = 'Before reboot'; Boot = $beforeBoot; Exists = $false; Hash = $null; Error = $null; Expected = 'AWAITING_REBOOT' },
    @{ Name = 'Removed'; Boot = $afterBoot; Exists = $false; Hash = $null; Error = $null; Expected = 'REMOVED_VERIFIED' },
    @{ Name = 'Same file'; Boot = $afterBoot; Exists = $true; Hash = 'A' * 64; Error = $null; Expected = 'STILL_PRESENT' },
    @{ Name = 'Replaced'; Boot = $afterBoot; Exists = $true; Hash = 'B' * 64; Error = $null; Expected = 'REPLACED_OR_RECREATED' },
    @{ Name = 'Unreadable'; Boot = $afterBoot; Exists = $true; Hash = $null; Error = 'Access denied'; Expected = 'VERIFICATION_INCOMPLETE' }
)
foreach ($case in $cases) {
    $decision = Get-VoidGuardPendingRecordState -Record $record -CurrentBootUtc $case.Boot -FileExists:$case.Exists -CurrentHash $case.Hash -HashError $case.Error
    if ($decision.Status -ne $case.Expected) {
        throw "$($case.Name): expected $($case.Expected), got $($decision.Status)"
    }
}
Write-Host '[OK] Верификация Pending Ledger учитывает реальную перезагрузку и ошибки хеширования.' -ForegroundColor Green
