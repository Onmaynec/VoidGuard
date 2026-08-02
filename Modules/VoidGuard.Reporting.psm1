Set-StrictMode -Version Latest

function ConvertTo-VoidGuardHtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [Security.SecurityElement]::Escape([string]$Value)
}

function Get-VoidGuardReportFindings {
    param([Parameter(Mandatory)]$InputObject)

    if ($InputObject.PSObject -and $InputObject.PSObject.Properties['Findings']) {
        return @($InputObject.Findings)
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        return @($InputObject)
    }
    return @()
}

function Get-VoidGuardReportKind {
    param([Parameter(Mandatory)]$InputObject)

    if ($InputObject.PSObject.Properties['Mode']) { return [string]$InputObject.Mode }
    if ($InputObject.PSObject.Properties['ComputerName']) { return 'SecurityStatus' }
    if ($InputObject.PSObject.Properties['Id'] -and $InputObject.PSObject.Properties['Status']) { return 'Remediation' }
    return 'Analysis'
}

function Export-VoidGuardJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    $document = [ordered]@{
        schemaVersion = 1
        product = 'VoidGuard'
        version = $Context.Version
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        computerName = $env:COMPUTERNAME
        reportKind = Get-VoidGuardReportKind -InputObject $InputObject
        data = $InputObject
    }
    $document | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return (Get-Item -LiteralPath $OutputPath).FullName
}

function Export-VoidGuardHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    $kind = Get-VoidGuardReportKind -InputObject $InputObject
    $findings = @(Get-VoidGuardReportFindings -InputObject $InputObject)
    $generated = (Get-Date).ToUniversalTime().ToString('u')
    $rows = New-Object Text.StringBuilder

    foreach ($finding in $findings) {
        $risk = if ($finding.PSObject.Properties['Risk']) { [string]$finding.Risk } else { '' }
        $score = if ($finding.PSObject.Properties['Score']) { [string]$finding.Score } else { '' }
        $path = if ($finding.PSObject.Properties['Path']) { [string]$finding.Path } elseif ($finding.PSObject.Properties['Command']) { [string]$finding.Command } else { [string]$finding }
        $signature = if ($finding.PSObject.Properties['SignatureStatus']) { [string]$finding.SignatureStatus } else { '' }
        $sha = if ($finding.PSObject.Properties['SHA256']) { [string]$finding.SHA256 } else { '' }
        $entropy = if ($finding.PSObject.Properties['Entropy']) { [string]$finding.Entropy } else { '' }
        $reasons = if ($finding.PSObject.Properties['Reasons']) { @($finding.Reasons) -join '; ' } else { '' }
        $yara = if ($finding.PSObject.Properties['YaraMatches']) { @($finding.YaraMatches | ForEach-Object { $_.Rule }) -join ', ' } else { '' }
        $class = switch ($risk) { 'CRITICAL' { 'critical' } 'HIGH' { 'high' } 'MEDIUM' { 'medium' } default { 'low' } }

        [void]$rows.AppendLine(('<tr><td class="{0}">{1}</td><td>{2}</td><td class="path">{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f
            $class,
            (ConvertTo-VoidGuardHtmlText $risk),
            (ConvertTo-VoidGuardHtmlText $score),
            (ConvertTo-VoidGuardHtmlText $path),
            (ConvertTo-VoidGuardHtmlText $signature),
            (ConvertTo-VoidGuardHtmlText $entropy),
            (ConvertTo-VoidGuardHtmlText $sha),
            (ConvertTo-VoidGuardHtmlText $yara),
            (ConvertTo-VoidGuardHtmlText $reasons)))
    }

    $summaryRows = New-Object Text.StringBuilder
    foreach ($property in @($InputObject.PSObject.Properties)) {
        if ($property.Name -eq 'Findings') { continue }
        $value = $property.Value
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $value = @($value).Count
        }
        [void]$summaryRows.AppendLine(('<tr><th>{0}</th><td>{1}</td></tr>' -f
            (ConvertTo-VoidGuardHtmlText $property.Name),
            (ConvertTo-VoidGuardHtmlText $value)))
    }

    $html = @"
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoidGuard $($Context.Version) — $(ConvertTo-VoidGuardHtmlText $kind)</title>
<style>
:root { color-scheme: dark; --bg:#050907; --panel:#0b1410; --line:#1d6b43; --text:#d7ffe8; --muted:#79a98d; --green:#34ff91; --yellow:#ffd166; --red:#ff5c5c; }
* { box-sizing:border-box; }
body { margin:0; background:radial-gradient(circle at top,#102119 0,#050907 48%); color:var(--text); font:14px/1.45 Consolas,"Cascadia Mono",monospace; }
main { max-width:1500px; margin:0 auto; padding:28px; }
header { border:1px solid var(--line); background:rgba(11,20,16,.94); padding:22px; box-shadow:0 0 28px rgba(52,255,145,.09); }
h1 { margin:0; color:var(--green); letter-spacing:.08em; }
.sub { color:var(--muted); margin-top:8px; }
section { margin-top:20px; border:1px solid #173d2a; background:rgba(7,15,11,.92); padding:18px; overflow:auto; }
h2 { color:#7dffb5; margin:0 0 14px; }
table { width:100%; border-collapse:collapse; }
th,td { padding:9px 10px; border-bottom:1px solid #153422; text-align:left; vertical-align:top; }
th { color:#91c8a7; }
.path { max-width:420px; word-break:break-all; }
.critical,.high { color:var(--red); font-weight:700; }
.medium { color:var(--yellow); font-weight:700; }
.low { color:var(--green); }
footer { margin-top:18px; color:var(--muted); }
</style>
</head>
<body>
<main>
<header>
<h1>VOIDGUARD // SECURITY REPORT</h1>
<div class="sub">Version $(ConvertTo-VoidGuardHtmlText $Context.Version) · $(ConvertTo-VoidGuardHtmlText $kind) · generated $generated UTC · host $(ConvertTo-VoidGuardHtmlText $env:COMPUTERNAME)</div>
</header>
<section>
<h2>SUMMARY MATRIX</h2>
<table><tbody>$summaryRows</tbody></table>
</section>
<section>
<h2>FINDINGS [$($findings.Count)]</h2>
<table>
<thead><tr><th>Risk</th><th>Score</th><th>Path / Command</th><th>Signature</th><th>Entropy</th><th>SHA-256</th><th>YARA</th><th>Reasons</th></tr></thead>
<tbody>$rows</tbody>
</table>
</section>
<footer>Offline report. No JavaScript, remote fonts, analytics, or network resources are embedded.</footer>
</main>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return (Get-Item -LiteralPath $OutputPath).FullName
}

function Export-VoidGuardReportBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Json', 'Html', 'Both')][string]$Format = 'Both'
    )

    $full = [IO.Path]::GetFullPath($OutputPath)
    $extension = [IO.Path]::GetExtension($full)
    $basePath = if ($extension) { $full.Substring(0, $full.Length - $extension.Length) } else { $full }
    $outputs = New-Object System.Collections.Generic.List[string]

    if ($Format -in @('Json', 'Both')) {
        $jsonPath = if ($Format -eq 'Json' -and $extension -eq '.json') { $full } else { "$basePath.json" }
        $outputs.Add((Export-VoidGuardJsonReport -InputObject $InputObject -Context $Context -OutputPath $jsonPath))
    }
    if ($Format -in @('Html', 'Both')) {
        $htmlPath = if ($Format -eq 'Html' -and $extension -in @('.html', '.htm')) { $full } else { "$basePath.html" }
        $outputs.Add((Export-VoidGuardHtmlReport -InputObject $InputObject -Context $Context -OutputPath $htmlPath))
    }

    return @($outputs)
}

Export-ModuleMember -Function @(
    'Export-VoidGuardJsonReport',
    'Export-VoidGuardHtmlReport',
    'Export-VoidGuardReportBundle'
)
