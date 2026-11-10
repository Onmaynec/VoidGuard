#requires -Version 5.1
Set-StrictMode -Version Latest

function New-VGIntegrityRecord {
    param([string]$Key,[AllowEmptyString()][string]$Value)
    [pscustomobject]@{Key=$Key;Value=$Value}
}

function Get-VGIntegritySnapshot {
    [CmdletBinding()]
    param(
        [string[]]$SelectedPaths=@(),
        [ValidateSet('Security','Services','Tasks','Startup','Files')][string[]]$Sections=@('Security','Services','Tasks','Startup','Files'),
        [bool]$IncludeHosts=$true
    )
    if (-not (Test-VoidGuardWindows)) { throw 'System Integrity requires Windows.' }
    if (@($SelectedPaths).Count -gt 128 -or @($Sections).Count -eq 0) { throw 'Invalid snapshot scope.' }
    $result=[ordered]@{}
    $problems=New-Object 'System.Collections.Generic.List[string]'
    foreach ($section in @($Sections | Sort-Object -Unique)) {
        $items=New-Object 'System.Collections.Generic.List[object]'
        $errors=New-Object 'System.Collections.Generic.List[string]'
        try {
            switch ($section) {
                'Security' {
                    $state=Get-VoidGuardSecurityStatus
                    foreach ($key in @('DefenderAvailable','DefenderEnabled','RealTimeProtection','BehaviorMonitor','IoavProtection','FirewallAvailable','UacEnabled','SmartScreenEnabled','UserProxyEnabled')) {
                        $prop=$state.PSObject.Properties[$key]
                        if (-not $prop -or $null -eq $prop.Value) { $errors.Add("Unknown setting: $key"); continue }
                        $items.Add((New-VGIntegrityRecord $key ([string]$prop.Value)))
                    }
                    foreach ($profile in @($state.FirewallProfiles)) {
                        $value=[ordered]@{Enabled=[string]$profile.Enabled;Inbound=[string]$profile.DefaultInboundAction;Outbound=[string]$profile.DefaultOutboundAction}
                        $items.Add((New-VGIntegrityRecord ('Firewall:'+[string]$profile.Name) (ConvertTo-Json -InputObject $value -Compress)))
                    }
                    foreach ($exclusion in @($state.DefenderExclusions)) {
                        if ($exclusion) { $items.Add((New-VGIntegrityRecord ('DefenderExclusion:'+[string]$exclusion) 'PRESENT')) }
                    }
                }
                'Services' {
                    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
                        if (-not $service.Name) { continue }
                        $v=[ordered]@{StartMode=[string]$service.StartMode;Path=[string]$service.PathName;Account=[string]$service.StartName;Type=[string]$service.ServiceType}
                        $items.Add((New-VGIntegrityRecord ([string]$service.Name) (ConvertTo-Json -InputObject $v -Compress)))
                    }
                }
                'Tasks' {
                    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
                        $key=[string]$task.TaskPath+[string]$task.TaskName
                        if (-not $key) { continue }
                        $actions=@($task.Actions | ForEach-Object { [ordered]@{Exe=[string]$_.Execute;Args=[string]$_.Arguments;Directory=[string]$_.WorkingDirectory} })
                        $triggers=@($task.Triggers | ForEach-Object { [ordered]@{Type=[string]$_.CimClass.CimClassName;Enabled=[string]$_.Enabled;Starts=[string]$_.StartBoundary} })
                        $v=[ordered]@{Enabled=[string]$task.Settings.Enabled;Actions=$actions;Triggers=$triggers}
                        $items.Add((New-VGIntegrityRecord $key (ConvertTo-Json -InputObject $v -Compress -Depth 8)))
                    }
                }
                'Startup' {
                    foreach ($entry in @(Get-VoidGuardStartupEntries)) {
                        $key='{0}|{1}|{2}|{3}' -f @([string]$entry.Type,[string]$entry.Scope,[string]$entry.Location,[string]$entry.Name)
                        $items.Add((New-VGIntegrityRecord $key ([string]$entry.Command)))
                    }
                }
                'Files' {
                    $paths=New-Object 'System.Collections.Generic.List[string]'
                    if ($IncludeHosts -and $env:windir) { $paths.Add((Join-Path $env:windir 'System32\drivers\etc\hosts')) }
                    foreach ($selected in @($SelectedPaths)) {
                        if (-not $selected) { continue }
                        if (-not [IO.Path]::IsPathRooted($selected) -or $selected -match '^\\') { $errors.Add("Unsafe file path: $selected"); continue }
                        $full=[IO.Path]::GetFullPath($selected)
                        if (-not $paths.Contains($full)) { $paths.Add($full) }
                    }
                    foreach ($path in $paths.ToArray()) {
                        try {
                            if (Get-VoidGuardPathReparseAncestor -Path $path) { throw 'Reparse point is blocked.' }
                            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                                $items.Add((New-VGIntegrityRecord $path 'MISSING'))
                                continue
                            }
                            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                            if ($item.Length -gt 268435456) { throw 'File exceeds 256 MiB.' }
                            $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                            $items.Add((New-VGIntegrityRecord $path ('SHA256:{0};SIZE:{1}' -f @($hash,[long]$item.Length))))
                        } catch { $errors.Add(('File '+$path+': '+$_.Exception.Message)) }
                    }
                }
            }
        } catch { $errors.Add(($section+': '+$_.Exception.Message)) }
        if ($items.Count -gt 10000) { $errors.Add('Section exceeds 10000 records.') }
        $result[$section]=[pscustomobject]@{
            State=if ($errors.Count -eq 0) { 'COMPLETE' } else { 'PARTIAL' }
            Records=@($items.ToArray() | Sort-Object Key)
            Errors=$errors.ToArray()
        }
        foreach ($err in $errors.ToArray()) { $problems.Add(($section+': '+$err)) }
    }
    [pscustomobject]@{
        SchemaVersion=1;Kind='VoidGuard.SystemIntegrity';Version='0.4.0'
        ComputerName=[string]$env:COMPUTERNAME;CapturedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SectionsRequested=@($Sections | Sort-Object -Unique)
        IncludeHosts=$IncludeHosts;SelectedPaths=@($SelectedPaths | Sort-Object -Unique)
        Complete=($problems.Count -eq 0);Sections=[pscustomobject]$result;Errors=$problems.ToArray()
    }
}

Export-ModuleMember -Function @('Get-VGIntegritySnapshot')
