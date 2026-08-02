rule VoidGuard_Suspicious_PowerShell_Downloader
{
    meta:
        author = "VoidGuard Project"
        description = "Multiple static indicators associated with scripted download-and-execute chains"
        severity = "high"
    strings:
        $a = "FromBase64String" ascii wide nocase
        $b = "DownloadString" ascii wide nocase
        $c = "Invoke-Expression" ascii wide nocase
        $d = "EncodedCommand" ascii wide nocase
        $e = "Net.WebClient" ascii wide nocase
    condition:
        2 of them
}

rule VoidGuard_Defender_Exclusion_Tamper
{
    meta:
        author = "VoidGuard Project"
        description = "Script content that modifies Microsoft Defender exclusions"
        severity = "high"
    strings:
        $a = "Add-MpPreference" ascii wide nocase
        $b = "Set-MpPreference" ascii wide nocase
        $c = "ExclusionPath" ascii wide nocase
        $d = "DisableRealtimeMonitoring" ascii wide nocase
    condition:
        ($a or $b) and ($c or $d)
}

rule VoidGuard_LOLBin_Remote_Execution
{
    meta:
        author = "VoidGuard Project"
        description = "Static command patterns for common signed-binary proxy execution"
        severity = "medium"
    strings:
        $a = "regsvr32" ascii wide nocase
        $b = "/i:http" ascii wide nocase
        $c = "rundll32" ascii wide nocase
        $d = "javascript:" ascii wide nocase
        $e = "mshta" ascii wide nocase
        $f = "http://" ascii wide nocase
        $g = "https://" ascii wide nocase
    condition:
        ($a and $b) or ($c and $d) or ($e and ($f or $g))
}
