Set-StrictMode -Version Latest

$script:NativeMethodsLoaded = $false

function Test-VoidGuardWindows {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-VoidGuardNativeMethods {
    if ($script:NativeMethodsLoaded -or -not (Test-VoidGuardWindows)) {
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

public static class VoidGuardNative
{
    [DllImport("sfc.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SfcIsFileProtected(IntPtr RpcHandle, string ProtFileName);
}
'@

    try {
        Add-Type -TypeDefinition $source -ErrorAction Stop
        $script:NativeMethodsLoaded = $true
    } catch {
        if ($_.Exception.Message -match 'already exists') {
            $script:NativeMethodsLoaded = $true
        }
    }
}

function Get-VoidGuardCanonicalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    $fullPath = [IO.Path]::GetFullPath($expanded)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    return $item.FullName
}

function Test-VoidGuardWmiProtectedFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-VoidGuardWindows)) {
        return $false
    }

    Initialize-VoidGuardNativeMethods
    if (-not $script:NativeMethodsLoaded) {
        return $false
    }

    try {
        return [VoidGuardNative]::SfcIsFileProtected([IntPtr]::Zero, $Path)
    } catch {
        return $false
    }
}

function Get-VoidGuardSignatureInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $result = [ordered]@{
        Status      = 'Unavailable'
        Subject     = $null
        IsMicrosoft = $false
    }

    if (-not (Test-VoidGuardWindows) -or -not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        return [pscustomobject]$result
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $result.Status = [string]$signature.Status
        if ($signature.SignerCertificate) {
            $result.Subject = [string]$signature.SignerCertificate.Subject
            $result.IsMicrosoft = $result.Subject -match 'Microsoft (Windows|Corporation|Code Signing)'
        }
    } catch {
        $result.Status = 'Error'
    }

    return [pscustomobject]$result
}

function Test-VoidGuardProtectedTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $reasons = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $canonical = $null
    $item = $null

    try {
        $canonical = Get-VoidGuardCanonicalPath -Path $Path
        $item = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
    } catch {
        $reasons.Add("Target cannot be resolved: $($_.Exception.Message)")
        return [pscustomobject]@{
            Path                 = $Path
            CanonicalPath        = $null
            Allowed              = $false
            ConfirmationRequired = $false
            Reasons              = @($reasons)
            Warnings             = @()
            Signature            = $null
        }
    }

    if ($item.PSIsContainer) {
        $reasons.Add('Directory quarantine is disabled in v0.1.0. Select an individual file.')
    }

    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $reasons.Add('Reparse points and symbolic links are blocked to prevent path redirection.')
    }

    $comparison = [StringComparison]::OrdinalIgnoreCase
    $root = [IO.Path]::GetPathRoot($canonical)
    if ([string]::Equals($canonical.TrimEnd('\'), $root.TrimEnd('\'), $comparison)) {
        $reasons.Add('Volume roots cannot be quarantined or removed.')
    }

    $protectedRoots = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $protectedRoots.Add(([IO.Path]::GetFullPath($candidate)).TrimEnd('\'))
        }
    }

    foreach ($protectedRoot in $protectedRoots) {
        if ($canonical.StartsWith($protectedRoot + '\', $comparison) -or [string]::Equals($canonical, $protectedRoot, $comparison)) {
            $reasons.Add("Protected system location: $protectedRoot")
            break
        }
    }

    if (Test-VoidGuardWmiProtectedFile -Path $canonical) {
        $reasons.Add('Windows Resource Protection reports that this file is protected.')
    }

    $signature = Get-VoidGuardSignatureInfo -Path $canonical
    if ($signature.Status -eq 'Valid' -and $signature.IsMicrosoft) {
        $reasons.Add('Valid Microsoft signature detected. Direct remediation is blocked.')
    } elseif ($signature.Status -eq 'Valid') {
        $warnings.Add("Valid third-party signature: $($signature.Subject)")
    }

    if (Test-VoidGuardWindows) {
        try {
            $owner = (Get-Acl -LiteralPath $canonical -ErrorAction Stop).Owner
            if ($owner -match 'TrustedInstaller') {
                $reasons.Add('The file is owned by Windows TrustedInstaller.')
            } elseif ($owner -match 'SYSTEM') {
                $warnings.Add('The file is owned by SYSTEM. Elevated review is required.')
            }
        } catch {
            $warnings.Add('File owner could not be verified.')
        }
    }

    $programData = $env:ProgramData
    $confirmationRequired = $warnings.Count -gt 0
    if ($programData -and $canonical.StartsWith(([IO.Path]::GetFullPath($programData).TrimEnd('\') + '\'), $comparison)) {
        $warnings.Add('ProgramData target: review persistence entries before quarantine.')
        $confirmationRequired = $true
    }

    return [pscustomobject]@{
        Path                 = $Path
        CanonicalPath        = $canonical
        Allowed              = ($reasons.Count -eq 0)
        ConfirmationRequired = $confirmationRequired
        Reasons              = @($reasons)
        Warnings             = @($warnings)
        Signature            = $signature
    }
}

function Get-VoidGuardLockingProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-VoidGuardWindows)) {
        return @()
    }

    $canonical = Get-VoidGuardCanonicalPath -Path $Path
    $matches = New-Object System.Collections.Generic.List[object]

    foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
        try {
            if ($process.Path -and [string]::Equals($process.Path, $canonical, [StringComparison]::OrdinalIgnoreCase)) {
                $matches.Add([pscustomobject]@{
                    Id   = $process.Id
                    Name = $process.ProcessName
                    Path = $process.Path
                })
            }
        } catch {
            # Access to protected processes is expected to fail.
        }
    }

    return @($matches)
}

Export-ModuleMember -Function @(
    'Test-VoidGuardWindows',
    'Get-VoidGuardCanonicalPath',
    'Test-VoidGuardWmiProtectedFile',
    'Get-VoidGuardSignatureInfo',
    'Test-VoidGuardProtectedTarget',
    'Get-VoidGuardLockingProcesses'
)
