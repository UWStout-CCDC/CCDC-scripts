#Requires -RunAsAdministrator

<#
.SYNOPSIS
Download the shed scripts, prepare WinGet, and install the competition tool set.
.DESCRIPTION
Run elevated in Windows PowerShell. Setup prepares C:\Tools and a transcript;
helper functions are defined before main installation begins.

MAIN FLOW
  Step 0 downloads missing shed-hardening.ps1, shed-scraper.ps1, shed-dns.ps1,
  and shed-recovery.ps1 first.
  WinGet setup then reuses an existing copy or tries modern/legacy bootstrapping.
  Step 1 downloads standalone tools and extracts/runs their payloads.
  The Sysinternals EULA is accepted immediately after the suite is extracted.
  Step 2 installs the WinGet package list, with selected direct-download fallbacks.
  Step 3 prints recorded results and updates PATH.

WHAT CHANGES
  This script performs installations; it is not a download-only audit. MSI/EXE
  installers run locally. MSSQL operators can opt into Docker with reboots deferred. Malwarebytes
  is intentionally interactive. Bootstrap may install modules/providers, mark
  PSGallery trusted on Server 2025+, and install the VC++ runtime. Tools,
  permissions, machine PATH, and EULA registry settings can persist after exit.

DOWNLOADS AND OUTPUT
  Direct URL payloads use foreground BITS; package managers use their own network
  mechanisms. Downloads are kept in C:\Tools\downloads; installed/copied tools
  use C:\Tools. Logs are in C:\Tools\logs\install-<timestamp>.log. BITS success
  means a completed nonempty file, not an independent malware/signature verdict.
  WinGet uses --no-vt and console color resets to preserve the black background.
  WinGet candidates require a valid Microsoft signature and trusted owners/ACLs
  before version probes. Unsafe existing portable trees are left unused; a clean
  directory is used for bootstrap. Manual bootstrap downloads must match the SHA-256
  digests from the Microsoft WinGet release. Logs/downloads allow Administrators and SYSTEM.

FAILURES
  There is no automatic rollback. Results are tracked per tool/package; some
  setup/post-install errors are handled separately and are not rows in that table.
.NOTES
Version: 1.2
Release: Post-invitationals updates.

.PARAMETER Branch
Download missing shed scripts from shed-branch. The default branch is master.
.EXAMPLE
.\shed-installs.ps1
.EXAMPLE
.\shed-installs.ps1 -Branch
#>
[CmdletBinding()]
param([switch]$Branch)

function Write-RunHeading {
    param([string]$Title)
    Write-Host
    Write-Host "== $Title ==" -ForegroundColor Cyan -BackgroundColor Black
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO')
    $colors = @{ INFO = 'White'; WARN = 'Yellow'; ERROR = 'Red'; SUCCESS = 'Green' }
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $line -ForegroundColor $colors[$Level] -BackgroundColor Black
}

# Apply black/white colors to both .NET Console and the PowerShell host.
# Native programs do not inherit Write-Host parameter defaults as rendering rules.
function Set-InstallConsoleColors {
    # Write-Host defaults do not control native child-process console output.
    try {
        [Console]::BackgroundColor = [ConsoleColor]::Black
        [Console]::ForegroundColor = [ConsoleColor]::White
    } catch {}
    try {
        $Host.UI.RawUI.BackgroundColor = 'Black'
        $Host.UI.RawUI.ForegroundColor = 'White'
    } catch {}
}

# -----------------------------------------------------------------------------
# Console appearance and native-process color defaults
# -----------------------------------------------------------------------------
try {
    Set-InstallConsoleColors
    if ($Host.PrivateData) {
        $Host.PrivateData.WarningBackgroundColor = 'Black'
        $Host.PrivateData.WarningForegroundColor = 'Yellow'
        $Host.PrivateData.ErrorBackgroundColor   = 'Black'
        $Host.PrivateData.ErrorForegroundColor   = 'Red'
        $Host.PrivateData.VerboseBackgroundColor = 'Black'
        $Host.PrivateData.VerboseForegroundColor = 'Cyan'
        $Host.PrivateData.DebugBackgroundColor   = 'Black'
        $Host.PrivateData.DebugForegroundColor   = 'DarkCyan'
        $Host.PrivateData.ProgressBackgroundColor = 'Black'
        $Host.PrivateData.ProgressForegroundColor = 'White'
    }
    $PSDefaultParameterValues['Write-Host:BackgroundColor'] = 'Black'
    Clear-Host
} catch {}

# Installation, machine PATH/ACL changes, and AppX provisioning require elevation.
# Keep early errors visible in the console rather than attempting partial setup.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log 'Run this script as Administrator.' ERROR
    Write-Host "" -BackgroundColor Black
    Read-Host "Press Enter to exit"
    exit 1
}

# Keep console window open on terminating errors
trap {
    Write-Log $_.Exception.Message ERROR
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Script encountered an error. Press Enter to exit"
    break
}

# Keep scripts/tool copies, cached payloads, and transcripts in separate
# subdirectories. Changing the working directory also avoids network-share cwd issues.
$InstallDir = "C:\Tools"
$DownloadsDir = "$InstallDir\downloads"
$LogsDir = "$InstallDir\logs"

# global preferences to stop catch errors and hide progress bars
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Disable native command terminating errors in modern PowerShell so tools like robocopy (exit code 1 = success) do not throw
if (Test-Path variable:global:PSNativeCommandUseErrorActionPreference) {
    $global:PSNativeCommandUseErrorActionPreference = $false
}
$PSNativeCommandUseErrorActionPreference = $false
# TLS 1.2 for REST/package-manager requests; BITS uses Windows networking settings.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-installs.ps1              |
     | ,      ,_ `\_/~\-           |    made for MWCCDC 2026-27' qualifiers     |
     >/'>/ ~|||`\( ,~\-            |     v1.2 - post-invitationals updates      |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black

# Kept in each standalone script so downloaded copies need no companion module.
function Get-TrustedOwnerSids {
    @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
}

# Check ownership, write permissions, and every ancestor without following links.
# A trusted signature alone cannot prevent DLL loading from a writable directory.
function Test-TrustedPath {
    param([string]$Path, [switch]$Recurse)
    try {
        $trusted = @(Get-TrustedOwnerSids)
        $writeRights = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $pending = [Collections.Generic.Stack[object]]::new()
        $pending.Push($item)
        if ($Recurse -and $item.PSIsContainer) {
            # Enumerate manually: do not recurse through a junction before checking it.
            $directories = [Collections.Generic.Stack[object]]::new()
            $directories.Push($item)
            while ($directories.Count) {
                foreach ($child in @(Get-ChildItem -LiteralPath $directories.Pop().FullName -Force -ErrorAction Stop)) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
                    $pending.Push($child)
                    if ($child.PSIsContainer) { $directories.Push($child) }
                }
            }
        }
        $parent = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
        # Drive-root create-folder permissions do not grant access to existing
        # protected children. Check every directory below the drive root.
        while ($parent -and $parent.Parent) { $pending.Push($parent); $parent = $parent.Parent }
        while ($pending.Count) {
            $current = $pending.Pop()
            if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $acl = Get-Acl -LiteralPath $current.FullName -ErrorAction Stop
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { return $false }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and
                    ($rule.FileSystemRights -band $writeRights) -and $rule.IdentityReference.Value -notin $trusted) { return $false }
            }
        }
        return $true
    } catch { return $false }
}

# Create a directory with an explicit ACL before writing tools or sensitive reports.
# Reject linked paths/foreign ownership; retain existing directory contents.
function Initialize-Directory {
    param([string]$Path, [switch]$Private)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = [IO.DirectoryInfo]::new($fullPath)
    $trustedOwners = @(Get-TrustedOwnerSids)
    while ($parent -and $parent.Parent) {
        if (Test-Path -LiteralPath $parent.FullName) {
            $existing = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
            if (-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Refusing linked/non-directory workspace: $($parent.FullName)"
            }
            $owner = (Get-Acl -LiteralPath $parent.FullName -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($owner -notin $trustedOwners) { throw "Untrusted workspace owner at $($parent.FullName). Use a clean Administrator-owned directory." }
        }
        $parent = $parent.Parent
    }
    $null = New-Item -ItemType Directory -Path $fullPath -Force -ErrorAction Stop
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if (-not $Private) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $fullPath -AclObject $security -ErrorAction Stop
    if (-not (Test-TrustedPath $fullPath)) { throw "Workspace permission verification failed: $fullPath" }
    $verified = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
    if (-not $verified.AreAccessRulesProtected) { throw "Workspace still inherits permissions: $fullPath" }
    if ($Private) {
        foreach ($rule in $verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
                throw "Private workspace has unexpected access: $fullPath"
            }
        }
    }
}

# Create install directory for tools
Write-Log "Creating install directory at $InstallDir"
# Check the old tree BEFORE tightening its parent ACL. Fixing permissions does
# not make binaries previously writable by another user trustworthy.
$script:PortableWingetDirectory = Join-Path $InstallDir 'winget'
$script:RejectedWingetDirectories = @()
if ((Test-Path -LiteralPath $script:PortableWingetDirectory) -and
    -not (Test-TrustedPath $script:PortableWingetDirectory -Recurse)) {
    $script:RejectedWingetDirectories += $script:PortableWingetDirectory
    Write-Warning "Existing portable WinGet tree is untrusted; leaving it unused: $script:PortableWingetDirectory"
    $script:PortableWingetDirectory = Join-Path $InstallDir "winget-clean-$([guid]::NewGuid().ToString('N'))"
}
$env:Path = (@($env:Path -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -notin $script:RejectedWingetDirectories }) -join ';')
Initialize-Directory $InstallDir
Initialize-Directory $LogsDir -Private
Initialize-Directory $DownloadsDir -Private
Set-Location -Path $InstallDir
[System.IO.Directory]::SetCurrentDirectory($InstallDir)

# Log everything from CLI to file (safely ignore if a transcript is already running)
$script:TranscriptPath = "$LogsDir\install-$(Get-Date -f yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N')).log"
try {
    Start-Transcript -Path $script:TranscriptPath -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not start transcript (an existing transcript may already be active): $($_.Exception.Message)"
}

# Role Detection: Domain Controller & MSSQL Server
$isDC = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
    if ($os -and $os.ProductType -eq 2) { $isDC = $true }
} catch {}

if (-not $isDC -and (Get-Service -Name NTDS -ErrorAction SilentlyContinue)) {
    $isDC = $true
}

$sqlServices = @('MSSQLSERVER', 'MSSQL$*', 'SQLSERVER*', 'SQLBrowser')
$foundSqlSvc = foreach ($s in $sqlServices) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) { $svc; break }
}
$isMSSQL = [bool]$foundSqlSvc -or [bool](Get-Process -Name sqlservr -ErrorAction SilentlyContinue)

Write-Log "Domain controller: $isDC. SQL Server detected: $isMSSQL."

# Build the standalone download queue now; these entries do not download or
# execute until the main installation flow reaches the standalone-tools loop.
$Downloads = [System.Collections.Generic.List[hashtable]]::new()

# Sysinternals Suite is always directly downloaded & extracted to C:\Tools\Sysinternals
Write-Log "Queuing Sysinternals Suite for direct download."
$Downloads.Add(@{
    Name = 'Sysinternals'
    Url  = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
})

Write-Log "Queuing the interactive Npcap setup wizard."
# The public installer uses a wizard. Preselect WinPcap compatibility in the GUI.
$Downloads.Add(@{
    Name        = 'Npcap'
    Url         = 'https://npcap.com/dist/npcap-1.90.exe'
    InstallArgs = '/winpcap_mode=yes'
})

# -----------------------------------------------------------------------------
# Log one start and outcome per operation so the console and transcript agree.
function Invoke-WithStatus {
    param(
        [Parameter(Mandatory=$true)][string]$StatusText,
        [Parameter(Mandatory=$true)][string]$DoneText,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    Write-Log $StatusText
    try {
        & $ScriptBlock @ArgumentList
    } catch {
        Write-Log "${StatusText} failed: $($_.Exception.Message)" WARN
        throw
    }
    Write-Log $DoneText SUCCESS
}

# Download one URL through BITS and return exactly true/false to the caller.
# Publish a nonempty staged file only on success; cleanup is limited to this job/temp path.
function Invoke-BitsDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [string]$Description = (Split-Path -Leaf $OutFile)
    )

    # Unique names prevent cleanup from canceling another application's BITS
    # job or overwriting its partial download. Existing final files survive a failed transfer.
    $jobName = "shed-installs-$([guid]::NewGuid())"
    $partialPath = $null
    try {
        # BITS is a Windows service. Enable Manual startup only if disabled,
        # then start it if needed; do not restart a service that is already running.
        Import-Module BitsTransfer -ErrorAction Stop
        $bits = Get-Service -Name BITS -ErrorAction Stop
        if ($bits.StartType -eq 'Disabled') {
            Write-Log 'BITS was disabled; enabling Manual startup for downloads.' 'INFO'
            Set-Service -Name BITS -StartupType Manual -ErrorAction Stop
        }
        if ($bits.Status -ne 'Running') { Start-Service -Name BITS -ErrorAction Stop }

        # Download beside the final destination under a unique temporary name.
        # Callers must honor the Boolean result before executing/extracting the final path.
        $destination = [IO.Path]::GetFullPath($OutFile)
        $parent = [IO.Path]::GetDirectoryName($destination)
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        $partialPath = Join-Path $parent (".$([IO.Path]::GetFileName($destination)).$([guid]::NewGuid()).partial")
        Invoke-WithStatus "Downloading $Description via BITS" "Downloaded $Description via BITS" {
            param($source, $temporaryPath, $finalPath, $displayName, $label)
            # Synchronous Foreground transfers complete before installation starts.
            # Bound transient-error retries instead of using BITS' 14-day default.
            Start-BitsTransfer -Source $source -Destination $temporaryPath -TransferType Download `
                -Priority Foreground -DisplayName $displayName -Description $label `
                -RetryInterval 60 -RetryTimeout 180 -ErrorAction Stop | Out-Null
            if (-not (Test-Path -LiteralPath $temporaryPath -PathType Leaf) -or
                (Get-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop).Length -le 0) {
                throw 'BITS did not produce a nonempty download.'
            }
            Move-Item -LiteralPath $temporaryPath -Destination $finalPath -Force -ErrorAction Stop
        } @($Url, $partialPath, $destination, $jobName, $Description)
        return $true
    } catch {
        Write-Log "BITS download failed for $Description`: $($_.Exception.Message)" 'ERROR'
        # A failed synchronous transfer may leave a queued job. Remove only this
        # request's uniquely named job; other BITS jobs are never canceled.
        try {
            Get-BitsTransfer -ErrorAction Stop | Where-Object DisplayName -EQ $jobName |
                Remove-BitsTransfer -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "Could not check/clean up BITS job $jobName`: $($_.Exception.Message)" 'WARN'
        }
        return $false
    } finally {
        if ($partialPath -and (Test-Path -LiteralPath $partialPath)) {
            try { Remove-Item -LiteralPath $partialPath -Force -ErrorAction Stop }
            catch { Write-Log "Could not remove partial download $partialPath`: $_" 'WARN' }
        }
    }
}

# Extract an archive, preferring installed 7-Zip and falling back to Expand-Archive.
# Extraction writes into the requested destination; callers choose whether/how to install it.
function Expand-FastArchive {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$DestinationPath
    )
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Try 7-Zip if installed
    $7z = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($7z) {
        $p = Start-Process -FilePath $7z -ArgumentList "x", "-y", "`"-o$DestinationPath`"", "`"$Path`"" -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -eq 0) {
            [System.GC]::Collect()
            return
        }
    }

    # Fallback to Expand-Archive with explicit garbage collection
    Expand-Archive -Path $Path -DestinationPath $DestinationPath -Force
    [System.GC]::Collect()
}

# Validate Microsoft Authenticode identity without executing the candidate.
function Test-MicrosoftSignedBinary {
    param([string]$Path)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($signature.Status -eq 'Valid' -and $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)')
    } catch { return $false }
}

# Check ACLs/owner throughout the binary directory and reject earlier unsafe
# trees, then verify Microsoft's signature BEFORE running even --version.
function Test-WingetExecutable {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    foreach ($rejected in $script:RejectedWingetDirectories) {
        if ([IO.Path]::GetFullPath($Path).StartsWith($rejected.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    if (-not (Test-TrustedPath (Split-Path $Path -Parent) -Recurse) -or
        -not (Test-MicrosoftSignedBinary $Path)) {
        Write-Warning "Skipping untrusted or non-Microsoft WinGet candidate: $Path"
        return $false
    }
    Set-InstallConsoleColors
    try {
        try {
            $p = Start-Process -FilePath $Path -ArgumentList '--version', '--no-vt' -NoNewWindow -Wait -PassThru -ErrorAction Stop
            if ($p.ExitCode -eq 0) { return $true }
        } catch {}

        try {
            $out = & $Path --version --no-vt 2>&1
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch {}

        return $false
    } finally { Set-InstallConsoleColors }
}

# Search standard, app-alias, staged-package, and local portable locations in order.
# Return the first candidate passing the version check, or no path when none works.
function Get-WingetPath {
    # 1. In existing PATH
    foreach ($cmd in @(Get-Command winget -CommandType Application -All -ErrorAction SilentlyContinue)) {
        if (Test-WingetExecutable $cmd.Source) { return $cmd.Source }
    }

    # 2. Local tool installation
    $local = Join-Path $script:PortableWingetDirectory 'winget.exe'
    if (Test-WingetExecutable $local) { return $local }

    # 3. User app execution alias
    $alias = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
    if (Test-WingetExecutable $alias) { return $alias }

    # 4. Search WindowsApps for staged DesktopAppInstaller
    $appxDir = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -Last 1
    if ($appxDir) {
        $candidate = Join-Path $appxDir.FullName 'winget.exe'
        if (Test-Path $candidate) {
            if (Test-WingetExecutable $candidate) { return $candidate }
        }
    }

    # 5. AppxPackage InstallLocation
    $pkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($pkg -and $pkg.InstallLocation) {
        $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
        if (Test-Path $candidate) {
            if (Test-WingetExecutable $candidate) { return $candidate }
        }
    }

    # 6. Portable Program Files directory
    $prog = "$env:ProgramFiles\Microsoft\winget\winget.exe"
    if (Test-WingetExecutable $prog) { return $prog }

    return $null
}

# Copy staged WinGet files into C:\Tools\winget, ensure the VC++ runtime is available,
# and set permissions for elevated use. The caller adds a verified executable to PATH.
function Install-WingetLocal {
    param([string]$SourceDir)

    $dest = $script:PortableWingetDirectory
    Initialize-Directory $dest -Private

    if (-not $SourceDir) {
        $pkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation -and (Test-Path $pkg.InstallLocation)) {
            $SourceDir = $pkg.InstallLocation
        }
        else {
            $found = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue |
                Sort-Object Name | Select-Object -Last 1
            if ($found) { $SourceDir = $found.FullName }
        }
    }

    if ($SourceDir -and (Test-Path $SourceDir)) {
        # Read from WindowsApps using backup-mode copy instead of taking
        # ownership/changing the installed package's original directory permissions.
        # Robocopy with /B (backup operator mode to safely copy without modifying WindowsApps ACLs)
        robocopy $SourceDir $dest /B /E /MT:2 /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "WinGet copy failed (robocopy exit $LASTEXITCODE)." }
    }

    Install-WingetRuntime
    if (-not (Test-TrustedPath $dest -Recurse)) { throw 'Portable WinGet directory failed permission verification.' }

    # The caller locates and verifies winget.exe before adding it to PATH.
}

function Install-WingetRuntime {
    # Ensure VC++ Redistributable is installed (required by standalone winget runtime)
    $vcKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
    $hasVc = (Test-Path $vcKey) -and ((Get-ItemProperty -Path $vcKey -Name Installed -ErrorAction SilentlyContinue).Installed -eq 1)
    if (-not $hasVc) {
        $vc = "$DownloadsDir\vc_redist.x64.exe"
        $vcAvailable = (Test-TrustedPath $vc) -and (Test-MicrosoftSignedBinary $vc)
        if (-not $vcAvailable) {
            $vcAvailable = Invoke-BitsDownload 'https://aka.ms/vs/17/release/vc_redist.x64.exe' $vc 'VC++ Redistributable'
        }
        if ($vcAvailable) {
            if (-not (Test-TrustedPath $vc) -or -not (Test-MicrosoftSignedBinary $vc)) {
                throw 'VC++ runtime installer failed trust/signature verification.'
            }
            Invoke-WithStatus "Installing VC++ Redistributable" "Installed VC++ Redistributable" {
                param($exe)
                $process = Start-Process $exe -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
                if ($process.ExitCode -notin 0, 3010) { throw "VC++ runtime installer exited with code $($process.ExitCode)." }
            } @($vc)
        }
    }
}

function Save-WingetReleaseAsset {
    param($Asset, [string]$Destination)
    if (@($Asset).Count -ne 1 -or $Asset.digest -notmatch '^sha256:[0-9a-f]{64}$' -or
        $Asset.browser_download_url -notlike 'https://github.com/microsoft/winget-cli/releases/download/*') {
        throw "Missing verified WinGet release metadata for $Destination."
    }
    if (-not (Invoke-BitsDownload $Asset.browser_download_url $Destination $Asset.name)) { throw "Download failed: $($Asset.name)" }
    $hash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256 -ErrorAction Stop).Hash
    if ("sha256:$hash" -ne $Asset.digest) { throw "SHA-256 mismatch: $($Asset.name)" }
}

function Publish-PortableWinget {
    param([string]$Bundle, [string[]]$Dependencies, [string]$Work, [string]$Destination)
    $unpacked = Join-Path $Work 'bundle'
    $staged = Join-Path $Work 'portable'
    [IO.Compression.ZipFile]::ExtractToDirectory($Bundle, $unpacked)
    $engine = @(Get-ChildItem -LiteralPath $unpacked -File -Filter '*x64*.msix' | Where-Object Name -NotMatch 'stub')
    if ($engine.Count -ne 1) { throw 'Cannot identify one x64 WinGet engine package.' }
    [IO.Compression.ZipFile]::ExtractToDirectory($engine[0].FullName, $staged)
    foreach ($dependency in $Dependencies) {
        # Each AppX has its own manifest and metadata. Merge missing runtime
        # files only after that dependency has fully extracted.
        $expanded = Join-Path $Work ([guid]::NewGuid().ToString('N'))
        [IO.Compression.ZipFile]::ExtractToDirectory($dependency, $expanded)
        foreach ($file in Get-ChildItem -LiteralPath $expanded -Recurse -File) {
            $target = Join-Path $staged $file.FullName.Substring($expanded.Length + 1)
            if ([IO.File]::Exists($target)) { continue }
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            [IO.File]::Copy($file.FullName, $target)
        }
    }
    if (-not (Test-WingetExecutable (Join-Path $staged 'winget.exe'))) { throw 'Staged WinGet failed its permissions, signature or version check.' }
    # Both paths are under C:\Tools. Directory.Move publishes the complete
    # tree in one rename and refuses to overwrite an existing installation.
    [IO.Directory]::Move($staged, $Destination)
    $script:PortableWingetDirectory = $Destination
    return (Join-Path $Destination 'winget.exe')
}

# Older servers may reject AppX registration of the Windows App Runtime.
# Extract verified x64 packages privately and run the candidate's version check.
function Install-PortableWinget {
    Write-Log 'Trying portable WinGet from verified Microsoft release packages'
    $work = $null
    try {
        Install-WingetRuntime
        $attempt = [guid]::NewGuid().ToString('N')
        $work = (New-Item -ItemType Directory -Path (Join-Path $DownloadsDir "winget-bootstrap-$attempt") -ErrorAction Stop).FullName
        $release = Invoke-RestMethod 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 15 -ErrorAction Stop
        $bundle = Join-Path $work 'winget.msixbundle'
        $depsZip = Join-Path $work 'winget-deps.zip'
        Save-WingetReleaseAsset ($release.assets | Where-Object name -EQ 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle') $bundle
        Save-WingetReleaseAsset ($release.assets | Where-Object name -EQ 'DesktopAppInstaller_Dependencies.zip') $depsZip
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $depsRoot = Join-Path $work 'dependencies'
        [IO.Compression.ZipFile]::ExtractToDirectory($depsZip, $depsRoot)
        $depsPath = Join-Path $depsRoot 'x64'
        if (-not (Test-Path -LiteralPath $depsPath)) { $depsPath = $depsRoot }
        $deps = @(Get-ChildItem -LiteralPath $depsPath -File | Where-Object { $_.Extension -in '.appx', '.msix' } | Select-Object -ExpandProperty FullName)

        return (Publish-PortableWinget $bundle $deps $work (Join-Path $InstallDir "winget-ready-$attempt"))
    }
    catch {
        Write-Log "Portable WinGet setup failed: $($_.Exception.Message)" ERROR
        return $null
    } finally {
        if ($work -and (Test-Path -LiteralPath $work)) {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Continue
        }
    }
}

# On Server 2019/2022 the portable path avoids AppX deployment entirely.
# Server 2025 starts at build 26100 and supports the packaged repair client.
function Initialize-Winget {
    param([int]$Build)
    $path = Get-WingetPath
    if ($path) { return $path }

    if ($Build -ge 26100) {
        try {
            if (-not (Get-Module -Name Microsoft.WinGet.Client)) {
                if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                    Install-Module -Name Microsoft.WinGet.Client -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
                }
                Import-Module Microsoft.WinGet.Client -ErrorAction Stop
            }
            Invoke-WithStatus "Running Repair-WinGetPackageManager on build $Build (this may lag)" 'Completed WinGet package manager repair' {
                Microsoft.WinGet.Client\Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop | Out-Null
            }
            $path = Get-WingetPath
            if ($path) { return $path }
            Install-WingetLocal
            $path = Get-WingetPath
            if ($path) { return $path }
        } catch { Write-Warning "Packaged WinGet repair failed: $_" }
    } else {
        Write-Log "Server build $Build uses the portable WinGet setup."
    }
    return (Install-PortableWinget)
}

# WFC setup stays open unless told to close. A WinGet manifest may also
# launch the tray UI. Supply the same vendor switches on both install paths.
function Invoke-FirewallControlSetup {
    param([string]$FilePath, [string[]]$WingetArguments)
    $setupArgs = if (Get-Service -Name wfcs -ErrorAction SilentlyContinue) { '-update -close' } else { '-install -close' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.Arguments = if ($WingetArguments) {
        ($WingetArguments -join ' ') + ' --override "' + $setupArgs + '"'
    } else { $setupArgs }

    # Wait for setup (or WinGet) to return its exit code. Tray processes can
    # outlive the installer and should never hold up the remaining packages.
    $process = [Diagnostics.Process]::Start($start)
    try {
        $process.WaitForExit()
        return $process.ExitCode
    } finally { $process.Dispose() }
}

# MAIN EXECUTION: helpers above are ready; the shed scripts are fetched before
# WinGet bootstrap and before any standalone tool or application install.
try {
    # 0. Fetch the shed scripts before WinGet bootstrap or any tool installation.
    Write-RunHeading 'Competition scripts'
    Write-Log "Checking for shed-hardening, shed-scraper, shed-dns, and shed-recovery in $InstallDir."
    $scriptBranch = if ($Branch) { 'shed-branch' } else { 'master' }
    $repo = "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/$scriptBranch/windows"
    foreach ($script in @("shed-hardening.ps1", "shed-scraper.ps1", "shed-dns.ps1", "shed-recovery.ps1")) {
        $target = "$InstallDir\$script"
        if (-not (Test-Path $target)) {
            $downloadSucceeded = Invoke-BitsDownload "$repo/$script" $target
            if (-not $downloadSucceeded) { Write-Warning "Could not fetch $script via BITS." }
        }
    }

    if ($isMSSQL -and -not $isDC) {
        $dockerChoice = Read-Host 'Install Docker CE on this SQL host and defer any required reboot? [Y/N] (Enter = N)'
        if ($dockerChoice.Trim() -in @('y', 'yes')) {
            $Downloads.Add(@{
                Name = 'Docker'
                Url  = 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1'
            })
        }
    }

    Write-RunHeading 'WinGet setup'
    $wingetPath = Initialize-Winget -Build ([Environment]::OSVersion.Version.Build)

    if ($wingetPath) {
        Write-Log "WinGet executable: $wingetPath" SUCCESS
        # Ensure winget directory is in current session path
        $wDir = Split-Path -Parent $wingetPath
        if ($wDir -and $env:Path -notlike "*$wDir*") { $env:Path = "$wDir;$env:Path" }

        try {
            Set-InstallConsoleColors
            $null = & $wingetPath --version --no-vt
            # Initialize / update community source index
            Write-Log "Initializing winget package source"
            & $wingetPath source update --disable-interactivity --no-vt 2>&1 | Out-Null
        } catch {
            Write-Warning "Could not execute winget version check: $($_.Exception.Message)"
        } finally { Set-InstallConsoleColors }
    }
    else {
        Write-Log "WinGet is unavailable. Direct installers will be used where available." WARN
    }

    #----------------------------------------------------------
    # SEQUENTIAL INSTALLATION & DOWNLOAD PIPELINE
    #----------------------------------------------------------
    # The result table begins here. It covers standalone tools and package
    # installs, not every prior bootstrap or later post-install operation.
    $jobResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Process Standalone Tool Downloads & Extractions
    Write-RunHeading 'Standalone tools'
    foreach ($d in $Downloads) {
        $name = $d.Name
        $url = $d.Url
        $installArgs = $d.InstallArgs

        $filename = Split-Path -Leaf $url
        if (-not $filename -or $filename -notlike "*.*") {
            $filename = if ($installArgs) { "$name.exe" } else { "$name.dat" }
        }
        $outFile = Join-Path $DownloadsDir $filename

        # A stale file may exist from an earlier run. Never use its existence
        # as evidence that the current download succeeded.
        $downloadSucceeded = Invoke-BitsDownload $url $outFile "$name ($filename)"

        if ($downloadSucceeded -and (Test-Path -LiteralPath $outFile) -and (Get-Item -LiteralPath $outFile).Length -gt 0) {
            # Extract archive if zip
            if ($filename -like "*.zip") {
                $extractPath = Join-Path $InstallDir $name
                Write-Log "[$name] Extracting archive to $extractPath"
                try {
                    Expand-FastArchive -Path $outFile -DestinationPath $extractPath
                    Write-Log "[$name] Archive extracted successfully." SUCCESS
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Success"
                        Details = "Extracted to $extractPath"
                    })
                } catch {
                    Write-Warning "[$name] Archive extraction failed: $($_.Exception.Message)"
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Failed"
                        Details = "Extraction error: $($_.Exception.Message)"
                    })
                    continue
                }
                if ($name -eq 'Sysinternals') {
                    foreach ($key in @('HKCU:\Software\Sysinternals', 'HKLM:\SOFTWARE\Sysinternals')) {
                        try {
                            if (-not (Test-Path $key)) { New-Item -Path $key -Force -ErrorAction Stop | Out-Null }
                            Set-ItemProperty -Path $key -Name 'EulaAccepted' -Value 1 -Type DWord -Force -ErrorAction Stop
                            Write-Log "Sysinternals EULA accepted at $key." SUCCESS
                        } catch { Write-Warning "Could not record Sysinternals EULA acceptance at ${key}: $_" }
                    }
                }
            }
            elseif ($name -eq 'Docker') {
                try {
                    $windowsPowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                    $proc = Start-Process -FilePath $windowsPowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$outFile`" -NoRestart" -Wait -PassThru
                    if ($proc.ExitCode -notin 0, 3010) { throw "Installer exited with code $($proc.ExitCode)." }
                    $dockerService = Get-Service -Name docker -ErrorAction SilentlyContinue
                    if ($dockerService.Status -ne 'Running') {
                        throw 'Docker service is missing or stopped. Check whether Containers requires a reboot, then rerun setup.'
                    }
                    $jobResults.Add([PSCustomObject]@{ JobName=$name; Status='Success'; Details='Docker service verified running' })
                } catch {
                    Write-Warning "Docker installation needs attention: $_"
                    $jobResults.Add([PSCustomObject]@{ JobName=$name; Status='Failed'; Details=$_.Exception.Message })
                }
            }
            # Wait for the interactive installer before starting the next tool.
            elseif ($installArgs) {
                try {
                    Write-Log "Complete the $name setup wizard to continue."
                    $proc = Start-Process -FilePath $outFile -ArgumentList $installArgs -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -eq 1 -and $name -eq 'Npcap') { throw 'Npcap setup was canceled.' }
                    if ($proc.ExitCode -notin 0, 3010) { throw "Installer exited with code $($proc.ExitCode)." }
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Success"
                        Details = $(if ($proc.ExitCode -eq 3010) { 'Installed; reboot required' } else { 'Installed' })
                    })
                } catch {
                    Write-Warning "[$name] Installation failed: $($_.Exception.Message)"
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Failed"
                        Details = "$($_.Exception.Message)"
                    })
                }
            }
            else {
                $jobResults.Add([PSCustomObject]@{
                    JobName = $name
                    Status  = "Success"
                    Details = "Downloaded to $outFile"
                })
            }
        } else {
            $jobResults.Add([PSCustomObject]@{
                JobName = $name
                Status  = "Failed"
                Details = "Download failed"
            })
        }
    }

    # 2. Process WinGet Package Installations
    Write-RunHeading 'Application packages'
    if ($wingetPath) {
        # These are package identifiers, not executable names. Keep --exact
        # matching for normal installs; WFC has a deliberate second-attempt name fallback.
        $packages = @('Mozilla.Firefox', '7zip.7zip', 'BiniSoft.WindowsFirewallControl', 'Malwarebytes.Malwarebytes')
        Write-Log "Installing packages sequentially via winget: $($packages -join ', ')"

        $maxRetries = 2
        $retryDelay = 3

        foreach ($pkgId in $packages) {
            Write-Log "[$pkgId] Starting WinGet installation"
            $installed = $false
            $lastCode = 0

            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                Write-Log "[$pkgId] (Attempt $attempt/$maxRetries) Running winget install"
                
                # Malwarebytes is interactive so the operator can manually work through it
                if ($pkgId -match 'Malwarebytes') {
                    $wingetArgs = @('install', '--id', $pkgId, '--exact', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements')
                } elseif ($attempt -eq 2 -and $pkgId -match 'WindowsFirewallControl') {
                    # Broaden search if exact ID was not found on first attempt
                    # Start-Process flattens argument arrays; retain native quotes
                    # around this multiword name in the resulting command line.
                    $wingetArgs = @('install', '--name', '"Windows Firewall Control"', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                } else {
                    $wingetArgs = @('install', '--id', $pkgId, '--exact', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                }
                
                # WinGet's VT reset sequences can restore the console's original
                # blue background. Plain native output retains our black theme.
                $wingetArgs += '--no-vt'
                Set-InstallConsoleColors
                try {
                    if ($pkgId -eq 'BiniSoft.WindowsFirewallControl') {
                        $lastCode = Invoke-FirewallControlSetup $wingetPath $wingetArgs
                    } else {
                        $proc = Start-Process -FilePath $wingetPath -ArgumentList $wingetArgs -NoNewWindow -Wait -PassThru
                        $lastCode = $proc.ExitCode
                    }
                } catch {
                    $lastCode = -1
                } finally { Set-InstallConsoleColors }

                # 0 is success; 3010 is success with a restart requested.
                # Verification below tries winget list, but exit-code success is
                # still recorded even when the list verification cannot confirm the package.
                if ($lastCode -in 0, 3010) {
                    # Validate installation via winget list
                    $isVerified = $false
                    try {
                        $listOut = & $wingetPath list --id $pkgId --exact --disable-interactivity --no-vt 2>&1
                        if ($LASTEXITCODE -eq 0 -and "$listOut" -match [regex]::Escape($pkgId)) {
                            $isVerified = $true
                        }
                    } catch {} finally { Set-InstallConsoleColors }

                    if ($isVerified) {
                        Write-Log "[$pkgId] Installation verified by WinGet" SUCCESS
                        $details = "Installed & verified via winget"
                    } else {
                        Write-Log "[$pkgId] Installer returned success (exit code $lastCode). WinGet could not verify the package." SUCCESS
                        $details = "Installed via winget"
                    }

                    if ($lastCode -eq 3010) { $details += '. Restart required.' }
                    $installed = $true
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $pkgId
                        Status  = "Success"
                        Details = $details
                    })
                    break
                } else {
                    if ($attempt -lt $maxRetries) {
                        Write-Warning "[$pkgId] Winget returned code $lastCode. Retrying in ${retryDelay}s..."
                        Start-Sleep -Seconds $retryDelay
                    }
                }
            }

            # Failure of one package does not undo previous installs. Only the
            # listed products have a direct-installer fallback; others retain a failed result.
            # Direct fallback if winget installation failed
            if (-not $installed) {
                Write-Warning "[$pkgId] Winget install failed (exit code $lastCode). Triggering direct fallback..."
                if ($pkgId -match 'Firefox') {
                    try {
                        $targetExe = Join-Path $DownloadsDir "FirefoxInstaller.exe"
                        $downloadSucceeded = Invoke-BitsDownload 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' $targetExe 'Firefox direct installer'
                        if ($downloadSucceeded -and (Test-Path -LiteralPath $targetExe)) {
                            $proc = Start-Process -FilePath $targetExe -ArgumentList '/S' -Wait -PassThru
                            if ($proc.ExitCode -in 0, 3010) {
                                Write-Log "[$pkgId] Firefox installed directly via silent installer" SUCCESS
                                $installed = $true
                                $jobResults.Add([PSCustomObject]@{
                                    JobName = $pkgId
                                    Status  = "Success"
                                    Details = "Installed via direct installer"
                                })
                            }
                        }
                    } catch {
                        Write-Warning "Firefox direct install failed: $($_.Exception.Message)"
                    }
                }
                elseif ($pkgId -match '7zip') {
                    try {
                        $targetMsi = Join-Path $DownloadsDir "7z-x64.msi"
                        $downloadSucceeded = Invoke-BitsDownload 'https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi' $targetMsi '7-Zip direct MSI'
                        if ($downloadSucceeded -and (Test-Path -LiteralPath $targetMsi)) {
                            $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$targetMsi`" /qn /norestart" -Wait -PassThru
                            if ($proc.ExitCode -in 0, 3010) {
                                Write-Log "[$pkgId] 7-Zip installed directly via MSI" SUCCESS
                                $installed = $true
                                $jobResults.Add([PSCustomObject]@{
                                    JobName = $pkgId
                                    Status  = "Success"
                                    Details = "Installed via direct MSI"
                                })
                            }
                        }
                    } catch {
                        Write-Warning "7-Zip direct install failed: $($_.Exception.Message)"
                    }
                }
                elseif ($pkgId -match 'WindowsFirewallControl') {
                    try {
                        $targetExe = Join-Path $DownloadsDir "wfc6setup.exe"
                        $downloadSucceeded = Invoke-BitsDownload 'https://binisoft.org/download/wfc6setup.exe' $targetExe 'Windows Firewall Control installer'
                        if ($downloadSucceeded -and (Test-Path -LiteralPath $targetExe)) {
                            Invoke-WithStatus "Installing Windows Firewall Control" "Windows Firewall Control installed successfully" {
                                $exitCode = Invoke-FirewallControlSetup $targetExe
                                if ($exitCode -notin 0, 3010) {
                                    $exitCode = Invoke-FirewallControlSetup $targetExe
                                }
                                if ($exitCode -notin 0, 3010) { throw "Firewall Control installer failed (exit $exitCode)." }
                            }
                            Write-Log "[$pkgId] Windows Firewall Control installed directly" SUCCESS
                            $installed = $true
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $pkgId
                                Status  = "Success"
                                Details = "Installed via direct installer"
                            })
                        }
                    } catch {
                        Write-Warning "Windows Firewall Control direct install failed: $($_.Exception.Message)"
                    }
                }
            }

            if (-not $installed) {
                Write-Log "[$pkgId] Installation failed (code $lastCode)." ERROR
                $jobResults.Add([PSCustomObject]@{
                    JobName = $pkgId
                    Status  = "Failed"
                    Details = "Exit code $lastCode"
                })
            }
        }
    }
    else {
        Write-Warning "winget unavailable. Falling back to direct silent installers..."
        # Firefox Direct Fallback
        $targetExe = Join-Path $DownloadsDir "FirefoxInstaller.exe"
        $downloadSucceeded = Invoke-BitsDownload 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' $targetExe 'Firefox installer'
        if ($downloadSucceeded -and (Test-Path -LiteralPath $targetExe)) {
            $proc = Start-Process -FilePath $targetExe -ArgumentList '/S' -Wait -PassThru
            if ($proc.ExitCode -in 0, 3010) {
                Write-Log "Firefox installed directly" SUCCESS
                $jobResults.Add([PSCustomObject]@{
                    JobName = 'Firefox'
                    Status  = "Success"
                    Details = "Installed via direct silent installer"
                })
            } else {
                Write-Log "Firefox direct installer failed with code $($proc.ExitCode)" ERROR
                $jobResults.Add([PSCustomObject]@{
                    JobName = 'Firefox'
                    Status  = "Failed"
                    Details = "Exit code $($proc.ExitCode)"
                })
            }
        } else {
            $jobResults.Add([PSCustomObject]@{ JobName = 'Firefox'; Status = 'Failed'; Details = 'BITS download failed' })
        }

        # Windows Firewall Control Direct Fallback
        $wfcExe = Join-Path $DownloadsDir "wfc6setup.exe"
        $downloadSucceeded = Invoke-BitsDownload 'https://binisoft.org/download/wfc6setup.exe' $wfcExe 'Windows Firewall Control installer'
        if ($downloadSucceeded -and (Test-Path -LiteralPath $wfcExe)) {
            try {
                $exitCode = Invoke-FirewallControlSetup $wfcExe
                if ($exitCode -notin 0, 3010) { throw "Installer exited with code $exitCode." }
                $jobResults.Add([PSCustomObject]@{ JobName = 'BiniSoft.WindowsFirewallControl'; Status = 'Success'; Details = "Installed directly (exit code $exitCode)" })
            } catch {
                $jobResults.Add([PSCustomObject]@{ JobName = 'BiniSoft.WindowsFirewallControl'; Status = 'Failed'; Details = $_.Exception.Message })
            }
        } else {
            $jobResults.Add([PSCustomObject]@{ JobName = 'BiniSoft.WindowsFirewallControl'; Status = 'Failed'; Details = 'BITS download failed' })
        }
    }

    # This summarizes recorded package/tool outcomes. Review earlier warnings
    # too, because optional/bootstrap/post-install work may not be included.
    # 3. Final Status Output
    $successCount = ($jobResults | Where-Object { $_.Status -eq 'Success' }).Count
    $failCount = ($jobResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $totalCount = $jobResults.Count

    Write-RunHeading 'Installation results'
    $jobResults | Format-Table @{Name='Item'; Expression={$_.JobName}}, Status, Details -AutoSize -Wrap | Out-String | Write-Host

    if ($failCount -eq 0) {
        Write-Log "All $totalCount listed operations succeeded." SUCCESS
    }
    else {
        Write-Log "Listed operations: $successCount succeeded, $failCount failed." ERROR
    }

    # Post-install: Add Tools, Sysinternals & winget directory to system PATH if not already present
    try {
        $sysinternalsDir = "$InstallDir\Sysinternals"
        $wingetDir = if ($wingetPath -and (Split-Path -Parent $wingetPath) -eq $script:PortableWingetDirectory) { $script:PortableWingetDirectory }
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $machineEntries = @($machinePath -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -notin $script:RejectedWingetDirectories })
        $pathsToAdd = @($InstallDir, $sysinternalsDir, $wingetDir) | Where-Object { $_ -and (Test-TrustedPath $_) -and $_ -notin $machineEntries }
        $newPath = (@($machineEntries) + @($pathsToAdd) | Select-Object -Unique) -join ';'
        if ($newPath -ne $machinePath) {
            [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            $processEntries = @($env:Path -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -notin $script:RejectedWingetDirectories })
            $env:Path = (@($newPath -split ';') + $processEntries | Select-Object -Unique) -join ';'
            Write-Log "System PATH updated with $InstallDir" SUCCESS
        }
    } catch {}

    Write-Log "Installation run finished."
}
catch {
    Write-Log "Installation stopped: $($_.Exception.Message)" ERROR
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
finally {
    if (Test-Path -LiteralPath $script:TranscriptPath) { Write-Log "Transcript: $script:TranscriptPath" }
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
}

Write-Host ""
Read-Host "Press Enter to exit"
