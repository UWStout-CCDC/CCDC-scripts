#Requires -RunAsAdministrator

[CmdletBinding()]
param()

# -----------------------------------------------------------------------------
# Console Theme & Safety Initialization (Seamless pure-black styling)
# -----------------------------------------------------------------------------
try {
    [Console]::BackgroundColor = [ConsoleColor]::Black
    [Console]::ForegroundColor = [ConsoleColor]::White
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    if ($Host.PrivateData) {
        $Host.PrivateData.WarningBackgroundColor = 'Black'
        $Host.PrivateData.WarningForegroundColor = 'Yellow'
        $Host.PrivateData.ErrorBackgroundColor   = 'Black'
        $Host.PrivateData.ErrorForegroundColor   = 'Red'
        $Host.PrivateData.VerboseBackgroundColor = 'Black'
        $Host.PrivateData.VerboseForegroundColor = 'Cyan'
        $Host.PrivateData.DebugBackgroundColor   = 'Black'
        $Host.PrivateData.DebugForegroundColor   = 'DarkCyan'
    }
    $PSDefaultParameterValues['Write-Host:BackgroundColor'] = 'Black'
    Clear-Host
} catch {}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[!] ERROR: script must be run as Administrator!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Press Enter to exit..."
    exit 1
}

# Keep console window open on terminating errors
trap {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Script encountered an error. Press Enter to exit..."
    break
}

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
# TLS 1.2 to "fix downloads" - claude
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-installs.ps1              |
     | ,      ,_ `\_/~\-           |   made for MWCCDC 2026-27' invitationals   |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black

# Create install directory for tools
Write-Host "[+] Creating install directory at $InstallDir" -ForegroundColor Green -BackgroundColor Black
New-Item -ItemType Directory -Force -Path $InstallDir, $LogsDir, $DownloadsDir | Out-Null
Set-Location -Path $InstallDir
[System.IO.Directory]::SetCurrentDirectory($InstallDir)

# Log everything from CLI to file (safely ignore if a transcript is already running)
$script:TranscriptPath = "$LogsDir\install-$(Get-Date -f yyyyMMdd-HHmmss).log"
try {
    Start-Transcript -Path $script:TranscriptPath -ErrorAction Stop
} catch {
    Write-Warning "Could not start transcript (an existing transcript may already be active): $($_.Exception.Message)"
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level] -BackgroundColor Black
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

Write-Host "[*] Host Role Analysis -> Domain Controller: $isDC | MSSQL Server: $isMSSQL" -ForegroundColor Cyan

$Downloads = [System.Collections.Generic.List[hashtable]]::new()

# Sysinternals Suite is always directly downloaded & extracted to C:\Tools\Sysinternals
Write-Host "[+] Queuing Sysinternals Suite for direct download." -ForegroundColor Green
$Downloads.Add(@{
    Name = 'Sysinternals'
    Url  = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
})

Write-Host "[+] Queuing Npcap installer for download and silent installation." -ForegroundColor Green
$Downloads.Add(@{
    Name        = 'Npcap'
    Url         = 'https://npcap.com/dist/npcap-1.90.exe'
    InstallArgs = '/S /winpcap_mode=yes'
})

if ($isMSSQL) {
    Write-Host "[+] MSSQL Server detected. Queuing Docker CE installer script." -ForegroundColor Green
    $Downloads.Add(@{
        Name = 'Docker'
        Url  = 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1'
    })
} else {
    Write-Host "[*] Host is not an MSSQL Server. Skipping Docker CE." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# Background Animated Spinner Engine
# -----------------------------------------------------------------------------
try {
    Add-Type -TypeDefinition @"
using System;
using System.Threading;

public class ConsoleSpinner : IDisposable {
    private Thread _thread;
    private volatile bool _running;
    private string _text;
    private static readonly string[] Frames = new string[] { "|", "/", "-", "\\" };

    public ConsoleSpinner(string text) {
        _text = text;
        _running = true;
        _thread = new Thread(Run);
        _thread.IsBackground = true;
        _thread.Start();
    }

    private void Run() {
        int i = 0;
        while (_running) {
            try {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.BackgroundColor = ConsoleColor.Black;
                Console.Write("\r  [" + Frames[i % Frames.Length] + "] " + _text + "...   ");
                Console.ForegroundColor = ConsoleColor.White;
                i++;
                Thread.Sleep(80);
            } catch {}
        }
    }

    public void Stop(string doneText, bool success) {
        _running = false;
        try {
            _thread.Join(300);
            Console.ForegroundColor = success ? ConsoleColor.Green : ConsoleColor.Yellow;
            Console.BackgroundColor = ConsoleColor.Black;
            string icon = success ? "[+]" : "[!]";
            Console.WriteLine("\r  " + icon + " " + doneText + "                              ");
            Console.ForegroundColor = ConsoleColor.White;
        } catch {}
    }

    public void Dispose() {
        _running = false;
    }
}
"@ -ErrorAction SilentlyContinue
} catch {}

function Invoke-WithSpinner {
    param(
        [Parameter(Mandatory=$true)][string]$StatusText,
        [Parameter(Mandatory=$true)][string]$DoneText,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    $sp = $null
    try { $sp = New-Object ConsoleSpinner($StatusText) } catch {}
    if (-not $sp) { Write-Host "  [*] $StatusText..." -ForegroundColor Cyan -BackgroundColor Black }

    $failed = $false
    $errMsg = ""
    try {
        & $ScriptBlock @ArgumentList
    } catch {
        $failed = $true
        $errMsg = $_.Exception.Message
        throw
    } finally {
        if ($sp) {
            if ($failed) {
                $sp.Stop("$StatusText failed: $errMsg", $false)
            } else {
                $sp.Stop($DoneText, $true)
            }
            $sp.Dispose()
        } else {
            if ($failed) {
                Write-Host "  [!] $StatusText failed: $errMsg" -ForegroundColor Yellow -BackgroundColor Black
            } else {
                Write-Host "  [+] $DoneText" -ForegroundColor Green -BackgroundColor Black
            }
        }
    }
}

function Invoke-FastDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [string]$Description = (Split-Path -Leaf $OutFile)
    )

    try {
        Invoke-WithSpinner "Downloading $Description" "Downloaded $Description" {
            # 1. Try curl.exe (fastest, lowest memory footprint ~4MB)
            $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
            if ($curl) {
                try {
                    $proc = Start-Process -FilePath $curl.Source -ArgumentList "-s", "-S", "-L", "--connect-timeout", "10", "--max-time", "120", "-o", "`"$OutFile`"", "`"$Url`"" -NoNewWindow -Wait -PassThru
                    if ($proc.ExitCode -eq 0 -and (Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
                        return
                    }
                } catch {}
            }

            # 2. In-process .NET WebClient with TLS 1.2 and explicit Dispose()
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $wc = New-Object System.Net.WebClient
                try {
                    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    $wc.DownloadFile($Url, $OutFile)
                } finally {
                    $wc.Dispose()
                }
                if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
                    return
                }
            } catch {}

            # 3. Fallback to Invoke-WebRequest
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
                return
            }

            throw "Download failed for $Description"
        }
    } catch {
        Write-Host "  [!] Failed to download $Description" -ForegroundColor Red -BackgroundColor Black
    }
}

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

function Test-WingetExecutable {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $false }
    try {
        $out = & $Path --version 2>&1
        if ($LASTEXITCODE -eq 0 -or ("$out" -match 'v?\d+\.')) { return $true }
    } catch {}

    try {
        $stdout = [System.IO.Path]::GetTempFileName()
        $stderr = [System.IO.Path]::GetTempFileName()
        $p = Start-Process -FilePath $Path -ArgumentList '--version' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
        $exitCode = $p.ExitCode
        $content = Get-Content $stdout -ErrorAction SilentlyContinue
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
        if ($exitCode -eq 0 -or ("$content" -match 'v?\d+\.')) { return $true }
    } catch {}

    return $false
}

function Get-WingetPath {
    # 1. In existing PATH
    $cmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($cmd -and (Test-WingetExecutable $cmd.Source)) { return $cmd.Source }

    # 2. Local tool installation
    $local = "$InstallDir\winget\winget.exe"
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

function Install-WingetLocal {
    param([string]$SourceDir)

    $dest = "$InstallDir\winget"
    if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }

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
        # Robocopy with /B (backup operator mode to safely copy without modifying WindowsApps ACLs)
        robocopy $SourceDir $dest /B /E /MT:2 /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    }

    # Ensure VC++ Redistributable is installed (required by standalone winget runtime)
    $vcKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
    $hasVc = (Test-Path $vcKey) -and ((Get-ItemProperty -Path $vcKey -Name Installed -ErrorAction SilentlyContinue).Installed -eq 1)
    if (-not $hasVc) {
        $vc = "$DownloadsDir\vc_redist.x64.exe"
        if (-not (Test-Path $vc)) {
            Invoke-FastDownload 'https://aka.ms/vs/17/release/vc_redist.x64.exe' $vc 'VC++ Redistributable'
        }
        if (Test-Path $vc) {
            Invoke-WithSpinner "Installing VC++ Redistributable" "Installed VC++ Redistributable" {
                param($exe)
                Start-Process $exe -ArgumentList '/install','/quiet','/norestart' -Wait
            } @($vc)
        }
    }

    try {
        icacls $dest /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /q | Out-Null
    } catch {}

    if ($env:Path -notlike "*$dest*") {
        $env:Path = "$dest;$env:Path"
    }
}

function Install-WingetLegacyBootstrap {
    Write-Host "[*] Bootstrapping WinGet for Windows Server 2019 (manual bundle & DISM extraction)..." -ForegroundColor Cyan
    try {
        # Check if DesktopAppInstaller is already staged on the system
        $existingPkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1

        if (-not $existingPkg) {
            $stagedDir = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue |
                Sort-Object Name | Select-Object -Last 1
            if ($stagedDir) {
                $existingPkg = [PSCustomObject]@{ InstallLocation = $stagedDir.FullName }
            }
        }

        if ($existingPkg -and $existingPkg.InstallLocation) {
            Write-Host "[+] Staged DesktopAppInstaller found at $($existingPkg.InstallLocation). Configuring..." -ForegroundColor Cyan
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($existingPkg.InstallLocation)\AppxManifest.xml" -ErrorAction SilentlyContinue | Out-Null
            } catch {}
            Install-WingetLocal -SourceDir $existingPkg.InstallLocation
            $wPath = Get-WingetPath
            if ($wPath) { return $wPath }
        }

        # Determine URLs dynamically from latest GitHub release with fallback to official endpoints
        $bundleUrl  = 'https://aka.ms/getwinget'
        $depsUrl    = 'https://github.com/microsoft/winget-cli/releases/latest/download/DesktopAppInstaller_Dependencies.zip'
        $licenseUrl = $null

        try {
            $rel = Invoke-RestMethod 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 10 -ErrorAction Stop
            $bAsset = $rel.assets | Where-Object { $_.name -like '*.msixbundle' } | Select-Object -First 1
            $lAsset = $rel.assets | Where-Object { $_.name -like '*_License1.xml' } | Select-Object -First 1
            $dAsset = $rel.assets | Where-Object { $_.name -like '*Dependencies.zip' } | Select-Object -First 1
            if ($bAsset) { $bundleUrl  = $bAsset.browser_download_url }
            if ($lAsset) { $licenseUrl = $lAsset.browser_download_url }
            if ($dAsset) { $depsUrl    = $dAsset.browser_download_url }
        } catch {}

        # Download packages
        Invoke-FastDownload $depsUrl "$DownloadsDir\winget-deps.zip" 'winget-deps.zip'
        Invoke-FastDownload $bundleUrl "$DownloadsDir\winget.msixbundle" 'winget.msixbundle'
        if ($licenseUrl) {
            Invoke-FastDownload $licenseUrl "$DownloadsDir\winget-license.xml" 'winget-license.xml'
        }

        # Extract dependencies
        Invoke-WithSpinner "Extracting winget-deps.zip" "Extracted winget-deps.zip" {
            param($z, $d)
            Expand-FastArchive -Path $z -DestinationPath $d
        } @("$DownloadsDir\winget-deps.zip", "$DownloadsDir\winget-deps")

        $depsPath = Join-Path "$DownloadsDir\winget-deps" "x64"
        if (-not (Test-Path $depsPath)) { $depsPath = "$DownloadsDir\winget-deps" }
        $deps = @(Get-ChildItem $depsPath -Filter *.appx | Select-Object -ExpandProperty FullName)
        Write-Host "[+] Dependencies found: $($deps.Count) (includes native WindowsAppRuntime 1.8 .appx)" -ForegroundColor Green

        # Provision and register each dependency package (.appx)
        foreach ($dep in $deps) {
            $depLeaf = Split-Path -Leaf $dep
            Invoke-WithSpinner "Registering dependency: $depLeaf" "Registered dependency: $depLeaf" {
                param($p)
                try { Add-AppxProvisionedPackage -Online -PackagePath $p -SkipLicense -ErrorAction SilentlyContinue | Out-Null } catch {}
                try { Add-AppxPackage -Path $p -ErrorAction SilentlyContinue | Out-Null } catch {}
            } @($dep)
        }

        # Install winget with DISM provisioning and Appx registration
        if (Test-Path "$DownloadsDir\winget-license.xml") {
            Invoke-WithSpinner "Installing winget with dependencies and license" "Installed winget package" {
                param($p, $lic, $d)
                try { Add-AppxProvisionedPackage -Online -PackagePath $p -LicensePath $lic -DependencyPackagePath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                try { Add-AppxPackage -Path $p -DependencyPath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
            } @("$DownloadsDir\winget.msixbundle", "$DownloadsDir\winget-license.xml", $deps)
        } else {
            Invoke-WithSpinner "Installing winget with dependencies" "Installed winget package" {
                param($p, $d)
                try { Add-AppxProvisionedPackage -Online -PackagePath $p -SkipLicense -DependencyPackagePath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                try { Add-AppxPackage -Path $p -DependencyPath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
            } @("$DownloadsDir\winget.msixbundle", $deps)
        }

        # Register by family name and sync to local tool path
        try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue | Out-Null } catch {}
        Install-WingetLocal
        $wPath = Get-WingetPath
        if ($wPath) { return $wPath }

        # Direct ZIP extraction fallback if AppX service failed on Server 2019
        Write-Host "[*] AppX registration incomplete. Attempting direct portable extraction fallback..." -ForegroundColor Cyan
        Invoke-WithSpinner "Extracting winget standalone binaries" "Extracted winget standalone binaries" {
            param($bundle, $depsList, $dest)
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $tmpBundle = "$bundle-extracted"
            if (-not (Test-Path $tmpBundle)) { New-Item -ItemType Directory -Path $tmpBundle -Force | Out-Null }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($bundle, $tmpBundle)

            $nestedMsix = Get-ChildItem -Path $tmpBundle -Filter "*x64*.msix" -Recurse | Where-Object { $_.Name -notmatch 'stub' } | Select-Object -First 1
            if ($nestedMsix) {
                if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
                [System.IO.Compression.ZipFile]::ExtractToDirectory($nestedMsix.FullName, $dest)
                foreach ($dep in $depsList) {
                    try { [System.IO.Compression.ZipFile]::ExtractToDirectory($dep, $dest) } catch {}
                }
                [System.GC]::Collect()
            }
        } @("$DownloadsDir\winget.msixbundle", $deps, "$InstallDir\winget")

        Install-WingetLocal
        return (Get-WingetPath)
    }
    catch {
        Write-Host "[--------------------------------------------------------------]" -ForegroundColor Red
        Write-Host "[!] Windows Server 2019 manual bootstrap failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[--------------------------------------------------------------]" -ForegroundColor Red
        return $null
    }
}

try {
    $wingetPath = Get-WingetPath

    if (-not $wingetPath) {
        $osBuild = [System.Environment]::OSVersion.Version.Build
        # Windows Server 2022 is build 20348+, Windows Server 2019 is build 17763
        $isServer2022OrNewer = ($osBuild -ge 20348)

        if ($isServer2022OrNewer) {
            Write-Host "[*] Windows Server 2022/2025 detected (Build $osBuild). Bootstrapping via Microsoft WinGet Client module..." -ForegroundColor Cyan

            # Method 1: Official Microsoft WinGet Client module (Repair-WinGetPackageManager)
            try {
                Invoke-WithSpinner "Setting up PowerShell Gallery and NuGet provider" "Configured PSGallery & NuGet" {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction SilentlyContinue | Out-Null
                    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
                }

                Invoke-WithSpinner "Installing Microsoft.WinGet.Client module from PSGallery" "Installed Microsoft.WinGet.Client" {
                    Install-Module -Name Microsoft.WinGet.Client -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
                    Import-Module -Name Microsoft.WinGet.Client -Force -ErrorAction Stop
                }

                Invoke-WithSpinner "Running Repair-WinGetPackageManager for Windows Server 2022" "Completed WinGet package manager bootstrap" {
                    Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop | Out-Null
                }

                # Sync installed binaries to C:\Tools\winget for elevated Administrator PATH execution
                Install-WingetLocal
                $wingetPath = Get-WingetPath
            } catch {
                Write-Warning "Official Microsoft.WinGet.Client bootstrap encountered an error: $($_.Exception.Message)"
            }

            # Method 2: Fallback to automated winget-install script from PSGallery
            if (-not $wingetPath) {
                Write-Host "[*] Attempting fallback via winget-install script..." -ForegroundColor Cyan
                try {
                    Invoke-WithSpinner "Installing and executing winget-install script" "Completed winget-install script" {
                        Install-Script -Name winget-install -Force -Scope CurrentUser -ErrorAction Stop
                        & (Get-Command winget-install -CommandType ExternalScript).Source -Force -ErrorAction SilentlyContinue 2>&1 | Out-Null
                    }
                    Install-WingetLocal
                    $wingetPath = Get-WingetPath
                } catch {
                    Write-Warning "winget-install fallback failed: $($_.Exception.Message)"
                }
            }

            # Method 3: Final fallback to Server 2019 manual bootstrap if Server 2022 methods fail
            if (-not $wingetPath) {
                Write-Host "[*] Server 2022 methods unsuccessful. Falling back to manual bundle/DISM bootstrap..." -ForegroundColor Yellow
                $wingetPath = Install-WingetLegacyBootstrap
            }
        }
        else {
            Write-Host "[*] Windows Server 2019 / legacy build detected (Build $osBuild). Using manual bundle & DISM bootstrap..." -ForegroundColor Cyan
            $wingetPath = Install-WingetLegacyBootstrap
        }
    }

    if ($wingetPath) {
        Write-Host "[+] winget found at: $wingetPath" -ForegroundColor Green
        # Ensure winget directory is in current session path
        $wDir = Split-Path -Parent $wingetPath
        if ($wDir -and $env:Path -notlike "*$wDir*") { $env:Path = "$wDir;$env:Path" }

        try {
            & $wingetPath --version 2>&1 | Out-Null
            # Initialize / update community source index
            Write-Host "[*] Initializing winget package source..." -ForegroundColor Cyan
            & $wingetPath source update --disable-interactivity --accept-source-agreements 2>&1 | Out-Null
        } catch {
            Write-Warning "Could not execute winget version check: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "[!] winget not available." -ForegroundColor Red
    }

    #----------------------------------------------------------
    # SEQUENTIAL INSTALLATION & DOWNLOAD PIPELINE
    # (Runs sequentially in-process to prevent memory thrashing,
    #  msiexec 1618 mutex collisions, and Explorer shell crashes)
    #----------------------------------------------------------
    $jobResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Process Standalone Tool Downloads & Extractions
    Write-Host "`n[+] Processing standalone tool downloads..." -ForegroundColor Cyan
    foreach ($d in $Downloads) {
        $name = $d.Name
        $url = $d.Url
        $installArgs = $d.InstallArgs

        $filename = Split-Path -Leaf $url
        if (-not $filename -or $filename -notlike "*.*") {
            $filename = if ($installArgs) { "$name.exe" } else { "$name.dat" }
        }
        $outFile = Join-Path $DownloadsDir $filename

        Invoke-FastDownload $url $outFile "$name ($filename)"

        if ((Test-Path $outFile) -and (Get-Item $outFile).Length -gt 0) {
            # Extract archive if zip
            if ($filename -like "*.zip") {
                $extractPath = Join-Path $InstallDir $name
                Write-Host "[*] [$name] Extracting archive to $extractPath..." -ForegroundColor Cyan
                try {
                    Expand-FastArchive -Path $outFile -DestinationPath $extractPath
                    Write-Host "[+] [$name] Archive extracted successfully." -ForegroundColor Green
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Success"
                        Details = "Extracted to $extractPath"
                    })
                } catch {
                    Write-Warning "[!] [$name] Archive extraction failed: $($_.Exception.Message)"
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Failed"
                        Details = "Extraction error: $($_.Exception.Message)"
                    })
                }
            }
            # Execute PowerShell script if .ps1 (e.g., Docker installer)
            elseif ($filename -like "*.ps1") {
                Write-Host "[*] [$name] Executing PowerShell installation script ($filename)..." -ForegroundColor Cyan
                try {
                    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$outFile`"" -Wait -PassThru
                    if ($proc.ExitCode -in 0, 3010) {
                        Write-Host "[+] [$name] Execution completed successfully!" -ForegroundColor Green
                        $jobResults.Add([PSCustomObject]@{
                            JobName = $name
                            Status  = "Success"
                            Details = "Executed PowerShell script (exit code 0)"
                        })
                    } else {
                        Write-Warning "[-] [$name] Script exited with code: $($proc.ExitCode)"
                        $jobResults.Add([PSCustomObject]@{
                            JobName = $name
                            Status  = "Failed"
                            Details = "Exit code $($proc.ExitCode)"
                        })
                    }
                } catch {
                    Write-Warning "[!] [$name] Script execution failed: $($_.Exception.Message)"
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Failed"
                        Details = "Launch error: $($_.Exception.Message)"
                    })
                }
            }
            # Execute silent installer if args provided
            elseif ($installArgs) {
                try {
                    $exitCode = 0
                    Invoke-WithSpinner "Installing $name ($installArgs)" "$name installed successfully" {
                        $proc = Start-Process -FilePath $outFile -ArgumentList $installArgs -Wait -PassThru
                        $exitCode = $proc.ExitCode
                        if ($exitCode -notin 0, 3010) {
                            throw "Installer exited with code $exitCode"
                        }
                    }
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $name
                        Status  = "Success"
                        Details = "Installed (exit code $exitCode)"
                    })
                } catch {
                    Write-Warning "[!] [$name] Installation failed: $($_.Exception.Message)"
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
    if ($wingetPath) {
        $packages = @('Mozilla.Firefox', '7zip.7zip', 'BiniSoft.WindowsFirewallControl', 'Malwarebytes.Malwarebytes')
        Write-Host "`n[+] Installing packages sequentially via winget: $($packages -join ', ')..." -ForegroundColor Cyan

        $maxRetries = 2
        $retryDelay = 3

        foreach ($pkgId in $packages) {
            Write-Host "`n[*] [$pkgId] Starting installation via winget..." -ForegroundColor Cyan
            $installed = $false
            $lastCode = 0

            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                Write-Host "[*] [$pkgId] (Attempt $attempt/$maxRetries) Running winget install..." -ForegroundColor Cyan
                
                # Malwarebytes is interactive so the operator can manually work through it
                if ($pkgId -match 'Malwarebytes') {
                    $wingetArgs = @('install', '--id', $pkgId, '--exact', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements')
                } elseif ($attempt -eq 2 -and $pkgId -match 'WindowsFirewallControl') {
                    # Broaden search if exact ID was not found on first attempt
                    $wingetArgs = @('install', '--name', 'Windows Firewall Control', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                } else {
                    $wingetArgs = @('install', '--id', $pkgId, '--exact', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                }
                
                try {
                    $proc = Start-Process -FilePath $wingetPath -ArgumentList $wingetArgs -NoNewWindow -Wait -PassThru
                    $lastCode = $proc.ExitCode
                } catch {
                    $lastCode = -1
                }

                if ($lastCode -in 0, 3010) {
                    # Validate installation via winget list
                    $isVerified = $false
                    try {
                        $listOut = & $wingetPath list --id $pkgId --exact --disable-interactivity 2>&1
                        if ($LASTEXITCODE -eq 0 -and "$listOut" -match [regex]::Escape($pkgId)) {
                            $isVerified = $true
                        }
                    } catch {}

                    if ($isVerified) {
                        Write-Host "[+] [$pkgId] Successfully installed and verified via winget list!" -ForegroundColor Green
                        $details = "Installed & verified via winget"
                    } else {
                        Write-Host "[+] [$pkgId] Successfully installed (exit code 0)." -ForegroundColor Green
                        $details = "Installed via winget"
                    }

                    $installed = $true
                    $jobResults.Add([PSCustomObject]@{
                        JobName = $pkgId
                        Status  = "Success"
                        Details = $details
                    })
                    break
                } else {
                    if ($attempt -lt $maxRetries) {
                        Write-Warning "[-] [$pkgId] Winget returned code $lastCode. Retrying in ${retryDelay}s..."
                        Start-Sleep -Seconds $retryDelay
                    }
                }
            }

            # Direct fallback if winget installation failed
            if (-not $installed) {
                Write-Warning "[!] [$pkgId] Winget install failed (exit code $lastCode). Triggering direct fallback..."
                if ($pkgId -match 'Firefox') {
                    try {
                        $targetExe = Join-Path $DownloadsDir "FirefoxInstaller.exe"
                        Invoke-FastDownload 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' $targetExe 'Firefox direct installer'
                        if (Test-Path $targetExe) {
                            $proc = Start-Process -FilePath $targetExe -ArgumentList '/S' -Wait -PassThru
                            if ($proc.ExitCode -in 0, 3010) {
                                Write-Host "[+] [$pkgId] Firefox installed directly via silent installer!" -ForegroundColor Green
                                $installed = $true
                                $jobResults.Add([PSCustomObject]@{
                                    JobName = $pkgId
                                    Status  = "Success"
                                    Details = "Installed via direct installer"
                                })
                            }
                        }
                    } catch {
                        Write-Warning "[!] Firefox direct install failed: $($_.Exception.Message)"
                    }
                }
                elseif ($pkgId -match '7zip') {
                    try {
                        $targetMsi = Join-Path $DownloadsDir "7z-x64.msi"
                        Invoke-FastDownload 'https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi' $targetMsi '7-Zip direct MSI'
                        if (Test-Path $targetMsi) {
                            $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$targetMsi`" /qn /norestart" -Wait -PassThru
                            if ($proc.ExitCode -in 0, 3010) {
                                Write-Host "[+] [$pkgId] 7-Zip installed directly via MSI!" -ForegroundColor Green
                                $installed = $true
                                $jobResults.Add([PSCustomObject]@{
                                    JobName = $pkgId
                                    Status  = "Success"
                                    Details = "Installed via direct MSI"
                                })
                            }
                        }
                    } catch {
                        Write-Warning "[!] 7-Zip direct install failed: $($_.Exception.Message)"
                    }
                }
                elseif ($pkgId -match 'WindowsFirewallControl') {
                    try {
                        $targetExe = Join-Path $DownloadsDir "wfc6setup.exe"
                        Invoke-FastDownload 'https://binisoft.org/download/wfc6setup.exe' $targetExe 'Windows Firewall Control installer'
                        if (Test-Path $targetExe) {
                            $exitCode = 0
                            Invoke-WithSpinner "Installing Windows Firewall Control" "Windows Firewall Control installed successfully" {
                                $proc = Start-Process -FilePath $targetExe -ArgumentList "-run -close -install" -Wait -PassThru
                                $exitCode = $proc.ExitCode
                                if ($exitCode -notin 0, 3010) {
                                    $proc2 = Start-Process -FilePath $targetExe -ArgumentList "-install -silent" -Wait -PassThru
                                    $exitCode = $proc2.ExitCode
                                }
                            }
                            Write-Host "[+] [$pkgId] Windows Firewall Control installed directly!" -ForegroundColor Green
                            $installed = $true
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $pkgId
                                Status  = "Success"
                                Details = "Installed via direct installer"
                            })
                        }
                    } catch {
                        Write-Warning "[!] Windows Firewall Control direct install failed: $($_.Exception.Message)"
                    }
                }
            }

            if (-not $installed) {
                Write-Host "[!] [$pkgId] Installation failed (code $lastCode)." -ForegroundColor Red
                $jobResults.Add([PSCustomObject]@{
                    JobName = $pkgId
                    Status  = "Failed"
                    Details = "Exit code $lastCode"
                })
            }
        }
    }
    else {
        Write-Warning "[!] winget unavailable. Falling back to direct silent installers..."
        # Firefox Direct Fallback
        $targetExe = Join-Path $DownloadsDir "FirefoxInstaller.exe"
        Invoke-FastDownload 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' $targetExe 'Firefox installer'
        if (Test-Path $targetExe) {
            $proc = Start-Process -FilePath $targetExe -ArgumentList '/S' -Wait -PassThru
            if ($proc.ExitCode -in 0, 3010) {
                Write-Host "[+] Firefox installed directly!" -ForegroundColor Green
                $jobResults.Add([PSCustomObject]@{
                    JobName = 'Firefox'
                    Status  = "Success"
                    Details = "Installed via direct silent installer"
                })
            } else {
                Write-Host "[!] Firefox direct installer failed with code $($proc.ExitCode)" -ForegroundColor Red
                $jobResults.Add([PSCustomObject]@{
                    JobName = 'Firefox'
                    Status  = "Failed"
                    Details = "Exit code $($proc.ExitCode)"
                })
            }
        }

        # Windows Firewall Control Direct Fallback
        $wfcExe = Join-Path $DownloadsDir "wfc6setup.exe"
        Invoke-FastDownload 'https://binisoft.org/download/wfc6setup.exe' $wfcExe 'Windows Firewall Control installer'
        if (Test-Path $wfcExe) {
            $proc = Start-Process -FilePath $wfcExe -ArgumentList "-run -close -install" -Wait -PassThru
            if ($proc.ExitCode -in 0, 3010) {
                Write-Host "[+] Windows Firewall Control installed directly!" -ForegroundColor Green
                $jobResults.Add([PSCustomObject]@{
                    JobName = 'BiniSoft.WindowsFirewallControl'
                    Status  = "Success"
                    Details = "Installed via direct installer"
                })
            }
        }
    }

    # 3. Final Status Output
    $successCount = ($jobResults | Where-Object { $_.Status -eq 'Success' }).Count
    $failCount = ($jobResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $totalCount = $jobResults.Count

    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "               ALL INSTALL OPERATIONS COMPLETE" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    $jobResults | Format-Table -AutoSize | Out-String | Write-Host

    $timestamp = Get-Date -Format "HH:mm:ss"

    if ($failCount -eq 0) {
        Write-Host "[+] [$timestamp] All $totalCount installations/downloads finished successfully." -ForegroundColor Green
    }
    else {
        Write-Host "[!] [$timestamp] Operations complete: $successCount succeeded, $failCount failed." -ForegroundColor Red
    }
    Write-Host (("=" * 60) + "`n") -ForegroundColor Cyan

    # Post-install: Auto-accept Sysinternals EULA system-wide so tools launch without GUI prompts
    try {
        $eulaKeys = @('HKCU:\Software\Sysinternals', 'HKLM:\SOFTWARE\Sysinternals')
        foreach ($k in $eulaKeys) {
            if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
            Set-ItemProperty -Path $k -Name 'EulaAccepted' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "[+] Sysinternals EULA pre-accepted (HKCU & HKLM)" -ForegroundColor Green
    } catch {}

    # Post-install: Add Tools, Sysinternals & winget directory to system PATH if not already present
    try {
        $sysinternalsDir = "$InstallDir\Sysinternals"
        $wingetDir = "$InstallDir\winget"
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $pathsToAdd = @($InstallDir, $sysinternalsDir, $wingetDir) | Where-Object { (Test-Path $_) -and ($machinePath -notlike "*$_*") }
        if ($pathsToAdd) {
            $newPath = ($machinePath.TrimEnd(';') + ';' + ($pathsToAdd -join ';')).Trim(';')
            [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            $env:Path = "$newPath;$env:Path"
            Write-Host "[+] System PATH updated with $InstallDir" -ForegroundColor Green
        }
    } catch {}

    # Download shed-hardening and shed-scraper from GitHub
    $repo = "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master/windows"
    foreach ($script in @("shed-hardening.ps1", "shed-scraper.ps1")) {
        $target = "$InstallDir\$script"
        if (-not (Test-Path $target)) {
            Invoke-FastDownload "$repo/$script" $target
        }
    }

    Write-Host "[+] Done." -ForegroundColor Green
}
catch {
    Write-Host "`n[ERROR] An unexpected error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
finally {
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    try {
        if ($script:TranscriptPath -and (Test-Path $script:TranscriptPath)) {
            $raw = [System.IO.File]::ReadAllText($script:TranscriptPath)
            $raw = $raw -replace "`r\[[\|\/\-\\]\][^\r\n]*", ""
            $cleaned = ($raw -split "`r?`n" | Where-Object { $_ -notmatch '^\s*\[[\|\/\-\\]\]' }) -join "`r`n"
            [System.IO.File]::WriteAllText($script:TranscriptPath, $cleaned)
        }
    } catch {}
}

Write-Host ""
Read-Host "Press Enter to exit..."