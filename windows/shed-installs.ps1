# tools installer:
#   install winget (use 2019 for 2019) (detect OS ?)
#   install Sysinternals :3333333
#   install firefox
#   install Docker if on non-AD server

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

# Elevation check (replaces #Requires to keep the console window open on failure)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[!] ERROR: shed-installs.ps1 must be run as Administrator!" -ForegroundColor Red
    Write-Host "[!] Please right-click PowerShell and select 'Run as administrator'." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit..."
    exit 1
}

# Keep console window open on terminating errors
trap {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    Write-Host ""
    Read-Host "Script encountered an error. Press Enter to exit..."
    break
}

$InstallDir = "C:\Tools"
$DownloadsDir = "$InstallDir\downloads"
$LogsDir = "$InstallDir\logs"
$dl = $DownloadsDir

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

try {
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host
} catch {}

$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-installs.ps1              |
     | ,      ,_ `\_/~\-           |                                            |
     >/'>/ ~|||`\( ,~\-            |  installs all of the fun tools we need :3  |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <-------- that's kayne whitney            |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red

# Create install directory for tools
Write-Host "[+] Creating install directory at $InstallDir" -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $InstallDir, $LogsDir, $DownloadsDir | Out-Null

# Log everything from CLI to file (safely ignore if a transcript is already running)
$script:TranscriptPath = "$LogsDir\install-$(Get-Date -f yyyyMMdd-HHmmss).log"
try {
    Start-Transcript -Path $script:TranscriptPath -ErrorAction Stop
} catch {
    Write-Warning "Could not start transcript (an existing transcript may already be active): $($_.Exception.Message)"
}

# Domain Controller check (ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server)
$isDC = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
    if ($os -and $os.ProductType -eq 2) { $isDC = $true }
} catch {}

if (-not $isDC -and (Get-Service -Name NTDS -ErrorAction SilentlyContinue)) {
    $isDC = $true
}

$Downloads = [System.Collections.Generic.List[hashtable]]::new()

# Sysinternals Suite is always directly downloaded & extracted to C:\Tools\Sysinternals
# (WinGet manifests for Sysinternals use portable ZIP packages which WinGet rejects on Windows Server with NoApplicableInstallers)
Write-Host "[+] Queuing Sysinternals Suite for direct download." -ForegroundColor Green
$Downloads.Add(@{
    Name = 'Sysinternals'
    Url  = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
})

Write-Host "[+] Queuing Npcap installer for direct download." -ForegroundColor Green
$Downloads.Add(@{
    Name = 'Npcap'
    Url  = 'https://npcap.com/dist/npcap-1.90.exe'
})

if ($isDC) {
    Write-Host "[!] Host is an Active Directory Domain Controller (AD DS). Skipping Docker CE." -ForegroundColor Yellow
} else {
    Write-Host "[+] Host is not an AD Domain Controller. Docker CE queued for download." -ForegroundColor Green
    $Downloads.Add(@{
        Name = 'Docker'
        Url  = 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1'
    })
}

function Write-SpinnerFrame {
    param([string]$Text)
    try {
        $prev = [System.Console]::ForegroundColor
        [System.Console]::ForegroundColor = [System.ConsoleColor]::Cyan
        [System.Console]::Write($Text)
        [System.Console]::ForegroundColor = $prev
    } catch {
        Write-Host $Text -NoNewline -ForegroundColor Cyan
    }
}

function Clear-SpinnerLine {
    try {
        [System.Console]::Write("`r" + (" " * 78) + "`r")
    } catch {
        Write-Host ("`r" + (" " * 78) + "`r") -NoNewline
    }
}

function Invoke-WithSpinner {
    param(
        [Parameter(Mandatory=$true)][string]$StatusText,
        [Parameter(Mandatory=$true)][string]$DoneText,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    $spinChars = @('|', '/', '-', '\')
    $spinIndex = 0
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    while ($job.State -eq 'Running' -or $job.State -eq 'NotStarted') {
        $frame = $spinChars[$spinIndex]
        Write-SpinnerFrame ("`r[$frame] $StatusText...".PadRight(75))
        $spinIndex = ($spinIndex + 1) % $spinChars.Count
        Start-Sleep -Milliseconds 120
    }
    Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
    $jobState = $job.State
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    Clear-SpinnerLine
    if ($jobState -eq 'Completed') {
        Write-Host "[+] $DoneText" -ForegroundColor Green
    } else {
        Write-Host "[!] $StatusText failed" -ForegroundColor Yellow
    }
}

function Invoke-FastDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [string]$Description = (Split-Path -Leaf $OutFile)
    )
    $spinChars = @('|', '/', '-', '\')
    $spinIndex = 0

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $proc = Start-Process -FilePath $curl.Source -ArgumentList "-s", "-S", "-L", "--connect-timeout", "10", "--max-time", "300", "-o", "`"$OutFile`"", "`"$Url`"" -NoNewWindow -PassThru
        while (-not $proc.HasExited) {
            $frame = $spinChars[$spinIndex]
            Write-SpinnerFrame ("`r[$frame] Downloading $Description...".PadRight(75))
            $spinIndex = ($spinIndex + 1) % $spinChars.Count
            Start-Sleep -Milliseconds 120
        }
        Clear-SpinnerLine
        if ($proc.ExitCode -eq 0 -and (Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
            Write-Host "[+] Downloaded $Description" -ForegroundColor Green
            return
        }
    }

    # Fallback to WebClient with live bracket spinner
    $wcJob = Start-Job -ScriptBlock {
        param($u, $o)
        $ErrorActionPreference = 'Stop'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($u, $o)
            return
        } catch {}
        Invoke-WebRequest -Uri $u -OutFile $o -UseBasicParsing -TimeoutSec 300
    } -ArgumentList $Url, $OutFile

    while ($wcJob.State -eq 'Running' -or $wcJob.State -eq 'NotStarted') {
        $frame = $spinChars[$spinIndex]
        Write-SpinnerFrame ("`r[$frame] Downloading $Description...".PadRight(75))
        $spinIndex = ($spinIndex + 1) % $spinChars.Count
        Start-Sleep -Milliseconds 120
    }
    Remove-Job -Job $wcJob -Force -ErrorAction SilentlyContinue
    Clear-SpinnerLine

    if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
        Write-Host "[+] Downloaded $Description" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to download $Description" -ForegroundColor Red
    }
}

function Test-WingetExecutable {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $false }
    try {
        $p = Start-Process -FilePath $Path -ArgumentList '--version' -NoNewWindow -Wait -PassThru -ErrorAction Stop
        if ($p.ExitCode -eq 0) { return $true }
    } catch {}

    try {
        $out = & $Path --version 2>&1
        if ($LASTEXITCODE -eq 0 -or ($out -match 'v\d+\.')) { return $true }
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
            try { icacls $appxDir.FullName /grant '*S-1-5-32-544:(OI)(CI)F' /t /q 2>$null } catch {}
            if (Test-WingetExecutable $candidate) { return $candidate }
        }
    }

    # 5. AppxPackage InstallLocation
    $pkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($pkg -and $pkg.InstallLocation) {
        $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
        if (Test-Path $candidate) {
            try { icacls $pkg.InstallLocation /grant '*S-1-5-32-544:(OI)(CI)F' /t /q 2>$null } catch {}
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
        try { icacls $SourceDir /grant '*S-1-5-32-544:(OI)(CI)F' /t /q 2>$null } catch {}
        # Robocopy with /B (backup operator mode to bypass WindowsApps ACL lockout)
        robocopy $SourceDir $dest /B /E /MT:8 /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    }

    # Ensure VC++ Redistributable is installed (required by standalone winget runtime)
    $vcKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
    $hasVc = (Test-Path $vcKey) -and ((Get-ItemProperty -Path $vcKey -Name Installed -ErrorAction SilentlyContinue).Installed -eq 1)
    if (-not $hasVc) {
        $vc = "$dl\vc_redist.x64.exe"
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

try {
    $wingetPath = Get-WingetPath

    if (-not $wingetPath) {
        # Check if DesktopAppInstaller is already staged on the system (standard on Server 2022)
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
                icacls $existingPkg.InstallLocation /grant '*S-1-5-32-544:(OI)(CI)F' /t /q 2>$null | Out-Null
                Add-AppxPackage -DisableDevelopmentMode -Register "$($existingPkg.InstallLocation)\AppxManifest.xml" -ErrorAction SilentlyContinue | Out-Null
            } catch {}
            Install-WingetLocal -SourceDir $existingPkg.InstallLocation
            $wingetPath = Get-WingetPath
        }

        # If still not found, bootstrap winget with fast downloads and DISM provisioning
        if (-not $wingetPath) {
            try {
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
                Invoke-FastDownload $depsUrl "$dl\winget-deps.zip" 'winget-deps.zip'
                Invoke-FastDownload $bundleUrl "$dl\winget.msixbundle" 'winget.msixbundle'
                if ($licenseUrl) {
                    Invoke-FastDownload $licenseUrl "$dl\winget-license.xml" 'winget-license.xml'
                }

                # Extract dependencies
                Invoke-WithSpinner "Extracting winget-deps.zip" "Extracted winget-deps.zip" {
                    param($z, $d)
                    Expand-Archive -Path $z -DestinationPath $d -Force
                } @("$dl\winget-deps.zip", "$dl\winget-deps")

                $depsPath = Join-Path "$dl\winget-deps" "x64"
                if (-not (Test-Path $depsPath)) { $depsPath = "$dl\winget-deps" }
                $deps = @(Get-ChildItem $depsPath -Filter *.appx | Select-Object -ExpandProperty FullName)
                Write-Host "[+] Dependencies found: $($deps.Count) (includes native WindowsAppRuntime 1.8 .appx)" -ForegroundColor Green

                # Provision and register each dependency package (.appx)
                foreach ($dep in $deps) {
                    $depLeaf = Split-Path -Leaf $dep
                    Invoke-WithSpinner "Registering dependency: $depLeaf" "Registered dependency: $depLeaf" {
                        param($p)
                        try { Add-AppxProvisionedPackage -Online -PackagePath $p -SkipLicense -ErrorAction SilentlyContinue | Out-Null } catch {}
                        try { Add-AppxPackage -Path $p -ErrorAction SilentlyContinue } catch {}
                    } @($dep)
                }

                # Install winget with DISM provisioning and Appx registration
                if (Test-Path "$dl\winget-license.xml") {
                    Invoke-WithSpinner "Installing winget with dependencies and license" "Installed winget package" {
                        param($p, $lic, $d)
                        try { Add-AppxProvisionedPackage -Online -PackagePath $p -LicensePath $lic -DependencyPackagePath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                        try { Add-AppxPackage -Path $p -DependencyPath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                    } @("$dl\winget.msixbundle", "$dl\winget-license.xml", $deps)
                } else {
                    Invoke-WithSpinner "Installing winget with dependencies" "Installed winget package" {
                        param($p, $d)
                        try { Add-AppxProvisionedPackage -Online -PackagePath $p -SkipLicense -DependencyPackagePath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                        try { Add-AppxPackage -Path $p -DependencyPath $d -ErrorAction SilentlyContinue | Out-Null } catch {}
                    } @("$dl\winget.msixbundle", $deps)
                }

                # Register by family name and sync to local tool path
                try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue | Out-Null } catch {}
                Install-WingetLocal
                $wingetPath = Get-WingetPath

                # Direct ZIP extraction fallback if AppX service failed on Server
                if (-not $wingetPath) {
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
                        }
                    } @("$dl\winget.msixbundle", $deps, "$InstallDir\winget")

                    Install-WingetLocal
                    $wingetPath = Get-WingetPath
                }
            }
            catch {
                Write-Host "[--------------------------------------------------------------]" -ForegroundColor Red
                Write-Host "[!] winget bootstrap FAILED: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "[--------------------------------------------------------------]" -ForegroundColor Red
            }

            $wingetPath = Get-WingetPath
        }
    }

    if ($wingetPath) {
        Write-Host "[+] winget found at: $wingetPath" -ForegroundColor Green
        # Ensure winget directory is in current session path
        $wDir = Split-Path -Parent $wingetPath
        if ($wDir -and $env:Path -notlike "*$wDir*") { $env:Path = "$wDir;$env:Path" }

        try {
            $null = & $wingetPath --version
            # Initialize / update community source index
            Write-Host "[*] Initializing winget package source..." -ForegroundColor Cyan
            & $wingetPath source update --disable-interactivity 2>&1 | Out-Null
        } catch {
            Write-Warning "Could not execute winget version check: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "[!] winget not available." -ForegroundColor Red
    }

    #----------------------------------------------------------
    # JOB QUEUE: Launch all installs and downloads concurrently
    #----------------------------------------------------------
    $Jobs = [System.Collections.Generic.List[PSObject]]::new()

    # 1. Winget package install jobs (Run sequentially to avoid msiexec and SQLite lock contention)
    if ($wingetPath) {
        $packages = @('Mozilla.Firefox', 'BiniSoft.WindowsFirewallControl', '7zip.7zip')
        
        Write-Host "[+] Queuing sequential winget install job for: $($packages -join ', ')" -ForegroundColor Cyan
        $job = Start-Job -Name "Install-WingetPackages" -ScriptBlock {
            param($pkgList, $exePath, $targetInstallDir, $downloadsPath)
            $ErrorActionPreference = 'Stop'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            # Ensure path is available in the background job process
            $exeDir = Split-Path -Parent $exePath
            if ($exeDir -and $env:Path -notlike "*$exeDir*") {
                $env:Path = "$exeDir;$env:Path"
            }
            if ($env:Path -notlike "*$env:LOCALAPPDATA\Microsoft\WindowsApps*") {
                $env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
            }

            function Invoke-FastDownload {
                param($u, $o)
                $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
                if ($curl) {
                    $p = Start-Process -FilePath $curl.Source -ArgumentList "-s", "-S", "-L", "--connect-timeout", "10", "--max-time", "300", "-o", "`"$o`"", "`"$u`"" -NoNewWindow -Wait -PassThru
                    if ($p.ExitCode -eq 0 -and (Test-Path $o) -and (Get-Item $o).Length -gt 0) { return }
                }
                try {
                    $wc = New-Object System.Net.WebClient
                    $wc.DownloadFile($u, $o)
                    return
                } catch {}
                Invoke-WebRequest -Uri $u -OutFile $o -UseBasicParsing -TimeoutSec 300
            }

            $maxRetries = 3
            $retryDelay = 5
            $failedPackages = [System.Collections.Generic.List[string]]::new()

            foreach ($pkgId in $pkgList) {
                Write-Host "`n[*] [$pkgId] Starting installation via winget..."
                $installed = $false
                $lastCode = 0

                for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                    Write-Host "[*] [$pkgId] (Attempt $attempt/$maxRetries) Running winget install..."
                    $wingetArgs = @('install', '--id', $pkgId, '--exact', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
                    & $exePath $wingetArgs

                    $lastCode = $LASTEXITCODE
                    if ($lastCode -eq 0) {
                        Write-Host "[+] [$pkgId] Successfully installed!"
                        $installed = $true
                        break
                    }
                    else {
                        if ($attempt -lt $maxRetries) {
                            Write-Warning "[-] [$pkgId] Winget returned code $lastCode. Retrying in ${retryDelay}s..."
                            Start-Sleep -Seconds $retryDelay
                        }
                    }
                }

                if (-not $installed) {
                    Write-Warning "[!] [$pkgId] Winget failed with exit code $lastCode. Triggering direct fallback..."
                    if ($pkgId -match 'Sysinternals') {
                        try {
                            $targetZip = Join-Path $downloadsPath "SysinternalsSuite.zip"
                            $targetDir = Join-Path $targetInstallDir "Sysinternals"
                            Write-Host "[*] Downloading Sysinternals directly..."
                            Invoke-FastDownload 'https://download.sysinternals.com/files/SysinternalsSuite.zip' $targetZip
                            if (Test-Path $targetZip) {
                                if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
                                Expand-Archive -Path $targetZip -DestinationPath $targetDir -Force
                                Write-Host "[+] [$pkgId] Sysinternals installed directly from zip!"
                                $installed = $true
                            }
                        } catch {
                            Write-Warning "[!] Sysinternals direct install failed: $($_.Exception.Message)"
                        }
                    }
                    elseif ($pkgId -match 'Firefox') {
                        try {
                            $targetExe = Join-Path $downloadsPath "FirefoxInstaller.exe"
                            Write-Host "[*] Downloading Firefox directly..."
                            Invoke-FastDownload 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' $targetExe
                            if (Test-Path $targetExe) {
                                $proc = Start-Process -FilePath $targetExe -ArgumentList '/S' -Wait -PassThru
                                if ($proc.ExitCode -in 0, 3010) {
                                    Write-Host "[+] [$pkgId] Firefox installed directly via silent installer!"
                                    $installed = $true
                                }
                            }
                        } catch {
                            Write-Warning "[!] Firefox direct install failed: $($_.Exception.Message)"
                        }
                    }
                }

                if (-not $installed) {
                    Write-Warning "[!] [$pkgId] Installation failed completely with exit code $lastCode"
                    $failedPackages.Add("$pkgId (code $lastCode)")
                }
            }

            if ($failedPackages.Count -gt 0) {
                throw "Package installation failed for: $($failedPackages -join ', ')"
            }
        } -ArgumentList $packages, $wingetPath, $InstallDir, $dl

        $Jobs.Add($job)
    }
    else {
        Write-Warning "[!] winget unavailable. Falling back to direct fast download for Firefox."

        # Add Firefox to direct download queue with silent installer switch
        $Downloads.Add(@{
            Name        = 'Firefox'
            Url         = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
            InstallArgs = '/S'
        })
    }

    # 2. Standalone file download & install jobs
    foreach ($d in $Downloads) {
        Write-Host "[+] Queuing download job for: $($d.Name)" -ForegroundColor Cyan
        $job = Start-Job -Name "Download-$($d.Name)" -ScriptBlock {
            param($name, $url, $destDir, $targetInstallDir, $installArgs)
            $ErrorActionPreference = 'Stop'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            function Invoke-FastDownload {
                param($u, $o)
                $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
                if ($curl) {
                    & $curl.Source -s -S -L --connect-timeout 10 --max-time 300 -o $o $u
                    if ($LASTEXITCODE -eq 0 -and (Test-Path $o) -and (Get-Item $o).Length -gt 0) { return }
                }
                try {
                    $wc = New-Object System.Net.WebClient
                    $wc.DownloadFile($u, $o)
                    return
                } catch {}
                Invoke-WebRequest -Uri $u -OutFile $o -UseBasicParsing -TimeoutSec 300
            }

            $filename = Split-Path -Leaf $url
            if (-not $filename -or $filename -notlike "*.*") {
                $filename = if ($installArgs) { "$name.exe" } else { "$name.dat" }
            }
            $outFile = Join-Path $destDir $filename

            Write-Host "[*] [$name] Downloading from $url to $outFile..."
            Invoke-FastDownload $url $outFile
            Write-Host "[+] [$name] Download complete."

            # If it's a zip file, unpack it
            if ($filename -like "*.zip") {
                $extractPath = Join-Path $targetInstallDir $name
                Write-Host "[*] [$name] Extracting archive to $extractPath..."
                Expand-Archive -Path $outFile -DestinationPath $extractPath -Force
                Write-Host "[+] [$name] Archive extracted."
            }
            # If silent installer args provided, execute installer
            elseif ($installArgs) {
                Write-Host "[*] [$name] Running silent installer ($installArgs)..."
                $proc = Start-Process -FilePath $outFile -ArgumentList $installArgs -Wait -PassThru
                if ($proc.ExitCode -in 0, 3010) {
                    Write-Host "[+] [$name] Installation successful!"
                } else {
                    Write-Warning "[-] [$name] Installer exited with code: $($proc.ExitCode)"
                }
            }
        } -ArgumentList $d.Name, $d.Url, $DownloadsDir, $InstallDir, $d.InstallArgs

        $Jobs.Add($job)
    }

    # MONITORING: Track running jobs and notify as each finishes
    # -----------------------------------------------------------
    if ($Jobs.Count -gt 0) {
        Write-Host "`n[+] Launched $($Jobs.Count) install/download job(s) in parallel. Waiting for completion..." -ForegroundColor Cyan
        $Jobs | Format-Table Id, Name, State -AutoSize | Out-String | Write-Host

        $completedIds = [System.Collections.Generic.HashSet[int]]::new()
        $jobResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $spinChars = @('|', '/', '-', '\')
        $spinIndex = 0

        while ($completedIds.Count -lt $Jobs.Count) {
            $runningJobs = @($Jobs | Where-Object { -not $completedIds.Contains($_.Id) } | ForEach-Object { $_.Name })
            $statusText = "`r[$($spinChars[$spinIndex])] Running ($($runningJobs.Count) active): $($runningJobs -join ', ')...".PadRight(75)
            Write-SpinnerFrame $statusText
            $spinIndex = ($spinIndex + 1) % $spinChars.Count

            foreach ($j in $Jobs) {
                if (-not $completedIds.Contains($j.Id)) {
                    $current = Get-Job -Id $j.Id
                    if ($current.State -ne 'Running' -and $current.State -ne 'NotStarted') {
                        $completedIds.Add($j.Id) | Out-Null

                        # Clear the spinner line before writing job completion output
                        Clear-SpinnerLine

                        $outputLines = $null
                        $isFailed = ($current.State -eq 'Failed')
                        $errMsg = $null

                        try {
                            $outputLines = Receive-Job -Job $current -ErrorAction Stop
                        }
                        catch {
                            $isFailed = $true
                            $errMsg = $_.Exception.Message
                        }

                        if (-not $isFailed -and $current.State -eq 'Completed') {
                            Write-Host "[+] Job '$($current.Name)' completed successfully!" -ForegroundColor Green
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $current.Name
                                Status  = "Success"
                                Details = "Completed"
                            })
                        }
                        else {
                            if (-not $errMsg) {
                                $errMsg = if ($current.ChildJobs.JobStateInfo.Reason) {
                                    $current.ChildJobs.JobStateInfo.Reason.Message
                                } else {
                                    "Exited with state $($current.State)"
                                }
                            }
                            Write-Host "[!] Job '$($current.Name)' failed: $errMsg" -ForegroundColor Red
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $current.Name
                                Status  = "Failed"
                                Details = $errMsg
                            })
                        }

                        if ($isFailed -and $outputLines) {
                            Write-Host "--- Output from $($current.Name) ---" -ForegroundColor DarkGray
                            $outputLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                            Write-Host "------------------------------------" -ForegroundColor DarkGray
                        }
                    }
                }
            }
            Start-Sleep -Milliseconds 250
        }

        # Clear spinner line once all jobs finish
        Clear-SpinnerLine

        # -----------------------------------------------------------
        # SUMMARY: Final status output
        # -----------------------------------------------------------
        $successCount = ($jobResults | Where-Object { $_.Status -eq 'Success' }).Count
        $failCount = ($jobResults | Where-Object { $_.Status -eq 'Failed' }).Count
        $totalCount = $jobResults.Count

        Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
        Write-Host "               ALL INSTALL JOBS COMPLETE" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan
        $jobResults | Format-Table -AutoSize | Out-String | Write-Host

        $timestamp = Get-Date -Format "HH:mm:ss"

        if ($failCount -eq 0) {
            Write-Host "[+] [$timestamp] All $totalCount installs finished successfully." -ForegroundColor Green
        }
        else {
            Write-Host "[!] [$timestamp] Installs complete: $successCount succeeded, $failCount failed." -ForegroundColor Red
        }
        Write-Host (("=" * 60) + "`n") -ForegroundColor Cyan

        # Cleanup jobs
        $Jobs | ForEach-Object { Remove-Job -Job $_ -Force -ErrorAction SilentlyContinue }

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
    }
    else {
        Write-Host "[!] No jobs queued to run." -ForegroundColor Yellow
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