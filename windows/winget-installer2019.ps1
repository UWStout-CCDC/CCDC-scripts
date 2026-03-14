# Install-Winget.ps1
# Installs winget (App Installer) on Windows Server 2019

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

function Write-Status($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "[-] $msg" -ForegroundColor Red
}

# ── 1. Install VCLibs (required dependency) ──────────────────────────────────
Write-Status "Downloading Microsoft Visual C++ Runtime (VCLibs)..."
# $vcLibsUrl  = "https://aka.ms/Microsoft.VCLibs.x64.14.00.appx"
$vcLibsUrl  = "https://github.com/aL3891/AppxInstaller/raw/refs/heads/master/StandaloneMsi/Dependencies/Microsoft.VCLibs.x64.14.00.appx"
$vcLibsPath = "$env:TEMP\Microsoft.VCLibs.x64.14.00.appx"

Invoke-WebRequest -Uri $vcLibsUrl -OutFile $vcLibsPath -UseBasicParsing

Write-Status "Installing VCLibs..."
Add-AppxPackage -Path $vcLibsPath
Write-Success "VCLibs installed."

# ── 2. Install Microsoft.UI.Xaml (required dependency) ───────────────────────
Write-Status "Downloading Microsoft.UI.Xaml..."
$xamlUrl  = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"
$xamlNupkg = "$env:TEMP\Microsoft.UI.Xaml.2.8.6.zip"
$xamlDir   = "$env:TEMP\Microsoft.UI.Xaml"

Invoke-WebRequest -Uri $xamlUrl -OutFile $xamlNupkg -UseBasicParsing

Write-Status "Extracting Microsoft.UI.Xaml..."
Expand-Archive -Path $xamlNupkg -DestinationPath $xamlDir -Force

$xamlAppx = "$xamlDir\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx"
if (-not (Test-Path $xamlAppx)) {
    # Fallback: find any matching appx
    $xamlAppx = Get-ChildItem -Path $xamlDir -Recurse -Filter "*x64*Release*.appx" |
                Select-Object -First 1 -ExpandProperty FullName
}

Write-Status "Installing Microsoft.UI.Xaml..."
Add-AppxPackage -Path $xamlAppx
Write-Success "Microsoft.UI.Xaml installed."

# ── 3. Download the Windows App Runtime 1.8 installer ───────────────────────────
$url      = "https://aka.ms/windowsappsdk/1.8/latest/windowsappruntimeinstall-x64.exe"
$installer = "$env:TEMP\WindowsAppRuntimeInstall-x64.exe"

Write-Host "[*] Downloading Windows App Runtime 1.8..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing

# ── Run the installer ────────────────────────────────────────────────
Write-Host "[*] Installing..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $installer -Wait -PassThru

if ($proc.ExitCode -eq 0) {
    Write-Host "[+] Windows App Runtime 1.8 installed successfully." -ForegroundColor Green
} else {
    Write-Host "[-] Installer exited with code: $($proc.ExitCode)" -ForegroundColor Red
}

# ── 4. Install winget (Microsoft.DesktopAppInstaller) ────────────────────────
Write-Status "Fetching latest winget release"
$releases  = Invoke-RestMethod -Uri " aka.ms/winget"
$msixBundle = $releases.assets | Where-Object { $_.name -match "\.msixbundle$" } |
              Select-Object -First 1

if (-not $msixBundle) {
    Write-Fail "Could not find winget msixbundle in latest release."
    exit 1
}

$wingetPath = "$env:TEMP\$($msixBundle.name)"
Write-Status "Downloading $($msixBundle.name)..."
Invoke-WebRequest -Uri $msixBundle.browser_download_url -OutFile $wingetPath -UseBasicParsing

Write-Status "Installing winget..."
Add-AppxPackage -Path $wingetPath
Write-Success "winget installed successfully!"

# ── 5. Add winget to PATH for the current session ────────────────────────────
$wingetExe = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WindowsApps" -Filter "winget.exe" -ErrorAction SilentlyContinue
if ($wingetExe) {
    $env:PATH += ";$($wingetExe.DirectoryName)"
}

# ── 6. Verify ─────────────────────────────────────────────────────────────────
Write-Status "Verifying installation..."
try {
    $ver = winget --version
    Write-Success "winget is working: $ver"
} catch {
    Write-Fail "winget installed but not found in PATH. Try opening a new terminal."
}
