$Host.UI.RawUI.ForegroundColor = "DarkGreen"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# add eventlook, https://www.binisoft.org/wfc

Write-Host "Installer Script"

# Download necessary tools
$tools = @(
    @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
    @{ Name = "Eventlook Installer"; Url = "https://github.com/kmaki565/EventLook/releases/download/1.6.4.0/EventLook-bin-18e54c9.zip"; Path = "$toolsPath\EventLook-bin-18e54c9.zip" },
    @{ Name = "Firewall Control"; Url = "https://www.binisoft.org/download/wfc6setup.exe"; Path = "$toolsPath\wfc6setup.exe" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}
# Check if PSWindowsUpdate is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing..."
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
}

# Winget installs
Write-Host "Installing tools via winget..."
winget install Mozilla.Firefox -e --silent
winget install WiresharkFoundation.Wireshark -e --silent
winget install Microsoft.Sysinternals.Suite -e --silent

# NPCAP
$npcapInstallerPath = "C:\CCDC\npcap-1.80.exe"
Write-Host "Installing NPCAP..."
Start-Process -FilePath $npcapInstallerPath -Wait

# Eventlook
Write-Host "Installing Eventlook..."
Expand-Archive -Path "C:\CCDC\EventLook-bin-18e54c9.zip" -DestinationPath "C:\CCDC\tools-Windows\EventLook" -Force


# Firewall Control
$firewallControlInstallerPath = "C:\CCDC\wfc6setup.exe"
Write-Host "Installing Firewall Control..."
$release = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release | Select-Object -ExpandProperty Release

if ($release -ge 528040) {
    Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?LinkId=2085155" -Destination "C:\CCDC\dotnet-runtime.exe"
    Start-Process -FilePath "C:\CCDC\dotnet-runtime.exe" -Wait
} else {
    # do nothing
}
Start-Process -FilePath $firewallControlInstallerPath -Wait

$eventlookPath = "C:\CCDC\tools-Windows\EventLook\x64\Release\net8.0-windows10.0.17763\win-x64\EventLook.exe"
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$WScriptObj = New-Object -ComObject ("WScript.Shell")
$shortcutFile = Join-Path -Path $desktopPath -ChildPath Eventlook.Lnk
$shortcut = $WScriptObj.CreateShortcut($shortcutFile)
$shortcut.TargetPath = $eventlookPath
$shortcut.Save()