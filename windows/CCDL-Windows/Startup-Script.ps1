# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Clear startup items from registry
$startupRegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run"
)

foreach ($path in $startupRegistryPaths) {
    Write-Host "Clearing startup items from $path"
    $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($items) {
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider") {
                Remove-ItemProperty -Path $path -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
    }
}

# Clear startup items from startup folders
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    Write-Host "Clearing startup items from $folder"
    Get-ChildItem -Path $folder | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

# Clear scheduled tasks
Write-Host "Clearing scheduled tasks..."
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
}

# Prevent users from adding scheduled tasks into the \Microsoft\* directory
Write-Host "Setting permissions to prevent users from adding scheduled tasks into the \Microsoft\* directory..."
$taskSchedulerPath = "C:\Windows\System32\Tasks\Microsoft"
icacls $taskSchedulerPath /inheritance:r
icacls $taskSchedulerPath /deny "Everyone:(OI)(CI)W"
icacls $taskSchedulerPath /grant "BUILTIN\Administrators:(OI)(CI)F"

Write-Host "Permissions set to prevent users from adding scheduled tasks into the \Microsoft\* directory, except for Administrators."

Write-Host "All startup items, scheduled tasks, and auto-start services have been cleared."

# Prompt for new administrator password and confirmation
try {
    do {
        $newAdminPassword = Read-Host -AsSecureString "Enter new password for the local administrator account"
        $confirmAdminPassword = Read-Host -AsSecureString "Confirm new password for the local administrator account"

        $newAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newAdminPassword))
        $confirmAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmAdminPassword))

        if ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain) {
            Write-Host "Passwords do not match. Please try again."
        }
    } while ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain)

    # Change local administrator password
    $adminAccount = Get-LocalUser -Name "Administrator"
    Set-LocalUser -Name $adminAccount -Password $newAdminPassword
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Administrator password changed."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while changing the administrator password: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}


# Set directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"

# Download the install script
$installScriptPath = "$toolsPath\Installs.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Installs.ps1" -OutFile $installScriptPath

# Download the update script
$installScriptPath = "$toolsPath\Win-Update.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Win-Update.ps1" -OutFile $installScriptPath

# Download necessary tools
$tools = @(
    @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
    @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" },
    @{ Name = "ClamAV Installer Part 1"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.1"; Path = "$toolsPath\setup_part.1" },
    @{ Name = "ClamAV Installer Part 2"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.2"; Path = "$toolsPath\setup_part.2" },
    @{ Name = "Wireshark Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Wireshark-4.4.3-x64.exe"; Path = "$toolsPath\Wireshark-4.4.3-x64.exe" },
    @{ Name = "Autoruns"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Autoruns.zip"; Path = "$toolsPath\Autoruns.zip" },
    @{ Name = "ProcessExplorer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessExplorer.zip"; Path = "$toolsPath\ProcessExplorer.zip" },
    @{ Name = "ProcessMonitor"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessMonitor.zip"; Path = "$toolsPath\ProcessMonitor.zip" },
    @{ Name = "TCPView"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/TCPView.zip"; Path = "$toolsPath\TCPView.zip" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}
$destPrefix = "$toolsPath\setup_part"
# Verify the split
$part1Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.1")
$part2Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.2")
$part1Bytes.Length, $part2Bytes.Length 

# Combine the parts back into a single file
$combinedFile = "$toolsPath\combined.msi"
$combinedBytes = [byte[]]::new($part1Bytes.Length + $part2Bytes.Length)
[System.Array]::Copy($part1Bytes, 0, $combinedBytes, 0, $part1Bytes.Length)
[System.Array]::Copy($part2Bytes, 0, $combinedBytes, $part1Bytes.Length, $part2Bytes.Length)
[System.IO.File]::WriteAllBytes($combinedFile, $combinedBytes)

# Verify the combined file
$combinedBytes = [System.IO.File]::ReadAllBytes($combinedFile)
$combinedBytes.Length, $totalSize

# Check if PSWindowsUpdate is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing..."
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
}

Import-Module -Name PSWindowsUpdate

# Get what Windows is running
$productName = (Get-ComputerInfo).WindowsProductName
if ($productName -eq "Windows Server 2019 Standard") {
    if ((Get-WindowsFeature -Name AD-Domain-Services).installed) {
        # Download hardening script
        $ScriptPath = "$toolsPath\ad-hardening.ps1"
        Write-Host "Downloading hardening script..."
        Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/ad-hardening.ps1" -OutFile $ScriptPath
        . "$toolsPath\ad-hardening.ps1"
    } else {
        # Download hardening script
        $ScriptPath = "$toolsPath\server2019-hardening.ps1"
        Write-Host "Downloading hardening script..."
        Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/server2019-hardening.ps1" -OutFile $ScriptPath
        . "$toolsPath\server2019-hardening.ps1"
    }
}
else {
    $ScriptPath = "$toolsPath\consumner-windows-hardening.ps1"
    Write-Host "Downloading hardening script..."
    Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/consumer-windows-hardening.ps1" -OutFile $ScriptPath
    . "$toolsPath\consumner-windows-hardening.ps1"
}

# Set the installer script run on start
$scriptPath = "$toolsPath\Installs.ps1"
$entryName = "MyStartupScript"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

Write-Host "All jobs have completed or maximum wait time exceeded."
# Wait for all jobs to complete
Get-Job | Wait-Job
Write-Host "All jobs have completed."
$entryName = "StartupScript"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName
# Restart the computer
Write-Host "--------------------------------------------------------------------------------"
Write-Host "Restarting Computer"
Write-Host "--------------------------------------------------------------------------------"
Restart-Computer