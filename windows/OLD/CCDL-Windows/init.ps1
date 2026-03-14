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

# Create directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir $ccdcPath 
mkdir "$ccdcPath\DNS" 
mkdir "C:\CCDC\tools-Windows" 

# Download the GPO script
$scriptPath = "$toolsPath\GPOs.ps1"
Write-Host "Downloading GPO script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/GPOs.ps1" -OutFile $scriptPath
. $scriptPath

# Set the Startup Script run on start
$scriptPath = "$toolsPath\Startup-Script.ps1"
Write-Host "Downloading Startup script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Startup-Script.ps1" -OutFile $scriptPath
$entryName = "StartupScript"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

Write-Host "Enforce the GPOs and press ENTER to restart."
Restart-Computer