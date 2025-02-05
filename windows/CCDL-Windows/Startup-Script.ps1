# # Import necessary modules
# Import-Module -Name Microsoft.PowerShell.LocalAccounts
# Import-Module -Name NetSecurity
# Import-Module -Name BitsTransfer

# # Create directories
# $ccdcPath = "C:\CCDC"
# $toolsPath = "$ccdcPath\tools-Windows"
# mkdir $ccdcPath -wait

# mkdir "$ccdcPath\DNS" -wait

# mkdir "C:\CCDC\tools-Windows" -wait

# # Download the install script
# $installScriptPath = "$toolsPath\Installs.ps1"
# Write-Host "Downloading install script..."
# Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Installs.ps1" -OutFile $installScriptPath

# # Download necessary tools
# $tools = @(
#     @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
#     @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" },
#     @{ Name = "ClamAV Installer Part 1"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.1"; Path = "$toolsPath\setup_part.1" },
#     @{ Name = "ClamAV Installer Part 2"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.2"; Path = "$toolsPath\setup_part.2" },
#     @{ Name = "Wireshark Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Wireshark-4.4.3-x64.exe"; Path = "$toolsPath\Wireshark-4.4.3-x64.exe" },
#     @{ Name = "Autoruns"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Autoruns.zip"; Path = "$toolsPath\Autoruns.zip" },
#     @{ Name = "ProcessExplorer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessExplorer.zip"; Path = "$toolsPath\ProcessExplorer.zip" },
#     @{ Name = "ProcessMonitor"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessMonitor.zip"; Path = "$toolsPath\ProcessMonitor.zip" },
#     @{ Name = "TCPView"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/TCPView.zip"; Path = "$toolsPath\TCPView.zip" }
# )

# foreach ($tool in $tools) {
#     Write-Host "Downloading $($tool.Name)..."
#     Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
# }
# $destPrefix = "$toolsPath\setup_part"
# # Verify the split
# $part1Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.1")
# $part2Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.2")
# $part1Bytes.Length, $part2Bytes.Length 

# # Combine the parts back into a single file
# $combinedFile = "$toolsPath\combined.msi"
# $combinedBytes = [byte[]]::new($part1Bytes.Length + $part2Bytes.Length)
# [System.Array]::Copy($part1Bytes, 0, $combinedBytes, 0, $part1Bytes.Length)
# [System.Array]::Copy($part2Bytes, 0, $combinedBytes, $part1Bytes.Length, $part2Bytes.Length)
# [System.IO.File]::WriteAllBytes($combinedFile, $combinedBytes)

# # Verify the combined file
# $combinedBytes = [System.IO.File]::ReadAllBytes($combinedFile)
# $combinedBytes.Length, $totalSize

# # Check if PSWindowsUpdate is installed, if not, install it
# if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
#     Write-Host "PSWindowsUpdate module not found. Installing..."
#     Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
# }

# Import-Module -Name PSWindowsUpdate

# # Ask the user if it is the scored 2019 box
# $server = Read-Host "Does this server have AD/DNS? (yes/no)"

# # Ask the user if they want to run the setup
# $runSetup = Read-Host "Do you want to run the setup? (yes/no)"
# if ($runSetup -ne "yes") {
#     Write-Host "Skipping setup..."
#     goto installs
# }

# Write-Host "Synchronizing system time..."
# Start-Job -ScriptBlock { w32tm /resync }

# # Prompt for new administrator password and confirmation
# do {
#     $newAdminPassword = Read-Host -AsSecureString "Enter new password for the local administrator account"
#     $confirmAdminPassword = Read-Host -AsSecureString "Confirm new password for the local administrator account"

#     $newAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newAdminPassword))
#     $confirmAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmAdminPassword))

#     if ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain) {
#         Write-Host "Passwords do not match. Please try again."
#     }
# } while ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain)

# # Change local administrator password
# $adminAccount = Get-LocalUser -Name "Administrator"
# Set-LocalUser -Name $adminAccount -Password $newAdminPassword

# # Rename administrator account for security
# # $newAdminName = Read-Host "Enter a new name for the administrator account"
# # Rename-LocalUser -Name "Administrator" -NewName $newAdminName
# # Write-Host "Administrator account renamed to $newAdminName."

# # List all user accounts
# Write-Host "Listing all user accounts:"
# Get-LocalUser | Format-Table -Property Name, Enabled, LastLogon

# # Disable guest account
# $guestAccount = Get-LocalUser -Name "Guest"
# if ($guestAccount.Enabled) {
#     Disable-LocalUser -Name "Guest"
#     Write-Host "Guest account has been disabled."
# } else {
#     Write-Host "Guest account is already disabled."
# }

# # Set strong password policies
# Write-Host "Setting strong password policies..."
# Start-Job -ScriptBlock { net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 }

# # Disable unnecessary services
# $servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
# foreach ($service in $servicesToDisable) {
#     Start-Job -ScriptBlock {
#         param ($service)
#         Write-Host "Disabling service: $service"
#         Stop-Service -Name $service -Force
#         Set-Service -Name $service -StartupType Disabled
#     } -ArgumentList $service
# }

# # Enable Windows Defender with real-time protection and PUA protection
# Write-Host "Enabling Windows Defender and configuring protection settings..."
# Start-Job -ScriptBlock {
#     Set-MpPreference -DisableRealtimeMonitoring $false
#     Set-MpPreference -PUAProtection Enabled
# }

# # Enable Windows Firewall with basic rules
# Write-Host "Configuring Windows Firewall..."
# Start-Job -ScriptBlock {
#     # Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#     # Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    
#     # Export existing Firewall
#     Export-WindowsFirewallRules -FilePath "$ccdcPath\firewall.old"
#     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#     # Block by default
#     Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
#     Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
#     # Enable Logging
#     Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True
#     Set-NetFirewallSetting -StatefulFtp Disable
#     Set-NetFirewallSetting -StatefulPptp Disable
    
#     # Disable existing rules
#     Get-NetFirewallRule | Set-NetFirewallRule -Enabled False
    
#     # Firewall inbound rules
#     New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#     New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
#     New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol TCP
#     New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol UDP
#     New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3268 -Protocol TCP
#     New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" -Direction Inbound -Action Allow -Program "System" -Enabled True -Profile Any -LocalPort 138 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Secure LDAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 636 -Protocol TCP
#     New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3269 -Protocol TCP
#     New-NetFirewallRule -DisplayName "RPC IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP
#     New-NetFirewallRule -DisplayName "RPC-EPMAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort RPC-EPMap -Protocol TCP
#     New-NetFirewallRule -DisplayName "DHCP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 67,68 -Protocol UDP
#     New-NetFirewallRule -DisplayName "RPC for DNS IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP

#     # Outbound rules
#     New-NetFirewallRule -DisplayName "Allow Pings out" -Direction Outbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#     New-NetFirewallRule -DisplayName "Splunk OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
#     New-NetFirewallRule -DisplayName "Web OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 80,443 -Protocol TCP
#     New-NetFirewallRule -DisplayName "NTP OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 123 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Active Directory TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol TCP
#     New-NetFirewallRule -DisplayName "Active Directory UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol TCP
#     New-NetFirewallRule -DisplayName "DNS UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 53 -Protocol UDP
#     New-NetFirewallRule -DisplayName "DHCP" -Direction Outbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 68 -RemotePort 67 -Protocol UDP
# }

# # Disable SMBv1 to mitigate vulnerabilities
# Write-Host "Disabling SMBv1 protocol..."
# Start-Job -ScriptBlock {
#     Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#     Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
# }

# # Configure Remote Desktop settings (disable if not needed)
# Write-Host "Disabling Remote Desktop Protocol..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
# }

# # Set account lockout policies
# Write-Host "Configuring account lockout policies..."
# Start-Job -ScriptBlock { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }

# # Enable audit policies for key events
# Write-Host "Enabling audit policies for login and account management..."
# Start-Job -ScriptBlock {
#     AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
#     AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
# }

# # Remove unnecessary network shares
# Write-Host "Removing unnecessary network shares..."
# Start-Job -ScriptBlock {
#     Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" } | ForEach-Object {
#         Write-Host "Removing share: $($_.Name)"
#         Remove-SmbShare -Name $_.Name -Force
#     }
# }

# # Enable Windows Firewall (reaffirm if previously configured)
# Write-Host "Reaffirming Windows Firewall enabled..."
# Start-Job -ScriptBlock {
#     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# }

# # Disable IPv6 if not needed
# Write-Host "Disabling IPv6..."
# Start-Job -ScriptBlock {
#     Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
#     Set-NetIPv6Protocol -State Disabled
# }

# # Ensure Windows Update is set to automatic
# Write-Host "Setting Windows Update to automatic..."
# Start-Job -ScriptBlock {
#     Set-Service -Name wuauserv -StartupType Automatic
#     Write-Host "Checking for Windows updates..."
#     Install-WindowsUpdate -AcceptAll -Install
# }

# # Secure and backup DNS
# Write-Host "Securing DNS..."
# Get-DNSServerZone
# $zone = Read-Host "Enter the DNS zone used by the scoring engine"
# Start-Job -ScriptBlock {
#     dnscmd.exe /Config /SocketPoolSize 10000
#     dnscmd.exe /Config /CacheLockingPercent 100
#     dnscmd.exe /ZoneExport $zone $toolsPath
# }

# # Additional security measures
# # Write-Host "Enabling Secure Boot..."
# # Start-Job -ScriptBlock { Confirm-SecureBootUEFI }
# Write-Host "Configuring Windows Defender Exploit Guard..."
# Start-Job -ScriptBlock { Set-MpPreference -EnableControlledFolderAccess Enabled }

# # Write-Host "Enabling BitLocker for drive encryption..."
# # Start-Job -ScriptBlock { Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector }

# Write-Host "Configuring Network Level Authentication for Remote Desktop..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 }

# Write-Host "Disabling LM and NTLMv1 protocols..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 }

# Write-Host "Enabling Windows Defender Credential Guard..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
#     Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
# }

# Write-Host "Configuring Windows Update to install updates automatically..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4 }

# Write-Host "Enabling logging for PowerShell..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name "EnableScriptBlockLogging" -Value 1
#     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name "EnableTranscripting" -Value 1
# }

# # Ask the user if they want to run the installs
# $runInstalls = Read-Host "Do you want to run the installs? (yes/no)"
# if ($runInstalls -ne "yes") {
#     Write-Host "Skipping installs..."
#     exit
# }
# else {
#     # Set the installer script run on start
#     $scriptPath = "$toolsPath\Installs.ps1"
#     $entryName = "MyStartupScript"
#     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""
# }

# Write-Host "Performing a quick scan with Windows Defender..."
# Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan }

# Write-Host "Basic security checks and configurations are complete."
# Write-Host "Please review if there are Windows updates available."

# # Wait for all jobs to complete
# Get-Job | Wait-Job

# Write-Host "Restarting Computer"
# Restart-Computer

# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Create directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir $ccdcPath 
mkdir "$ccdcPath\DNS" 
mkdir "C:\CCDC\tools-Windows" 

# Download the install script
$installScriptPath = "$toolsPath\Installs.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Installs.ps1" -OutFile $installScriptPath

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

# Ask the user if it is the scored 2019 box
$server = Read-Host "Does this server have AD/DNS? (yes/no)"

# Ask the user if they want to run the setup
$runSetup = Read-Host "Do you want to run the setup? (yes/no)"
if ($runSetup -ne "yes") {
    Write-Host "Skipping setup..."
    goto installs
}


# Initialize the global jobs array
$global:jobs = @()

function Start-LoggedJob {
    param (
        [string]$JobName,
        [scriptblock]$ScriptBlock
    )
    
    $job = Start-Job -Name $JobName -ScriptBlock $ScriptBlock
    $global:jobs += @($job)  # Ensure the job is added as an array element
    Write-Host "Started job: $JobName"
}

# Monitor jobs
while ($global:jobs.Count -gt 0) {
    foreach ($job in $global:jobs) {
        if ($job.State -eq 'Completed') {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - $($job.Name) has completed."
            $job | Receive-Job
            Remove-Job -Job $job
            $global:jobs = $global:jobs | Where-Object { $_.Id -ne $job.Id }
        }
    }
    Start-Sleep -Seconds 5
}

# Sync system time
Start-LoggedJob -JobName "Synchronize System Time" -ScriptBlock {
    tzutil /s "Central Standard Time"
    w32tm /resync
}

# Prompt for new administrator password and confirmation
Start-LoggedJob -JobName "Change Admin Password" -ScriptBlock {
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
}

# Disable guest account
Start-LoggedJob -JobName "Disable Guest Account" -ScriptBlock {
    $guestAccount = Get-LocalUser -Name "Guest"
    if ($guestAccount.Enabled) {
        Disable-LocalUser -Name "Guest"
        Write-Host "Guest account has been disabled."
    } else {
        Write-Host "Guest account is already disabled."
    }
}

# Set strong password policies
Start-LoggedJob -JobName "Set Password Policies" -ScriptBlock { net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 }

# Disable unnecessary services
$servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
foreach ($service in $servicesToDisable) {
    Start-LoggedJob -JobName "Disable Service: $service" -ScriptBlock {
        param ($service)
        Write-Host "Disabling service: $service"
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
    } -ArgumentList $service
}

# Enable Windows Defender with real-time protection and PUA protection
Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -PUAProtection Enabled
}

# Enable Windows Firewall with basic rules
Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
    # Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    # Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    
    # Export existing Firewall
    Export-WindowsFirewallRules -FilePath "$ccdcPath\firewall.old"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    # Block by default
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
    # Enable Logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True
    Set-NetFirewallSetting -StatefulFtp Disable
    Set-NetFirewallSetting -StatefulPptp Disable
    
    # Disable existing rules
    Get-NetFirewallRule | Set-NetFirewallRule -Enabled False
    
    # Firewall inbound rules
    New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
    New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
    New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
    New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
    New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol TCP
    New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol UDP
    New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3268 -Protocol TCP
    New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" -Direction Inbound -Action Allow -Program "System" -Enabled True -Profile Any -LocalPort 138 -Protocol UDP
    New-NetFirewallRule -DisplayName "Secure LDAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 636 -Protocol TCP
    New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3269 -Protocol TCP
    New-NetFirewallRule -DisplayName "RPC IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP
    New-NetFirewallRule -DisplayName "RPC-EPMAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort RPC-EPMap -Protocol TCP
    New-NetFirewallRule -DisplayName "DHCP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 67,68 -Protocol UDP
    New-NetFirewallRule -DisplayName "RPC for DNS IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP

    # Outbound rules
    New-NetFirewallRule -DisplayName "Allow Pings out" -Direction Outbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
    New-NetFirewallRule -DisplayName "Splunk OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
    New-NetFirewallRule -DisplayName "Web OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 80,443 -Protocol TCP
    New-NetFirewallRule -DisplayName "NTP OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 123 -Protocol UDP
    New-NetFirewallRule -DisplayName "Active Directory TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol TCP
    New-NetFirewallRule -DisplayName "Active Directory UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol UDP
    New-NetFirewallRule -DisplayName "DNS TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol TCP
    New-NetFirewallRule -DisplayName "DNS UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol UDP
    New-NetFirewallRule -DisplayName "DNS OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 53 -Protocol UDP
    New-NetFirewallRule -DisplayName "DHCP" -Direction Outbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 68 -RemotePort 67 -Protocol UDP
}

# Disable SMBv1 to mitigate vulnerabilities
Start-LoggedJob -JobName "Disable SMBv1" -ScriptBlock {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $regPath -Name "SMB1" -Value 0
}

# Configure Remote Desktop settings (disable if not needed)
Start-LoggedJob -JobName "Disable Remote Desktop" -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
}

# Set account lockout policies
Start-LoggedJob -JobName "Set Account Lockout Policies" -ScriptBlock { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }

# Enable audit policies for key events like login, account management, file system changes, and registry changes
Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
    AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
    AuditPol.exe /set /subcategory:"File System" /success:enable /failure:enable
    AuditPol.exe /set /subcategory:"Registry" /success:enable /failure:enable
}

# Remove unnecessary network shares
Start-LoggedJob -JobName "Remove Unnecessary Network Shares" -ScriptBlock {
    Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" } | ForEach-Object {
        Write-Host "Removing share: $($_.Name)"
        Remove-SmbShare -Name $_.Name -Force
    }
}

# Enable Windows Firewall (reaffirm if previously configured)
Start-LoggedJob -JobName "Reaffirm Windows Firewall" -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# Disable IPv6 if not needed
Start-LoggedJob -JobName "Disable IPv6" -ScriptBlock {
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    Set-NetIPv6Protocol -State Disabled
}

# Ensure Windows Update is set to automatic
Start-LoggedJob -JobName "Set Windows Update to Automatic" -ScriptBlock {
    Set-Service -Name wuauserv -StartupType Automatic
    Write-Host "Checking for Windows updates..."
    Install-WindowsUpdate -AcceptAll -Install
}

# Install Windows updates
Start-LoggedJob -JobName "Install Windows Updates" -ScriptBlock {
    Write-Host "Installing Windows updates..."
    #sleep for 2 minute
    Start-Sleep -Seconds 120
    Install-WindowsUpdate -AcceptAll -Install
}

# Secure and backup DNS to ccdc folder
Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock {
    $zone = Read-Host "Enter the DNS zone used by the scoring engine"
    dnscmd.exe /Config /SocketPoolSize 10000
    dnscmd.exe /Config /CacheLockingPercent 100
    dnscmd.exe /ZoneExport $zone "$ccdcPath\DNS\$zone.dns"
}

# Backup AD
Start-LoggedJob -JobName "Backup Active Directory" -ScriptBlock {
    mkdir "$ccdcPath\AD" 
    $backupPath = "$ccdcPath\AD\ADBackup"
    mkdir $backupPath 
    ntdsutil.exe "activate instance ntds" "ifm" "create full $backupPath" quit quit
}

# Backup SAM and System Hives
Start-LoggedJob -JobName "Backup SAM and System Hives" -ScriptBlock {
    mkdir "$ccdcPath\Registry" 
    $backupPath = "$ccdcPath\Registry\RegistryBackupSamSystem"
    mkdir $backupPath 
    reg save HKLM\SAM "$backupPath\SAM"
    reg save HKLM\SYSTEM "$backupPath\SYSTEM"
}

# Restrict access to the SAM and System hives to just necessary system accounts
Start-LoggedJob -JobName "Restrict Access to SAM and System Hives" -ScriptBlock {
    $backupPath = "$ccdcPath\Registry\RegistryBackupSamSystem"
    
    # Define necessary system accounts
    $adminUser = [System.Security.Principal.NTAccount]"Administrator"
    $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
    $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
    
    # Get the current ACL for the SAM hive
    $samAcl = Get-Acl "$backupPath\SAM"
    $samAcl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $samAcl.Access | ForEach-Object { $samAcl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
    $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
    $samAcl.AddAccessRule($adminRule)
    $samAcl.AddAccessRule($systemRule)
    $samAcl.AddAccessRule($trustedInstallerRule)
    
    # Apply the modified ACL to the SAM hive
    Set-Acl "$backupPath\SAM" $samAcl
    
    # Get the current ACL for the SYSTEM hive
    $systemAcl = Get-Acl "$backupPath\SYSTEM"
    $systemAcl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $systemAcl.Access | ForEach-Object { $systemAcl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $systemAcl.AddAccessRule($adminRule)
    $systemAcl.AddAccessRule($systemRule)
    $systemAcl.AddAccessRule($trustedInstallerRule)
    
    # Apply the modified ACL to the SYSTEM hive
    Set-Acl "$backupPath\SYSTEM" $systemAcl
}

# Create alert for new startup items, create message box when new startup item is created, check every 5 seconds, this should be run as a scheduled task
Start-LoggedJob -JobName "Create Alert for New Startup Items" -ScriptBlock {
    $scriptPath = "$toolsPath\StartupAlert.ps1"
    $taskName = "StartupItemAlert"
    
    # Create the script
    @"
    $startupItems = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
    $previousItems = $startupItems.PSObject.Properties.Name
    
    while ($true) {
        Start-Sleep -Seconds 5
        $currentItems = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
        $newItems = Compare-Object -ReferenceObject $previousItems -DifferenceObject $currentItems.PSObject.Properties.Name | Where-Object { $_.SideIndicator -eq '=>' }
        
        if ($newItems) {
            [System.Windows.MessageBox]::Show("New startup item detected: $($newItems.InputObject)")
            $previousItems += $newItems.InputObject
        }
    }
"@ | Set-Content -Path $scriptPath

    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
}

# Lockdown the CCDC folder
Start-LoggedJob -JobName "Lockdown CCDC Folder" -ScriptBlock {
    $ccdcPath = "C:\CCDC"
    $acl = Get-Acl $ccdcPath
    $acl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $adminUser = [System.Security.Principal.NTAccount]"Administrator"
    $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
    $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminUser, "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemUser, "FullControl", "Allow")
    $trustedInstallerRule = New-Object System.Security.AccessControl.FileSystemAccessRule($trustedInstaller, "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($trustedInstallerRule)
    
    # Apply the modified ACL to the CCDC folder
    Set-Acl -Path $ccdcPath -AclObject $acl
}

# Restrict access to running any commands to Administrator
Start-LoggedJob -JobName "Restrict Access to Commands" -ScriptBlock {
    $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $acl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $adminUser = [System.Security.Principal.NTAccount]"Administrator"
    $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
    $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
    $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($trustedInstallerRule)
    
    # Apply the modified ACL to the registry key
    Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -AclObject $acl
}

# Disable all ports except the ones needed for AD/DNS
Start-LoggedJob -JobName "Disable All Ports Except AD/DNS" -ScriptBlock {
    # Block all inbound traffic
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    # Allow inbound traffic for necessary services
    New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
    New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
    New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
    New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
    New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389,636,3268,3269,135,1024-65535,49152-65535,88,464,53,123,445,135,137-139,389-636,3268-3269,135-135,1024-65535,49152-65535,88-88,464-464,53-53,123-123,445-445
    New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any 
    New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow 
    New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" 
    New-NetFirewallRule -DisplayName "Secure LDAP IN" 
    New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" 
    New-NetFirewallRule -DisplayName "RPC IN" 
    New-NetFirewallRule -DisplayName "RPC-EPMAP IN" 
    New-NetFirewallRule -DisplayName "DHCP UDP IN" 
}

# Create alert for Audit WMI subscriptions
Start-LoggedJob -JobName "Create Alert for Audit WMI Subscriptions" -ScriptBlock {
    $scriptPath = "$toolsPath\WmiAlert.ps1"
    $taskName = "WmiAlert"
    
    # Create the script
    @"
    $wmiSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
    $previousSubscriptions = $wmiSubscriptions.PSObject.Properties.Name
    
    while ($true) {
        Start-Sleep -Seconds 5
        $currentSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
        $newSubscriptions = Compare-Object -ReferenceObject $previousSubscriptions -DifferenceObject $currentSubscriptions.PSObject.Properties.Name | Where-Object { $_.SideIndicator -eq '=>' }
        
        if ($newSubscriptions) {
            [System.Windows.MessageBox]::Show("New WMI subscription detected: $($newSubscriptions.InputObject)")
            $previousSubscriptions += $newSubscriptions.InputObject
        }
    }
"@ | Set-Content -Path $scriptPath
    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
}

# Remove .bat or .lnk files in startup folder using scheduled task to fight persistence
Start-LoggedJob -JobName "Remove .bat or .lnk Files in Startup Folder" -ScriptBlock {
    $scriptPath = "$toolsPath\RemoveStartupFiles.ps1"
    $taskName = "RemoveStartupFiles"
    
    # Create the script
    @"
    $startupFolder = [System.Environment]::GetFolderPath('Startup')
    $filesToRemove = Get-ChildItem -Path $startupFolder -Filter "*.bat", "*.lnk"
    
    foreach ($file in $filesToRemove) {
        Remove-Item -Path $file.FullName -Force
        [System.Windows.MessageBox]::Show("Removed startup file: $($file.Name)")
    }
"@ | Set-Content -Path $scriptPath
    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
}

# Stop non admin users from installing software or running commands
Start-LoggedJob -JobName "Restrict Non-Admin Users from Installing Software" -ScriptBlock {
    $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $acl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $adminUser = [System.Security.Principal.NTAccount]"Administrator"
    $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
    $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
    $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($trustedInstallerRule)
    
    # Apply the modified ACL to the registry key
    Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -AclObject $acl
}

# Block credential dumping
Start-LoggedJob -JobName "Block Credential Dumping" -ScriptBlock {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "NoLmHash" -Value 1
    Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1
}

# block unecessary winrm traffic
Start-LoggedJob -JobName "Block Unnecessary WinRM Traffic" -ScriptBlock {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Firewall"
    Set-ItemProperty -Path $regPath -Name "AllowWinRM" -Value 0
}

# disable remote sign in
Start-LoggedJob -JobName "Disable Remote Sign-in" -ScriptBlock {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0
}

# Enable LSA Protection, restrict debug privileges, disable WDigest
Start-LoggedJob -JobName "Enable LSA Protection" -ScriptBlock {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "LsaCfgFlags" -Value 1
    Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1
}
Start-LoggedJob -JobName "Restrict Debug Privileges" -ScriptBlock {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
}
Start-LoggedJob -JobName "Disable WDigest" -ScriptBlock {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
}

# disable powershell remoting
Start-LoggedJob -JobName "Disable PowerShell Remoting" -ScriptBlock {
    Disable-PSRemoting -Force
}



# Additional security measures
Start-LoggedJob -JobName "Configure Windows Defender Exploit Guard" -ScriptBlock { Set-MpPreference -EnableControlledFolderAccess Enabled }

Start-LoggedJob -JobName "Configure Network Level Authentication for Remote Desktop" -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 }

Start-LoggedJob -JobName "Disable LM and NTLMv1 Protocols" -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 }

Start-LoggedJob -JobName "Enable Windows Defender Credential Guard" -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
}

Start-LoggedJob -JobName "Configure Windows Update to Install Updates Automatically" -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4 }

Start-LoggedJob -JobName "Enable Logging for PowerShell" -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name "EnableScriptBlockLogging" -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name "EnableTranscripting" -Value 1
}

# Disable PSExec
Start-LoggedJob -JobName "Disable PSExec" -ScriptBlock {
    $psexecPath = "C:\Windows\System32\psexec.exe"
    if (Test-Path $psexecPath) {
        Remove-Item $psexecPath -Force
        Write-Host "PSExec has been disabled."
    } else {
        Write-Host "PSExec is not present on the system."
    }
}

# Disable Sing in for users not Administrator
Start-LoggedJob -JobName "Disable Sign-in for Non-Admin Users" -ScriptBlock {
    $users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
    foreach ($user in $users) {
        Set-LocalUser -Name $user.Name -PasswordNeverExpires $true
        Write-Host "Sign-in for user $($user.Name) has been disabled."
    }
}

# Disable RDP
Start-LoggedJob -JobName "Disable RDP" -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
}



# Monitor jobs
while ($jobs.Count -gt 0) {
    foreach ($job in $jobs) {
        if ($job.State -eq 'Completed') {
            $job | Receive-Job
            $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
        }
    }
    Start-Sleep -Seconds 5
}
# Ask the user if they want to run the installs
$runInstalls = Read-Host "Do you want to run the installs? (yes/no)"
if ($runInstalls -ne "yes") {
    Write-Host "Skipping installs..."
    exit
}
else {
    # Set the installer script run on start
    $scriptPath = "$toolsPath\Installs.ps1"
    $entryName = "MyStartupScript"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""
}
# Perform a quick scan with Windows Defender
Start-LoggedJob -JobName "Quick Scan with Windows Defender" -ScriptBlock { Start-MpScan -ScanType QuickScan }
# Wait for all jobs to complete
Get-Job | Wait-Job
Write-Host "Restarting Computer"
Restart-Computer
