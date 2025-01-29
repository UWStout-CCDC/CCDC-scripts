# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Create directories
mkdir C:\CCDC
mkdir C:\CCDC\DNS

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

Write-Host "Synchronizing system time..."
Start-Job -ScriptBlock { w32tm /resync }

# Prompt for new administrator password and confirmation
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

# Rename administrator account for security
# $newAdminName = Read-Host "Enter a new name for the administrator account"
# Rename-LocalUser -Name "Administrator" -NewName $newAdminName
# Write-Host "Administrator account renamed to $newAdminName."

# List all user accounts
Write-Host "Listing all user accounts:"
Get-LocalUser | Format-Table -Property Name, Enabled, LastLogon

# Disable guest account
$guestAccount = Get-LocalUser -Name "Guest"
if ($guestAccount.Enabled) {
    Disable-LocalUser -Name "Guest"
    Write-Host "Guest account has been disabled."
} else {
    Write-Host "Guest account is already disabled."
}

# Set strong password policies
Write-Host "Setting strong password policies..."
Start-Job -ScriptBlock { net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 }

# Disable unnecessary services
$servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
foreach ($service in $servicesToDisable) {
    Start-Job -ScriptBlock {
        param ($service)
        Write-Host "Disabling service: $service"
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
    } -ArgumentList $service
}

# Enable Windows Defender with real-time protection and PUA protection
Write-Host "Enabling Windows Defender and configuring protection settings..."
Start-Job -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -PUAProtection Enabled
}

# Enable Windows Firewall with basic rules
Write-Host "Configuring Windows Firewall..."
Start-Job -ScriptBlock {
    # Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    # Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    
    # Export existing Firewall
    Export-WindowsFirewallRules -FilePath "$ccdcpath\firewall.old"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    # Block by default
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
    # Enable Logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcpath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True
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
Write-Host "Disabling SMBv1 protocol..."
Start-Job -ScriptBlock {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
}

# Configure Remote Desktop settings (disable if not needed)
Write-Host "Disabling Remote Desktop Protocol..."
Start-Job -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
}

# Set account lockout policies
Write-Host "Configuring account lockout policies..."
Start-Job -ScriptBlock { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }

# Enable audit policies for key events
Write-Host "Enabling audit policies for login and account management..."
Start-Job -ScriptBlock {
    AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
}

# Remove unnecessary network shares
Write-Host "Removing unnecessary network shares..."
Start-Job -ScriptBlock {
    Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" } | ForEach-Object {
        Write-Host "Removing share: $($_.Name)"
        Remove-SmbShare -Name $_.Name -Force
    }
}

# Enable Windows Firewall (reaffirm if previously configured)
Write-Host "Reaffirming Windows Firewall enabled..."
Start-Job -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# Disable IPv6 if not needed
Write-Host "Disabling IPv6..."
Start-Job -ScriptBlock {
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    Set-NetIPv6Protocol -State Disabled
}

# Ensure Windows Update is set to automatic
Write-Host "Setting Windows Update to automatic..."
Start-Job -ScriptBlock {
    Set-Service -Name wuauserv -StartupType Automatic
    Write-Host "Checking for Windows updates..."
    Install-WindowsUpdate -AcceptAll
}

# Secure and backup DNS
Write-Host "Securing DNS..."
Get-DNSServerZone
$zone = Read-Host "Enter the DNS zone used by the scoring engine"
Start-Job -ScriptBlock {
    dnscmd.exe /Config /SocketPoolSize 10000
    dnscmd.exe /Config /CacheLockingPercent 100
    dnscmd.exe /ZoneExport $zone C:\CCDC\DNS\
}

# Additional security measures
# Write-Host "Enabling Secure Boot..."
# Start-Job -ScriptBlock { Confirm-SecureBootUEFI }
Write-Host "Configuring Windows Defender Exploit Guard..."
Start-Job -ScriptBlock { Set-MpPreference -EnableControlledFolderAccess Enabled }

# Write-Host "Enabling BitLocker for drive encryption..."
# Start-Job -ScriptBlock { Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector }

Write-Host "Configuring Network Level Authentication for Remote Desktop..."
Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 }

Write-Host "Disabling LM and NTLMv1 protocols..."
Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 }

Write-Host "Enabling Windows Defender Credential Guard..."
Start-Job -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
}

Write-Host "Configuring Windows Update to install updates automatically..."
Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4 }

Write-Host "Enabling logging for PowerShell..."
Start-Job -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name "EnableScriptBlockLogging" -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name "EnableTranscripting" -Value 1
}

# Ask the user if they want to run the installs
$runInstalls = Read-Host "Do you want to run the installs? (yes/no)"
if ($runInstalls -ne "yes") {
    Write-Host "Skipping installs..."
    exit
}
else {
    # Set the installer script run on start
    $scriptPath = "C:\Users\Administrator\Installs.ps1"
    $entryName = "MyStartupScript"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""
}

Write-Host "Performing a quick scan with Windows Defender..."
Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan }

Write-Host "Basic security checks and configurations are complete."
Write-Host "Please review if there are Windows updates available."

# Wait for all jobs to complete
Get-Job | Wait-Job

Write-Host "Restarting Computer"
Restart-Computer