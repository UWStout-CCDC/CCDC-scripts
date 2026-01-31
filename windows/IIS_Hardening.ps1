# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

$Host.UI.RawUI.ForegroundColor = "DarkGreen"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

Write-Host " _       ___           __                      ________                          "
Write-Host "| |     / (_)___  ____/ /___ _      _______   / ____/ /__  ____ _____  ___  _____"
Write-Host "| | /| / / / __ \/ __  / __ \ | /| / / ___/  / /   / / _ \/ __ `/ __ \/ _ \/ ___/"
Write-Host "| |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  )  / /___/ /  __/ /_/ / / / /  __/ /    "
Write-Host "|__/|__/_/_/ /_/\__,_/\____/|__/|__/____/   \____/_/\___/\__,_/_/ /_/\___/_/  "

$site = "UWStout-CCDC/windows" # Change when changing repo
Create-Item -Path "C:\CCDC" -ItemType Directory
Create-Item -Path "C:\CCDC\tools-Windows" -ItemType Directory

## Clear persistence and document it ##

# Registry persistence
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
                $items >> "C:\CCDC\persistence-registry.txt"
                Remove-ItemProperty -Path $path -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
    }
}

# Start menu persistence
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    Write-Host "Clearing startup items from $folder"
    Get-ChildItem -Path $folder | ForEach-Object {
        $_.FullName >> "C:\CCDC\persistence-startup.txt"
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

# Clear scheduled tasks
Write-Host "Clearing scheduled tasks..."
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
    $_.TaskName >> "C:\CCDC\persistence-schtasks.txt"
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
}

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


# Rotate Kerberos account password
try {
    $count = 0;
    while ($count -lt 3) {
        Write-Host "Rotating Kerberos account password..."
        $letterNumberArray = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8','9','0', '!', '@', '#', '$', '%', '^', '&', '*')
        for(($counter=0); $counter -lt 20; $counter++)
        {
        $randomCharacter = get-random -InputObject $letterNumberArray
        $password = $randomString + $randomCharacter
        }

        $krbtgt = Get-LocalUser -Name "krbtgt"
        Set-LocalUser -Name $krbtgt -Password $password
    }
    
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Kerberos account password rotated successfully."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while rotating Kerberos password: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

# Create directories
$ccdcPath = "C:\CCDC"
mkdir $ccdcPath 
mkdir "$ccdcPath\DNS"

# Download the GPO script
# We will uncomment this section once we find working GPOs
# $scriptPath = "$toolsPath\GPOs.ps1"
# Write-Host "Downloading GPO script..."
# Invoke-WebRequest "https://github.com/$site/raw/refs/heads/master/windows/CCDL-Windows/GPOs.ps1" -OutFile $scriptPath
# . $scriptPath

# Download the install script
$path = "$ccdcPath\Installs.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/$site/raw/refs/heads/main/Installs.ps1" -OutFile $path

# Set the installer script run on start
$scriptPath = "$ccdcPath\Installs.ps1"
$entryName = "MyStartupScript"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

# Download the update script
$path = "$ccdcPath\Win-Update.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/$site/raw/refs/heads/main/Win-Update.ps1" -OutFile $path

# Check if PSWindowsUpdate is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing..."
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
}

Import-Module -Name PSWindowsUpdate

# Print out all DNS zones
Get-DNSServerZone
# Ask the user for the DNS zone
$zone = Read-Host "Enter the DNS zone used by the scoring engine"

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

# Disable guest account
Start-LoggedJob -JobName "Disable Guest Account" -ScriptBlock {
    try {
        $guestAccount = Get-LocalUser -Name "Guest"
        if ($guestAccount.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Guest account has been disabled."
            Write-Host "--------------------------------------------------------------------------------"
        } else {
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Guest account is already disabled."
            Write-Host "--------------------------------------------------------------------------------"
        }
    } catch {
        Write-Hos   t "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling the guest account: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable Windows Defender with real-time protection and PUA protection
Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -PUAProtection Enabled
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender enabled with real-time protection and PUA protection."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling Windows Defender: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Configure IIS Passive Port Range" -ScriptBlock {
    try {
        $passivePortRange = "5000-5100"
        Write-Host "Configuring IIS Passive Port Range to $passivePortRange..." -ForegroundColor Cyan
        Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" -Name "lowDataChannelPort" -Value 5000
        Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" -Name "highDataChannelPort" -Value 5100
        Restart-Service ftpsvc
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "Configured IIS passive port range"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
    catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while setting passive port range (do this manually in IIS Manager)"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
    
}

# Enable Windows Firewall with basic rules
Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
    try {
        #Passive Port range for FTP
        $passivePortRange = "5000-5100"

        # Export existing Firewall rules using netsh
        netsh advfirewall export "$ccdcPath\firewall.old"

        # Enable Windows Firewall profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Block by default
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
        Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True

        # Enable Logging
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True

        # Disable existing on all profiles rules
        Get-NetFirewallRule | Set-NetFirewallRule -Profile Domain -Enabled False
        Get-NetFirewallRule | Set-NetFirewallRule -Profile Private -Enabled False
        Get-NetFirewallRule | Set-NetFirewallRule -Profile Public -Enabled False

        # Firewall inbound rules
        New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
        New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
        New-NetFirewallRule -DisplayName "Splunk IN" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
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
        New-NetFirewallRule -DisplayName "FTP Service (Inbound)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 21 -Description "Allows FTP control traffic."
        New-NetFirewallRule -DisplayName "FTP Passive Data (Inbound)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $passivePortRange -Description "Allows FTP passive data traffic."


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
        New-NetFirewallRule -DisplayName "FTP Service (Outbound)" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 21
        New-NetFirewallRule -DisplayName "FTP Passive Data (Outbound)" -Direction Outbound -Action Allow -Protocol TCP -LocalPort $passivePortRange


        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Firewall configured with basic rules."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Firewall: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Configure Remote Desktop settings (disable if not needed)
Start-LoggedJob -JobName "Disable Remote Desktop" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Remote Desktop Protocol disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while disabling Remote Desktop: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# Set account lockout policies
Start-LoggedJob -JobName "Set Account Lockout Policies" -ScriptBlock { 
    try {
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Account lockout policies set."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while setting account lockout policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# Enable audit policies for key events like login, account management, file system changes, and registry changes
Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
    try {
        AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"File System" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"Registry" /success:enable /failure:enable
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Audit policies for login, account management, file system changes, and registry changes enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling audit policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Remove Unnecessary Network Shares" -ScriptBlock {
    try {
        Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" -and $_.Name -ne "IPC$" -and $_.Name -ne "NETLOGON" -and $_.Name -ne "SYSVOL" } | ForEach-Object {
            Write-Host "Removing share: $($_.Name)"
            Remove-SmbShare -Name $_.Name -Force
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Unnecessary network shares removed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while removing unnecessary network shares: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}


# Install Windows updates
Start-LoggedJob -JobName "Install Windows Updates" -ScriptBlock {
    try {
        Set-Service -Name wuauserv -StartupType Automatic
        Write-Host "Installing Windows updates..."
        Start-Sleep -Seconds 60

        $maxRetries = 3
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                Install-WindowsUpdate -AcceptAll -Install
                Write-Host "--------------------------------------------------------------------------------"
                Write-Host "Windows updates installed."
                Write-Host "--------------------------------------------------------------------------------"
                $success = $true
            } catch {
                $retryCount++
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Write-Host "An error occurred while installing Windows updates: $_"
                Write-Host "Retrying... ($retryCount/$maxRetries)"
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Start-Sleep -Seconds 60
            }
        }

        if (-not $success) {
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            Write-Host "Failed to install Windows updates after $maxRetries attempts."
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An unexpected error occurred: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Secure and backup DNS to ccdc folder NOTE TO SELF: figure out how to restore
Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock {
    try {
        dnscmd.exe /Config /SocketPoolSize 10000
        dnscmd.exe /Config /CacheLockingPercent 100
        dnscmd.exe /ZoneExport $zone "$ccdcPath\DNS\$zone.dns"
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "DNS secured and backed up."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while securing and backing up DNS: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Lockdown the CCDC folder
Start-LoggedJob -JobName "Lockdown CCDC Folder" -ScriptBlock {
    try {
        $ccdcPath = "C:\CCDC"
        $acl = Get-Acl $ccdcPath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Remove existing access rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        
        # Add full control for necessary system accounts
        $adminUser = [System.Security.Principal.NTAccount]"Administrator"
        $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
        $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
        $currentUser = [System.Security.Principal.NTAccount]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminUser, "FullControl", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemUser, "FullControl", "Allow")
        $trustedInstallerRule = New-Object System.Security.AccessControl.FileSystemAccessRule($trustedInstaller, "FullControl", "Allow")
        $currentUserRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
        
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($trustedInstallerRule)
        $acl.AddAccessRule($currentUserRule)
        
        # Apply the modified ACL to the CCDC folder
        Set-Acl -Path $ccdcPath -AclObject $acl
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "CCDC folder lockdown complete."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while locking down the CCDC folder: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Block credential dumping
Start-LoggedJob -JobName "Block Credential Dumping" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "NoLmHash" -Value 1
        Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
        Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
        Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0
        Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0
        Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 1
        Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value ""
        Set-ItemProperty -Path $regPath -Name "NullSessionShares" -Value ""
        Set-ItemProperty -Path $regPath -Name "Samba" -Value 0

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Set-ItemProperty -Path $regPath -Name "EnableSecuritySignature" -Value 1
        Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1
        Set-ItemProperty -Path $regPath -Name "EnablePlainTextPassword" -Value 0
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Credential dumping blocked."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while blocking credential dumping: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# disable remote sign in
Start-LoggedJob -JobName "Disable Remote Sign-in" -ScriptBlock {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Remote sign-in disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling remote sign-in: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable LSA Protection, restrict debug privileges, disable WDigest
Start-LoggedJob -JobName "Enable LSA Protection" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "LsaCfgFlags" -Value 1
        Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "LSA Protection enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling LSA Protection: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Restrict Debug Privileges" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
        Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
        Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Debug privileges restricted."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while restricting debug privileges: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Disable WDigest" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "WDigest disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling WDigest: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# disable powershell remoting
Start-LoggedJob -JobName "Disable PowerShell Remoting" -ScriptBlock {
    try {
        # Disable PSRemoting
        Disable-PSRemoting -Force

        # Stop and disable the WinRM service
        Stop-Service -Name WinRM -Force
        Set-Service -Name WinRM -StartupType Disabled

        # Delete the listener that accepts requests on any IP address
        winrm delete winrm/config/Listener?Address=*+Transport=HTTP
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

        # Disable the firewall exceptions for WS-Management communications
        Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled False
        Set-NetFirewallRule -Name "WINRM-HTTPS-In-TCP" -Enabled False

        # Restore the value of the LocalAccountTokenFilterPolicy to 0
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "LocalAccountTokenFilterPolicy" -Value 0

        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "PowerShell remoting disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling PowerShell remoting: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Configuring Defender
Start-LoggedJob -JobName "Configure Windows Defender Exploit Guard" -ScriptBlock {
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        
        # Configure system-level mitigations
        Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy
        
        # Configure attack surface reduction rules
        Set-MpPreference -AttackSurfaceReductionRules_Ids @(
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block executable content from email and webmail clients
            "3B576869-A4EC-4529-8536-B80A7769E899",  # Block executable content from Office files
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block credential stealing from LSASS
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C"   # Block executable content from Office files that contain macros
        )
        Set-MpPreference -AttackSurfaceReductionRules_Actions @("Enable", "Enable", "Enable", "Enable")
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender Exploit Guard configured."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Defender Exploit Guard: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Enable Windows Defender Credential Guard" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RunAsPPL" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender Credential Guard enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling Windows Defender Credential Guard: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

## Reminder to look into theese two later
Start-LoggedJob -JobName "Patch Mimikatz" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Mimikatz patched."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while patching Mimikatz: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}



## Make sure the only SMB allowed is SMBv2 (we hate SMBv1)
Start-LoggedJob -JobName "Upgrade SMB" -ScriptBlock {
    try {
        $smbv1Enabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
        $smbv2Enabled = (Get-SmbServerConfiguration).EnableSMB2Protocol
        $restart = $false

        if ($smbv1Enabled -eq $true) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            $restart = $true
        }

        if ($smbv2Enabled -eq $false) {
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            $restart = $true
        }

        if ($restart -eq $true) {
            Write-Host "Please consider restarting the machine for changes to take effect."
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "SMB upgraded."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while upgrading SMB: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
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