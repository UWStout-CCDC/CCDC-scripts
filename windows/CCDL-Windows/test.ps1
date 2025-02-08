# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Create directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir $ccdcPath -Force
mkdir "$ccdcPath\DNS" -Force
mkdir $toolsPath -Force

# Ask if tools should be downloaded
$downloadTools = Read-Host "Do you want to download the necessary tools? (yes/no)"
if ($downloadTools -eq "yes") {
    # Download necessary tools
    $tools = @(
        @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
        @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" }
    )

    foreach ($tool in $tools) {
        Write-Host "Downloading $($tool.Name)..."
        Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
    }
} else {
    Write-Host "Skipping download of tools."
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

# # Sync system time
# Start-LoggedJob -JobName "Synchronize System Time" -ScriptBlock {
#     try {
#         tzutil /s "Central Standard Time"
#         w32tm /resync
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "System time synchronized to Central Standard Time."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while synchronizing system time: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Set strong password policies
# Start-LoggedJob -JobName "Set Password Policies" -ScriptBlock {
#     try {
#         net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Password policies set successfully."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while setting password policies: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Disable unnecessary services
# $servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
# foreach ($service in $servicesToDisable) {
#     Start-LoggedJob -JobName "Disable Service: $service" -ScriptBlock {
#         param ($service)
#         Write-Host "Disabling service: $service"
#         Stop-Service -Name $service -Force
#         Set-Service -Name $service -StartupType Disabled
#     } -ArgumentList $service
# }

# # Additional test jobs
# Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
#     try {
#         Set-MpPreference -DisableRealtimeMonitoring $false
#         Set-MpPreference -PUAProtection Enabled
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Windows Defender enabled and PUA protection configured."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while enabling Windows Defender: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
#     try {
#         Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#         Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Windows Firewall configured."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while configuring Windows Firewall: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Start-LoggedJob -JobName "Disable SMBv1" -ScriptBlock {
#     try {
#         Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#         Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "SMBv1 disabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while disabling SMBv1: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }
# Perform a quick scan with Windows Defender
Start-LoggedJob -JobName "Quick Scan with Windows Defender" -ScriptBlock { 
    try {
        Start-MpScan -ScanType QuickScan
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Quick scan with Windows Defender completed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while performing a quick scan with Windows Defender: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# Secure and backup DNS to ccdc folder
Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock {
    try {
        $zone = Read-Host "Enter the DNS zone used by the scoring engine"
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

# Enable Windows Firewall with basic rules
Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
    try {
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
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Firewall configured with basic rules."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Firewall: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable audit policies for key events like login, account management, file system changes, and registry changes
Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
    try {
        AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
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

# Disable IPv6 if not needed
Start-LoggedJob -JobName "Disable IPv6" -ScriptBlock {
    try {
        Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
        Set-NetIPv6Protocol -State Disabled
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "IPv6 disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling IPv6: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Create alert for Audit WMI subscriptions
Start-LoggedJob -JobName "Create Alert for Audit WMI Subscriptions" -ScriptBlock {
    try {
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
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Alert for Audit WMI subscriptions created."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while creating alert for Audit WMI subscriptions: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Stop non admin users from installing software or running commands
Start-LoggedJob -JobName "Restrict Non-Admin Users from Installing Software" -ScriptBlock {
    try {
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
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Non-admin users restricted from installing software."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while restricting non-admin users from installing software: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Additional security measures
Start-LoggedJob -JobName "Configure Windows Defender Exploit Guard" -ScriptBlock {
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Set-MpPreference -EnableExploitProtection Enabled
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

# Disable Sign-in for users not Administrator
Start-LoggedJob -JobName "Disable Sign-in for Non-Admin Users" -ScriptBlock {
    try {
        $users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
        foreach ($user in $users) {
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $true
            Set-LocalUser -Name $user.Name -AccountNeverExpires $true
            Set-LocalUser -Name $user.Name -Enabled $false
            # Generate a random 64 character password
            $password = [System.Web.Security.Membership]::GeneratePassword(64, 0)
            # Set the password to the random password
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
            Set-LocalUser -Name $user.Name -UserMayNotChangePassword $true
            Set-LocalUser -Name $user.Name -PasswordRequired $true
            Set-LocalUser -Name $user.Name -Description "Disabled for security reasons"
            Set-LocalUser -Name $user.Name -UserMayNotChangePassword $true

            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Sign-in for user $($user.Name) has been disabled."
            Write-Host "--------------------------------------------------------------------------------"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
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

Write-Host "All jobs have completed."