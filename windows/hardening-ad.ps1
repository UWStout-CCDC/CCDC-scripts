# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

$Host.UI.RawUI.ForegroundColor = "Blue"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

Write-Host " _       ___           __                      ________                          "
Write-Host "| |     / (_)___  ____/ /___ _      _______   / ____/ /__  ____ _____  ___  _____"
Write-Host "| | /| / / / __ \/ __  / __ \ | /| / / ___/  / /   / / _ \/ __ `/ __ \/ _ \/ ___/"
Write-Host "| |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  )  / /___/ /  __/ /_/ / / / /  __/ /    "
Write-Host "|__/|__/_/_/ /_/\__,_/\____/|__/|__/____/   \____/_/\___/\__,_/_/ /_/\___/_/  "

$site = "UWStout-CCDC/CCDC-scripts" # Change when changing repo
New-Item -Path "C:\CCDC" -ItemType Directory
New-Item -Path "C:\CCDC\tools-Windows" -ItemType Directory
New-Item -Path "C:\CCDC\DNS" -ItemType Directory
$ccdcPath = "C:\CCDC"
$env:Path += ";C:\CCDC"

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
        $password = ""
        $letterNumberArray = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8','9','0', '!', '@', '#', '$', '%', '^', '&', '*')
        for(($counter=0); $counter -lt 20; $counter++)
        {
        $randomCharacter = get-random -InputObject $letterNumberArray
        $password += $randomCharacter
        }

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $krbtgt = Get-LocalUser -Name "krbtgt"
        Set-LocalUser -Name $krbtgt -Password $securePassword
        $count++
    }
    
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Kerberos account password rotated successfully."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while rotating Kerberos password: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}


# Download the install script
$path = "$ccdcPath\Installs.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/$site/raw/refs/heads/main/Installs.ps1" -OutFile $path



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


# Configure Remote Desktop settings (disable if not needed)
Start-LoggedJob -JobName "Disable Remote Desktop" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Ser\ver' -Name "fDenyTSConnections" -Value 1
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

#Enable audit policies for key events like login, account management, file system changes, and registry changes
Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
    try {
        AuditPol.exe /set /category:"System" /subcategory:"Security State Change" /success:enable /failure:enable
        AuditPol.exe /set /category:"System" /subcategory:"System Integrity" /success:enable /failure:enable
        AuditPol.exe /set /category:"System" /subcategory:"Other System Events" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Logon" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Special Logon" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Group Membership" /success:enable /failure:enable
        AuditPol.exe /set /category:"Logon/Logoff" /subcategory:"Access Rights" /success:enable /failure:enable
        AuditPol.exe /set /category:"Object Access" /subcategory:"File System" /success:enable /failure:enable
        AuditPol.exe /set /category:"Object Access" /subcategory:"Registry" /success:enable /failure:enable
        AuditPol.exe /set /category:"Object Access" /subcategory:"SAM" /success:enable /failure:enable
        AuditPol.exe /set /category:"Object Access" /subcategory:"File Share" /success:enable /failure:enable
        AuditPol.exe /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable
        AuditPol.exe /set /category:"Detailed Tracking" /subcategory:"Process Termination" /success:enable /failure:enable
        AuditPol.exe /set /category:"Policy Change" /subcategory:"Audit Policy Change" /success:enable /failure:enable
        AuditPol.exe /set /category:"Policy Change" /subcategory:"Authentication Policy Change" /success:enable /failure:enable
        AuditPol.exe /set /category:"Policy Change" /subcategory:"Authorization Policy Change" /success:enable /failure:enable
        AuditPol.exe /set /category:"Policy Change" /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
        AuditPol.exe /set /category:"Account Management" /subcategory:"User Account Management" /success:enable /failure:enable
        AuditPol.exe /set /category:"Account Management" /subcategory:"Other Account Management Events" /success:enable /failure:enable
        AuditPol.exe /set /category:"DS Access" /subcategory:"Directory Service Access" /success:enable /failure:enable
        AuditPol.exe /set /category:"DS Access" /subcategory:"Directory Service Changes" /success:enable /failure:enable
        AuditPol.exe /set /category:"Account Logon" /subcategory:"Credential Validation" /success:enable /failure:enable
        AuditPol.exe /set /category:"Account Logon" /subcategory:"Kerberos Authentication" /success:enable /failure:enable
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Audit policies for login, account management, file system changes, and registry changes enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling audit policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Secure and backup DNS to ccdc folder NOTE TO SELF: figure out how to restore
# Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock { back up manually
#     try {
#         dnscmd.exe /Config /SocketPoolSize 10000
#         dnscmd.exe /Config /CacheLockingPercent 100
#         dnscmd.exe /ZoneExport $zone "$ccdcPath\DNS\$zone.dns"
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "DNS secured and backed up."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while securing and backing up DNS: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }


# Block credential dumping
# Start-LoggedJob -JobName "Block Credential Dumping" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
#         Set-ItemProperty -Path $regPath -Name "NoLmHash" -Value 1
#         Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1
#         Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
#         Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
#         Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
#         Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
        
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
#         Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0
#         Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0
#         Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value ""
#         Set-ItemProperty -Path $regPath -Name "NullSessionShares" -Value ""
#         Set-ItemProperty -Path $regPath -Name "Samba" -Value 0

#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
#         Set-ItemProperty -Path $regPath -Name "EnableSecuritySignature" -Value 1
#         Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1
#         Set-ItemProperty -Path $regPath -Name "EnablePlainTextPassword" -Value 0
        
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Credential dumping blocked."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#         Write-Host "An error occurred while blocking credential dumping: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#     }
# }

# # disable remote sign in
# Start-LoggedJob -JobName "Disable Remote Sign-in" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#         Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Remote sign-in disabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while disabling remote sign-in: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Enable LSA Protection, restrict debug privileges, disable WDigest
# Start-LoggedJob -JobName "Enable LSA Protection" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
#         Set-ItemProperty -Path $regPath -Name "LsaCfgFlags" -Value 1
#         Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "LSA Protection enabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while enabling LSA Protection: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }
# Start-LoggedJob -JobName "Restrict Debug Privileges" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
#         Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
#         Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
#         Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
#         Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
#         Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Debug privileges restricted."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while restricting debug privileges: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }
# Start-LoggedJob -JobName "Disable WDigest" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
#         Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "WDigest disabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while disabling WDigest: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# disable powershell remoting
Start-LoggedJob -JobName "Disable PowerShell Remoting" -ScriptBlock {
    try {
        # Disable PSRemoting
        Disable-PSRemoting -Force

        # Delete the listener that accepts requests on any IP address
        winrm delete winrm/config/Listener?Address=*+Transport=HTTP
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

        # Stop and disable the WinRM service
        Stop-Service -Name WinRM -Force
        Set-Service -Name WinRM -StartupType Disabled
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
# Start-LoggedJob -JobName "Enable Windows Defender Credential Guard" -ScriptBlock {
#     try {
#         Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
#         Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
#         Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RunAsPPL" -Value 1
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Windows Defender Credential Guard enabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while enabling Windows Defender Credential Guard: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

## Reminder to look into theese two later
# Start-LoggedJob -JobName "Patch Mimikatz" -ScriptBlock {
#     try {
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
#         if (Test-Path $regPath) {
#             Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
#         }
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Mimikatz patched."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while patching Mimikatz: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

Start-LoggedJob -JobName "Patch DCSync Vulnerability" -ScriptBlock {
    try {
        Import-Module ActiveDirectory
        $permissions = Get-ACL "AD:\$((Get-ADDomain))" | Select-Object -ExpandProperty Access
        $criticalPermissions = $permissions | Where-Object { $_.ObjectType -eq "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.ObjectType -eq "4c164200-20c0-11d0-a768-00aa006e0529" }
        foreach ($permission in $criticalPermissions) {
            if ($permission.ActiveDirectoryRights -match "Replicating Directory Changes") {
                Write-Host "Removing Replicating Directory Changes permission from $($permission.IdentityReference)"
                $permissions.RemoveAccessRule($permission)
            }
        }
        Set-ACL -Path "AD:\$((Get-ADDomain))" -AclObject $permissions
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "DCSync vulnerability patched."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while patching DCSync vulnerability: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

## Make sure the only SMB allowed is SMBv2 (we hate SMBv1)
Start-LoggedJob -JobName "Force the Good SMB" -ScriptBlock {
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        
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

# Install winget
try {
    Write-Host "Installing winget..."
    Install-Script -Name winget-install
    winget-install
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Winget installation complete."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while installing winget: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}