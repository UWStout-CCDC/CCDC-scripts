#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Jump Box Hardening Script - Maximum Security Configuration
.DESCRIPTION
    Comprehensive hardening script for Windows firewall jump boxes.
    Implements strict security controls, enables all security features,
    configures restrictive firewall rules, and applies security-focused registry changes.
    Changes are based off Windows hardening checklist: https://www.digitalcitizen.life/restore-windows-firewall-defaults/
.NOTES
    Author: doshowipospf
    Version: 1.0
    Requires: Administrator privileges
    WARNING: This script makes significant system changes!
#>

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# Create log file
$LogPath = "$env:TEMP\WindowsHardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage }
    }
}

Write-Log "========================================" "INFO"
Write-Log "Windows Hardening Script Started" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Log file: $LogPath" "INFO"

# Confirm execution
Write-Host "`nWARNING: This script will make significant changes to system security settings." -ForegroundColor Yellow
Write-Host "It is recommended to:" -ForegroundColor Yellow
Write-Host "  1. Create a system restore point" -ForegroundColor Yellow
Write-Host "  2. Test before competition usage" -ForegroundColor Yellow
Write-Host "  3. Review the script before running" -ForegroundColor Yellow
$Confirmation = Read-Host "`nDo you want to continue? (YES to proceed)"
if ($Confirmation -ne "YES") {
    Write-Log "Script execution cancelled by user" "WARNING"
    exit
}

# Create system restore point
Write-Log "Creating system restore point..." "INFO"
try {
    Checkpoint-Computer -Description "Before Windows Hardening" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    Write-Log "System restore point created successfully" "SUCCESS"
} catch {
    Write-Log "Failed to create restore point: $($_.Exception.Message)" "WARNING"
}

# ============================================
# REGISTRY HARDENING
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "REGISTRY HARDENING" "INFO"
Write-Log "========================================" "INFO"

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [object]$Value,
        [string]$Description
    )
    
    try {
        # Create path if it doesnt exist
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        # Set the registry value
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Write-Log "[+] $Description" "SUCCESS"
    } catch {
        Write-Log "[-] Failed to set $Description : $($_.Exception.Message)" "ERROR"
    }
}

# Enable User Account Control (UAC)
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Type "DWord" -Value 1 `
    -Description "Enable User Account Control (UAC)"

Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Type "DWord" -Value 2 `
    -Description "UAC: Admin Approval Mode for built-in Administrator"

Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "FilterAdministratorToken" -Type "DWord" -Value 1 `
    -Description "UAC: Run all administrators in Admin Approval Mode"

# Enable Windows Defender (remove DisableAntiSpyware if it exists)
Write-Log "Enabling Windows Defender Antivirus..." "INFO"
try {
    Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    Write-Log "[+] Windows Defender Antivirus enabled" "SUCCESS"
} catch {
    Write-Log "[-] Windows Defender already enabled or key does not exist" "SUCCESS"
}

# Enable Automatic Updates
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" `
    -Name "NoAutoUpdate" -Type "DWord" -Value 0 `
    -Description "Enable Automatic Updates"

Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" `
    -Name "AUOptions" -Type "DWord" -Value 3 `
    -Description "Automatically download and notify for install"

# Network Security Settings
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Type "DWord" -Value 1 `
    -Description "Restrict anonymous access"

Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Type "DWord" -Value 1 `
    -Description "Block anonymous enumeration of SAM accounts"

Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "EveryoneIncludesAnonymous" -Type "DWord" -Value 0 `
    -Description "Prevent Everyone group SID in anonymous token"

Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Type "DWord" -Value 5 `
    -Description "Send NTLMv2 response only; refuse LM & NTLM"

# Disable admin autologon
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "AutoAdminLogon" -Type "DWord" -Value 0 `
    -Description "Disable admin autologon"

# Disable plain text password
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnablePlainTextPassword" -Type "DWord" -Value 0 `
    -Description "Disable plain text password"

# Disable IPv6 (optional - may not be needed in all environments)
Write-Log "Note: IPv6 disabling - evaluate your environment needs" "INFO"
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\TCPIP6\Parameters" `
    -Name "DisabledComponents" -Type "DWord" -Value 255 `
    -Description "Disable IPv6"

# Disable Remote Desktop Protocol (RDP) - comment if needed
Write-Log "Note: RDP disabling - evaluate your environment needs" "INFO"
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Type "DWord" -Value 1 `
    -Description "Disable Remote Desktop Protocol (RDP)"

# Screen saver settings
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Type "DWord" -Value 900 `
    -Description "Machine inactivity limit: 900 seconds (15 minutes)"

# Interactive logon settings
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DisableCAD" -Type "DWord" -Value 0 `
    -Description "Require CTRL+ALT+DEL for logon"

Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "PasswordExpiryWarning" -Type "DWord" -Value 14 `
    -Description "Prompt user to change password 14 days before expiration"

# ============================================
# WINDOWS DEFENDER CONFIGURATION
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "WINDOWS DEFENDER CONFIGURATION" "INFO"
Write-Log "========================================" "INFO"

try {
    # Enable real-time monitoring
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Log "[+] Real-time monitoring enabled" "SUCCESS"
    
    # Enable cloud-delivered protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Write-Log "[+] Cloud-delivered protection enabled" "SUCCESS"
    
    # Enable automatic sample submission
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
    Write-Log "[+] Automatic sample submission enabled" "SUCCESS"
    
    # Enable PUA protection
    Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    Write-Log "[+] Potentially Unwanted Application (PUA) protection enabled" "SUCCESS"
    
    # Update definitions
    Write-Log "Updating Windows Defender definitions..." "INFO"
    Update-MpSignature -ErrorAction Stop
    Write-Log "[+] Windows Defender definitions updated" "SUCCESS"
} catch {
    Write-Log "[-] Windows Defender configuration error: $($_.Exception.Message)" "ERROR"
}

# ============================================
# FIREWALL CONFIGURATION
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "FIREWALL CONFIGURATION" "INFO"
Write-Log "========================================" "INFO"

try {
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Log "[+] Windows Firewall enabled for all profiles" "SUCCESS"
    
    # Reset the firewall rules for all profiles (Domain, Private, Public)
    netsh advfirewall reset -ErrorAction Stop
    Write-Log "[+] Windows Firewall Rules reset to Default" "SUCCESS"

    # Set default inbound action to block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
    Write-Log "[+] Default inbound action set to Block" "SUCCESS"
    
    # Set default outbound action to allow (can be changed to Block for stricter control)
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Log "[+] Default outbound action set to Allow" "SUCCESS"
    
    # Enable logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -ErrorAction Stop
    Write-Log "[+] Firewall logging enabled" "SUCCESS"
} catch {
    Write-Log "[-] Firewall configuration error: $($_.Exception.Message)" "ERROR"
}

# ============================================
# LOCAL SECURITY POLICY
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "LOCAL SECURITY POLICY" "INFO"
Write-Log "========================================" "INFO"

# Export current security policy
$SecEditPath = "$env:TEMP\secedit.cfg"
$SecEditDB = "$env:TEMP\secedit.sdb"

try {
    secedit /export /cfg $SecEditPath /quiet
    
    # Read the policy file
    $SecPolicy = Get-Content $SecEditPath
    
    # Password Policy
    $SecPolicy = $SecPolicy -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 8"
    $SecPolicy = $SecPolicy -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 90"
    $SecPolicy = $SecPolicy -replace "MinimumPasswordAge = \d+", "MinimumPasswordAge = 1"
    $SecPolicy = $SecPolicy -replace "PasswordComplexity = \d+", "PasswordComplexity = 1"
    $SecPolicy = $SecPolicy -replace "ClearTextPassword = \d+", "ClearTextPassword = 0"
    
    # Account Lockout Policy
    $SecPolicy = $SecPolicy -replace "LockoutBadCount = \d+", "LockoutBadCount = 10"
    $SecPolicy = $SecPolicy -replace "ResetLockoutCount = \d+", "ResetLockoutCount = 15"
    $SecPolicy = $SecPolicy -replace "LockoutDuration = \d+", "LockoutDuration = 15"
    
    # Save modified policy
    $SecPolicy | Set-Content $SecEditPath
    
    # Import the policy
    secedit /configure /db $SecEditDB /cfg $SecEditPath /quiet
    
    Write-Log "[+] Password policy: Min length 8, Max age 90 days, Min age 1 day" "SUCCESS"
    Write-Log "[+] Password policy: Complexity enabled, reversible encryption disabled" "SUCCESS"
    Write-Log "[+] Lockout policy: 10 attempts, 15 min duration, 15 min reset" "SUCCESS"
    
    # Cleanup
    Remove-Item $SecEditPath -Force -ErrorAction SilentlyContinue
    Remove-Item $SecEditDB -Force -ErrorAction SilentlyContinue
} catch {
    Write-Log "[-] Failed to configure security policy: $($_.Exception.Message)" "ERROR"
}

# ============================================
# SERVICES HARDENING
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "SERVICES HARDENING" "INFO"
Write-Log "========================================" "INFO"

# Disable Remote Registry service
try {
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction Stop
    Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction Stop
    Write-Log "[+] Remote Registry service disabled" "SUCCESS"
} catch {
    Write-Log "[-] Failed to disable Remote Registry: $($_.Exception.Message)" "ERROR"
}

# List of unnecessary services to disable
$ServicesToConsider = @(
    "RemoteAccess",      # Routing and Remote Access
    "WMPNetworkSvc",     # Windows Media Player Network Sharing
    "LxssManager",       # Linux Subsystem Manager (WSL)
    "Fax",               # Fax service
    "XblAuthManager",    # Xbox Live Auth Manager
    "XblGameSave",       # Xbox Live Game Save
    "XboxGipSvc",        # Xbox Accessory Management
    "XboxNetApiSvc"      # Xbox Live Networking
)

Write-Log "Checking optional services (review before disabling):" "INFO"
foreach ($ServiceName in $ServicesToConsider) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($Service) {
        Write-Log "  - Found: $($Service.DisplayName) [$($Service.Status)] - Consider disabling if not needed" "INFO"
        # comment below to not actually disable:
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# ============================================
# DISABLE UNNECESSARY FEATURES
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "WINDOWS FEATURES" "INFO"
Write-Log "========================================" "INFO"

# Check if Telnet client is installed
$TelnetClient = Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -ErrorAction SilentlyContinue
if ($TelnetClient -and $TelnetClient.State -eq "Enabled") {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -ErrorAction Stop
        Write-Log "[+] Telnet Client disabled" "SUCCESS"
    } catch {
        Write-Log "[+] Failed to disable Telnet Client: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "[-] Telnet Client already disabled or not installed" "SUCCESS"
}

# Check if TFTP client is installed
$TFTPClient = Get-WindowsOptionalFeature -Online -FeatureName "TFTP" -ErrorAction SilentlyContinue
if ($TFTPClient -and $TFTPClient.State -eq "Enabled") {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "TFTP" -NoRestart -ErrorAction Stop
        Write-Log "[+] TFTP Client disabled" "SUCCESS"
    } catch {
        Write-Log "[+] Failed to disable TFTP Client: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "[-] TFTP Client already disabled or not installed" "SUCCESS"
}

# ============================================
# USER ACCOUNT MANAGEMENT
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "USER ACCOUNT MANAGEMENT" "INFO"
Write-Log "========================================" "INFO"

# Disable Guest account
try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Log "✓ Guest account disabled" "SUCCESS"
} catch {
    Write-Log "Guest account already disabled or does not exist" "INFO"
}

# List all local users for review
Write-Log "Local user accounts on this system:" "INFO"
Get-LocalUser | ForEach-Object {
    $Status = if ($_.Enabled) { "ENABLED" } else { "DISABLED" }
    Write-Log "  - $($_.Name) [$Status] - Last Logon: $($_.LastLogon)" "INFO"
}

Write-Log "`nReview the above accounts and disable any unnecessary ones manually" "INFO"
Read-Host -Prompt "Press Enter to continue..."

# ============================================
# AUDIT POLICY
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "AUDIT POLICY CONFIGURATION" "INFO"
Write-Log "========================================" "INFO"

try {
    # Enable audit policies for security monitoring
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
    
    Write-Log "[+] Audit policies configured for security monitoring" "SUCCESS"
} catch {
    Write-Log "[-] Failed to configure audit policies: $($_.Exception.Message)" "ERROR"
}

# ============================================
# WINDOWS UPDATE CHECK
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "WINDOWS UPDATE STATUS" "INFO"
Write-Log "========================================" "INFO"

try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    Write-Log "Checking for Windows updates..." "INFO"
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
    
    if ($SearchResult.Updates.Count -eq 0) {
        Write-Log "[+] No pending Windows updates found" "SUCCESS"
    } else {
        Write-Log "[=] $($SearchResult.Updates.Count) pending Windows updates found" "WARNING"
        Write-Log "Please install all available updates" "WARNING"
    }
} catch {
    Write-Log "[-] Failed to check Windows Update status: $($_.Exception.Message)" "ERROR"
}

# ============================================
# Download Sysinternals Suite
# ============================================
try {
    New-Item -Path "C:\Troubleshoot" -ItemType Directory   
    $url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
    $destination = "C:\Troubleshoot\sysinternals.zip"
    Invoke-WebRequest -Uri $url -OutFile $destination
    Write-Log "[+] Windows Sysinterals Suite Installed" "SUCCESS"
} catch {
    Write-Log "[-] Failed to check Windows Update status: $($_.Exception.Message)" "ERROR"
}

# ============================================
# ADDITIONAL RECOMMENDATIONS
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "ADDITIONAL RECOMMENDATIONS" "INFO"
Write-Log "========================================" "INFO"

Write-Log "The following items require manual configuration:" "INFO"
Write-Log "  1. Enable BitLocker drive encryption via Control Panel or GPO" "INFO"
Write-Log "  2. Configure AppLocker to restrict executables (if needed)" "INFO"
Write-Log "  3. Review and configure screen saver password protection" "INFO"
Write-Log "  4. Review startup programs using Sysinternals Autoruns" "INFO"
Write-Log "  5. Configure firewall rules for specific services as needed" "INFO"
Write-Log "  6. Test all changes in your specific environment" "INFO"

# ============================================
# SUMMARY
# ============================================
Write-Log "`n========================================" "INFO"
Write-Log "HARDENING COMPLETE" "INFO"
Write-Log "========================================" "INFO"

Write-Log "Summary:" "INFO"
Write-Log "  - Registry security settings applied" "INFO"
Write-Log "  - Windows Defender configured and updated" "INFO"
Write-Log "  - Firewall enabled and configured" "INFO"
Write-Log "  - Password and lockout policies set" "INFO"
Write-Log "  - Unnecessary services reviewed" "INFO"
Write-Log "  - Unnecessary features disabled" "INFO"
Write-Log "  - Audit policies configured" "INFO"
Write-Log "  - User accounts reviewed" "INFO"

Write-Log "`nLog file saved to: $LogPath" "INFO"
Write-Log "`nRECOMMENDED NEXT STEPS:" "WARNING"
Write-Log "  1. Review the log file for any errors" "WARNING"
Write-Log "  2. Restart the computer to apply all changes" "WARNING"
Write-Log "  3. Test system functionality" "WARNING"
Write-Log "  4. Address any manual configuration items listed above" "WARNING"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Script execution completed!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nA system restart is recommended to apply all changes." -ForegroundColor Yellow
$Restart = Read-Host "`nWould you like to restart now? (Y/N)"
if ($Restart -eq "Y" -or $Restart -eq "y") {
    Write-Log "System restart initiated by user" "INFO"
    Restart-Computer -Force
} else {
    Write-Log "System restart deferred by user" "INFO"
    Write-Host "Please restart your computer at your earliest convenience." -ForegroundColor Yellow
}
