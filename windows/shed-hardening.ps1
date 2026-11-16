# general hardening/setup script:
#   prompt admin password change (DC-aware + DSRM sync)
#   rotate kerberos pass (krbtgt stage 1)
#   mass disable unneeded base services (interactive prompt)
#   mass firewall settings (role-aware: ICMP, DNS, DHCP, AD, WinRM on AD, RDP on MSSQL)
#   rotate kerberos pass AGAIN (krbtgt stage 2)
#   list users, groups, accounts, disable unneeded NON-SCORING users
#   list network config / open ncpa.cpl
#   REMOVE SSH, TELNET, OTHER REMOTE ACCESS
#   secure RDP (MSSQL only) and WinRM (AD only)

# services that need to stay open: 
# ICMP
# AD/LDAP (AD DC)
# DNS 53 (AD DC)
# DHCP 67/68
# WinRM 5985/5986 (AD DC only)
# RDP 3389 (MSSQL only)

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$NonInteractive,
    [switch]$KeepRDP,
    [string]$DefaultScoringUsers = "Administrator,scoring_user"
)

# -----------------------------------------------------------------------------
# Console Theme & Safety Initialization (Seamless pure-black styling)
# -----------------------------------------------------------------------------
try {
    [Console]::BackgroundColor = [ConsoleColor]::Black
    [Console]::ForegroundColor = [ConsoleColor]::White
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    if ($Host.PrivateData) {
        $Host.PrivateData.WarningBackgroundColor = 'Black'
        $Host.PrivateData.WarningForegroundColor = 'Yellow'
        $Host.PrivateData.ErrorBackgroundColor   = 'Black'
        $Host.PrivateData.ErrorForegroundColor   = 'Red'
        $Host.PrivateData.VerboseBackgroundColor = 'Black'
        $Host.PrivateData.VerboseForegroundColor = 'Cyan'
        $Host.PrivateData.DebugBackgroundColor   = 'Black'
        $Host.PrivateData.DebugForegroundColor   = 'DarkCyan'
    }
    $PSDefaultParameterValues['Write-Host:BackgroundColor'] = 'Black'
    Clear-Host
} catch {}

# -----------------------------------------------------------------------------
# 0. Initial Safety, Environment, & Logging Setup
# -----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[!] ERROR: script must be run as Administrator!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Press Enter to exit..."
    exit 1
}

# Keep console window open on terminating errors
trap {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Script encountered an error. Press Enter to exit..."
    break
}

# Global preferences
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Standardize Tools and Logs directories
$ToolsDir = "C:\Tools"
$LogsDir  = "$ToolsDir\logs"
$BackupDir = "$ToolsDir\backups"
New-Item -ItemType Directory -Force -Path $ToolsDir, $LogsDir, $BackupDir | Out-Null

# Ensure working directory is a local NTFS path (C:\Tools).
# Prevents Win32 executables (net.exe, netsh.exe) from failing with "The directory name is invalid"
# if the script was launched from a network share or RDP redirected drive (\\tsclient\...).
Set-Location -Path $ToolsDir
[System.IO.Directory]::SetCurrentDirectory($ToolsDir)

$script:LogFile = "$LogsDir\hardening-$(Get-Date -f yyyyMMdd-HHmmss).log"
try {
    Start-Transcript -Path $script:LogFile -Append -ErrorAction SilentlyContinue | Out-Null
} catch {}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level] -BackgroundColor Black
}

# -----------------------------------------------------------------------------
# Role Detection: Domain Controller (AD/DNS) vs MSSQL vs Standalone
# -----------------------------------------------------------------------------
Write-Log "Detecting system roles (DC, DNS, MSSQL)..." "INFO"
$script:isDC = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
    if ($os -and $os.ProductType -eq 2) { $script:isDC = $true }
} catch {}

if (-not $script:isDC -and (Get-Service -Name NTDS -ErrorAction SilentlyContinue)) {
    $script:isDC = $true
}

$script:isDNS = [bool](Get-Service -Name DNS -ErrorAction SilentlyContinue)

# Robust MSSQL detection checking default/named service patterns and running process
$sqlServices = @('MSSQLSERVER', 'MSSQL$*', 'SQLSERVER*', 'SQLBrowser')
$foundSqlSvc = foreach ($s in $sqlServices) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) { $svc; break }
}
$script:isMSSQL = [bool]$foundSqlSvc -or [bool](Get-Process -Name sqlservr -ErrorAction SilentlyContinue)

$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |            shed-hardening.ps1              |
     | ,      ,_ `\_/~\-           |   made for MWCCDC 2026-27' invitationals   |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black

Write-Log "Detected Host: $(hostname)" "INFO"
Write-Log "Role Analysis -> Domain Controller: $($script:isDC) | DNS Server: $($script:isDNS) | MSSQL Server: $($script:isMSSQL)" "INFO"

# -----------------------------------------------------------------------------
# 1. Administrator Password Change + DSRM Sync
# -----------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------------------"
Write-Host "Please input a new Administrator password."
Write-Host "--------------------------------------------------------------------------------"

$adminPasswordChanged = $false
while (-not $adminPasswordChanged) {
    try {
        $newAdminPassword = Read-Host -AsSecureString "Enter new password for the Administrator account"
        $confirmAdminPassword = Read-Host -AsSecureString "Confirm new password for the Administrator account"

        $newAdminPasswordPlain = [System.Net.NetworkCredential]::new('', $newAdminPassword).Password
        $confirmAdminPasswordPlain = [System.Net.NetworkCredential]::new('', $confirmAdminPassword).Password

        if ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain) {
            Write-Host "Passwords do not match. Please try again." -ForegroundColor Yellow
            continue
        }

        if ($script:isDC) {
            # On Active Directory Domain Controller, update domain Administrator using SecureString where possible
            $adPasswordUpdated = $false
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                try {
                    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                    Set-ADAccountPassword -Identity "Administrator" -NewPassword $newAdminPassword -Reset -ErrorAction Stop
                    Write-Log "Domain Administrator password successfully changed via Set-ADAccountPassword (SecureString)." "SUCCESS"
                    $adPasswordUpdated = $true
                } catch {
                    Write-Log "Set-ADAccountPassword failed: $_. Falling back to net.exe..." "WARN"
                }
            }
            if (-not $adPasswordUpdated) {
                $netOut = & net user Administrator "$newAdminPasswordPlain" /domain 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "net user Administrator /domain failed: $netOut"
                }
                Write-Log "Domain Administrator password successfully changed via net.exe." "SUCCESS"
            }

            # Synchronize Directory Services Restore Mode (DSRM) administrator password
            Write-Log "Synchronizing DSRM administrator password with domain Administrator..." "INFO"
            $ntdsOut = & ntdsutil "set dsrm password" "sync from domain account Administrator" q q 2>&1
            if ($LASTEXITCODE -eq 0 -or "$ntdsOut" -match "successfully") {
                Write-Log "DSRM password synchronized successfully." "SUCCESS"
            } else {
                Write-Log "DSRM password sync output: $ntdsOut" "WARN"
            }
        } else {
            # Standalone or Member Server local account
            $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
            if ($adminAccount) {
                Set-LocalUser -Name "Administrator" -Password $newAdminPassword -ErrorAction Stop
            } else {
                $netOut = & net user Administrator "$newAdminPasswordPlain" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "$netOut" }
            }
            Write-Log "Local Administrator password successfully changed." "SUCCESS"
        }

        $adminPasswordChanged = $true
    } catch {
        Write-Log "An error occurred while changing the administrator password: $_" "ERROR"
        if ($NonInteractive) { break }
        $retry = Read-Host "Retry password change? (y/n)"
        if ($retry -ne 'y') { break }
    }
}

# -----------------------------------------------------------------------------
# 2. Rotate Kerberos (krbtgt) Password - STAGE 1 (AD DC Only)
# -----------------------------------------------------------------------------
function Reset-KrbtgtAccount {
    param([int]$Stage = 1)
    if (-not $script:isDC) {
        Write-Log "Skipping krbtgt rotation (Host is not a Domain Controller)." "INFO"
        return
    }

    Write-Log "Rotating Kerberos account (krbtgt) password (Stage $Stage of 2)..." "INFO"
    try {
        $letterNumberArray = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8','9','0', '!', '@', '#', '$', '%', '^', '&', '*')
        $password = ""
        for ($counter = 0; $counter -lt 30; $counter++) {
            $password += (Get-Random -InputObject $letterNumberArray)
        }

        $securePassword = New-Object System.Security.SecureString
        $password.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
        $securePassword.MakeReadOnly()

        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePassword -Reset -ErrorAction Stop
        } else {
            $netOut = & net user krbtgt "$password" /domain 2>&1
            if ($LASTEXITCODE -ne 0) { throw "$netOut" }
        }
        Write-Log "Kerberos account (krbtgt) password rotated successfully (Stage $Stage)." "SUCCESS"
    } catch {
        Write-Log "An error occurred while rotating Kerberos password: $_" "ERROR"
    }
}

Reset-KrbtgtAccount -Stage 1

# -----------------------------------------------------------------------------
# 3. Mass Disable Unneeded Base Services (Interactive Selection)
# -----------------------------------------------------------------------------
# Only target genuine base services known for security issues/unneeded attack surface.
# NEVER include critical core/scoring services (NTDS, Kdc, Netlogon, DNS, Dhcp, W32Time, WinRM, TermService, LanmanServer).
$baseServicesList = @(
    @{ Name = "Spooler";        Desc = "Print Spooler (PrintNightmare CVE-2021-34527)" },
    @{ Name = "RemoteRegistry"; Desc = "Remote Registry (Remote SAM/Registry enumeration)" },
    @{ Name = "DiagTrack";      Desc = "Connected User Experiences and Telemetry" },
    @{ Name = "PeerDistSvc";    Desc = "BranchCache" },
    @{ Name = "SharedAccess";   Desc = "Internet Connection Sharing (ICS)" },
    @{ Name = "lltdsvc";        Desc = "Link-Layer Topology Discovery Mapper" },
    @{ Name = "SSDPSRV";        Desc = "SSDP Discovery Service" },
    @{ Name = "upnphost";       Desc = "Universal Plug and Play (UPnP) Device Host" },
    @{ Name = "WbioSrvc";       Desc = "Windows Biometric Service" },
    @{ Name = "SNMPTRAP";       Desc = "SNMP Trap" }
)

Write-Host "`n--------------------------------------------------------------------------------"
Write-Host "Unneeded Base Services Hardening"
Write-Host "--------------------------------------------------------------------------------"

# Detect which base services actually exist and are running/enabled
$detectedBaseServices = @()
foreach ($svcItem in $baseServicesList) {
    $svc = Get-Service -Name $svcItem.Name -ErrorAction SilentlyContinue
    if ($svc) {
        $detectedBaseServices += [PSCustomObject]@{
            Name        = $svcItem.Name
            Description = $svcItem.Desc
            Status      = $svc.Status
            StartType   = $svc.StartType
        }
    }
}

if ($detectedBaseServices.Count -eq 0) {
    Write-Log "No vulnerable base services found on this system." "INFO"
} else {
    Write-Host "Detected base services eligible for disabling:" -ForegroundColor Cyan
    $detectedBaseServices | Format-Table -Property Name, Status, StartType, Description -AutoSize | Out-String | Write-Host -ForegroundColor DarkCyan

    $svcChoice = "A"
    if (-not $NonInteractive) {
        $svcChoice = Read-Host "Choose action: [A] Disable All listed base services, [S] Selectively prompt for each, [N] Skip (Default: A)"
        if ([string]::IsNullOrWhiteSpace($svcChoice)) { $svcChoice = "A" }
    }

    if ($svcChoice -eq "A" -or $svcChoice -eq "a") {
        foreach ($s in $detectedBaseServices) {
            try {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled base service: $($s.Name)" "SUCCESS"
            } catch {
                Write-Log "Could not disable service $($s.Name): $_" "WARN"
            }
        }
    } elseif ($svcChoice -eq "S" -or $svcChoice -eq "s") {
        foreach ($s in $detectedBaseServices) {
            $prompt = Read-Host "Disable service '$($s.Name)' ($($s.Description))? (Y/n)"
            if ($prompt -ne 'n' -and $prompt -ne 'N') {
                try {
                    Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log "Disabled base service: $($s.Name)" "SUCCESS"
                } catch {
                    Write-Log "Could not disable service $($s.Name): $_" "WARN"
                }
            } else {
                Write-Log "Skipped base service: $($s.Name)" "INFO"
            }
        }
    } else {
        Write-Log "Skipping base service disablement per operator request." "INFO"
    }
}

# -----------------------------------------------------------------------------
# 4. Remove SSH, Telnet, and Rogue Remote Access Backdoors
# -----------------------------------------------------------------------------
Write-Log "Hunting and eliminating unauthorized remote access services & RATs..." "INFO"

# OpenSSH Server cleanup
try {
    # Terminate SSH processes immediately
    Get-Process -Name "sshd", "ssh-agent" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated SSH process: $($_.Name) (PID: $($_.Id))" "WARN"
    }

    # Stop and disable OpenSSH services
    Get-Service -Name "sshd", "ssh-agent" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
        & sc.exe config "$($_.Name)" start= disabled 2>&1 | Out-Null
        Write-Log "Disabled OpenSSH service: $($_.Name)" "WARN"
    }
} catch {
    Write-Log "Error disabling OpenSSH: $_" "WARN"
}

# Telnet cleanup
try {
    # Terminate Telnet processes
    Get-Process -Name "tlntsvr", "telnet" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated Telnet process: $($_.Name) (PID: $($_.Id))" "WARN"
    }

    # Stop and disable Telnet service
    Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
        & sc.exe config "$($_.Name)" start= disabled 2>&1 | Out-Null
        Write-Log "Disabled Telnet service." "WARN"
    }
} catch {
    Write-Log "Error disabling Telnet: $_" "WARN"
}

# Third-party remote software / RATs (AnyDesk, TeamViewer, VNC, RustDesk)
$ratProcesses = @("AnyDesk", "TeamViewer*", "tv_x64", "tv_w32", "winvnc", "vncserver", "rustdesk")
foreach ($proc in $ratProcesses) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated rogue remote process: $($_.Name) (PID: $($_.Id))" "WARN"
    }
}

$ratServices = @("AnyDesk", "TeamViewer", "uvnc_service", "tightvnc", "tvnserver", "rustdesk")
foreach ($svc in $ratServices) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "Disabled rogue remote access service: $($_.Name)" "WARN"
    }
}

New-NetFirewallRule -DisplayName "CCDC-Block-SSH"    -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "CCDC-Block-Telnet" -Direction Inbound -Action Block -Protocol TCP -LocalPort 23 -Profile Any -ErrorAction SilentlyContinue | Out-Null

# -----------------------------------------------------------------------------
# 5. Secure RDP (MSSQL Only) and WinRM (AD Only)
# -----------------------------------------------------------------------------
# Requirement:
# - RDP: Enabled for scoring on MSSQL server; DISABLED on AD/DNS server.
# - WinRM: Enabled with PowerShell functionality on AD ONLY; DISABLED on non-AD.

Write-Host "`n--------------------------------------------------------------------------------"
Write-Host "Configuring Remote Management (RDP on MSSQL only / WinRM on AD only)"
Write-Host "--------------------------------------------------------------------------------"

# RDP Configuration
if ($KeepRDP) {
    Write-Log "KeepRDP flag active: Retaining and hardening Remote Desktop (RDP) for testing..." "INFO"
    try {
        $tsPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $rdpTcp = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

        Set-ItemProperty -Path $tsPath -Name "fDenyTSConnections" -Value 0
        Set-ItemProperty -Path $rdpTcp -Name "UserAuthentication" -Value 0
        Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name TermService -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Write-Log "Remote Desktop preserved and enabled for testing." "SUCCESS"
    } catch {
        Write-Log "Error configuring RDP for testing: $_" "WARN"
    }
}
elseif ($script:isDC -or $script:isDNS) {
    Write-Log "Host is AD/DNS Server: Disabling Remote Desktop (RDP) to eliminate attack surface..." "INFO"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1 -ErrorAction SilentlyContinue
        Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
        Set-Service -Name TermService -StartupType Disabled -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Log "Remote Desktop Protocol successfully disabled on AD/DNS." "SUCCESS"
    } catch {
        Write-Log "Could not disable RDP: $_" "WARN"
    }
} else {
    Write-Log "Host is not AD/DNS (MSSQL / Member Server): Enabling and hardening RDP for scoring..." "INFO"
    try {
        $tsPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $rdpTcp = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

        Set-ItemProperty -Path $tsPath -Name "fDenyTSConnections" -Value 0
        # Require Network Level Authentication (NLA)
        Set-ItemProperty -Path $rdpTcp -Name "UserAuthentication" -Value 1
        # Require TLS/SSL High Encryption
        Set-ItemProperty -Path $rdpTcp -Name "SecurityLayer" -Value 2
        Set-ItemProperty -Path $rdpTcp -Name "MinEncryptionLevel" -Value 3
        # 15 minute idle session timeout
        Set-ItemProperty -Path $rdpTcp -Name "MaxIdleTime" -Value 900000

        Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name TermService -ErrorAction SilentlyContinue
        Write-Log "RDP enabled and hardened with NLA and TLS encryption for scoring." "SUCCESS"
    } catch {
        Write-Log "Error configuring RDP on MSSQL server: $_" "WARN"
    }
}

# WinRM Configuration
if ($script:isDC) {
    Write-Log "Host is AD Server: Enabling and securing WinRM for PowerShell remoting & auth..." "INFO"
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
        Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name WinRM -ErrorAction SilentlyContinue

        # Ensure WSMan provider is available
        if (-not (Get-PSDrive -Name WSMan -ErrorAction SilentlyContinue)) {
            Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
        }

        # Safely harden WinRM properties if path exists, avoiding terminating errors on older builds
        $winrmItems = @(
            @{ Path = "WSMan:\localhost\Service\AllowUnencrypted"; Val = $false },
            @{ Path = "WSMan:\localhost\Service\Auth\Basic";       Val = $false },
            @{ Path = "WSMan:\localhost\Client\Auth\Basic";        Val = $false },
            @{ Path = "WSMan:\localhost\Service\CbtHardeningLevel"; Val = "Strict" }
        )
        foreach ($item in $winrmItems) {
            try {
                if (Test-Path $item.Path) {
                    Set-Item -Path $item.Path -Value $item.Val -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }

        # Universal fallback configuration via winrm.cmd
        try {
            & winrm.cmd set winrm/config/service '@{AllowUnencrypted="false"}' 2>&1 | Out-Null
            & winrm.cmd set winrm/config/service/auth '@{Basic="false"}' 2>&1 | Out-Null
            & winrm.cmd set winrm/config/client/auth '@{Basic="false"}' 2>&1 | Out-Null
        } catch {}

        Write-Log "WinRM active and hardened on AD server." "SUCCESS"
    } catch {
        Write-Log "Error configuring WinRM on AD: $_" "WARN"
    }
} else {
    Write-Log "Host is not an AD Server: Disabling WinRM (AD-only policy)..." "INFO"
    try {
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "WinRM disabled on non-AD host." "SUCCESS"
    } catch {
        Write-Log "Error disabling WinRM: $_" "WARN"
    }
}

# -----------------------------------------------------------------------------
# 6. Mass Firewall Settings
# -----------------------------------------------------------------------------
Write-Log "Configuring Windows Firewall..." "INFO"
try {
    # Export backup of current firewall rules (non-fatal)
    try {
        $fwBackup = "$BackupDir\firewall-rules-$(Get-Date -f yyyyMMdd-HHmmss).wfw"
        & netsh.exe advfirewall export $fwBackup 2>&1 | Out-Null
        Write-Log "Exported firewall configuration backup to $fwBackup" "INFO"
    } catch {
        Write-Log "Firewall backup export skipped: $_" "WARN"
    }

    # Default policy: Block Inbound, Allow Outbound (preserves scoring engine traffic, updates, logs)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -NotifyOnListen False -ErrorAction Stop

    # Enable drop logging
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -LogFileName "$LogsDir\pfirewall.log" `
        -LogMaxSizeKilobytes 8192 `
        -LogAllowed False `
        -LogBlocked True -ErrorAction SilentlyContinue

    # Base rules: ICMP, DHCP, NTP (Always open)
    $firewallRules = @(
        @{ Name="CCDC-ICMP-In";  Protocol="ICMPv4"; LocalPort=$null; IcmpType="8" },
        @{ Name="CCDC-DHCP-In";  Protocol="UDP";    LocalPort="67,68"; IcmpType=$null },
        @{ Name="CCDC-NTP-In";   Protocol="UDP";    LocalPort="123";   IcmpType=$null }
    )

    # AD/DNS specific firewall allowances
    if ($script:isDC -or $script:isDNS) {
        $firewallRules += @(
            @{ Name="CCDC-DNS-UDP-In";     Protocol="UDP"; LocalPort="53"; IcmpType=$null },
            @{ Name="CCDC-DNS-TCP-In";     Protocol="TCP"; LocalPort="53"; IcmpType=$null },
            @{ Name="CCDC-WinRM-HTTP-In";  Protocol="TCP"; LocalPort="5985"; IcmpType=$null },
            @{ Name="CCDC-WinRM-HTTPS-In"; Protocol="TCP"; LocalPort="5986"; IcmpType=$null }
        )
    }

    if ($script:isDC) {
        $firewallRules += @(
            @{ Name="CCDC-AD-Kerberos-TCP"; Protocol="TCP"; LocalPort="88"; IcmpType=$null },
            @{ Name="CCDC-AD-Kerberos-UDP"; Protocol="UDP"; LocalPort="88"; IcmpType=$null },
            @{ Name="CCDC-AD-LDAP-TCP";     Protocol="TCP"; LocalPort="389,636,3268,3269"; IcmpType=$null },
            @{ Name="CCDC-AD-SMB-TCP";      Protocol="TCP"; LocalPort="445"; IcmpType=$null },
            @{ Name="CCDC-AD-RPC-EPMAP";    Protocol="TCP"; LocalPort="135"; IcmpType=$null }
        )
    }

    # MSSQL / Non-AD Server RDP allowance (or if KeepRDP is set)
    if ((-not $script:isDC -and -not $script:isDNS) -or $KeepRDP) {
        $firewallRules += @(
            @{ Name="CCDC-RDP-TCP-In"; Protocol="TCP"; LocalPort="3389"; IcmpType=$null },
            @{ Name="CCDC-RDP-UDP-In"; Protocol="UDP"; LocalPort="3389"; IcmpType=$null }
        )
        if ($script:isMSSQL) {
            $firewallRules += @(
                @{ Name="CCDC-MSSQL-TCP-In"; Protocol="TCP"; LocalPort="1433"; IcmpType=$null },
                @{ Name="CCDC-MSSQL-UDP-In"; Protocol="UDP"; LocalPort="1434"; IcmpType=$null }
            )
        }
    }

    foreach ($r in $firewallRules) {
        Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $params = @{
            Name        = $r.Name
            DisplayName = $r.Name
            Direction   = "Inbound"
            Action      = "Allow"
            Enabled     = "True"
            Protocol    = $r.Protocol
            Profile     = "Any"
        }
        if ($r.LocalPort) { $params["LocalPort"] = $r.LocalPort.Split(',') }
        if ($r.IcmpType)  { $params["IcmpType"]  = $r.IcmpType }
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        Write-Log "Firewall Allowed Inbound: $($r.Name)" "SUCCESS"
    }
} catch {
    Write-Log "Firewall configuration error: $_" "ERROR"
}

# -----------------------------------------------------------------------------
# 7. Rotate Kerberos (krbtgt) Password - STAGE 2 (AD DC Only)
# -----------------------------------------------------------------------------
# Rotating krbtgt twice purges Golden Ticket historical keys
Reset-KrbtgtAccount -Stage 2

# -----------------------------------------------------------------------------
# 8. User & Account Triage (Safeguard Scoring Users)
# -----------------------------------------------------------------------------
Write-Log "Auditing accounts and privileged groups..." "INFO"

# Auto-disable default vulnerable accounts
$vulnerableAccounts = @("Guest", "DefaultAccount", "WDAGUtilityAccount")
foreach ($va in $vulnerableAccounts) {
    try {
        if ($script:isDC) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                Disable-ADAccount -Identity $va -ErrorAction SilentlyContinue
            }
            & net.exe user $va /active:no /domain 2>&1 | Out-Null
            Write-Log "Disabled dormant domain account: $va" "SUCCESS"
        } else {
            $u = Get-LocalUser -Name $va -ErrorAction SilentlyContinue
            if ($u -and $u.Enabled) {
                Disable-LocalUser -Name $va -ErrorAction SilentlyContinue
                Write-Log "Disabled dormant local account: $va" "SUCCESS"
            }
        }
    } catch {}
}

# Audit Administrators / Domain Admins group
if ($script:isDC) {
    Write-Log "Querying members of Domain Admins group:" "INFO"
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host "   -> $($_.SamAccountName) ($($_.objectClass))" -ForegroundColor Yellow
            }
        } else {
            & net group "Domain Admins" /domain | Out-String | Write-Host -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Could not query Domain Admins: $_" "WARN"
    }
} else {
    Write-Log "Querying members of Administrators group:" "INFO"
    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        foreach ($m in $adminMembers) {
            Write-Host "   -> $($m.Name) ($($m.ObjectClass))" -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Could not query Administrators group: $_" "WARN"
    }
}

# Interactive non-scoring user disablement
if (-not $NonInteractive) {
    Write-Host "`n[?] USER TRIAGE: Review accounts below before disabling non-scoring users." -ForegroundColor Cyan
    $userList = @()
    if ($script:isDC) {
        Write-Log "Querying Active Directory domain user accounts..." "INFO"
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            try {
                $userList = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue |
                    Select-Object @{N="Name";E={$_.SamAccountName}}, Enabled, @{N="LastLogon";E={$_.LastLogonDate}}, PasswordLastSet
            } catch {
                Write-Log "Failed to query AD users: $_" "WARN"
            }
        } else {
            Write-Log "ActiveDirectory module not available on Domain Controller." "WARN"
        }
        if ($userList.Count -eq 0) {
            Write-Log "Warning: No domain user accounts retrieved on Domain Controller! Skipping local account triage to prevent disabling essential DC service/local accounts." "WARN"
        }
    } else {
        Write-Log "Querying local user accounts..." "INFO"
        $userList = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, PasswordLastSet
    }

    if ($userList) {
        $userList | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor DarkCyan

        $keepInput = Read-Host "Enter comma-separated usernames to PROTECT from disablement (Default: $DefaultScoringUsers)"
        if ([string]::IsNullOrWhiteSpace($keepInput)) {
            $protectedList = $DefaultScoringUsers.Split(',') | ForEach-Object { $_.Trim() }
        } else {
            $protectedList = $keepInput.Split(',') | ForEach-Object { $_.Trim() }
        }

        $disableChoice = Read-Host "Disable all enabled accounts NOT in the protected list? (y/N)"
        if ($disableChoice -eq 'y' -or $disableChoice -eq 'Y') {
            foreach ($user in $userList) {
                if ($user.Enabled -and ($protectedList -notcontains $user.Name)) {
                    try {
                        if ($script:isDC) {
                            & net user "$($user.Name)" /active:no /domain 2>&1 | Out-Null
                        } else {
                            Disable-LocalUser -Name $user.Name -ErrorAction Stop
                        }
                        Write-Log "Disabled non-scoring account: $($user.Name)" "SUCCESS"
                    } catch {
                        Write-Log "Failed to disable $($user.Name): $_" "ERROR"
                    }
                }
            }
        } else {
            Write-Log "Non-scoring user accounts left unchanged per operator choice." "INFO"
        }
    }
}

# -----------------------------------------------------------------------------
# 9. List Network Config, Audit Hosts File, & Open ncpa.cpl
# -----------------------------------------------------------------------------
Write-Log "Dumping active network adapter configurations..." "INFO"
try {
    Get-NetIPConfiguration | ForEach-Object {
        Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host " Interface    : $($_.InterfaceAlias) ($($_.InterfaceDescription))" -ForegroundColor White
        Write-Host " IPv4 Address : $($_.IPv4Address.IPAddress)" -ForegroundColor Green
        Write-Host " IPv4 Gateway : $($_.IPv4DefaultGateway.NextHop)" -ForegroundColor Cyan
        Write-Host " DNS Servers  : $($_.DNSServer.ServerAddresses -join ', ')" -ForegroundColor Yellow
    }
    Write-Host "--------------------------------------------------------`n" -ForegroundColor DarkGray
} catch {
    Write-Log "Could not query NetIPConfiguration: $_" "WARN"
}

# Check hosts file for malicious redirects
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
if (Test-Path $hostsFile) {
    $hostsEntries = Get-Content $hostsFile | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
    if ($hostsEntries) {
        Write-Log "WARNING: Custom hosts file entries detected:" "WARN"
        $hostsEntries | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    } else {
        Write-Log "Hosts file is clean (no active non-comment overrides)." "SUCCESS"
    }
}

Write-Log "Opening Network Connections control panel (ncpa.cpl)..." "INFO"
Start-Process "ncpa.cpl"

# -----------------------------------------------------------------------------
# 10. Enable Defender Baseline & Conservative Lockout Policy
# -----------------------------------------------------------------------------
Write-Log "Applying Microsoft Defender & account lockout baseline..." "INFO"
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Log "Windows Defender enabled with real-time & PUA protection." "SUCCESS"
} catch {}

try {
    # 10 attempts / 15m duration to protect scoring engine accounts from Red Team brute lockout
    if ($script:isDC) {
        & net.exe accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 /domain 2>&1 | Out-Null
    } else {
        & net.exe accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 2>&1 | Out-Null
    }
    Write-Log "Account lockout threshold set (Threshold: 10, Duration: 15m)." "SUCCESS"
} catch {}

# Enforce SMB Signing (Mitigates NTLM relay attacks & SMB spoofing)
Write-Log "Enforcing SMB signing on client and server to prevent NTLM relay attacks..." "INFO"
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    Write-Log "SMB signing enforced via PowerShell SMB cmdlets." "SUCCESS"
} catch {
    Write-Log "PowerShell SMB cmdlets failed ($_); configuring SMB signing via registry..." "WARN"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log "SMB signing enforced via registry." "SUCCESS"
    } catch {
        Write-Log "Failed to configure SMB signing via registry: $_" "WARN"
    }
}

# -----------------------------------------------------------------------------
# 11. Download Install Script to C:\Tools (Fixing Directory Path Bug)
# -----------------------------------------------------------------------------
try {
    $installScriptPath = "$ToolsDir\shed-installs.ps1"
    if (-not (Test-Path $installScriptPath)) {
        Write-Log "Downloading install script to $installScriptPath..." "INFO"
        Invoke-WebRequest "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master/windows/shed-installs.ps1" -OutFile $installScriptPath -UseBasicParsing -ErrorAction SilentlyContinue
        Write-Log "Install script downloaded to $installScriptPath" "SUCCESS"
    }
} catch {
    Write-Log "Could not download install script: $_" "WARN"
}

Write-Log "Hardening routine completed successfully." "SUCCESS"
try { Stop-Transcript | Out-Null } catch {}
Write-Host "`n[+] Hardening complete. Press Enter to exit..." -ForegroundColor Green
if (-not $NonInteractive) { Read-Host }
