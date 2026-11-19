#Requires -RunAsAdministrator

<#
.SYNOPSIS
Interactive Windows competition hardening with account and group cleanup.
.DESCRIPTION
Run without arguments and answer the prompts. All configuration is interactive.
On a DC, reviews the current AD domain; elsewhere, reviews local accounts.
Administrator keeps its memberships. Every other user keeps only Domain Users
(local Users on non-DCs), including protected scoring and service accounts.
OS-issued service identities may retain non-administrative application groups;
these exceptions are audited and never exempt ordinary service usernames.
Enter scoring login wildcards (use *.* for lastname.firstname), optional exact
scoring names, and existing service usernames at the account prompts. Then choose
Preview, Audit, Disable, or Remove. Preview changes only the account/group step;
other hardening still runs. Choose AD-DNS or MSSQL at startup; optional DHCP and
AD CS web enrollment apply only to AD-DNS. SQL ports/Browser apply only to MSSQL.
Reports are saved under C:\Tools\backups; transcripts under C:\Tools\logs.
During base service hardening, check essential services or choose to enable/start
those required for this host. Essential-service and remote-access disablement
reports are saved as CSV files under C:\Tools\logs.
Internal management rules accept sources in 172.20.240.0/24. Scored endpoints
remain publicly reachable. The firewall step backs up and audits local/effective
rules, then prompts to audit, disable, or remove selected old local rules.
Remaining broad/GPO conflicts are reported; audit-only does not close them.
AD-DNS exposes only WinRM TCP 5985/5986, DNS TCP/UDP 53, and ICMPv4 ping
externally. AD DS, AD CS, SMB, NTP, and optional DHCP stay internal.
MSSQL exposes configured SQL TCP ports, SMB TCP 445, RDP TCP/UDP 3389, and ping.
Optional SQL Browser UDP 1434 is internal only. External TCP/UDP guards apply
regardless of the old-rule cleanup choice, while preserving DHCP bootstrap.
.NOTES
READING GUIDE
  Setup prepares the console, elevation checks, C:\Tools folders, and transcript.
  The function library defines menus, firewall audits, service handling, and
  account handling. Main execution resumes at the server-profile selection.

MAIN FLOW
  1: Administrator password and AD-DNS DSRM synchronization.
  2/7: Review one krbtgt reset on AD-DNS, then a follow-up reminder.
       AD-DNS also offers Kerberos follow-up only before full hardening.
  3: Base-service disable menu, then essential-service check/optional repair.
  4/5: Named remote-tool cleanup, then profile-specific RDP/WinRM policy.
  6: Firewall backup, scoped profile rules, old-rule review, effective-rule audit.
  8: Account categories, membership plan, optional account disablement/deletion.
  9/10/11: Network review, security baseline, and installer-script download.

DEFAULTS AND EFFECTS
  Base-service choice A disables the listed base services; essential-service
  choice C only checks them. Optional DHCP/web enrollment/SQL Browser default No.
  Account Preview and old-firewall Audit apply only to their respective steps;
  the rest of this script still changes the host. RDP remains a scored endpoint
  on MSSQL; internal management allowances use source 172.20.240.0/24.
  Kerberos defaults to status only. Each visit permits one confirmed reset;
  follow-up-only mode avoids rerunning the other hardening steps. Early competition
  resets require a chosen minimum wait, healthy replication, and typed confirmation.

REPORTS AND RECOVERY
  Transcripts and CSV reports are in C:\Tools\logs. Firewall .wfw exports and
  account inventories are in C:\Tools\backups. Membership/account reports do not
  restore deleted accounts or passwords. Changes are not automatically rolled
  back when a later step fails. Read-back checks cover the specific operations
  documented below; the final issue count is not a complete health assessment.
.EXAMPLE
.\shed-hardening.ps1
#>
# Reject old switches or positional arguments before any hardening begins.
if ($args.Count -gt 0) {
    throw 'This script accepts no command-line options.'
}

# -----------------------------------------------------------------------------
# Console colors
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
# Startup checks and logging
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
    exit 1
}

# Global preferences
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Kept in each standalone script so downloaded copies need no companion module.
function Get-TrustedOwnerSids {
    @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
}

# Check ownership, write permissions, and every ancestor without following links.
# A trusted signature alone cannot prevent DLL loading from a writable directory.
function Test-TrustedPath {
    param([string]$Path, [switch]$Recurse)
    try {
        $trusted = @(Get-TrustedOwnerSids)
        $writeRights = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $pending = [Collections.Generic.Stack[object]]::new()
        $pending.Push($item)
        if ($Recurse -and $item.PSIsContainer) {
            # Enumerate manually: do not recurse through a junction before checking it.
            $directories = [Collections.Generic.Stack[object]]::new()
            $directories.Push($item)
            while ($directories.Count) {
                foreach ($child in @(Get-ChildItem -LiteralPath $directories.Pop().FullName -Force -ErrorAction Stop)) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
                    $pending.Push($child)
                    if ($child.PSIsContainer) { $directories.Push($child) }
                }
            }
        }
        $parent = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
        # Drive-root create-folder permissions do not grant access to existing
        # protected children. Check every directory below the drive root.
        while ($parent -and $parent.Parent) { $pending.Push($parent); $parent = $parent.Parent }
        while ($pending.Count) {
            $current = $pending.Pop()
            if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $acl = Get-Acl -LiteralPath $current.FullName -ErrorAction Stop
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { return $false }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and
                    ($rule.FileSystemRights -band $writeRights) -and $rule.IdentityReference.Value -notin $trusted) { return $false }
            }
        }
        return $true
    } catch { return $false }
}

# Create a directory with an explicit ACL before writing tools or sensitive reports.
# Reject linked paths/foreign ownership; retain existing directory contents.
function Initialize-Directory {
    param([string]$Path, [switch]$Private)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = [IO.DirectoryInfo]::new($fullPath)
    $trustedOwners = @(Get-TrustedOwnerSids)
    while ($parent -and $parent.Parent) {
        if (Test-Path -LiteralPath $parent.FullName) {
            $existing = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
            if (-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Refusing linked/non-directory workspace: $($parent.FullName)"
            }
            $owner = (Get-Acl -LiteralPath $parent.FullName -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($owner -notin $trustedOwners) { throw "Untrusted workspace owner at $($parent.FullName). Use a clean Administrator-owned directory." }
        }
        $parent = $parent.Parent
    }
    $null = New-Item -ItemType Directory -Path $fullPath -Force -ErrorAction Stop
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if (-not $Private) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $fullPath -AclObject $security -ErrorAction Stop
    if (-not (Test-TrustedPath $fullPath)) { throw "Workspace permission verification failed: $fullPath" }
    $verified = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
    if (-not $verified.AreAccessRulesProtected) { throw "Workspace still inherits permissions: $fullPath" }
    if ($Private) {
        foreach ($rule in $verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
                throw "Private workspace has unexpected access: $fullPath"
            }
        }
    }
}

# Standardize Tools and Logs directories
$ToolsDir = "C:\Tools"
$LogsDir  = "$ToolsDir\logs"
$BackupDir = "$ToolsDir\backups"
Initialize-Directory $ToolsDir
Initialize-Directory $LogsDir -Private
Initialize-Directory $BackupDir -Private

# Ensure working directory is a local NTFS path (C:\Tools).
# Prevents Win32 executables (net.exe, netsh.exe) from failing with "The directory name is invalid"
# if the script was launched from a network share or RDP redirected drive (\\tsclient\...).
Set-Location -Path $ToolsDir
[System.IO.Directory]::SetCurrentDirectory($ToolsDir)

$script:LogFile = "$LogsDir\hardening-$(Get-Date -f yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N')).log"
$script:HardeningIssues = 0
try {
    Start-Transcript -Path $script:LogFile -ErrorAction Stop | Out-Null
} catch {
    $script:HardeningIssues++
    Write-Warning "Could not start the hardening transcript: $_"
}

# -----------------------------------------------------------------------------
# Function library: shared logging and menus
# -----------------------------------------------------------------------------
# Write a timestamped console message that the transcript can capture.
# WARN/ERROR messages also increment the final issue-message count.
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($Level -in @('WARN', 'ERROR')) { $script:HardeningIssues++ }
    $colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level] -BackgroundColor Black
}

# Repeat menu prompts on invalid input; a blank answer uses the displayed default.
# Return a validated menu answer; letters/names are matched without case sensitivity.
# An empty default forces an explicit answer, as used for the server profile.
function Read-MenuChoice {
    param([string]$Prompt, [string[]]$Choices, [string]$Default)
    while ($true) {
        $answer = (Read-Host $Prompt).Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        if ($answer -in $Choices) { return $answer }
        Write-Host "Please enter one of: $($Choices -join ', ')." -ForegroundColor Yellow
    }
}

# Profile selection and firewall helpers are kept together so ports, source
# limits, and service expectations all derive from the same settings object.
# There are exactly two competition hosts. Choose the intended profile explicitly.
# Collect the two-host configuration and return one settings object.
# This records choices only; it does not install roles, change SQL listeners, or open ports.
function Read-ServerConfiguration {
    $choice = Read-MenuChoice -Prompt 'Server profile: [A] AD-DNS (AD DS, AD CS, DNS, optional DHCP, ping), [M] MSSQL (SQL Server, SMB, RDP); choose A or M' -Choices @('A', 'AD-DNS', 'M', 'MSSQL') -Default ''
    $configuration = [PSCustomObject]@{
        Profile = $(if ($choice -in @('A', 'AD-DNS')) { 'AD-DNS' } else { 'MSSQL' })
        EnableDhcp = $false; AdcsWeb = $false; SqlTcpPorts = @('1433'); SqlBrowser = $false
    }
    if ($configuration.Profile -eq 'AD-DNS') {
        $configuration.EnableDhcp = (Read-MenuChoice -Prompt 'Provide DHCP on AD-DNS (UDP 67 server, internal clients and initial requests)? (y/N)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
        $configuration.AdcsWeb = (Read-MenuChoice -Prompt 'Use AD CS web enrollment/IIS and allow internal HTTP/HTTPS 80/443? (y/N; internal RPC enrollment is supported either way)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
    } else {
        while ($true) {
            $portInput = Read-Host 'MSSQL TCP listening port(s), comma-separated (default 1433)'
            if ([string]::IsNullOrWhiteSpace($portInput)) { $portInput = '1433' }
            $ports = @($portInput -split ',' | ForEach-Object { $_.Trim() })
            $invalid = @($ports | Where-Object { $_ -notmatch '^\d{1,5}$' -or [int]$_ -lt 1 -or [int]$_ -gt 65535 })
            if (-not $invalid.Count) {
                $configuration.SqlTcpPorts = @($ports | ForEach-Object { [string][int]$_ } | Select-Object -Unique)
                break
            }
            Write-Host 'Enter TCP port numbers from 1 through 65535.' -ForegroundColor Yellow
        }
        $configuration.SqlBrowser = (Read-MenuChoice -Prompt 'Require internal SQL Browser discovery on UDP 1434? (y/N; never allowed externally)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
    }
    return $configuration
}

# Return default/named SQL database-engine service names for the service report.
# SQL Browser and SQL Agent are separate services, not database-engine instances.
function Get-SqlEngineServiceNames {
    # Query the service database so named instances are included even when stopped.
    $names = @(Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' } | Select-Object -ExpandProperty Name)
    if ($names.Count) { return $names }
    # Keep a required row in the report when no database engine is installed.
    return 'MSSQLSERVER'
}

# Return the complement of an allowed port list within valid TCP/UDP ports.
# Ranges keep the external guard compact while excluding scored endpoints exactly.
function Get-BlockedFirewallPortRanges {
    param([int[]]$AllowedPorts)
    if (@($AllowedPorts | Where-Object { $_ -lt 1 -or $_ -gt 65535 }).Count) { throw 'Invalid external port allowlist.' }
    $next = 1
    foreach ($port in @($AllowedPorts | Sort-Object -Unique)) {
        if ($port -gt $next) { if ($port -eq $next + 1) { [string]$next } else { "$next-$($port - 1)" } }
        $next = $port + 1
    }
    if ($next -le 65535) { if ($next -eq 65535) { '65535' } else { "$next-65535" } }
}

# Build rule descriptions from the profile; this function does not apply them.
# Each returned rule carries its ports, optional program/service filters, and source scope.
function Get-ServerFirewallRules {
    param($Configuration)
    if ($Configuration.Profile -notin @('AD-DNS', 'MSSQL')) { throw 'Unsupported server profile.' }
    # Only explicitly listed scored endpoints get Any sources. All other service
    # allowances default to the internal subnet; outside TCP/UDP guards follow.
    $rules = @(
    # SMB serves SQL shares on MSSQL and SYSVOL/NETLOGON on AD-DNS.
    @{ Name = 'CCDC-SMB-TCP-In'; Protocol = 'TCP'; LocalPort = '445' }
    @{ Name = 'CCDC-ICMP-In'; Protocol = 'ICMPv4'; IcmpType = '8' }
    if ($Configuration.Profile -eq 'AD-DNS') {
        @(
            @{ Name = 'CCDC-NTP-In'; Protocol = 'UDP'; LocalPort = '123' },
            @{ Name = 'CCDC-DNS-UDP-In'; Protocol = 'UDP'; LocalPort = '53' },
            @{ Name = 'CCDC-DNS-TCP-In'; Protocol = 'TCP'; LocalPort = '53' },
            @{ Name = 'CCDC-WinRM-HTTP-In'; Protocol = 'TCP'; LocalPort = '5985' },
            @{ Name = 'CCDC-WinRM-HTTPS-In'; Protocol = 'TCP'; LocalPort = '5986' },
            @{ Name = 'CCDC-AD-Kerberos-TCP'; Protocol = 'TCP'; LocalPort = '88,464' },
            @{ Name = 'CCDC-AD-Kerberos-UDP'; Protocol = 'UDP'; LocalPort = '88,464' },
            @{ Name = 'CCDC-AD-LDAP-TCP'; Protocol = 'TCP'; LocalPort = '389,636,3268,3269' },
            @{ Name = 'CCDC-AD-LDAP-UDP'; Protocol = 'UDP'; LocalPort = '389' },
            @{ Name = 'CCDC-AD-ADWS-TCP'; Protocol = 'TCP'; LocalPort = '9389' },
            @{ Name = 'CCDC-AD-RPC-EPMAP'; Protocol = 'TCP'; LocalPort = '135' },
            @{ Name = 'CCDC-AD-RPC-Dynamic'; Protocol = 'TCP'; LocalPort = 'RPC'; Program = "$env:SystemRoot\System32\lsass.exe" },
            @{ Name = 'CCDC-ADCS-RPC-In'; Protocol = 'TCP'; LocalPort = 'RPC'; Service = 'CertSvc' }
        )
        # Initial DHCP clients have no assigned IP yet, so the separate 0.0.0.0
        # exception also requires exact UDP ports, the server service, and an internal NIC.
        if ($Configuration.EnableDhcp) {
            @{ Name = 'CCDC-DHCP-In'; Protocol = 'UDP'; LocalPort = '67'; RemotePort = '67,68'; Service = 'DHCPServer' }
            if (-not $Configuration.InternalInterfaceAliases) { throw 'DHCP requires an interface with an IPv4 address in 172.20.240.0/24.' }
            @{ Name = 'CCDC-DHCP-Bootstrap-In'; Protocol = 'UDP'; LocalPort = '67'; RemotePort = '68'; RemoteAddress = '0.0.0.0'; Service = 'DHCPServer'; InterfaceAlias = $Configuration.InternalInterfaceAliases }
        }
        if ($Configuration.AdcsWeb) {
            @{ Name = 'CCDC-ADCS-Web-In'; Protocol = 'TCP'; LocalPort = '80,443' }
        }
    } else {
        @(
            @{ Name = 'CCDC-MSSQL-TCP-In'; Protocol = 'TCP'; LocalPort = ($Configuration.SqlTcpPorts -join ',') },
            @{ Name = 'CCDC-RDP-TCP-In'; Protocol = 'TCP'; LocalPort = '3389' },
            @{ Name = 'CCDC-RDP-UDP-In'; Protocol = 'UDP'; LocalPort = '3389' }
        )
        if ($Configuration.SqlBrowser) {
            @{ Name = 'CCDC-MSSQL-UDP-In'; Protocol = 'UDP'; LocalPort = '1434' }
        }
    }
    )
    # These are client-source restrictions, not listener bindings. New service
    # allowances stay internal unless explicitly added to this external list.
    $externalNames = if ($Configuration.Profile -eq 'AD-DNS') {
        @('CCDC-ICMP-In','CCDC-DNS-TCP-In','CCDC-DNS-UDP-In','CCDC-WinRM-HTTP-In','CCDC-WinRM-HTTPS-In')
    } else {
        @('CCDC-ICMP-In','CCDC-MSSQL-TCP-In','CCDC-SMB-TCP-In','CCDC-RDP-TCP-In','CCDC-RDP-UDP-In')
    }
    foreach ($rule in $rules) {
        $rule.Action = 'Allow'
        if ($rule.Name -eq 'CCDC-DHCP-Bootstrap-In') { $rule.Scope = 'DHCP bootstrap' }
        elseif ($rule.Name -in $externalNames) { $rule.RemoteAddress = 'Any'; $rule.Scope = 'Scored' }
        else { $rule.RemoteAddress = '172.20.240.0/24'; $rule.Scope = 'Internal' }
    }
    # Explicit blocks enforce the external TCP/UDP allowlist even if old broad
    # Allow rules are only audited. Outbound policy remains stateful Allow.
    $outside = @('0.0.0.0-172.20.239.255','172.20.241.0-255.255.255.255','::/0')
    foreach ($protocol in @('TCP','UDP')) {
        $ports = @($rules | Where-Object { $_.Scope -eq 'Scored' -and $_.Protocol -eq $protocol } | ForEach-Object { $_.LocalPort -split ',' } | ForEach-Object { [int]$_ })
        # Initial DHCP requests use 0.0.0.0. Exclude UDP 67 from the broad guard
        # only when DHCP is selected; a separate rule blocks other outside clients.
        if ($protocol -eq 'UDP' -and $Configuration.EnableDhcp) { $ports += 67 }
        $blocked = @(Get-BlockedFirewallPortRanges $ports)
        if ($blocked.Count) {
            $rules += @{ Name = "CCDC-External-$protocol-Block"; Protocol = $protocol; LocalPort = ($blocked -join ','); Action = 'Block'; RemoteAddress = $outside; Scope = 'Outside internal network' }
        }
    }
    if ($Configuration.EnableDhcp) {
        $rules += @{ Name = 'CCDC-DHCP-External-UDP-Block'; Protocol = 'UDP'; LocalPort = '67'; Action = 'Block'; RemoteAddress = @('0.0.0.1-172.20.239.255','172.20.241.0-255.255.255.255','::/0'); Scope = 'Outside internal network' }
    }
    $rules
}


# Return true only when every supplied IPv4 address/subnet/range is inside
# 172.20.240.0/24. Unknown keywords, IPv6, and wider scopes fail this test.
function Test-InternalFirewallScope {
    param([string[]]$Addresses)
    # Every allowed source must fit wholly inside the exact competition /24.
    if (-not $Addresses.Count) { return $false }
    foreach ($entry in $Addresses) {
        $parts = $entry.Trim() -split '/'
        if ($parts.Count -gt 2) { return $false }
        if ($parts.Count -eq 2) {
            $prefixLength = 0
            if ([int]::TryParse($parts[1], [ref]$prefixLength)) {
                if ($prefixLength -lt 24 -or $prefixLength -gt 32) { return $false }
            } else {
                $mask = $null
                if (-not [Net.IPAddress]::TryParse($parts[1], [ref]$mask) -or $mask.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
                $maskBytes = $mask.GetAddressBytes()
                if ($maskBytes[0] -ne 255 -or $maskBytes[1] -ne 255 -or $maskBytes[2] -ne 255 -or $maskBytes[3] -notin @(0,128,192,224,240,248,252,254,255)) { return $false }
            }
        }
        $ends = $parts[0] -split '-'
        if ($ends.Count -gt 2 -or ($ends.Count -eq 2 -and $parts.Count -eq 2)) { return $false }
        foreach ($endpoint in $ends) {
            $ip = $null
            if (-not [Net.IPAddress]::TryParse($endpoint.Trim(), [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
            $bytes = $ip.GetAddressBytes()
            if ($bytes[0] -ne 172 -or $bytes[1] -ne 20 -or $bytes[2] -ne 240) { return $false }
        }
    }
    return $true
}

# Find interface aliases with an IPv4 address in the internal /24.
# These aliases bind the DHCP bootstrap exception to the intended network adapter.
function Get-InternalFirewallInterfaces {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { Test-InternalFirewallScope @($_.IPAddress) } |
        Select-Object -ExpandProperty InterfaceAlias -Unique)
}

# Return local stored rules and effective merged rules, with their filters.
# PersistentStore is locally editable; ActiveStore also reflects GPO/other policy sources.
function Get-FirewallAuditInventory {
    $id = 0
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = if ($store -eq 'ActiveStore') {
            @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
        } else { @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) }
        Write-Log "Auditing $($rules.Count) firewall rules and associated filters from $store..."
        foreach ($rule in $rules) {
            # Read every associated filter; incomplete inventories stop cleanup.
            $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
            $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
            $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
            $interface = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
            $security = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
            if (-not $address -or -not $port -or -not $application -or -not $service) { throw "Incomplete firewall filters for $($rule.Name)." }
            $id++
            if ($id % 100 -eq 0) { Write-Log "Audited $id firewall rule records..." }
            [PSCustomObject]@{
                ID = $id; Store = $store; Name = $rule.Name; DisplayName = $rule.DisplayName
                Enabled = ([string]$rule.Enabled -eq 'True'); Direction = [string]$rule.Direction
                Action = [string]$rule.Action; Profile = [string]$rule.Profile
                SourceType = [string]$rule.PolicyStoreSourceType; Source = [string]$rule.PolicyStoreSource
                CanChange = ($store -eq 'PersistentStore' -and [string]$rule.PolicyStoreSourceType -notin @('GroupPolicy', 'Dynamic', 'Generated', 'Hardcoded'))
                Protocol = [string]$port.Protocol; LocalPort = @($port.LocalPort); RemotePort = @($port.RemotePort)
                LocalAddress = @($address.LocalAddress); RemoteAddress = @($address.RemoteAddress)
                Program = [string]$application.Program; Service = [string]$service.Service
                InterfaceAlias = @($interface.InterfaceAlias); OverrideBlockRules = [string]$security.OverrideBlockRules
                RuleObject = $rule; Filters = @($address, $port, $application, $service, $interface, $security)
            }
        }
    }
}

# Save a readable CSV plus CLIXML retaining the original rule/filter objects.
# These inventories explain the policy; the separate .wfw export is the full firewall backup.
function Save-FirewallAuditInventory {
    param([object[]]$Inventory, [string]$Prefix)
    $Inventory | Export-Clixml -LiteralPath "$Prefix.xml" -ErrorAction Stop
    $Inventory | Select-Object ID, Store, Name, DisplayName, Enabled, Direction, Action, Profile, SourceType, Source, CanChange,
        Protocol, @{N='LocalPort';E={$_.LocalPort -join ','}}, @{N='RemotePort';E={$_.RemotePort -join ','}},
        @{N='LocalAddress';E={$_.LocalAddress -join ','}}, @{N='RemoteAddress';E={$_.RemoteAddress -join ','}},
        Program, Service, @{N='InterfaceAlias';E={$_.InterfaceAlias -join ','}}, OverrideBlockRules |
        Export-Csv -LiteralPath "$Prefix.csv" -NoTypeInformation -ErrorAction Stop
}

# Export current firewall policy with netsh and verify a nonempty backup exists.
# Throw on failure so the caller stops before changing profiles or rules in this step.
function Save-FirewallPolicyBackup {
    param([string]$Path)
    & netsh.exe advfirewall export $Path 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        (Get-Item -LiteralPath $Path -ErrorAction Stop).Length -le 0) { throw 'Firewall backup failed; firewall changes will not be applied.' }
    Write-Log "Firewall policy backup: $Path"
}

# Compare individual ports, ranges, and Any. Treat RPC/unknown keywords
# conservatively as possible overlaps; this is triage, not an actual connection test.
function Test-FirewallPortOverlap {
    param([string[]]$Left, [string[]]$Right)
    foreach ($leftPort in $Left) {
        foreach ($rightPort in $Right) {
            if ($leftPort -in @('Any', '*') -or $rightPort -in @('Any', '*') -or $leftPort -eq $rightPort) { return $true }
            # RPC uses dynamically assigned endpoints, not a fixed numeric port.
            # Conservatively flag potentially overlapping TCP allowances for review.
            if ($leftPort -notmatch '^\d+(-\d+)?$' -or $rightPort -notmatch '^\d+(-\d+)?$') { return $true }
            $leftEnds = $leftPort -split '-'; $rightEnds = $rightPort -split '-'
            $leftMin = [int]$leftEnds[0]; $leftMax = [int]$leftEnds[-1]
            $rightMin = [int]$rightEnds[0]; $rightMax = [int]$rightEnds[-1]
            if ($leftMin -le $rightMax -and $rightMin -le $leftMax) { return $true }
        }
    }
    return $false
}

# Compare filter values as unordered, case-insensitive sets after expanding
# environment variables. Missing values are treated as the unrestricted Any filter.
function Test-FirewallFilterEqual {
    param([string[]]$Actual, [string[]]$Expected)
    $left = @($Actual | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $right = @($Expected | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if (-not $left.Count) { $left = @('any') }
    if (-not $right.Count) { $right = @('any') }
    return @(Compare-Object $left $right).Count -eq 0
}

# Recognize intended public scoring/DHCP exceptions only when their complete
# listed filters match the plan. A matching display/name alone is not sufficient.
function Test-PlannedFirewallException {
    param($Rule, [object[]]$PlannedRules)
    # Public scoring rules and DHCP bootstrap are intentional exceptions, but a
    # familiar name alone cannot hide a wider GPO or modified effective rule.
    foreach ($plan in @($PlannedRules | Where-Object { $_.Name -eq $Rule.Name -and $_.Scope -ne 'Internal' -and $_.Action -ne 'Block' })) {
        $protocol = switch ($plan.Protocol) { 'TCP' { '6' } 'UDP' { '17' } 'ICMPv4' { '1' } default { [string]$plan.Protocol } }
        if ($Rule.Protocol -notin @($plan.Protocol, $protocol)) { continue }
        if (-not (Test-FirewallFilterEqual $Rule.RemoteAddress @($plan.RemoteAddress))) { continue }
        if (-not (Test-FirewallFilterEqual $Rule.LocalPort @($plan.LocalPort -split ','))) { continue }
        if (-not (Test-FirewallFilterEqual $Rule.RemotePort @($plan.RemotePort -split ','))) { continue }
        if (-not (Test-FirewallFilterEqual @($Rule.Program) @($plan.Program))) { continue }
        if (-not (Test-FirewallFilterEqual @($Rule.Service) @($plan.Service))) { continue }
        if (-not (Test-FirewallFilterEqual $Rule.InterfaceAlias @($plan.InterfaceAlias))) { continue }
        return $true
    }
    return $false
}

# Return enabled inbound Allow rules that may expose an internal endpoint to
# outside sources. Disabled, outbound, block, already-internal, and exact exception rules are skipped.
function Get-FirewallScopeConflicts {
    param([object[]]$Inventory, [object[]]$PlannedRules)
    $internalRules = @($PlannedRules | Where-Object { $_.Scope -eq 'Internal' })
    foreach ($old in $Inventory) {
        if (-not $old.Enabled -or $old.Direction -ne 'Inbound' -or $old.Action -ne 'Allow') { continue }
        if (Test-InternalFirewallScope $old.RemoteAddress) { continue }
        if (Test-PlannedFirewallException $old $PlannedRules) { continue }
        $overlaps = @()
        foreach ($required in $internalRules) {
            $protocol = switch ($required.Protocol) { 'TCP' { '6' } 'UDP' { '17' } default { [string]$required.Protocol } }
            if ($old.Protocol -notin @('Any', '256', $required.Protocol, $protocol)) { continue }
            $oldProgram = [Environment]::ExpandEnvironmentVariables($old.Program)
            $newProgram = [Environment]::ExpandEnvironmentVariables([string]$required.Program)
            if ($oldProgram -and $oldProgram -ne 'Any' -and $newProgram -and $oldProgram -ne $newProgram) { continue }
            if ($old.Service -and $old.Service -ne 'Any' -and $required.Service -and $old.Service -ne $required.Service) { continue }
            if (Test-FirewallPortOverlap $old.LocalPort @($required.LocalPort -split ',')) { $overlaps += $required.Name }
        }
        if ($overlaps.Count) {
            [PSCustomObject]@{ ID = $old.ID; Name = $old.Name; DisplayName = $old.DisplayName; Store = $old.Store
                SourceType = $old.SourceType; CanChange = $old.CanChange; RemoteAddress = $old.RemoteAddress -join ','
                LocalPort = $old.LocalPort -join ','; Overlaps = $overlaps -join ',' }
        }
    }
}

# Verify explicit block filters in merged effective policy, not just local storage.
# Authenticated bypass rules can override ordinary blocks and must be reported.
function Get-FirewallBlockRuleIssues {
    param([object[]]$Inventory, [object[]]$PlannedRules)
    $blocks=@($PlannedRules | Where-Object Action -EQ Block)
    if ($blocks.Count) {
        try {
            $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
            if ($profiles.Count -lt 3) {[PSCustomObject]@{Name='Firewall profiles';Issue='Could not verify all three effective firewall profiles.'}}
            foreach ($profile in $profiles) {
                if ([string]$profile.Enabled -ne 'True' -or [string]$profile.AllowLocalFirewallRules -eq 'False') {
                    [PSCustomObject]@{Name=[string]$profile.Name;Issue='Effective profile disables the firewall or local rule merging; external port blocks cannot be assumed effective.'}
                }
            }
        } catch {[PSCustomObject]@{Name='Firewall profiles';Issue="Effective profile read failed: $_"}}
    }
    foreach ($plan in $blocks) {
        $protocol=if($plan.Protocol -eq 'TCP'){'6'}elseif($plan.Protocol -eq 'UDP'){'17'}else{[string]$plan.Protocol}
        $matches=@($Inventory | Where-Object {
            $_.Store -eq 'ActiveStore' -and $_.Name -eq $plan.Name -and $_.Enabled -and
            $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' -and $_.Profile -eq 'Any' -and
            $_.Protocol -in @($plan.Protocol,$protocol)
        })
        $verified=$false
        foreach ($rule in $matches) {
            if ((Test-FirewallFilterEqual $rule.RemoteAddress @($plan.RemoteAddress)) -and
                (Test-FirewallFilterEqual $rule.LocalPort @($plan.LocalPort -split ',')) -and
                (Test-FirewallFilterEqual $rule.RemotePort @('Any')) -and
                (Test-FirewallFilterEqual $rule.LocalAddress @('Any')) -and
                (Test-FirewallFilterEqual @($rule.Program) @('Any')) -and
                (Test-FirewallFilterEqual @($rule.Service) @('Any')) -and
                (Test-FirewallFilterEqual $rule.InterfaceAlias @('Any'))) {$verified=$true;break}
        }
        if (-not $verified) {[PSCustomObject]@{Name=$plan.Name;Issue='Required block is missing or its effective filters differ from the plan.'}}
    }
    foreach ($rule in @($Inventory | Where-Object {
        $_.Store -eq 'ActiveStore' -and $_.Enabled -and $_.Direction -eq 'Inbound' -and
        $_.Action -eq 'Allow' -and $_.OverrideBlockRules -in @('True','1')
    })) {
        if (Test-InternalFirewallScope $rule.RemoteAddress) {continue}
        foreach ($plan in $blocks) {
            $protocol=if($plan.Protocol -eq 'TCP'){'6'}else{'17'}
            if ($rule.Protocol -in @('Any','256',$plan.Protocol,$protocol) -and
                (Test-FirewallPortOverlap $rule.LocalPort @($plan.LocalPort -split ','))) {
                [PSCustomObject]@{Name=$rule.Name;Issue='Authenticated bypass rule may override external port blocks; review this rule at its policy source.'}
                break
            }
        }
    }
}

# Present old-rule audit/selection menus, save the chosen plan, and optionally
# disable/remove exact local rules. Default A only audits; GPO rules remain report-only.
function Invoke-OldFirewallRuleReview {
    param([object[]]$Inventory, [object[]]$PlannedRules, [string[]]$ManagedNames, [string]$ReportPrefix, [string]$BackupPath)
    $legacy = @($Inventory | Where-Object { $_.Name -notin $ManagedNames -and $_.DisplayName -notin $ManagedNames })
    # Audit both stores, but select mutations only from locally editable rows.
    # IDs refer to this saved inventory; display names can be duplicated.
    $conflicts = @(Get-FirewallScopeConflicts $legacy $PlannedRules)
    $conflicts | Export-Csv -LiteralPath "$ReportPrefix-conflicts-before.csv" -NoTypeInformation -ErrorAction Stop
    $local = @($legacy | Where-Object CanChange)
    Write-Log "Old firewall inventory: $ReportPrefix-before.csv. Local rules: $($local.Count); potential scope conflicts (local/effective): $($conflicts.Count)."
    $local | Format-Table ID, DisplayName, Enabled, Direction, Action, Protocol, @{N='Ports';E={$_.LocalPort -join ','}}, @{N='Sources';E={$_.RemoteAddress -join ','}} -AutoSize | Out-String | Write-Host
    if ($conflicts.Count) { $conflicts | Format-Table ID, DisplayName, Store, SourceType, LocalPort, RemoteAddress -AutoSize | Out-String | Write-Host }
    $scope = Read-MenuChoice -Prompt 'Old firewall rules: [A] Audit only, [C] Review internal-scope conflicts, [I] Review all old local inbound Allow rules, [S] Select local IDs (default A; profile rules still apply)' -Choices @('A', 'C', 'I', 'S') -Default 'A'
    if ($scope -eq 'A') {
        if ($conflicts.Count) { Write-Log "Audited only: $($conflicts.Count) potential conflict records remain. Existing broad allows may bypass the new internal-source limits." 'WARN' }
        else { Write-Log 'Old rules audited only; no old-rule changes selected.' }
        return
    }
    $selected = @()
    # C targets possible bypasses; I is broader and may include OS/application
    # allowances. S can include block/outbound rules only by explicitly chosen ID.
    if ($scope -eq 'C') {
        $ids = @($conflicts | Where-Object CanChange | Select-Object -ExpandProperty ID)
        $selected = @($local | Where-Object { $_.ID -in $ids })
    } elseif ($scope -eq 'I') {
        $selected = @($local | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' })
    } else {
        $inputIds = Read-Host 'Exact comma-separated local rule IDs (blank cancels; no wildcards)'
        if ([string]::IsNullOrWhiteSpace($inputIds)) { return }
        $ids = @($inputIds -split ',' | ForEach-Object { $_.Trim() })
        if (@($ids | Where-Object { $_ -notmatch '^\d+$' -or $_ -notin @($local.ID | ForEach-Object { [string]$_ }) }).Count) {
            Write-Log 'Invalid or non-local rule ID. No old rules changed.' 'WARN'; return
        }
        $selected = @($local | Where-Object { [string]$_.ID -in $ids })
    }
    if (-not $selected.Count) { Write-Log 'No changeable old rules selected. GPO/effective-only rules are report-only.'; return }
    $selected | Format-Table ID, Name, DisplayName, Enabled, Direction, Action -AutoSize | Out-String | Write-Host
    $choice = Read-MenuChoice -Prompt 'Selected old rules: [D] Disable, [R] Remove, [A] Audit only (default D)' -Choices @('D', 'R', 'A') -Default 'D'
    if ($choice -eq 'A') { return }
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf) -or (Get-Item -LiteralPath $BackupPath).Length -le 0) { throw 'A verified firewall backup is required before changing old rules.' }
    $selected | Select-Object ID, Name, DisplayName, Enabled, Direction, Action | Export-Csv -LiteralPath "$ReportPrefix-cleanup-plan.csv" -NoTypeInformation -ErrorAction Stop
    if ($choice -eq 'R' -and (Read-Host "Type REMOVE to delete $($selected.Count) selected old rules; Enter cancels") -cne 'REMOVE') { return }
    # Keep an outcome for each attempted change, even if a previous rule failed.
    # The backup/plan have already been saved before entering this loop.
    $outcomes = [Collections.Generic.List[object]]::new()
    foreach ($row in $selected) {
        try {
            # Resolve the exact local identity again, never a display-name wildcard or ActiveStore/GPO object.
            $current = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -EQ $row.Name)
            if ($current.Count -ne 1 -or [string]$current[0].PolicyStoreSourceType -in @('GroupPolicy', 'Dynamic', 'Generated', 'Hardcoded')) {
                throw 'Selected rule is missing, ambiguous, or not locally changeable.'
            }
            if ($choice -eq 'D') {
                if ([string]$current[0].Enabled -eq 'True') { $current[0] | Disable-NetFirewallRule -ErrorAction Stop | Out-Null }
                $outcome = 'Disabled or already disabled'
            } else {
                $current[0] | Remove-NetFirewallRule -ErrorAction Stop | Out-Null
                $outcome = 'Removed'
            }
            $after = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -EQ $row.Name)
            if (($choice -eq 'R' -and $after.Count) -or
                ($choice -eq 'D' -and ($after.Count -ne 1 -or [string]$after[0].Enabled -ne 'False'))) { throw 'Rule change did not pass read-back verification.' }
            Write-Log "Old firewall rule $($row.Name): $outcome" 'SUCCESS'
        } catch { $outcome = "Failed: $($_.Exception.Message)"; Write-Log "Old firewall rule $($row.Name): $outcome" 'ERROR' }
        $outcomes.Add([PSCustomObject]@{ ID = $row.ID; Name = $row.Name; DisplayName = $row.DisplayName; Outcome = $outcome })
        $outcomes | Export-Csv -LiteralPath "$ReportPrefix-cleanup-results.csv" -NoTypeInformation -ErrorAction Stop
    }
}

# Service operations below are separate from firewall rules: a running service
# still needs its listener/application configuration and network allowance.
# Service checks distinguish absent services from access/query failures.
# Read one service into a common record used by status and cleanup reports.
# Not installed and Query failed are distinct results; neither means the service is healthy.
function Get-ServiceState {
    param([string]$Name)
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        [PSCustomObject]@{
            Name = $Name; DisplayName = $service.DisplayName; Exists = $true
            Status = [string]$service.Status; StartType = [string]$service.StartType; Error = ''
        }
    } catch {
        $missing = $_.FullyQualifiedErrorId -like 'NoServiceFoundForGivenName*'
        [PSCustomObject]@{
            Name = $Name; DisplayName = ''; Exists = $false
            Status = $(if ($missing) { 'Not installed' } else { 'Query failed' })
            StartType = 'Unknown'; Error = $(if ($missing) { '' } else { $_.Exception.Message })
        }
    }
}

# Describe which services should run or remain disabled for the chosen host.
# Optional DHCP/IIS/SQL Browser choices determine which additional services are required.
function Get-EssentialServicePolicy {
    param($Configuration, [bool]$DomainJoined, [string[]]$SqlEngineNames = @('MSSQLSERVER'))
    if ($Configuration.Profile -notin @('AD-DNS', 'MSSQL')) { throw 'Unsupported server profile.' }
    $adDns = $Configuration.Profile -eq 'AD-DNS'
    # Dhcp is the DHCP CLIENT and is distinct from optional DHCPServer.
    # LanmanServer provides SMB; TermService provides RDP; CertSvc provides AD CS.
    $policy = @(
        @{ Name = 'Dhcp'; Expected = 'Running' }, # client, not the optional DHCP server
        @{ Name = 'W32Time'; Expected = 'Running' },
        @{ Name = 'LanmanServer'; Expected = 'Running' },
        @{ Name = 'Netlogon'; Expected = $(if ($adDns -or $DomainJoined) { 'Running' } else { 'Not required' }) },
        @{ Name = 'WinRM'; Expected = $(if ($adDns) { 'Running' } else { 'Disabled' }) },
        @{ Name = 'TermService'; Expected = $(if ($adDns) { 'Disabled' } else { 'Running' }) }
    )
    if ($adDns) {
        $policy += @(
            @{ Name = 'NTDS'; Expected = 'Running' },
            @{ Name = 'Kdc'; Expected = 'Running' },
            @{ Name = 'ADWS'; Expected = 'Running' },
            @{ Name = 'DNS'; Expected = 'Running' },
            @{ Name = 'CertSvc'; Expected = 'Running' },
            @{ Name = 'DHCPServer'; Expected = $(if ($Configuration.EnableDhcp) { 'Running' } else { 'Not required' }) }
        )
        if ($Configuration.AdcsWeb) {
            $policy += @{ Name = 'WAS'; Expected = 'Running' }, @{ Name = 'W3SVC'; Expected = 'Running' }
        }
    } else {
        if (-not $SqlEngineNames.Count) { $SqlEngineNames = @('MSSQLSERVER') }
        foreach ($name in @($SqlEngineNames | Select-Object -Unique)) {
            $policy += @{ Name = $name; Expected = 'Running' }
        }
        $policy += @{ Name = 'SQLBrowser'; Expected = $(if ($Configuration.SqlBrowser) { 'Running' } else { 'Not required' }) }
    }
    $policy | ForEach-Object { [PSCustomObject]$_ }
}

# Compare observed service state with the profile expectation without changing it.
# NeedsAttention identifies missing/stopped/disabled required services and policy mismatches.
function Get-EssentialServiceStatus {
    param([object[]]$Policy)
    foreach ($item in $Policy) {
        $state = Get-ServiceState $item.Name
        $required = $item.Expected -eq 'Running'
        $needsAttention = $required -and ($state.Status -ne 'Running' -or $state.StartType -eq 'Disabled')
        if ($item.Expected -eq 'Disabled' -and $state.Exists) {
            $needsAttention = $state.Status -ne 'Stopped' -or $state.StartType -ne 'Disabled'
        }
        [PSCustomObject]@{
            Name = $item.Name; DisplayName = $state.DisplayName; Expected = $item.Expected
            Status = $state.Status; StartType = $state.StartType; Exists = $state.Exists
            Required = $required; NeedsAttention = ($needsAttention -or [bool]$state.Error)
            Details = $state.Error
        }
    }
}

# Display and save the status table, then log each row needing attention.
# The running state is a service check, not proof that a scored application works.
function Write-EssentialServiceReport {
    param([object[]]$Report, [string]$Path, [string]$Stage)
    Write-Log "Essential service status ($Stage):"
    $Report | Format-Table Name, Expected, Status, StartType, NeedsAttention -AutoSize | Out-String | Write-Host
    $Report | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
    $problems = @($Report | Where-Object NeedsAttention)
    foreach ($problem in $problems) {
        Write-Log "Service needs attention: $($problem.Name); expected $($problem.Expected); status $($problem.Status); startup $($problem.StartType). $($problem.Details)" 'WARN'
    }
    Write-Log "Service report: $Path | Services needing attention: $($problems.Count)."
}

# For required services only, set Automatic startup and start stopped services.
# Wait for Running, read back the state, and return per-service outcomes without restarting running services.
function Repair-EssentialServices {
    param([object[]]$Report, [ValidateRange(1, 60)][int]$WaitSeconds = 15)
    foreach ($item in $Report) {
        # Never enable RDP/WinRM where the host policy requires them disabled.
        if (-not $item.Required) { continue }
        # A missing role is reported for manual work; repair does not install
        # Windows features, create certificates, or configure SQL protocols.
        $errors = @()
        try {
            if (-not $item.Exists) { throw "Service is unavailable: $($item.Status). $($item.Details)" }
            Write-Log "Enabling and checking essential service: $($item.Name)..."
            Set-Service -Name $item.Name -StartupType Automatic -ErrorAction Stop
            $service = Get-Service -Name $item.Name -ErrorAction Stop
            if ([string]$service.Status -ne 'Running') {
                Start-Service -Name $item.Name -ErrorAction Stop
                $service = Get-Service -Name $item.Name -ErrorAction Stop
                $service.WaitForStatus('Running', [TimeSpan]::FromSeconds($WaitSeconds))
            }
        } catch {
            $errors += $_.Exception.Message
        }
        $after = Get-ServiceState $item.Name
        $healthy = $after.Status -eq 'Running' -and $after.StartType -eq 'Automatic'
        if (-not $healthy) { $errors += "Observed status $($after.Status), startup $($after.StartType). $($after.Error)" }
        $outcome = if ($healthy -and -not $errors.Count) { 'Running' } else { 'Needs attention' }
        $level = if ($outcome -eq 'Running') { 'SUCCESS' } else { 'WARN' }
        Write-Log "Essential service $($item.Name): $outcome. $($errors -join ' ')" $level
        [PSCustomObject]@{
            Name = $item.Name; Outcome = $outcome; Status = $after.Status
            StartType = $after.StartType; Details = $errors -join ' '
        }
    }
}

# Check the listed remote-access service names, disable startup, and stop them.
# Return/log before-and-after states; partial failures are recorded rather than called Disabled.
function Disable-RemoteAccessServices {
    param([string[]]$Names, [string]$ReportPath)
    # Create the log before making changes, even when no matching services exist.
    '"Timestamp","Name","DisplayName","BeforeStatus","BeforeStartType","AfterStatus","AfterStartType","Outcome","Details"' |
        Set-Content -Path $ReportPath -Encoding UTF8 -ErrorAction Stop
    foreach ($name in @($Names | Select-Object -Unique)) {
        $before = Get-ServiceState $name
        if ($before.Status -eq 'Not installed') { continue }
        $errors = @()
        # Attempt startup disablement and stopping separately so one failure
        # does not hide the other result. Already-disabled/stopped items are logged too.
        if ($before.Exists) {
            # A failed stop must not prevent disabling startup, or vice versa.
            try {
                if ($before.StartType -ne 'Disabled') {
                    Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
                }
            } catch { $errors += "Disable failed: $($_.Exception.Message)" }
            try {
                if ($before.Status -ne 'Stopped') {
                    Stop-Service -Name $name -Force -ErrorAction Stop
                }
            } catch { $errors += "Stop failed: $($_.Exception.Message)" }
        } else {
            $errors += "Service query failed: $($before.Error)"
        }
        $after = Get-ServiceState $name
        $disabled = $after.Status -eq 'Stopped' -and $after.StartType -eq 'Disabled'
        $outcome = if ($disabled -and -not $errors.Count) {
            if ($before.Status -eq 'Stopped' -and $before.StartType -eq 'Disabled') { 'Already disabled' } else { 'Disabled' }
        } else { 'Needs attention' }
        if (-not $disabled) { $errors += "Observed status $($after.Status), startup $($after.StartType). $($after.Error)" }
        $entry = [PSCustomObject]@{
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Name = $name; DisplayName = $before.DisplayName
            BeforeStatus = $before.Status; BeforeStartType = $before.StartType
            AfterStatus = $after.Status; AfterStartType = $after.StartType
            Outcome = $outcome; Details = $errors -join ' '
        }
        # The transcript also records the result if writing the CSV later fails.
        $level = if ($outcome -eq 'Needs attention') { 'ERROR' } else { 'SUCCESS' }
        Write-Log "Remote-access service $name`: $outcome. $($entry.Details)" $level
        try { $entry | Export-Csv -Path $ReportPath -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
        catch { Write-Log "Could not append remote-access service log $ReportPath`: $_" 'ERROR' }
        $entry
    }
    Write-Log "Remote-access service disablement log: $ReportPath"
}

# Account helpers use normalized records so AD and local cleanup follow one policy.
# Turn comma-separated menu entries into trimmed, nonempty, unique values.
# This only splits input; the caller decides whether values are exact names or wildcards.
function Split-AccountInput {
    param([string[]]$Value)
    @($Value | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
        Where-Object { $_ } | Select-Object -Unique)
}

# Return normalized Users/Groups records from AD on AD-DNS or local SAM on MSSQL.
# Read failures throw instead of producing a partial inventory suitable for destructive cleanup.
function Get-AccountInventory {
    param([bool]$DomainController)
    # Use SIDs for mutations. DNs link the membership inventory to its groups.
    # AD primary groups must be read explicitly because MemberOf omits them.
    if ($DomainController) {
        $users = @(Get-ADUser -Filter * -Server $script:AccountServer -Properties Enabled, LastLogonDate,
            PasswordLastSet, MemberOf, PrimaryGroupID, 'msDS-SecondaryKrbTgtNumber' -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.SamAccountName; Identity = $_.DistinguishedName; SID = [string]$_.SID
                    Enabled = $_.Enabled; LastLogon = $_.LastLogonDate; PasswordLastSet = $_.PasswordLastSet
                    MemberOf = @($_.MemberOf); PrimaryGroupID = $_.PrimaryGroupID
                    IsKerberos = ([string]$_.SID -match '-502$' -or [int]$_.'msDS-SecondaryKrbTgtNumber' -gt 0)
                }
            })
        $groups = @(Get-ADGroup -Filter * -Server $script:AccountServer -Properties MemberOf -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name; Identity = $_.DistinguishedName; SID = [string]$_.SID
                    MemberOf = @($_.MemberOf); Members = @()
                }
            })
    } else {
        $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name; Identity = $_.Name; SID = [string]$_.SID
                Enabled = $_.Enabled; LastLogon = $_.LastLogon; PasswordLastSet = $_.PasswordLastSet
                MemberOf = @(); PrimaryGroupID = $null; IsKerberos = $false
            }
        })
        # Fail on incomplete enumeration, including unresolved/orphaned principals.
        # Never delete accounts after silently skipping a group we could not read.
        $groups = @(Get-LocalGroup -ErrorAction Stop | ForEach-Object {
            $group = $_
            $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; SID = [string]$_.SID }
            })
            [PSCustomObject]@{
                Name = $group.Name; Identity = [string]$group.SID; SID = [string]$group.SID
                MemberOf = @(); Members = $members
            }
        })
        foreach ($user in $users) {
            $user.MemberOf = @($groups | Where-Object { $user.SID -in @($_.Members.SID) } | Select-Object -ExpandProperty Name)
        }
    }
    [PSCustomObject]@{ Users = $users; Groups = $groups }
}

# Classify Administrator by SID first, then Kerberos, explicit service names, and
# scoring names/patterns. Protection preserves the account, not non-default group memberships.
function Get-AccountCategory {
    param($User, [string]$AdministratorSid, [string[]]$Patterns, [string[]]$ScoringNames, [string[]]$ServiceNames)
    if ($User.SID -eq $AdministratorSid) { return 'Administrator' }
    if ($User.IsKerberos) { return 'Kerberos' }
    if ($ServiceNames -contains $User.Name) { return 'Service' }
    if ($ScoringNames -contains $User.Name) { return 'Scoring' }
    foreach ($pattern in $Patterns) {
        if ($User.Name -like $pattern) { return 'Scoring' }
    }
    return 'Other'
}

# Identify OS service memberships that can remain for application access.
# Account allowlists do not grant this exception to ordinary service usernames.
function Get-ServiceMembershipPreservations {
    param($Inventory)
    # These are OS-issued identities, not usernames or operator-created users.
    # Never exempt them from administrative groups, even through nested groups.
    $privileged = @{}
    foreach ($group in $Inventory.Groups) {
        if ($group.SID -match '^S-1-5-32-(544|547|548|549|550|551|552|555|556|578|580)$' -or
            $group.Name -match '(?i)admin|operator|backup|remote desktop|remote management|hyper-v') {
            $privileged[$group.SID] = $true
        }
    }
    do {
        $added = $false
        foreach ($group in $Inventory.Groups) {
            if (-not $privileged.ContainsKey($group.SID)) { continue }
            foreach ($member in $group.Members) {
                if ($member.SID -in @($Inventory.Groups.SID) -and -not $privileged.ContainsKey($member.SID)) {
                    $privileged[$member.SID] = $true
                    $added = $true
                }
            }
        }
    } while ($added)
    foreach ($group in $Inventory.Groups) {
        if ($privileged.ContainsKey($group.SID)) { continue }
        foreach ($member in $group.Members) {
            if ($member.SID -match '^S-1-5-(18|19|20)$|^S-1-5-(80|82)-') {
                [PSCustomObject]@{
                    Account = $member.Name; Member = $member.SID; Group = $group.Name
                    GroupIdentity = $group.Identity; Reason = 'OS service identity in a non-administrative application group'
                }
            }
        }
    }
}

# Build membership changes without applying them. Administrator is exempt;
# ordinary users retain only Users, while OS service exceptions are reported.
function Get-GroupCleanupPlan {
    param($Inventory, [bool]$DomainController, [string]$AdministratorSid, [string]$DefaultGroupSid)
    $defaultGroup = @($Inventory.Groups | Where-Object SID -EQ $DefaultGroupSid)
    if ($defaultGroup.Count -ne 1) { throw "Cannot uniquely identify the default Users group ($DefaultGroupSid)." }
    $defaultGroup = $defaultGroup[0]
    $groupsBySid = @{}
    $groupsByIdentity = @{}
    foreach ($group in $Inventory.Groups) {
        $groupsBySid[$group.SID] = $group
        $groupsByIdentity[$group.Identity] = $group
    }
    if ($DomainController) {
        foreach ($user in $Inventory.Users) {
            if ($user.SID -eq $AdministratorSid) { continue }
            $memberships = @($user.MemberOf)
            if ($user.PrimaryGroupID -ne 513) {
                $primarySid = ($user.SID -replace '-\d+$', '') + '-' + $user.PrimaryGroupID
                if (-not $groupsBySid.ContainsKey($primarySid)) { throw "Cannot resolve primary group for $($user.Name)." }
                [PSCustomObject]@{
                    Action = 'ResetPrimaryGroup'; Account = $user.Name; Member = $user.SID
                    Group = $defaultGroup.Name; GroupIdentity = $defaultGroup.SID
                }
                # AD does not include the primary group in MemberOf. Resetting it
                # leaves an explicit membership which must also be removed.
                $memberships += $groupsBySid[$primarySid].Identity
            }
            foreach ($membership in @($memberships | Select-Object -Unique)) {
                if ($membership -eq $defaultGroup.Identity) { continue }
                if (-not $groupsByIdentity.ContainsKey($membership)) { throw "Cannot resolve group '$membership' for $($user.Name)." }
                [PSCustomObject]@{
                    Action = 'RemoveMembership'; Account = $user.Name; Member = $user.SID
                    Group = $groupsByIdentity[$membership].Name; GroupIdentity = $groupsByIdentity[$membership].SID
                }
            }
        }
        # Otherwise all users could inherit extra rights through Domain Users.
        foreach ($parent in $defaultGroup.MemberOf) {
            if (-not $groupsByIdentity.ContainsKey($parent)) { throw "Cannot resolve parent group '$parent'." }
            [PSCustomObject]@{
                Action = 'RemoveMembership'; Account = $defaultGroup.Name; Member = $defaultGroup.SID
                Group = $groupsByIdentity[$parent].Name; GroupIdentity = $groupsByIdentity[$parent].SID
            }
        }
    } else {
        # Ordinary users and nested/domain groups lose non-default memberships.
        # OS service SIDs may retain non-administrative application access only.
        $preserved = @{}
        foreach ($entry in @(Get-ServiceMembershipPreservations $Inventory)) {
            $preserved["$($entry.GroupIdentity)/$($entry.Member)"] = $true
        }
        foreach ($group in $Inventory.Groups) {
            if ($group.SID -eq $DefaultGroupSid) { continue }
            # Remove domain/nested groups too, so they cannot grant local rights.
            foreach ($member in $group.Members) {
                if ($member.SID -eq $AdministratorSid) { continue }
                if ($preserved.ContainsKey("$($group.Identity)/$($member.SID)")) { continue }
                [PSCustomObject]@{
                    Action = 'RemoveMembership'; Account = $member.Name; Member = $member.SID
                    Group = $group.Name; GroupIdentity = $group.Identity
                }
            }
        }
    }
}

# Apply the saved membership plan with terminating errors handled per change.
# Return a failure count; later account disablement/deletion requires clean read-back verification.
function Invoke-GroupCleanup {
    param([object[]]$Plan, [bool]$DomainController)
    $failures = 0
    foreach ($change in $Plan) {
        try {
            if ($DomainController) {
                if ($change.Action -eq 'ResetPrimaryGroup') {
                    Add-ADGroupMember -Identity $change.GroupIdentity -Members $change.Member -Server $script:AccountServer -ErrorAction Stop
                    Set-ADUser -Identity $change.Member -Replace @{ primaryGroupID = 513 } -Server $script:AccountServer -ErrorAction Stop
                } else {
                    Remove-ADGroupMember -Identity $change.GroupIdentity -Members $change.Member -Server $script:AccountServer -Confirm:$false -ErrorAction Stop
                }
            } else {
                Remove-LocalGroupMember -SID $change.GroupIdentity -Member $change.Member -Confirm:$false -ErrorAction Stop
            }
            Write-Log "$($change.Action): $($change.Account) -> $($change.Group)" 'SUCCESS'
        } catch {
            $failures++
            Write-Log "Group change failed for $($change.Account) in $($change.Group): $_" 'ERROR'
        }
    }
    return $failures
}

# Apply Audit/Disable/Remove only to accounts categorized Other.
# Protected accounts are checked again here; reserved Windows accounts are disabled instead of deleted.
function Invoke-AccountCleanup {
    param([object[]]$Users, [string]$Action, [bool]$DomainController,
        [string]$AdministratorSid, [string[]]$Patterns, [string[]]$ScoringNames, [string[]]$ServiceNames)
    if ($Action -notin @('Remove','Disable')) { return }
    foreach ($user in $Users) {
        if ($user.Category -ne 'Other' -or $user.SID -match '-(500|502)$' -or $user.IsKerberos) { continue }
        try {
            # Bind both the final read and the write to the previewed SID. A
            # replacement at the same name has a different SID and cannot be selected.
            if ($DomainController) {
                $current = Get-ADUser -Identity $user.SID -Server $script:AccountServer -Properties 'msDS-SecondaryKrbTgtNumber' -ErrorAction Stop
                $name = $current.SamAccountName
            } else {
                $current = Get-LocalUser -SID $user.SID -ErrorAction Stop
                $name = $current.Name
            }
            $live = [PSCustomObject]@{
                Name = $name; SID = [string]$current.SID
                IsKerberos = ([int]$current.'msDS-SecondaryKrbTgtNumber' -gt 0)
            }
            $category = Get-AccountCategory $live $AdministratorSid $Patterns $ScoringNames $ServiceNames
            if ($live.SID -ne $user.SID -or $name -ne $user.Name -or $category -ne 'Other') {
                Write-Log "Skipped $($user.Name): identity or protection changed since preview." 'WARN'
                continue
            }
            # Windows reserves these accounts; disable instead of trying to delete.
            $reserved = $user.SID -match '-(501|503|504)$'
            if ($Action -eq 'Remove' -and -not $reserved) {
                if ($DomainController) {
                    Remove-ADUser -Identity $user.SID -Server $script:AccountServer -Confirm:$false -ErrorAction Stop
                } else {
                    Remove-LocalUser -SID $user.SID -Confirm:$false -ErrorAction Stop
                }
                Write-Log "Removed account: $($user.Name)" 'SUCCESS'
            } elseif ($Action -eq 'Disable' -or ($Action -eq 'Remove' -and $reserved)) {
                if (-not $current.Enabled) { continue }
                if ($DomainController) {
                    Disable-ADAccount -Identity $user.SID -Server $script:AccountServer -ErrorAction Stop
                } else {
                    Disable-LocalUser -SID $user.SID -ErrorAction Stop
                }
                Write-Log "Disabled account: $($user.Name)$(if ($reserved -and $Action -eq 'Remove') { ' (reserved Windows account)' })" 'SUCCESS'
            }
        } catch {
            Write-Log "Could not $Action account $($user.Name): $_" 'ERROR'
        }
    }
}

# Save account details as CSV and a richer CLIXML snapshot including groups.
# These are audit records, not password/profile backups that can recreate a deleted account.
function Save-AccountInventory {
    param($Inventory, [string]$Path)
    $Inventory | Export-Clixml -Path "$Path.xml" -ErrorAction Stop
    $Inventory.Users | Select-Object Name, SID, Enabled, Category, LastLogon, PasswordLastSet,
        PrimaryGroupID, @{ N = 'MemberOf'; E = { $_.MemberOf -join '; ' } } |
        Export-Csv -Path "$Path.csv" -NoTypeInformation -ErrorAction Stop
}

# Run account inventory, protection prompts, plan export, and the action menu.
# Preview returns before membership changes; applying a plan verifies groups before touching accounts.
function Invoke-AccountReview {
    param(
        [bool]$DomainController, [string]$CurrentSid, [string]$ReportDirectory
    )
    # Pin AD reads/writes to one DC so replication timing does not make local
    # verification appear successful or incomplete merely by switching servers.
    if ($DomainController) {
        Import-Module ActiveDirectory -ErrorAction Stop
        # Pin reads/writes to one DC so replication delay does not spoil verification.
        $script:AccountServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    }
    $inventory = Get-AccountInventory -DomainController $DomainController
    $administrator = @($inventory.Users | Where-Object SID -Match '-500$')
    if ($administrator.Count -ne 1 -or $administrator[0].SID -ne $CurrentSid) {
        throw 'Account cleanup requires signing in as the built-in Administrator of the account database being reviewed.'
    }
    $administratorSid = $administrator[0].SID
    $defaultGroupSid = if ($DomainController) { ($administratorSid -replace '-500$', '-513') } else { 'S-1-5-32-545' }
    Write-Log "Account database: $(if ($DomainController) { "AD on $script:AccountServer" } else { 'local machine' }). Administrator: $($administrator[0].Name)."
    $inventory.Users | Sort-Object Name | Format-Table Name, Enabled, LastLogon, PasswordLastSet -AutoSize | Out-String | Write-Host

    # *.* matches any login with a dot, including dotted service accounts.
    # Exact service/scoring names provide exceptions to account cleanup, not to group cleanup.
    $Patterns = @(Split-AccountInput @(Read-Host 'Scoring login wildcard(s), comma-separated (score_* or *.* for lastname.firstname; blank = none)'))
    $ScoringNames = @(Split-AccountInput @(Read-Host 'Additional exact scoring login name(s), comma-separated (blank = none)'))
    $ServiceNames = @(Split-AccountInput @(Read-Host 'Existing service login name(s) you created, comma-separated (blank = none; does not create accounts)'))
    foreach ($pattern in $Patterns) {
        # Validate all patterns before making any group/account changes.
        $null = [System.Management.Automation.WildcardPattern]::new($pattern).IsMatch('')
        $matches = @($inventory.Users | Where-Object Name -Like $pattern)
        Write-Log "Scoring pattern '$pattern': $($matches.Count) matching account(s)."
        if ($matches.Count) { Write-Log "Matched logins: $($matches.Name -join ', ')" }
    }
    foreach ($name in @($ScoringNames + $ServiceNames)) {
        if ($name -notin @($inventory.Users.Name)) { Write-Log "Protected login '$name' does not currently exist in this database." 'WARN' }
    }
    foreach ($user in $inventory.Users) {
        $category = Get-AccountCategory $user $administratorSid $Patterns $ScoringNames $ServiceNames
        $user | Add-Member -NotePropertyName Category -NotePropertyValue $category -Force
    }
    $inventory.Users | Sort-Object Category, Name | Format-Table Name, Enabled, Category -AutoSize | Out-String | Write-Host
    Write-Log 'Administrator keeps its groups. ALL other users keep only Domain Users (local Users on non-DCs), including scoring/service accounts.'
    Write-Log 'Group objects and computer accounts are retained. Scoring/service protection applies only to account disablement/deletion.'

    $reportPrefix = Join-Path $ReportDirectory "accounts-$([guid]::NewGuid())"
    $plan = @(Get-GroupCleanupPlan $inventory $DomainController $administratorSid $defaultGroupSid)
    if (-not $DomainController) {
        $preservations = @(Get-ServiceMembershipPreservations $inventory)
        $preservations | Export-Csv -Path "$reportPrefix-service-memberships-preserved.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log "Preserving $($preservations.Count) OS service membership(s) in non-administrative groups; see $reportPrefix-service-memberships-preserved.csv."
    }
    # All reports must save successfully before any mutation.
    Save-AccountInventory $inventory "$reportPrefix-before"
    $plan | Export-Csv -Path "$reportPrefix-group-plan.csv" -NoTypeInformation -ErrorAction Stop
    Write-Log "Account inventory and group plan saved: $reportPrefix*"
    if ($plan.Count) { $plan | Format-Table Action, Account, Group -AutoSize | Out-String | Write-Host }
    Write-Log "Planned group changes: $($plan.Count)."
    # P changes no accounts/groups. A still strips non-default memberships;
    # D/R also disable/delete Other accounts only after group verification passes.
    $selection = Read-MenuChoice `
        -Prompt 'Account step: [P] Preview only, [A] Apply group cleanup/audit accounts, [D] Apply group cleanup/disable others, [R] Apply group cleanup/remove others (default P)' `
        -Choices @('P', 'Preview', 'A', 'Audit', 'D', 'Disable', 'R', 'Remove') -Default 'P'
    $actions = @{ P = 'Preview'; Preview = 'Preview'; A = 'Audit'; Audit = 'Audit'; D = 'Disable'; Disable = 'Disable'; R = 'Remove'; Remove = 'Remove' }
    $Action = $actions[$selection]
    if ($Action -eq 'Preview') {
        Write-Log 'Preview: no account or group changes applied. Other hardening steps still run.'
        return
    }
    $candidates = @($inventory.Users | Where-Object Category -EQ 'Other')
    Write-Log "Account action: $Action; $($candidates.Count) other account(s)."
    if ($Action -eq 'Remove' -and $candidates.Count) {
        if ((Read-Host "Type REMOVE to delete $($candidates.Count) unprotected accounts (reserved Windows accounts will be disabled)") -cne 'REMOVE') {
            $Action = 'Audit'
            Write-Log 'Deletion canceled. Accounts will only be audited; group cleanup still applies.'
        }
    }
    $failures = Invoke-GroupCleanup $plan $DomainController
    $afterGroups = Get-AccountInventory -DomainController $DomainController
    $administratorAfter = @($afterGroups.Users | Where-Object SID -EQ $administratorSid)
    if ($administratorAfter.Count -ne 1 -or
        $administratorAfter[0].PrimaryGroupID -ne $administrator[0].PrimaryGroupID -or
        @(Compare-Object @($administrator[0].MemberOf | Sort-Object) @($administratorAfter[0].MemberOf | Sort-Object)).Count) {
        throw 'Administrator account or memberships changed during cleanup. Account disablement/deletion skipped.'
    }
    # Rebuild the plan from fresh state rather than assuming cmdlet success.
    # Any remaining membership or recorded write failure blocks account deletion.
    $remaining = @(Get-GroupCleanupPlan $afterGroups $DomainController $administratorSid $defaultGroupSid)
    $remaining | Export-Csv -Path "$reportPrefix-groups-remaining.csv" -NoTypeInformation -ErrorAction Stop
    Save-AccountInventory $afterGroups "$reportPrefix-after-groups"
    if ($failures -or $remaining.Count) {
        throw "Group cleanup incomplete ($failures failures; $($remaining.Count) remaining changes). Account disablement/deletion skipped. See $reportPrefix*."
    }
    Write-Log 'Verified: reviewed users have only their default Users group; Administrator memberships were retained.' 'SUCCESS'
    Invoke-AccountCleanup -Users $candidates -Action $Action -DomainController $DomainController `
        -AdministratorSid $administratorSid -Patterns $Patterns -ScoringNames $ScoringNames -ServiceNames $ServiceNames
    Save-AccountInventory (Get-AccountInventory -DomainController $DomainController) "$reportPrefix-after"
    Write-Log "Account review finished. Reports: $reportPrefix*"
}

# -----------------------------------------------------------------------------
# Apply and read back SMB signing separately for server and client on BOTH roles.
# A registry fallback is reported as pending until the running SMB setting is verified.
function Invoke-SmbSigningBaseline {
    foreach ($side in @('Server', 'Client')) {
        $registryPath = if ($side -eq 'Server') { 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' } else { 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' }
        try {
            if ($side -eq 'Server') { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop }
            else { Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop }
            $state = if ($side -eq 'Server') { Get-SmbServerConfiguration -ErrorAction Stop } else { Get-SmbClientConfiguration -ErrorAction Stop }
            if (-not $state.RequireSecuritySignature) { throw 'Read-back still shows signing is not required.' }
            Write-Log "SMB $side signing verified." 'SUCCESS'
        } catch {
            Write-Log "SMB $side cmdlet configuration/verification failed: $_. Trying the registry." 'WARN'
            try {
                Set-ItemProperty -LiteralPath $registryPath -Name RequireSecuritySignature -Value 1 -Type DWord -Force -ErrorAction Stop
                if ((Get-ItemProperty -LiteralPath $registryPath -Name RequireSecuritySignature -ErrorAction Stop).RequireSecuritySignature -ne 1) { throw 'Registry read-back did not match.' }
                $active = $false
                try {
                    $state = if ($side -eq 'Server') { Get-SmbServerConfiguration -ErrorAction Stop } else { Get-SmbClientConfiguration -ErrorAction Stop }
                    $active = [bool]$state.RequireSecuritySignature
                } catch {}
                if ($active) { Write-Log "SMB $side signing verified after registry fallback." 'SUCCESS' }
                else { Write-Log "SMB $side signing saved in registry; runtime enforcement is unverified. A service restart/reboot may be needed." 'WARN' }
            } catch { Write-Log "SMB $side signing could not be applied/verified: $_" 'ERROR' }
        }
    }
}

# Verify requested Defender preferences and actual real-time protection state.
# Missing cmdlets, passive mode, and tamper-protected changes remain visible.
function Invoke-DefenderBaseline {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        $preferences = Get-MpPreference -ErrorAction Stop
        $health = Get-MpComputerStatus -ErrorAction Stop
        if ($preferences.DisableRealtimeMonitoring -ne $false -or [int]$preferences.PUAProtection -ne 1 -or
            $health.RealTimeProtectionEnabled -ne $true) { throw 'Defender read-back does not show real-time protection active and PUA blocking enabled.' }
        Write-Log 'Defender real-time protection and PUA blocking verified.' 'SUCCESS'
    } catch { Write-Log "Defender baseline needs attention: $_" 'ERROR' }
}

# AD uses domain policy cmdlets; MSSQL uses local net.exe policy plus an effective
# policy export for read-back. Native nonzero exits are failures, not exceptions.
function Invoke-LockoutBaseline {
    param([bool]$DomainController, [string]$ReportDirectory)
    try {
        if ($DomainController) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $domain = Get-ADDomain -ErrorAction Stop
            Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $domain.PDCEmulator -LockoutThreshold 10 -LockoutDuration ([timespan]::FromMinutes(15)) -LockoutObservationWindow ([timespan]::FromMinutes(15)) -ErrorAction Stop
            $policy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $domain.PDCEmulator -ErrorAction Stop
            if ($policy.LockoutThreshold -ne 10 -or $policy.LockoutDuration.TotalMinutes -ne 15 -or $policy.LockoutObservationWindow.TotalMinutes -ne 15) { throw 'Domain lockout policy read-back did not match.' }
        } else {
            Invoke-CheckedNativeCommand "$env:SystemRoot\System32\net.exe" @('accounts', '/lockoutthreshold:10', '/lockoutduration:15', '/lockoutwindow:15')
            $policy = Get-EffectiveSecuritySettings $ReportDirectory
            if ($policy['System Access/LockoutBadCount'] -ne '10' -or $policy['System Access/LockoutDuration'] -ne '15' -or $policy['System Access/ResetLockoutCount'] -ne '15') { throw 'Effective local lockout policy read-back did not match.' }
        }
        Write-Log 'Lockout policy verified: 10 failures, 15-minute lockout and reset window.' 'SUCCESS'
    } catch { Write-Log "Lockout baseline needs attention: $_" 'ERROR' }
}

# AD-DNS enables and verifies WinRM; MSSQL disables and verifies it.
# No success message is emitted merely because a suppressed command returned.
function Invoke-WinRmBaseline {
    param([bool]$DomainController)
    try {
        if ($DomainController) {
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
            Start-Service -Name WinRM -ErrorAction Stop
            Import-Module Microsoft.WSMan.Management -ErrorAction Stop
            foreach ($setting in @(
                @{ Path = 'WSMan:\localhost\Service\AllowUnencrypted'; Value = $false },
                @{ Path = 'WSMan:\localhost\Service\Auth\Basic'; Value = $false },
                @{ Path = 'WSMan:\localhost\Client\Auth\Basic'; Value = $false },
                @{ Path = 'WSMan:\localhost\Service\CbtHardeningLevel'; Value = 'Strict' }
            )) {
                Set-Item -LiteralPath $setting.Path -Value $setting.Value -Force -ErrorAction Stop
                if ([string](Get-Item -LiteralPath $setting.Path -ErrorAction Stop).Value -ne [string]$setting.Value) { throw "WinRM setting read-back failed: $($setting.Path)" }
            }
            $service = Get-ServiceState WinRM
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Automatic') { throw 'WinRM service state does not match AD-DNS policy.' }
            Write-Log 'AD-DNS WinRM service and security settings verified.' 'SUCCESS'
        } else {
            $errors = @()
            # Attempt every operation, even if remoting configuration fails.
            try { Disable-PSRemoting -Force -ErrorAction Stop | Out-Null } catch { $errors += "Disable-PSRemoting: $_" }
            try { Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop } catch { $errors += "Startup: $_" }
            try { Stop-Service -Name WinRM -Force -ErrorAction Stop } catch { $errors += "Stop: $_" }
            $service = Get-ServiceState WinRM
            if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') { $errors += "Observed WinRM: $($service.Status), $($service.StartType)." }
            if ($errors.Count) { throw ($errors -join ' ') }
            Write-Log 'MSSQL WinRM verified stopped and disabled.' 'SUCCESS'
        }
    } catch { Write-Log "WinRM baseline needs attention: $_" 'ERROR' }
}

# Treat native nonzero exits as errors even on Windows PowerShell 5.1.
function Invoke-CheckedNativeCommand {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $FilePath (exit $LASTEXITCODE)." }
}

# Export effective local/domain security policy to a private, uniquely named file.
# Values are keyed by section/name, avoiding localized net.exe output parsing.
function Get-EffectiveSecuritySettings {
    param([string]$ReportDirectory)
    $path = Join-Path $ReportDirectory "security-policy-$([guid]::NewGuid().ToString('N')).inf"
    Invoke-CheckedNativeCommand "$env:SystemRoot\System32\secedit.exe" @('/export', '/mergedpolicy', '/cfg', $path, '/areas', 'SECURITYPOLICY', '/log', "$path.log", '/quiet')
    $values = @{}
    $section = ''
    foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction Stop)) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1] }
        elseif ($line -match '^\s*([^;=]+?)\s*=\s*(.*?)\s*$') { $values["$section/$($Matches[1])"] = $Matches[2] }
    }
    return $values
}

# Inspect the current key version on every writable DC. A successful query is
# a point-in-time replication check, not a guarantee about future network health.
function Get-KrbtgtRotationStatus {
    param([string]$ReportDirectory)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $server = $domain.PDCEmulator
    $krbtgtSid = "$($domain.DomainSID)-502"
    $account = Get-ADUser -Identity $krbtgtSid -Server $server -Properties PasswordLastSet, 'msDS-KeyVersionNumber' -ErrorAction Stop
    if (-not $account.PasswordLastSet) { throw 'Cannot determine the previous krbtgt reset time.' }
    $lastSet = ([datetime]$account.PasswordLastSet).ToUniversalTime()
    $version = [long]$account.'msDS-KeyVersionNumber'
    $policyVerified = $false
    # Keep at least the default lifetime as a conservative baseline: reducing
    # today's policy does not retroactively shorten tickets already issued.
    $waitMinutes = 600.0
    try {
        $policy = Get-EffectiveSecuritySettings $ReportDirectory
        $userHours = 0; $serviceMinutes = 0; $skewMinutes = 0
        if (-not [int]::TryParse($policy['Kerberos Policy/MaxTicketAge'], [ref]$userHours) -or $userHours -le 0 -or
            -not [int]::TryParse($policy['Kerberos Policy/MaxServiceAge'], [ref]$serviceMinutes) -or $serviceMinutes -le 0 -or
            -not [int]::TryParse($policy['Kerberos Policy/MaxClockSkew'], [ref]$skewMinutes) -or $skewMinutes -lt 0) {
            throw 'Finite Kerberos ticket lifetimes/clock skew were not found.'
        }
        $waitMinutes = [Math]::Max($waitMinutes, [Math]::Max($userHours * 60.0, $serviceMinutes)) + [Math]::Max(5, $skewMinutes)
        $policyVerified = $true
    } catch {
        $waitMinutes += 5
        Write-Log "Kerberos policy could not be verified: $_. Normal rotation is blocked; emergency rotation requires explicit confirmation." 'WARN'
    }
    $replicationReady = $true
    $controllers = @(Get-ADDomainController -Filter * -Server $server -ErrorAction Stop | Where-Object { -not $_.IsReadOnly })
    if (-not $controllers.Count) { throw 'Cannot enumerate writable domain controllers.' }
    foreach ($dc in $controllers) {
        $copy = Get-ADUser -Identity $krbtgtSid -Server $dc.HostName -Properties PasswordLastSet, 'msDS-KeyVersionNumber' -ErrorAction Stop
        if (-not $copy.PasswordLastSet -or [long]$copy.'msDS-KeyVersionNumber' -ne $version -or
            ([datetime]$copy.PasswordLastSet).ToUniversalTime() -ne $lastSet) { $replicationReady = $false }
    }
    if (@(Get-ADReplicationFailure -Target $domain.DNSRoot -Scope Domain -ErrorAction Stop).Count) { $replicationReady = $false }
    [PSCustomObject]@{
        CollectedAtUtc = [datetime]::UtcNow
        Domain = $domain.DNSRoot; SID = $krbtgtSid; Server = $server; Version = $version; LastSetUtc = $lastSet
        RecommendedAfterUtc = $lastSet.AddMinutes($waitMinutes); WaitMinutes = $waitMinutes
        PolicyVerified = $policyVerified; ReplicationReady = $replicationReady
    }
}

# One explicitly confirmed reset per visit. There is no background timer or
# second reset later in the same hardening run. Reopen in follow-up-only mode.
function Invoke-KrbtgtRotationReview {
    param([string]$ReportDirectory)
    try {
        $status = Get-KrbtgtRotationStatus $ReportDirectory
        $auditPath = Join-Path $ReportDirectory "krbtgt-$([guid]::NewGuid().ToString('N')).jsonl"
        $status | ConvertTo-Json -Compress | Add-Content -LiteralPath $auditPath -Encoding UTF8 -ErrorAction Stop
        Write-Log "krbtgt key version $($status.Version); last reset $($status.LastSetUtc.ToString('u')); recommended next reset after $($status.RecommendedAfterUtc.ToString('u'))."
        Write-Log "Policy verified: $($status.PolicyVerified). Replication ready: $($status.ReplicationReady). Audit: $auditPath"
        $choice = Read-MenuChoice -Prompt 'Kerberos: [S] Status only, [R] Reset once after recommended wait, [E] Early competition reset (default S)' -Choices @('S', 'R', 'E') -Default 'S'
        if ($choice -eq 'S') { return }
        if (-not $status.ReplicationReady) { throw 'krbtgt copies differ or AD replication reports failures. Repair replication before resetting.' }
        $now = [datetime]::UtcNow
        if ($choice -eq 'R') {
            if (-not $status.PolicyVerified -or $now -lt $status.RecommendedAfterUtc) {
                Write-Log "Normal reset deferred until $($status.RecommendedAfterUtc.ToString('u')) with verified policy. Use follow-up-only mode later." 'WARN'
                return
            }
            $confirmation = 'RESET KRBTGT'
        } else {
            Write-Log 'Early reset can invalidate existing tickets and interrupt scoring/services. A shorter wait does not make existing tickets expire sooner.' 'WARN'
            $minutes = 0
            $answer = Read-Host 'Minimum minutes since the previous reset (positive whole number; blank cancels)'
            if (-not $answer) { return }
            if (-not [int]::TryParse($answer, [ref]$minutes) -or $minutes -le 0 -or $minutes -gt 525600) {
                throw 'Enter a positive interval of at most one year in minutes.'
            }
            $earlyAfter = $status.LastSetUtc.AddMinutes($minutes)
            if ($now -lt $earlyAfter) {
                Write-Log "Early reset deferred until $($earlyAfter.ToString('u')). Nothing will reset automatically." 'WARN'
                return
            }
            $confirmation = 'RESET KRBTGT EARLY'
        }
        if ((Read-Host "Type $confirmation to reset once; Enter cancels") -cne $confirmation) { return }
        # Recheck after the operator's review: another administrator may have
        # reset the account while this menu was open.
        $fresh = Get-KrbtgtRotationStatus $ReportDirectory
        if ($fresh.SID -ne $status.SID -or $fresh.Server -ne $status.Server -or $fresh.Version -ne $status.Version -or
            $fresh.LastSetUtc -ne $status.LastSetUtc -or -not $fresh.ReplicationReady) { throw 'krbtgt/replication changed during review. Recheck before resetting.' }
        if ($choice -eq 'R' -and (-not $fresh.PolicyVerified -or [datetime]::UtcNow -lt $fresh.RecommendedAfterUtc)) {
            throw 'The recommended waiting period is no longer satisfied.'
        }
        $bytes = New-Object byte[] 64
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
        Set-ADAccountPassword -Identity $fresh.SID -Server $fresh.Server -NewPassword $password -Reset -ErrorAction Stop
        $after = Get-ADUser -Identity $fresh.SID -Server $fresh.Server -Properties PasswordLastSet, 'msDS-KeyVersionNumber' -ErrorAction Stop
        if ([long]$after.'msDS-KeyVersionNumber' -le $fresh.Version) { throw 'Reset was requested but a new key version was not observed on the target DC.' }
        [PSCustomObject]@{
            Outcome = 'Reset verified on target DC'; Server = $fresh.Server; Mode = $choice
            SelectedMinimumMinutes = $(if ($choice -eq 'E') { $minutes } else { $fresh.WaitMinutes })
            LastSetUtc = ([datetime]$after.PasswordLastSet).ToUniversalTime()
            Version = [long]$after.'msDS-KeyVersionNumber'
            RecommendedAfterUtc = ([datetime]$after.PasswordLastSet).ToUniversalTime().AddMinutes($fresh.WaitMinutes)
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $auditPath -Encoding UTF8 -ErrorAction Stop
        Write-Log "One krbtgt reset verified on $($fresh.Server). No second reset will run in this invocation; verify replication before the next visit." 'SUCCESS'
    } catch { Write-Log "Kerberos rotation needs attention: $_" 'ERROR' }
}

# Compare UTF-16 code units exactly and erase the temporary unmanaged copies.
function Test-PasswordMatch {
    param([securestring]$First, [securestring]$Second)
    if ($First.Length -ne $Second.Length) { return $false }
    $left = [IntPtr]::Zero
    $right = [IntPtr]::Zero
    try {
        $left = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $right = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        for ($i = 0; $i -lt $First.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($left, 2*$i) -ne [Runtime.InteropServices.Marshal]::ReadInt16($right, 2*$i)) { return $false }
        }
        return $true
    } finally {
        if ($left -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($left) }
        if ($right -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($right) }
    }
}

# Select one of the two competition hosts, then validate the account database.
# -----------------------------------------------------------------------------
# MAIN EXECUTION: all helper functions above are now available. Profile selection
# is checked against Windows DC status before password/service/firewall changes.
$serverConfiguration = Read-ServerConfiguration
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$script:isDC = $os.ProductType -eq 2
if (($serverConfiguration.Profile -eq 'AD-DNS') -ne $script:isDC) {
    throw "Selected profile $($serverConfiguration.Profile) does not match this host's domain-controller status. No hardening changes have been applied."
}
$script:isDomainJoined = $script:isDC
try {
    $script:isDomainJoined = $script:isDC -or [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
} catch {
    Write-Log "Could not detect domain membership: $_. Netlogon will be checked as required." 'WARN'
    $script:isDomainJoined = $true
}
$sqlEngineNames = @()
if ($serverConfiguration.Profile -eq 'MSSQL') {
    $sqlEngineNames = @(Get-SqlEngineServiceNames)
}

$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |            shed-hardening.ps1              |
     | ,      ,_ `\_/~\-           |    made for MWCCDC 2026-27' qualifiers     |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black

Write-Log "Detected Host: $(hostname)" "INFO"
Write-Log "Selected server profile: $($serverConfiguration.Profile)."
if ($serverConfiguration.Profile -eq 'AD-DNS') {
    Write-Log "AD-DNS: AD DS, AD CS, DNS, ping; DHCP: $($serverConfiguration.EnableDhcp); AD CS web enrollment: $($serverConfiguration.AdcsWeb)."
} else {
    Write-Log "MSSQL: SQL TCP $($serverConfiguration.SqlTcpPorts -join ', '), SMB, RDP; SQL Browser: $($serverConfiguration.SqlBrowser)."
}
Write-Log 'Steps: password / Kerberos, service cleanup, remote access, firewall, account cleanup, network review, security baseline.'
Write-Log 'Account/group actions will be selected at their prompts. Account preview is the default.'
Write-Log "Transcript: $script:LogFile | Reports and firewall backup: $BackupDir"

# Follow-up mode changes no passwords, services, firewall rules, or accounts
# outside the explicitly confirmed krbtgt operation.
if ($script:isDC) {
    $mode = Read-MenuChoice -Prompt '[H] Full hardening, [K] Kerberos follow-up only (default H)' -Choices @('H', 'K') -Default 'H'
    if ($mode -eq 'K') {
        Invoke-KrbtgtRotationReview $BackupDir
        try { Stop-Transcript -ErrorAction Stop | Out-Null } catch {}
        return
    }
}

# -----------------------------------------------------------------------------
# Capture the original firewall before any hardening steps can change it,
# including service startup, RDP settings and Enable-PSRemoting.
$firewallRun = [guid]::NewGuid()
$firewallReportPrefix = Join-Path $LogsDir "firewall-$firewallRun"
$fwBackup = Join-Path $BackupDir "firewall-rules-$firewallRun.wfw"
try {
    Save-FirewallPolicyBackup $fwBackup
    $beforeFirewall = @(Get-FirewallAuditInventory)
    Save-FirewallAuditInventory $beforeFirewall "$firewallReportPrefix-before"
} catch {
    Write-Log "Full hardening stopped before changes. Firewall backup or inventory failed: $_" 'ERROR'
    try { Stop-Transcript -ErrorAction Stop | Out-Null } catch {}
    return
}

# 1. Administrator Password Change + DSRM Sync
# -----------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------------------"
Write-Host "Please input a new Administrator password."
Write-Host "--------------------------------------------------------------------------------"

# The built-in Administrator keeps RID 500 even when renamed. DSRM sync
# takes a login name, so read it by SID from the same DC that receives the reset.
while ($true) {
    $newPassword = $null
    $confirmation = $null
    try {
        $newPassword = Read-Host -AsSecureString 'Enter the new built-in Administrator password'
        $confirmation = Read-Host -AsSecureString 'Confirm the new password'
        if (-not $newPassword.Length -or -not (Test-PasswordMatch $newPassword $confirmation)) {
            Write-Host 'Enter a nonempty password and match its capitalization exactly.' -ForegroundColor Yellow
            continue
        }
        if ($script:isDC) {
            $domain = Get-ADDomain -Server localhost -ErrorAction Stop
            $sid = "$($domain.DomainSID)-500"
            Set-ADAccountPassword -Identity $sid -Server localhost -NewPassword $newPassword -Reset -ErrorAction Stop
            Write-Log "Domain Administrator password changed for $sid." 'SUCCESS'
            try {
                $admin = Get-ADUser -Identity $sid -Server localhost -ErrorAction Stop
                $sync = & "$env:SystemRoot\System32\ntdsutil.exe" 'set dsrm password' "sync from domain account $($admin.SamAccountName)" q q 2>&1
                if ($LASTEXITCODE -ne 0 -or "$sync" -notmatch 'successfully') { throw "Review ntdsutil output: $sync" }
                Write-Log 'DSRM password synchronized.' 'SUCCESS'
            } catch { Write-Log "DSRM sync needs review: $_" 'WARN' }
        } else {
            $admin = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -match '-500$' })
            if ($admin.Count -ne 1) { throw 'Cannot identify the local built-in Administrator.' }
            Set-LocalUser -SID $admin[0].SID -Password $newPassword -ErrorAction Stop
            Write-Log "Local Administrator password changed for $($admin[0].SID)." 'SUCCESS'
        }
        break
    } catch {
        Write-Log "Administrator password change failed: $_" 'ERROR'
        if ((Read-Host 'Retry password change? (y/N)') -ne 'y') { break }
    } finally {
        if ($newPassword) { $newPassword.Dispose() }
        if ($confirmation) { $confirmation.Dispose() }
    }
}

# -----------------------------------------------------------------------------
# 2. Review Kerberos (krbtgt) rotation (AD-DNS only)
# -----------------------------------------------------------------------------
if ($script:isDC) { Invoke-KrbtgtRotationReview $BackupDir }
else { Write-Log 'Skipping krbtgt rotation on MSSQL.' }

# -----------------------------------------------------------------------------
# 3. Disable unneeded base services; check and optionally repair essential services
# -----------------------------------------------------------------------------
# This fixed list is offered for operator review; a listed service can still be
# needed by a specific workload. The profile essentials are checked separately.
# Keep AD DS/AD CS/DNS, SQL engine, SMB, and profile-managed remote-access services out of this list.
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
Write-Host "Base service hardening and essential service status"
Write-Host "--------------------------------------------------------------------------------"

# Show every installed listed base service, including stopped/disabled ones,
# so the operator can decide whether to disable the whole list or individual entries.
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

    $svcChoice = Read-MenuChoice -Prompt 'Base services: [A] Disable all listed, [S] Select individually, [N] Skip (default A)' -Choices @('A', 'S', 'N') -Default 'A'

    if ($svcChoice -eq "A" -or $svcChoice -eq "a") {
        foreach ($s in $detectedBaseServices) {
            try {
                Stop-Service -Name $s.Name -Force -ErrorAction Stop
                Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop
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
                    Stop-Service -Name $s.Name -Force -ErrorAction Stop
                    Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop
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

# Check essentials even if no base services exist or the operator skips disabling them.
$essentialServicePolicy = Get-EssentialServicePolicy -Configuration $serverConfiguration -DomainJoined $script:isDomainJoined -SqlEngineNames $sqlEngineNames
$essentialReportPrefix = Join-Path $LogsDir "essential-services-$(Get-Date -Format yyyyMMdd-HHmmss-fff)"
try {
    $essentialStatus = @(Get-EssentialServiceStatus $essentialServicePolicy)
    Write-EssentialServiceReport $essentialStatus "$essentialReportPrefix-before-repair.csv" 'base service hardening'
    Write-Log 'RDP/WinRM expectations follow the final host policy. Their remote-management configuration is applied in step 5.'
    # Check-only is the default here, unlike the separate base-disable menu.
    # R changes only required services; RDP/WinRM still follow the server profile.
    $serviceRepairChoice = Read-MenuChoice -Prompt 'Essential services: [C] Check only, [R] Set required services to Automatic and start them (default C)' -Choices @('C', 'R') -Default 'C'
    if ($serviceRepairChoice -eq 'R') {
        $repairResults = @(Repair-EssentialServices $essentialStatus)
        $repairResults | Export-Csv -Path "$essentialReportPrefix-repairs.csv" -NoTypeInformation -ErrorAction Stop
        $repairResults | Format-Table Name, Outcome, Status, StartType, Details -AutoSize -Wrap | Out-String | Write-Host
        Write-EssentialServiceReport @(Get-EssentialServiceStatus $essentialServicePolicy) "$essentialReportPrefix-after-repair.csv" 'after repair'
    }
} catch {
    Write-Log "Essential service check/repair incomplete: $_" 'ERROR'
}

# -----------------------------------------------------------------------------
# 4. Stop and disable SSH, Telnet, and third-party remote access
# -----------------------------------------------------------------------------
Write-Log "Stopping and disabling SSH, Telnet, AnyDesk, TeamViewer, VNC, and RustDesk..." "INFO"

# OpenSSH Server cleanup
try {
    # Terminate SSH processes immediately
    Get-Process -Name "sshd", "ssh-agent" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated SSH process: $($_.Name) (PID: $($_.Id))" "WARN"
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

} catch {
    Write-Log "Error disabling Telnet: $_" "WARN"
}

# Third-party remote software / RATs (AnyDesk, TeamViewer, VNC, RustDesk)
# Detection here is a fixed name/pattern list, not a general malware classifier.
# Matching processes are terminated; matching service disablement has its own CSV.
$ratProcesses = @("AnyDesk", "TeamViewer*", "tv_x64", "tv_w32", "winvnc", "vncserver", "rustdesk")
foreach ($proc in $ratProcesses) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated rogue remote process: $($_.Name) (PID: $($_.Id))" "WARN"
    }
}

$remoteServiceLog = Join-Path $LogsDir "remote-access-services-$(Get-Date -Format yyyyMMdd-HHmmss-fff).csv"
$remoteServiceNames = @('sshd', 'ssh-agent', 'TlntSvr', 'AnyDesk', 'TeamViewer', 'uvnc_service', 'tightvnc', 'tvnserver', 'rustdesk')
try {
    $remoteServiceResults = @(Disable-RemoteAccessServices -Names $remoteServiceNames -ReportPath $remoteServiceLog)
    if ($remoteServiceResults.Count) {
        $remoteServiceResults | Format-Table Name, BeforeStatus, BeforeStartType, AfterStatus, AfterStartType, Outcome -AutoSize | Out-String | Write-Host
    } else {
        Write-Log 'No matching remote-access services found. The service log contains only its header.'
    }
} catch {
    Write-Log "Remote-access service cleanup incomplete: $_" 'ERROR'
}

New-NetFirewallRule -DisplayName "CCDC-Block-SSH"    -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "CCDC-Block-Telnet" -Direction Inbound -Action Block -Protocol TCP -LocalPort 23 -Profile Any -ErrorAction SilentlyContinue | Out-Null

# -----------------------------------------------------------------------------
# 5. Remote management: RDP on MSSQL; WinRM on AD-DNS
# -----------------------------------------------------------------------------
# Requirement:
# - RDP: Enabled with NLA/TLS on MSSQL; disabled on AD-DNS.
# - WinRM: Enabled on AD-DNS; disabled on MSSQL.

Write-Host "`n--------------------------------------------------------------------------------"
Write-Host "Configuring remote management: RDP on MSSQL; WinRM on AD-DNS"
Write-Host "--------------------------------------------------------------------------------"

# RDP registry settings control connection permission, NLA, TLS, encryption, and
# idle timeout. Creating a firewall allowance alone would not configure any of these.
# RDP Configuration
if ($serverConfiguration.Profile -eq 'AD-DNS') {
    Write-Log "AD-DNS profile: disabling Remote Desktop (RDP)..." "INFO"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1 -ErrorAction Stop
        Stop-Service -Name TermService -Force -ErrorAction Stop
        Set-Service -Name TermService -StartupType Disabled -ErrorAction Stop
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction Stop
        Write-Log "Remote Desktop Protocol disabled on AD-DNS." "SUCCESS"
    } catch {
        Write-Log "Could not disable RDP: $_" "WARN"
    }
} else {
    Write-Log "MSSQL profile: enabling and hardening RDP for scoring..." "INFO"
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

        Set-Service -Name TermService -StartupType Automatic -ErrorAction Stop
        Start-Service -Name TermService -ErrorAction Stop
        Write-Log "RDP enabled and hardened with NLA and TLS encryption for scoring." "SUCCESS"
    } catch {
        Write-Log "Error configuring RDP on MSSQL server: $_" "WARN"
    }
}

# WinRM Configuration
# HTTPS firewall allowances do not create a certificate or HTTPS listener.
Invoke-WinRmBaseline -DomainController $script:isDC

# -----------------------------------------------------------------------------
# 6. Firewall rules by host role
# -----------------------------------------------------------------------------
Write-Log "Configuring Windows Firewall..." "INFO"
try {
    if ($serverConfiguration.EnableDhcp) {
        $aliases = @(Get-InternalFirewallInterfaces)
        if (-not $aliases.Count) { throw 'DHCP enabled but no interface is addressed in 172.20.240.0/24. Firewall changes skipped.' }
        $serverConfiguration | Add-Member -NotePropertyName InternalInterfaceAliases -NotePropertyValue $aliases -Force
    }
    $firewallRules = @(Get-ServerFirewallRules $serverConfiguration)
    Write-Log 'Internal management sources: 172.20.240.0/24. Scored endpoints retain public source access.'
    if ($serverConfiguration.Profile -eq 'AD-DNS') {
        Write-Log 'External plan: WinRM TCP 5985/5986, DNS TCP/UDP 53, and ping only. AD DS/AD CS/SMB/NTP/DHCP are internal.'
    } else { Write-Log 'External plan: configured SQL TCP ports, SMB TCP 445, RDP TCP/UDP 3389, and ping only. SQL Browser stays internal.' }
    $firewallRules | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Action = $_.Action; Protocol = $_.Protocol; Ports = $_.LocalPort; Sources = @($_.RemoteAddress) -join ','; Scope = $_.Scope } } |
        Export-Csv -LiteralPath "$firewallReportPrefix-profile-plan.csv" -NoTypeInformation -ErrorAction Stop

    # Default policy: Block Inbound, Allow Outbound (preserves scoring engine traffic, updates, logs)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -NotifyOnListen False -ErrorAction Stop

    # Keep drop logging in Windows' service-managed firewall directory. The
    # private transcript/evidence directory does not grant the firewall service access.
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" `
        -LogMaxSizeKilobytes 8192 `
        -LogAllowed False `
        -LogBlocked True -ErrorAction Stop

    # Remove only this script's obsolete allowances, including legacy role rules.
    $managedRuleNames = @(
        'CCDC-ICMP-In', 'CCDC-NTP-In', 'CCDC-DHCP-In', 'CCDC-DHCP-Bootstrap-In', 'CCDC-DNS-UDP-In', 'CCDC-DNS-TCP-In',
        'CCDC-WinRM-HTTP-In', 'CCDC-WinRM-HTTPS-In', 'CCDC-AD-Kerberos-TCP', 'CCDC-AD-Kerberos-UDP',
        'CCDC-AD-LDAP-TCP', 'CCDC-AD-LDAP-UDP', 'CCDC-AD-ADWS-TCP', 'CCDC-AD-SMB-TCP',
        'CCDC-AD-RPC-EPMAP', 'CCDC-AD-RPC-Dynamic', 'CCDC-ADCS-RPC-In', 'CCDC-ADCS-Web-In',
        'CCDC-AD-SMB-External-TCP-Block', 'CCDC-AD-SMB-External-UDP-Block',
        'CCDC-External-TCP-Block', 'CCDC-External-UDP-Block', 'CCDC-DHCP-External-UDP-Block',
        'CCDC-SMB-TCP-In', 'CCDC-MSSQL-TCP-In', 'CCDC-MSSQL-UDP-In', 'CCDC-RDP-TCP-In', 'CCDC-RDP-UDP-In'
    )
    foreach ($ruleName in @($managedRuleNames | Where-Object { $_ -notin @($firewallRules.Name) })) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    }

    # Replace exact script-owned names with the selected profile plan. Any
    # retained legacy/GPO Allow rule may still broaden access until reviewed.
    foreach ($r in $firewallRules) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        $params = @{
            Name        = $r.Name
            DisplayName = $r.Name
            Direction   = "Inbound"
            Action      = $r.Action
            Enabled     = "True"
            Protocol    = $r.Protocol
            Profile     = "Any"
            RemoteAddress = $r.RemoteAddress
            Group = "CCDC-Shed-Hardening"
            PolicyStore = "PersistentStore"
        }
        if ($r.LocalPort) { $params["LocalPort"] = $r.LocalPort.Split(',') }
        if ($r.IcmpType)  { $params["IcmpType"]  = $r.IcmpType }
        if ($r.RemotePort) { $params["RemotePort"] = $r.RemotePort.Split(',') }
        if ($r.InterfaceAlias) { $params["InterfaceAlias"] = $r.InterfaceAlias }
        if ($r.Program) { $params['Program'] = $r.Program }
        if ($r.Service) { $params['Service'] = $r.Service }
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        Write-Log "Firewall $($r.Action) inbound: $($r.Name); sources $(@($r.RemoteAddress) -join ','); $($r.Scope)." 'SUCCESS'
    }
    # Default old-rule action is Audit. The fresh scoped rules are applied
    # regardless; this menu separately decides whether old allowances are retired.
    Invoke-OldFirewallRuleReview -Inventory $beforeFirewall -PlannedRules $firewallRules -ManagedNames $managedRuleNames -ReportPrefix $firewallReportPrefix -BackupPath $fwBackup
    $afterFirewall = @(Get-FirewallAuditInventory)
    Save-FirewallAuditInventory $afterFirewall "$firewallReportPrefix-after"
    $blockIssues = @(Get-FirewallBlockRuleIssues $afterFirewall $firewallRules)
    $blockIssues | Export-Csv -LiteralPath "$firewallReportPrefix-block-issues.csv" -NoTypeInformation -ErrorAction Stop
    if ($blockIssues.Count) {
        Write-Log "EXTERNAL PORT BLOCKS NOT VERIFIED: $($blockIssues.Count) effective-policy issue(s). Review $firewallReportPrefix-block-issues.csv; policy-source changes may be required." 'WARN'
    } else {
        Write-Log 'External TCP/UDP guards match the effective policy. Verify scored endpoints externally and internal-only services from both networks.' 'SUCCESS'
    }
    # Check merged effective policy after cleanup, including policies this host
    # cannot edit locally. A clean comparison is not proof of network reachability.
    $remainingConflicts = @(Get-FirewallScopeConflicts @($afterFirewall | Where-Object Store -EQ ActiveStore) $firewallRules)
    $remainingConflicts | Export-Csv -LiteralPath "$firewallReportPrefix-conflicts-remaining.csv" -NoTypeInformation -ErrorAction Stop
    if ($remainingConflicts.Count) {
        Write-Log "INTERNAL SCOPE NOT VERIFIED: $($remainingConflicts.Count) effective allow rule(s) may bypass the source limits. Review $firewallReportPrefix-conflicts-remaining.csv; GPO rules require changes at their source." 'WARN'
    } else {
        Write-Log 'No potential broad effective-rule conflicts found for internal services. This is a rule audit; verify reachability from both networks.' 'SUCCESS'
    }
    Write-Log "Firewall audit, plans, results, and remaining conflicts: $firewallReportPrefix*"
} catch {
    Write-Log "Firewall configuration error: $_" "ERROR"
}

# -----------------------------------------------------------------------------
# 7. Kerberos follow-up reminder
# -----------------------------------------------------------------------------
if ($script:isDC) {
    Write-Log 'No automatic second krbtgt reset. Rerun this script and choose Kerberos follow-up only to review timing/replication and reset once.'
}

# -----------------------------------------------------------------------------
# 8. Account review and group membership cleanup
# -----------------------------------------------------------------------------
Write-Log 'Reviewing accounts and removing non-default group memberships...'
try {
    Invoke-AccountReview -DomainController $script:isDC `
        -CurrentSid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) `
        -ReportDirectory $BackupDir
} catch {
    Write-Log "Account review incomplete: $_" 'ERROR'
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
# Display active hosts-file overrides for review; do not rewrite the file
# or assume that every non-comment entry is malicious.
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
Write-Log 'Applying and verifying Defender, account lockout, and SMB signing on this host...'
Invoke-DefenderBaseline
Invoke-LockoutBaseline -DomainController $script:isDC -ReportDirectory $BackupDir
Invoke-SmbSigningBaseline

# -----------------------------------------------------------------------------
# 11. Download shed-installs.ps1 to C:\Tools (does not execute it)
# -----------------------------------------------------------------------------
try {
    # Fetch the installer script only if absent; downloading does not execute it.
    # Existing copies are preserved for the operator to review/run separately.
    $installScriptPath = "$ToolsDir\shed-installs.ps1"
    if (-not (Test-Path $installScriptPath)) {
        Write-Log "Downloading install script to $installScriptPath..." "INFO"
        Invoke-WebRequest "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master/windows/shed-installs.ps1" -OutFile $installScriptPath -UseBasicParsing -ErrorAction Stop
        Write-Log "Install script downloaded to $installScriptPath" "SUCCESS"
    }
} catch {
    Write-Log "Could not download install script: $_" "WARN"
}

# Refresh service status after remote-management policy and the remaining hardening.
try {
    Write-EssentialServiceReport @(Get-EssentialServiceStatus $essentialServicePolicy) "$essentialReportPrefix-final.csv" 'end of hardening'
} catch {
    Write-Log "Final essential service report failed: $_" 'ERROR'
}

# Report emitted warning/error messages, not a transactional success guarantee.
# Earlier changes remain in place if a later operation logged an error.
if ($script:HardeningIssues) {
    Write-Log "Hardening finished with $script:HardeningIssues warning/error message(s). Review the transcript: $script:LogFile" 'WARN'
} else {
    Write-Log "Hardening finished. Transcript: $script:LogFile" 'SUCCESS'
}
try { Stop-Transcript | Out-Null } catch {}
Read-Host 'Press Enter to exit'
