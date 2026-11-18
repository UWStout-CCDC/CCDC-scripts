#Requires -RunAsAdministrator

<#
.SYNOPSIS
Interactive Windows competition hardening with account and group cleanup.
.DESCRIPTION
Run without arguments and answer the prompts. All configuration is interactive.
On a DC, reviews the current AD domain; elsewhere, reviews local accounts.
Administrator keeps its memberships. Every other user keeps only Domain Users
(local Users on non-DCs), including protected scoring and service accounts.
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
.EXAMPLE
.\shed-hardening.ps1
#>
# Reject old switches or positional arguments before any hardening begins.
if ($args.Count -gt 0) {
    throw 'This script accepts no command-line options. Run .\shed-hardening.ps1 and answer the prompts.'
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
$script:HardeningIssues = 0
try {
    Start-Transcript -Path $script:LogFile -Append -ErrorAction SilentlyContinue | Out-Null
} catch {}

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
function Read-MenuChoice {
    param([string]$Prompt, [string[]]$Choices, [string]$Default)
    while ($true) {
        $answer = (Read-Host $Prompt).Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        if ($answer -in $Choices) { return $answer }
        Write-Host "Please enter one of: $($Choices -join ', ')." -ForegroundColor Yellow
    }
}

# There are exactly two competition hosts. Choose the intended profile explicitly.
function Read-ServerConfiguration {
    $choice = Read-MenuChoice -Prompt 'Server profile: [A] AD-DNS (AD DS, AD CS, DNS, optional DHCP, ping), [M] MSSQL (SQL Server, SMB, RDP); choose A or M' -Choices @('A', 'AD-DNS', 'M', 'MSSQL') -Default ''
    $configuration = [PSCustomObject]@{
        Profile = $(if ($choice -in @('A', 'AD-DNS')) { 'AD-DNS' } else { 'MSSQL' })
        EnableDhcp = $false; AdcsWeb = $false; SqlTcpPorts = @('1433'); SqlBrowser = $false
    }
    if ($configuration.Profile -eq 'AD-DNS') {
        $configuration.EnableDhcp = (Read-MenuChoice -Prompt 'Provide DHCP on AD-DNS (UDP 67 server, internal clients and initial requests)? (y/N)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
        $configuration.AdcsWeb = (Read-MenuChoice -Prompt 'Use AD CS web enrollment/IIS and allow HTTP/HTTPS 80/443? (y/N; RPC enrollment is supported either way)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
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
        $configuration.SqlBrowser = (Read-MenuChoice -Prompt 'Require SQL Browser for named-instance discovery and allow UDP 1434? (y/N)' -Choices @('Y', 'Yes', 'N', 'No') -Default 'N') -in @('Y', 'Yes')
    }
    return $configuration
}

function Get-SqlEngineServiceNames {
    # Query the service database so named instances are included even when stopped.
    $names = @(Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' } | Select-Object -ExpandProperty Name)
    if ($names.Count) { return $names }
    # Keep a required row in the report when no database engine is installed.
    return 'MSSQLSERVER'
}

function Get-ServerFirewallRules {
    param($Configuration)
    if ($Configuration.Profile -notin @('AD-DNS', 'MSSQL')) { throw 'Unsupported server profile.' }
    $rules = @(
    # SMB serves SQL shares on MSSQL and SYSVOL/NETLOGON on AD-DNS.
    @{ Name = 'CCDC-SMB-TCP-In'; Protocol = 'TCP'; LocalPort = '445' }
    if ($Configuration.Profile -eq 'AD-DNS') {
        @(
            @{ Name = 'CCDC-ICMP-In'; Protocol = 'ICMPv4'; IcmpType = '8' },
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
    $internalNames = @('CCDC-NTP-In', 'CCDC-WinRM-HTTP-In', 'CCDC-WinRM-HTTPS-In', 'CCDC-AD-ADWS-TCP', 'CCDC-AD-RPC-Dynamic', 'CCDC-DHCP-In')
    if ($Configuration.Profile -eq 'AD-DNS') { $internalNames += 'CCDC-SMB-TCP-In' }
    foreach ($rule in $rules) {
        if ($rule.Name -eq 'CCDC-DHCP-Bootstrap-In') { $rule.Scope = 'DHCP bootstrap' }
        elseif ($rule.Name -in $internalNames) { $rule.RemoteAddress = '172.20.240.0/24'; $rule.Scope = 'Internal' }
        else { $rule.RemoteAddress = 'Any'; $rule.Scope = 'Scored' }
        $rule
    }
}


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

function Get-InternalFirewallInterfaces {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { Test-InternalFirewallScope @($_.IPAddress) } |
        Select-Object -ExpandProperty InterfaceAlias -Unique)
}

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

function Save-FirewallAuditInventory {
    param([object[]]$Inventory, [string]$Prefix)
    $Inventory | Export-Clixml -LiteralPath "$Prefix.xml" -ErrorAction Stop
    $Inventory | Select-Object ID, Store, Name, DisplayName, Enabled, Direction, Action, Profile, SourceType, Source, CanChange,
        Protocol, @{N='LocalPort';E={$_.LocalPort -join ','}}, @{N='RemotePort';E={$_.RemotePort -join ','}},
        @{N='LocalAddress';E={$_.LocalAddress -join ','}}, @{N='RemoteAddress';E={$_.RemoteAddress -join ','}},
        Program, Service, @{N='InterfaceAlias';E={$_.InterfaceAlias -join ','}}, OverrideBlockRules |
        Export-Csv -LiteralPath "$Prefix.csv" -NoTypeInformation -ErrorAction Stop
}

function Save-FirewallPolicyBackup {
    param([string]$Path)
    & netsh.exe advfirewall export $Path 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        (Get-Item -LiteralPath $Path -ErrorAction Stop).Length -le 0) { throw 'Firewall backup failed; firewall changes will not be applied.' }
    Write-Log "Firewall policy backup: $Path"
}

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

function Test-FirewallFilterEqual {
    param([string[]]$Actual, [string[]]$Expected)
    $left = @($Actual | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $right = @($Expected | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if (-not $left.Count) { $left = @('any') }
    if (-not $right.Count) { $right = @('any') }
    return @(Compare-Object $left $right).Count -eq 0
}

function Test-PlannedFirewallException {
    param($Rule, [object[]]$PlannedRules)
    # Public scoring rules and DHCP bootstrap are intentional exceptions, but a
    # familiar name alone cannot hide a wider GPO or modified effective rule.
    foreach ($plan in @($PlannedRules | Where-Object { $_.Name -eq $Rule.Name -and $_.Scope -ne 'Internal' })) {
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

function Invoke-OldFirewallRuleReview {
    param([object[]]$Inventory, [object[]]$PlannedRules, [string[]]$ManagedNames, [string]$ReportPrefix, [string]$BackupPath)
    $legacy = @($Inventory | Where-Object { $_.Name -notin $ManagedNames -and $_.DisplayName -notin $ManagedNames })
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

# Service checks distinguish absent services from access/query failures.
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

function Get-EssentialServicePolicy {
    param($Configuration, [bool]$DomainJoined, [string[]]$SqlEngineNames = @('MSSQLSERVER'))
    if ($Configuration.Profile -notin @('AD-DNS', 'MSSQL')) { throw 'Unsupported server profile.' }
    $adDns = $Configuration.Profile -eq 'AD-DNS'
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

function Repair-EssentialServices {
    param([object[]]$Report, [ValidateRange(1, 60)][int]$WaitSeconds = 15)
    foreach ($item in $Report) {
        # Never enable RDP/WinRM where the host policy requires them disabled.
        if (-not $item.Required) { continue }
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

function Disable-RemoteAccessServices {
    param([string[]]$Names, [string]$ReportPath)
    # Create the log before making changes, even when no matching services exist.
    '"Timestamp","Name","DisplayName","BeforeStatus","BeforeStartType","AfterStatus","AfterStartType","Outcome","Details"' |
        Set-Content -Path $ReportPath -Encoding UTF8 -ErrorAction Stop
    foreach ($name in @($Names | Select-Object -Unique)) {
        $before = Get-ServiceState $name
        if ($before.Status -eq 'Not installed') { continue }
        $errors = @()
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
function Split-AccountInput {
    param([string[]]$Value)
    @($Value | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
        Where-Object { $_ } | Select-Object -Unique)
}

function Get-AccountInventory {
    param([bool]$DomainController)
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
                    Action = 'ResetPrimaryGroup'; Account = $user.Name; Member = $user.Identity
                    Group = $defaultGroup.Name; GroupIdentity = $defaultGroup.Identity
                }
                # AD does not include the primary group in MemberOf. Resetting it
                # leaves an explicit membership which must also be removed.
                $memberships += $groupsBySid[$primarySid].Identity
            }
            foreach ($membership in @($memberships | Select-Object -Unique)) {
                if ($membership -eq $defaultGroup.Identity) { continue }
                if (-not $groupsByIdentity.ContainsKey($membership)) { throw "Cannot resolve group '$membership' for $($user.Name)." }
                [PSCustomObject]@{
                    Action = 'RemoveMembership'; Account = $user.Name; Member = $user.Identity
                    Group = $groupsByIdentity[$membership].Name; GroupIdentity = $membership
                }
            }
        }
        # Otherwise all users could inherit extra rights through Domain Users.
        foreach ($parent in $defaultGroup.MemberOf) {
            if (-not $groupsByIdentity.ContainsKey($parent)) { throw "Cannot resolve parent group '$parent'." }
            [PSCustomObject]@{
                Action = 'RemoveMembership'; Account = $defaultGroup.Name; Member = $defaultGroup.Identity
                Group = $groupsByIdentity[$parent].Name; GroupIdentity = $parent
            }
        }
    } else {
        foreach ($group in $Inventory.Groups) {
            if ($group.SID -eq $DefaultGroupSid) { continue }
            # Remove domain/nested groups too, so they cannot grant local rights.
            foreach ($member in $group.Members) {
                if ($member.SID -eq $AdministratorSid) { continue }
                [PSCustomObject]@{
                    Action = 'RemoveMembership'; Account = $member.Name; Member = $member.SID
                    Group = $group.Name; GroupIdentity = $group.Identity
                }
            }
        }
    }
}

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

function Invoke-AccountCleanup {
    param([object[]]$Users, [string]$Action, [bool]$DomainController)
    foreach ($user in $Users) {
        # Defense in depth: callers cannot submit protected accounts for deletion.
        if ($user.Category -ne 'Other' -or $user.SID -match '-500$' -or $user.IsKerberos) { continue }
        try {
            # Windows reserves these accounts; disable instead of trying to delete.
            $reserved = $user.SID -match '-(501|503|504)$'
            if ($Action -eq 'Remove' -and -not $reserved) {
                if ($DomainController) {
                    Remove-ADUser -Identity $user.Identity -Server $script:AccountServer -Confirm:$false -ErrorAction Stop
                } else {
                    Remove-LocalUser -SID $user.SID -Confirm:$false -ErrorAction Stop
                }
                Write-Log "Removed account: $($user.Name)" 'SUCCESS'
            } elseif ($Action -eq 'Disable' -or ($Action -eq 'Remove' -and $reserved)) {
                if (-not $user.Enabled) { continue }
                if ($DomainController) {
                    Disable-ADAccount -Identity $user.Identity -Server $script:AccountServer -ErrorAction Stop
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

function Save-AccountInventory {
    param($Inventory, [string]$Path)
    $Inventory | Export-Clixml -Path "$Path.xml" -ErrorAction Stop
    $Inventory.Users | Select-Object Name, SID, Enabled, Category, LastLogon, PasswordLastSet,
        PrimaryGroupID, @{ N = 'MemberOf'; E = { $_.MemberOf -join '; ' } } |
        Export-Csv -Path "$Path.csv" -NoTypeInformation -ErrorAction Stop
}

function Invoke-AccountReview {
    param(
        [bool]$DomainController, [string]$CurrentSid, [string]$ReportDirectory
    )
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

    $plan = @(Get-GroupCleanupPlan $inventory $DomainController $administratorSid $defaultGroupSid)
    $reportPrefix = Join-Path $ReportDirectory "accounts-$(Get-Date -Format yyyyMMdd-HHmmss-fff)"
    # All reports must save successfully before any mutation.
    Save-AccountInventory $inventory "$reportPrefix-before"
    $plan | Export-Csv -Path "$reportPrefix-group-plan.csv" -NoTypeInformation -ErrorAction Stop
    Write-Log "Account inventory and group plan saved: $reportPrefix*"
    if ($plan.Count) { $plan | Format-Table Action, Account, Group -AutoSize | Out-String | Write-Host }
    Write-Log "Planned group changes: $($plan.Count)."
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
    $remaining = @(Get-GroupCleanupPlan $afterGroups $DomainController $administratorSid $defaultGroupSid)
    $remaining | Export-Csv -Path "$reportPrefix-groups-remaining.csv" -NoTypeInformation -ErrorAction Stop
    Save-AccountInventory $afterGroups "$reportPrefix-after-groups"
    if ($failures -or $remaining.Count) {
        throw "Group cleanup incomplete ($failures failures; $($remaining.Count) remaining changes). Account disablement/deletion skipped. See $reportPrefix*."
    }
    Write-Log 'Verified: reviewed users have only their default Users group; Administrator memberships were retained.' 'SUCCESS'
    Invoke-AccountCleanup -Users $candidates -Action $Action -DomainController $DomainController
    Save-AccountInventory (Get-AccountInventory -DomainController $DomainController) "$reportPrefix-after"
    Write-Log "Account review finished. Reports: $reportPrefix*"
}

# -----------------------------------------------------------------------------
# Select one of the two competition hosts, then validate the account database.
# -----------------------------------------------------------------------------
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
     | ,      ,_ `\_/~\-           |   made for MWCCDC 2026-27' invitationals   |
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
            # MSSQL host local account
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
# 3. Disable unneeded base services; check and optionally repair essential services
# -----------------------------------------------------------------------------
# Only target genuine base services known for security issues/unneeded attack surface.
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
if ($serverConfiguration.Profile -eq 'AD-DNS') {
    Write-Log "AD-DNS profile: enabling and securing WinRM for PowerShell remoting..." "INFO"
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
    Write-Log "MSSQL profile: disabling WinRM..." "INFO"
    try {
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "WinRM disabled on MSSQL." "SUCCESS"
    } catch {
        Write-Log "Error disabling WinRM: $_" "WARN"
    }
}

# -----------------------------------------------------------------------------
# 6. Firewall rules by host role
# -----------------------------------------------------------------------------
Write-Log "Configuring Windows Firewall..." "INFO"
try {
    $firewallReportPrefix = Join-Path $LogsDir "firewall-$(Get-Date -Format yyyyMMdd-HHmmss-fff)"
    $beforeFirewall = @(Get-FirewallAuditInventory)
    Save-FirewallAuditInventory $beforeFirewall "$firewallReportPrefix-before"
    $fwBackup = Join-Path $BackupDir "firewall-rules-$(Get-Date -Format yyyyMMdd-HHmmss-fff).wfw"
    Save-FirewallPolicyBackup $fwBackup
    if ($serverConfiguration.EnableDhcp) {
        $aliases = @(Get-InternalFirewallInterfaces)
        if (-not $aliases.Count) { throw 'DHCP enabled but no interface is addressed in 172.20.240.0/24. Firewall changes skipped.' }
        $serverConfiguration | Add-Member -NotePropertyName InternalInterfaceAliases -NotePropertyValue $aliases -Force
    }
    $firewallRules = @(Get-ServerFirewallRules $serverConfiguration)
    Write-Log 'Internal management sources: 172.20.240.0/24. Scored endpoints retain public source access.'
    $firewallRules | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Protocol = $_.Protocol; Ports = $_.LocalPort; Sources = $_.RemoteAddress; Scope = $_.Scope } } |
        Export-Csv -LiteralPath "$firewallReportPrefix-profile-plan.csv" -NoTypeInformation -ErrorAction Stop

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

    # Remove only this script's obsolete allowances, including legacy role rules.
    $managedRuleNames = @(
        'CCDC-ICMP-In', 'CCDC-NTP-In', 'CCDC-DHCP-In', 'CCDC-DHCP-Bootstrap-In', 'CCDC-DNS-UDP-In', 'CCDC-DNS-TCP-In',
        'CCDC-WinRM-HTTP-In', 'CCDC-WinRM-HTTPS-In', 'CCDC-AD-Kerberos-TCP', 'CCDC-AD-Kerberos-UDP',
        'CCDC-AD-LDAP-TCP', 'CCDC-AD-LDAP-UDP', 'CCDC-AD-ADWS-TCP', 'CCDC-AD-SMB-TCP',
        'CCDC-AD-RPC-EPMAP', 'CCDC-AD-RPC-Dynamic', 'CCDC-ADCS-RPC-In', 'CCDC-ADCS-Web-In',
        'CCDC-SMB-TCP-In', 'CCDC-MSSQL-TCP-In', 'CCDC-MSSQL-UDP-In', 'CCDC-RDP-TCP-In', 'CCDC-RDP-UDP-In'
    )
    foreach ($ruleName in @($managedRuleNames | Where-Object { $_ -notin @($firewallRules.Name) })) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    }

    foreach ($r in $firewallRules) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        $params = @{
            Name        = $r.Name
            DisplayName = $r.Name
            Direction   = "Inbound"
            Action      = "Allow"
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
        Write-Log "Firewall allowed inbound: $($r.Name); sources $($r.RemoteAddress); $($r.Scope)." 'SUCCESS'
    }
    Invoke-OldFirewallRuleReview -Inventory $beforeFirewall -PlannedRules $firewallRules -ManagedNames $managedRuleNames -ReportPrefix $firewallReportPrefix -BackupPath $fwBackup
    $afterFirewall = @(Get-FirewallAuditInventory)
    Save-FirewallAuditInventory $afterFirewall "$firewallReportPrefix-after"
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
# 7. Rotate Kerberos (krbtgt) Password - STAGE 2 (AD DC Only)
# -----------------------------------------------------------------------------
# Rotating krbtgt twice purges Golden Ticket historical keys
Reset-KrbtgtAccount -Stage 2

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
# 11. Download shed-installs.ps1 to C:\Tools (does not execute it)
# -----------------------------------------------------------------------------
try {
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

if ($script:HardeningIssues) {
    Write-Log "Hardening finished with $script:HardeningIssues warning/error message(s). Review the transcript: $script:LogFile" 'WARN'
} else {
    Write-Log "Hardening finished. Transcript: $script:LogFile" 'SUCCESS'
}
try { Stop-Transcript | Out-Null } catch {}
Read-Host 'Press Enter to exit'
