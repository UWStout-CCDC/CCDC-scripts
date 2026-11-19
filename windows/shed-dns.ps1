#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Interactive DNS checks and recovery for the AD-DNS competition server.
.DESCRIPTION
Run without arguments. Audit runs first; Enter at the action menu finishes.
Enter the AD DNS domain and internal IPv4 network. A locally verified AD domain
is offered at the prompt. The network determines the suggested addresses and
reverse zone. Supported prefixes are /8, /16 and /24 (one whole reverse zone).
The host table is editable. The actual DC hostname is also maintained and preferred
as its PTR target when ad-dns is an alias.

Repair creates missing secure AD-integrated zones and fixes managed A/PTR data.
Rebuild recreates those same managed records after typed confirmation. Unrelated
records in the selected domain/reverse/AD locator zones are audited and can be
removed. AD/DNS essentials, related mail MX records, and explicit exceptions stay.
Other zones and the AD forest are retained.
AD service records are re-registered through Netlogon, not fabricated.
.NOTES
FLOW: private workspace -> configuration -> audit -> optional recovery -> audit.
Recovery starts DNS-related services; verifies local AD; saves a verified snapshot;
shows a plan; then requires confirmation before zone/record/network changes.
Client DNS/listener repairs and optional forwarders are explicitly selected.

C:\Tools\logs\dns-<run> holds checks, plans, transcripts and action events.
C:\Tools\backups\dns-<run> holds CLIXML configuration/record snapshots and hashes.
Snapshots are data for manual recovery, not an AD system-state/record ACL backup.
Failed managed-record changes attempt to restore that node's original data/TTL.
Unrelated removals remain recorded in the snapshots/audit for manual recovery.
Earlier successful changes are not automatically rolled back.

This first version does not delete zones, recreate forests, reinstall AD DS,
change firewall rules, or reset all DNS settings. Use shed-hardening for firewall
policy. AD registration is asynchronous: retry audit and test from another host.
.EXAMPLE
.\shed-dns.ps1
#>
if ($args.Count) { throw 'Run .\shed-dns.ps1 without arguments and answer the prompts.' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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


# Log each decision and observed result; a requested change is not verification.
function Write-DnsLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level='INFO')
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor (@{INFO='Cyan';WARN='Yellow';ERROR='Red';SUCCESS='Green'}[$Level])
}
function Read-DnsChoice {
    param([string]$Prompt,[string[]]$Choices,[string]$Default)
    while ($true) {
        $value=(Read-Host $Prompt).Trim()
        if (-not $value) { $value=$Default }
        if ($value -in $Choices) { return $value }
        Write-Host "Enter one of: $($Choices -join ', ')."
    }
}
# Exclude apex, wildcard, and underscore-prefixed AD service names from edits.
function Test-DnsHostLabel {
    param([string]$Name)
    $Name.Length -le 63 -and $Name -match '^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
}
function Get-DnsDomainInput {
    param([string]$DomainName,$Context)
    $domain=$DomainName.Trim().TrimEnd('.').ToLowerInvariant()
    if ($domain.Length -gt 253 -or $domain -notmatch '\.' -or @($domain.Split('.') | Where-Object { -not (Test-DnsHostLabel $_) }).Count) { throw 'Enter a fully qualified DNS domain name.' }
    if ($Context.Verified -and $domain -ne $Context.DomainName) { throw "This DC belongs to $($Context.DomainName). Enter that domain to check or repair it." }
    $domain
}

# An octet boundary gives a single unambiguous in-addr.arpa zone.
function Get-DnsRecoveryNetwork {
    param([string]$NetworkId)
    if ($NetworkId.Trim() -notmatch '^([^/]+)/(8|16|24)$') {throw 'Enter the IPv4 network address followed by /8, /16 or /24.'}
    $base=$Matches[1]
    $prefix=[int]$Matches[2]
    $ip=$null
    if (-not [ipaddress]::TryParse($base,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -cne $base) {throw 'Enter a dotted-decimal IPv4 network address.'}
    $octets=$ip.GetAddressBytes()
    $count=[int]($prefix / 8)
    if (@($octets[$count..3] | Where-Object {$_ -ne 0}).Count) {throw "Host bits must be zero in a /$prefix network address."}
    $networkOctets=$octets[0..($count-1)]
    $reverseOctets=$octets[($count-1)..0]
    [PSCustomObject]@{
        NetworkId="$base/$prefix"
        AddressPrefix=($networkOctets -join '.') + '.'
        BaseAddress=$base
        BroadcastAddress=(@($networkOctets) + (@(255) * (4-$count))) -join '.'
        ReverseZone=($reverseOctets -join '.') + '.in-addr.arpa'
        NetworkOctets=$count
    }
}
function Test-DnsCompetitionAddress {
    param([string]$Address,$Network)
    $ip=$null
    [ipaddress]::TryParse($Address,[ref]$ip) -and $ip.AddressFamily -eq 'InterNetwork' -and
        $ip.ToString() -ceq $Address -and $Address.StartsWith($Network.AddressPrefix) -and
        $Address -notin @($Network.BaseAddress,$Network.BroadcastAddress)
}
# Local ADWS avoids discovering a DC through DNS that may be broken.
function Get-DnsDomainContext {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain=Get-ADDomain -Server localhost -ErrorAction Stop
    $forest=Get-ADForest -Server localhost -ErrorAction Stop
    $dc=Get-ADDomainController -Identity $env:COMPUTERNAME -Server localhost -ErrorAction Stop
    if ($dc.IsReadOnly) { throw 'A writable DC is required.' }
    $root=Get-ADRootDSE -Server localhost -ErrorAction Stop
    $servers=@(Get-ADObject -Server localhost -SearchBase "CN=Sites,$($root.configurationNamingContext)" -LDAPFilter '(objectClass=server)' -Properties dNSHostName -ErrorAction Stop)
    $controllers=@(@($servers | ForEach-Object {$_.dNSHostName} | Where-Object {$_} | ForEach-Object {$_.ToLowerInvariant()}) + $dc.HostName.ToLowerInvariant() | Sort-Object -Unique)
    [PSCustomObject]@{DomainName=$domain.DNSRoot.ToLowerInvariant();ForestName=$forest.Name.ToLowerInvariant();HostName=$dc.HostName.ToLowerInvariant();ControllerNames=$controllers;Verified=$true}
}
# Keep one PTR per address; the DC's canonical hostname wins over its alias.
function New-DnsRecoveryConfiguration {
    param([string]$DomainName,[object[]]$Records,$Context,$Network)
    $domain=Get-DnsDomainInput $DomainName $Context
    $names=@{}
    foreach ($record in $Records) {
        $name=$record.Name.Trim().ToLowerInvariant()
        if (-not (Test-DnsHostLabel $name) -or -not (Test-DnsCompetitionAddress $record.IPAddress $Network)) { throw "Invalid hostname or address for $($Network.NetworkId): $name $($record.IPAddress)" }
        if ($names.ContainsKey($name)) { throw "Duplicate hostname: $name" }
        $names[$name]=[PSCustomObject]@{Name=$name;IPAddress=$record.IPAddress;Canonical=$false}
    }
    if (-not $names.ContainsKey('ad-dns')) { throw 'Keep the reserved ad-dns entry identifying this server.' }
    $address=$names['ad-dns'].IPAddress
    $hostName=($Context.HostName -split '\.')[0].ToLowerInvariant()
    if (-not (Test-DnsHostLabel $hostName)) { throw 'Cannot identify the local DC hostname.' }
    if ($names.ContainsKey($hostName) -and $names[$hostName].IPAddress -ne $address) { throw "DC hostname '$hostName' conflicts with another planned host." }
    $names[$hostName]=[PSCustomObject]@{Name=$hostName;IPAddress=$address;Canonical=$true}
    $forward=@($names.Values | Sort-Object Name)
    $reverse=@(foreach ($group in @($forward | Group-Object IPAddress)) {
        $target=@($group.Group | Sort-Object @{Expression='Canonical';Descending=$true},Name)[0]
        $ptrName=($group.Name.Split('.')[3..$Network.NetworkOctets]) -join '.'
        [PSCustomObject]@{Name=$ptrName;IPAddress=$group.Name;Target="$($target.Name).$domain."}
    })
    [PSCustomObject]@{DomainName=$domain;ForestName=$Context.ForestName;HostName="$hostName.$domain";ControllerNames=@($Context.ControllerNames);ContextVerified=$Context.Verified;ExtraRetainedNames=@();ServerAddress=$address;NetworkId=$Network.NetworkId;ReverseZone=$Network.ReverseZone;Records=$forward;PtrRecords=$reverse}
}
function Read-DnsRecoveryConfiguration {
    param($Context)
    $prompt=if ($Context.Verified) {"AD DNS domain (Enter = $($Context.DomainName), verified locally)"} else {'AD DNS domain (required)'}
    while ($true) {
        $answer=(Read-Host $prompt).Trim()
        if (-not $answer -and $Context.Verified) {$answer=$Context.DomainName}
        try {$domain=Get-DnsDomainInput $answer $Context;break} catch {Write-Warning $_}
    }
    while ($true) {
        $answer=Read-Host 'Internal IPv4 network in CIDR notation (/8, /16 or /24, e.g. 192.168.50.0/24)'
        try {$network=Get-DnsRecoveryNetwork $answer;break} catch {Write-Warning $_}
    }
    Write-Host "Domain $domain | Network $($network.NetworkId) | Reverse zone $($network.ReverseZone)"
    $offsets=[ordered]@{ecomm=10;mail=15;splunk=20;'ad-dns'=100;mssql=120;vyos=254}
    $records=@(foreach ($entry in $offsets.GetEnumerator()) {
        [PSCustomObject]@{Name=$entry.Key;IPAddress=($network.BaseAddress -replace '0$', [string]$entry.Value)}
    })
    $records | Format-Table Name,IPAddress -AutoSize | Out-String | Write-Host
    if ((Read-DnsChoice '[K] Keep table, [E] Edit names/IPs (default K)' @('K','E') 'K') -eq 'E') {
        foreach ($record in $records) {
            if ($record.Name -ne 'ad-dns') {
                $value=Read-Host "Hostname for $($record.Name) (Enter keeps it)"
                if ($value) {$record.Name=$value}
            }
            $value=Read-Host "IPv4 for $($record.Name) (Enter = $($record.IPAddress))"
            if ($value) {$record.IPAddress=$value}
        }
    }
    New-DnsRecoveryConfiguration $domain $records $Context $network
}
# Read all zone data, services, and client/server settings. Any failed read keeps
# Complete false, so a partial inventory cannot authorize destructive record work.
function Get-DnsRecoverySnapshot {
    $errors=[Collections.Generic.List[string]]::new()
    $services=@(foreach ($name in @('DNS','NTDS','Netlogon','Kdc','Dnscache','ADWS')) {
        try {
            $service=Get-Service -Name $name -ErrorAction Stop
            [PSCustomObject]@{Name=$name;Status=[string]$service.Status;StartType=[string]$service.StartType}
        } catch {
            $errors.Add(('Service {0}: {1}' -f $name,$_))
            [PSCustomObject]@{Name=$name;Status='Unavailable';StartType='Unknown'}
        }
    })
    $zones=@();$items=[Collections.Generic.List[object]]::new();$settings=$null;$forwarders=$null
    try {
        $zones=@(Get-DnsServerZone -ComputerName localhost -ErrorAction Stop)
        foreach ($zone in $zones) {
            if ($zone.ZoneType -eq 'Cache' -or $zone.ZoneName -eq 'TrustAnchors') {continue}
            try {$items.Add([PSCustomObject]@{ZoneName=$zone.ZoneName;Records=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.ZoneName -ErrorAction Stop)})}
            catch {$errors.Add("Record inventory failed for $($zone.ZoneName): $_")}
        }
        $settings=Get-DnsServerSetting -ComputerName localhost -All -ErrorAction Stop
        $forwarders=Get-DnsServerForwarder -ComputerName localhost -ErrorAction Stop
    } catch {$errors.Add("DNS server inventory failed: $_")}
    $addresses=@();$resolvers=@()
    try {
        $addresses=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
        $resolvers=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)
    } catch {$errors.Add("Network inventory failed: $_")}
    [PSCustomObject]@{CapturedAtUtc=[datetime]::UtcNow;Complete=($errors.Count -eq 0);Errors=$errors.ToArray();Services=$services;Zones=$zones;ZoneRecords=$items.ToArray();Settings=$settings;Forwarders=$forwarders;Addresses=$addresses;Resolvers=$resolvers}
}
function Save-DnsRecoverySnapshot {
    param($Snapshot,[string]$Directory,[string]$Label)
    $path=Join-Path $Directory "$Label-$([guid]::NewGuid().ToString('N')).xml"
    $Snapshot | Export-Clixml -LiteralPath $path -Depth 12 -ErrorAction Stop
    $readBack=Import-Clixml -LiteralPath $path -ErrorAction Stop
    if (@($readBack.Zones).Count -ne @($Snapshot.Zones).Count -or @($readBack.ZoneRecords).Count -ne @($Snapshot.ZoneRecords).Count -or
        @($readBack.ZoneRecords | ForEach-Object {$_.Records}).Count -ne @($Snapshot.ZoneRecords | ForEach-Object {$_.Records}).Count) {throw 'Snapshot read-back failed.'}
    $manifest=[PSCustomObject]@{File=$path;Complete=$Snapshot.Complete;CapturedAtUtc=$Snapshot.CapturedAtUtc;Errors=$Snapshot.Errors;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$path.json" -Encoding UTF8 -ErrorAction Stop
    $manifest
}
# Normalize the three managed types without serializing unstable CIM metadata.
function Get-DnsRecordValue {
    param($Record)
    switch ([string]$Record.RecordType) {
        'A' {[string]$Record.RecordData.IPv4Address}
        'PTR' {([string]$Record.RecordData.PtrDomainName).TrimEnd('.').ToLowerInvariant()+'.'}
        'CNAME' {([string]$Record.RecordData.HostNameAlias).TrimEnd('.').ToLowerInvariant()+'.'}
        'AAAA' {[string]$Record.RecordData.IPv6Address}
        'NS' {[string]$Record.RecordData.NameServer}
        'MX' {"$($Record.RecordData.Preference) $($Record.RecordData.MailExchange)"}
        'SRV' {"$($Record.RecordData.DomainName):$($Record.RecordData.Port)"}
        'TXT' {@($Record.RecordData.DescriptiveText) -join ' | '}
        'SOA' {[string]$Record.RecordData.PrimaryServer}
        default {[string]$Record.RecordType}
    }
}
function Get-DnsNodeFingerprint {
    param([object[]]$Records)
    @($Records | ForEach-Object {"$($_.RecordType)|$(Get-DnsRecordValue $_)|$($_.TimeToLive.TotalSeconds)"} | Sort-Object) -join ';'
}
# The entire deletion/replacement scope is carried in the plan and shown before confirmation.
function Get-DnsManagedRecordPlan {
    param($Snapshot,$Configuration,[bool]$Rebuild=$false)
    $targets=@(
        foreach ($record in $Configuration.Records) {[PSCustomObject]@{Zone=$Configuration.DomainName;Name=$record.Name;Type='A';Expected=$record.IPAddress}}
        foreach ($record in $Configuration.PtrRecords) {[PSCustomObject]@{Zone=$Configuration.ReverseZone;Name=$record.Name;Type='PTR';Expected=$record.Target}}
    )
    foreach ($target in $targets) {
        $types=if ($target.Type -eq 'A') {@('A','CNAME')} else {@('PTR')}
        $original=@($Snapshot.ZoneRecords | Where-Object ZoneName -EQ $target.Zone | ForEach-Object {$_.Records} | Where-Object {$_.HostName -eq $target.Name -and $_.RecordType -in $types})
        $matching=@($original | Where-Object {$_.RecordType -eq $target.Type -and (Get-DnsRecordValue $_) -eq $target.Expected})
        $action=if (-not $original.Count) {'Add'} elseif ($Rebuild) {'Rebuild'} elseif ($matching.Count -eq $original.Count) {'Keep'} else {'Repair'}
        [PSCustomObject]@{Action=$action;Zone=$target.Zone;Name=$target.Name;Type=$target.Type;Expected=$target.Expected;Existing=(@($original | ForEach-Object {"$($_.RecordType):$(Get-DnsRecordValue $_)"}) -join ', ');Fingerprint=(Get-DnsNodeFingerprint $original);Original=$original}
    }
}
# Restore only records removed by this operation. This preserves data/TTL, not
# original AD record ownership, security descriptors, or dynamic timestamps.
function Restore-DnsRemovedRecords {
    param($Change,[object[]]$Removed)
    foreach ($record in $Removed) {
        Add-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -InputObject $record -Force -ErrorAction Stop
    }
}
# Fresh read + Prepared manifest precede changes. Never remove an entire node/zone.
function Invoke-DnsManagedRecordChange {
    param($Change,[string]$ActionsPath)
    if ($Change.Action -eq 'Keep') {return}
    $validName=switch ($Change.Type) {
        'A' {Test-DnsHostLabel $Change.Name}
        'PTR' {$Change.Name -match '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){0,2}$' -and
            -not @($Change.Name.Split('.') | Where-Object {[int]$_ -gt 255}).Count}
    }
    if (-not $validName -or $Change.Action -notin @('Add','Repair','Rebuild')) {throw 'Unsafe DNS record operation.'}
    $types=if ($Change.Type -eq 'A') {@('A','CNAME')} else {@('PTR')}
    $live=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $Change.Name -and $_.RecordType -in $types})
    if ((Get-DnsNodeFingerprint $live) -cne $Change.Fingerprint) {throw "DNS node changed since preview: $($Change.Name).$($Change.Zone)"}
    [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Change=$Change} | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
    $removed=[Collections.Generic.List[object]]::new();$added=$false
    try {
        foreach ($record in $live) {
            if ($Change.Action -eq 'Rebuild' -or $record.RecordType -eq 'CNAME') {
                Remove-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -InputObject $record -Force -ErrorAction Stop
                $removed.Add($record)
            }
        }
        $correct=@($live | Where-Object {$_ -notin $removed -and $_.RecordType -eq $Change.Type -and (Get-DnsRecordValue $_) -eq $Change.Expected})
        if (-not $correct.Count) {
            if ($Change.Type -eq 'A') {Add-DnsServerResourceRecordA -ComputerName localhost -ZoneName $Change.Zone -Name $Change.Name -IPv4Address $Change.Expected -TimeToLive ([timespan]::FromHours(1)) -ErrorAction Stop}
            else {Add-DnsServerResourceRecordPtr -ComputerName localhost -ZoneName $Change.Zone -Name $Change.Name -PtrDomainName $Change.Expected -TimeToLive ([timespan]::FromHours(1)) -ErrorAction Stop}
            $added=$true
        }
        $verified=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $Change.Name -and $_.RecordType -eq $Change.Type -and (Get-DnsRecordValue $_) -eq $Change.Expected})
        if (-not $verified.Count) {throw 'New record was not observed; stale values were retained.'}
        foreach ($record in $live) {
            if ($record -notin $removed -and (Get-DnsRecordValue $record) -ne $Change.Expected) {
                Remove-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -InputObject $record -Force -ErrorAction Stop
                $removed.Add($record)
            }
        }
        $final=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $Change.Name -and $_.RecordType -in $types})
        if ($final.Count -ne 1 -or (Get-DnsRecordValue $final[0]) -ne $Change.Expected) {throw 'DNS node still differs from the plan.'}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Zone=$Change.Zone;Name=$Change.Name;Expected=$Change.Expected} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        Write-DnsLog "$($Change.Action) verified: $($Change.Name).$($Change.Zone) -> $($Change.Expected)" SUCCESS
    } catch {
        $failure=$_.Exception.Message
        try {
            if ($added) {
                foreach ($record in @(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $Change.Name -and $_.RecordType -eq $Change.Type -and (Get-DnsRecordValue $_) -eq $Change.Expected})) {
                    Remove-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -InputObject $record -Force -ErrorAction Stop
                }
            }
            Restore-DnsRemovedRecords $Change $removed.ToArray()
            $restored=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Change.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $Change.Name -and $_.RecordType -in $types})
            if ((Get-DnsNodeFingerprint $restored) -cne $Change.Fingerprint) {throw 'Restored data/TTL did not match baseline.'}
            $recovery='Original record data/TTL restored; ACLs/timestamps were not restored.'
        } catch {$recovery="Manual recovery needed: $($_.Exception.Message)"}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Failed';Zone=$Change.Zone;Name=$Change.Name;Error=$failure;Recovery=$recovery} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        throw "$failure $recovery"
    }
}

# Include resource-data fields so a changed record cannot be deleted from stale evidence.
function Get-DnsFullRecordFingerprint {
    param($Record)
    $fields=[ordered]@{}
    $properties=if ($Record.RecordData.CimInstanceProperties) {$Record.RecordData.CimInstanceProperties} else {$Record.RecordData.PSObject.Properties}
    foreach ($property in @($properties | Sort-Object Name)) {
        if ($property.Name -like 'Cim*' -or $property.Name -like 'PS*') {continue}
        $fields[$property.Name]=@($property.Value | ForEach-Object {[string]$_})
    }
    [ordered]@{Name=$Record.HostName;Type=[string]$Record.RecordType;TTL=$Record.TimeToLive.TotalSeconds;Data=$fields} | ConvertTo-Json -Depth 8 -Compress
}
# Relatedness is based on configured hosts, forest DC identities from local AD,
# required locator namespaces/ports, DNS authority/crypto data, and related MX.
# A removal candidate is outside this allowlist; that does not prove it malicious.
function Get-DnsRecordDisposition {
    param($Record,[string]$Zone,$Configuration)
    $scope=@($Configuration.DomainName,$Configuration.ReverseZone)
    if ($Configuration.ForestName -eq $Configuration.DomainName) {$scope += "_msdcs.$($Configuration.ForestName)"}
    $name=([string]$Record.HostName).ToLowerInvariant();$type=[string]$Record.RecordType
    $action='Remove';$reason='Outside configured hosts and required DNS/AD records'
    $controllers=@(@($Configuration.ControllerNames) + @($Configuration.HostName,"ad-dns.$($Configuration.DomainName)"))
    $fqdn=if($name -in @('@','.')){$Zone}else{"$name.$Zone"}
    if ($Zone -notin $scope) {$action='Audit only';$reason='Outside selected recovery zones'}
    elseif (-not $Configuration.ContextVerified) {$action='Audit only';$reason='AD metadata must be verified before classification/removal'}
    elseif ($name -in $Configuration.ExtraRetainedNames -or $fqdn -in $Configuration.ExtraRetainedNames) {$action='Keep';$reason='Explicit operator exception'}
    elseif ($type -in @('SOA','DNSKEY','RRSIG','NSEC','NSEC3','NSEC3PARAM','DS','SIG','KEY')) {$action='Keep';$reason='DNS authority or DNSSEC infrastructure'}
    elseif ($type -eq 'NS' -and ([string]$Record.RecordData.NameServer).TrimEnd('.') -in $controllers) {$action='Keep';$reason='AD/DNS nameserver'}
    elseif ($Zone -eq $Configuration.DomainName -and $name -in @($Configuration.Records.Name) -and $type -in @('A','CNAME')) {$action='Keep';$reason='Managed host; record repair/rebuild handles its data'}
    elseif ($Zone -eq $Configuration.ReverseZone -and $name -in @($Configuration.PtrRecords.Name) -and $type -eq 'PTR') {$action='Keep';$reason='Managed reverse lookup'}
    elseif ($type -in @('A','AAAA') -and ($fqdn -in $controllers -or ($Zone -eq $Configuration.DomainName -and $name -in @('@','.','domaindnszones','forestdnszones','gc._msdcs')) -or ($Zone -like '_msdcs.*' -and $name -eq 'gc'))) {$action='Keep';$reason='AD controller/directory locator address'}
    elseif ($type -eq 'PTR' -and ([string]$Record.RecordData.PtrDomainName).TrimEnd('.') -in $controllers) {$action='Keep';$reason='AD controller reverse lookup'}
    elseif ($type -eq 'CNAME' -and $name -match '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}(\._msdcs)?$' -and ([string]$Record.RecordData.HostNameAlias).TrimEnd('.') -in $controllers) {$action='Keep';$reason='AD replication GUID alias'}
    elseif ($type -eq 'SRV' -and $name -match '^_(ldap|kerberos|kpasswd|gc)\._(tcp|udp)(\.|$)' -and ([string]$Record.RecordData.DomainName).TrimEnd('.') -in $controllers) {
        $service=$Matches[1];$protocol=$Matches[2]
        $port=switch ($service) {'ldap' {if($name -match '(^|\.)gc(\.|$)'){3268}else{389}} 'kerberos' {88} 'kpasswd' {464} 'gc' {3268}}
        $validProtocol=$protocol -eq 'tcp' -or $service -in @('kerberos','kpasswd')
        if ([int]$Record.RecordData.Port -eq $port -and $validProtocol) {$action='Keep';$reason='AD locator SRV with a verified DC target/port'}
    }
    elseif ($Zone -eq $Configuration.DomainName -and $type -eq 'MX' -and ([string]$Record.RecordData.MailExchange).TrimEnd('.') -in @($Configuration.Records | ForEach-Object {"$($_.Name).$($Configuration.DomainName)"})) {$action='Keep';$reason='Mail routing to a configured host'}
    [PSCustomObject]@{Action=$action;Reason=$reason}
}
# Export retained records too; CSV is readable, CLIXML preserves the full records.
function Get-DnsUnrelatedRecordPlan {
    param($Snapshot,$Configuration)
    foreach ($zone in $Snapshot.ZoneRecords) {
        foreach ($record in $zone.Records) {
            $decision=Get-DnsRecordDisposition $record $zone.ZoneName $Configuration
            [PSCustomObject]@{Action=$decision.Action;Zone=$zone.ZoneName;Name=$record.HostName;Type=[string]$record.RecordType;Value=(Get-DnsRecordValue $record);Reason=$decision.Reason;Data=(Get-DnsFullRecordFingerprint $record);Original=$record}
        }
    }
}
# Exact data/TTL matching permits deletion only of the record that was previewed.
# New or changed records require another audit rather than being swept up.
function Invoke-DnsUnrelatedRecordRemoval {
    param([object[]]$Plan,[string]$ActionsPath)
    foreach ($row in @($Plan | Where-Object Action -EQ Remove)) {
        $live=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $row.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $row.Name -and $_.RecordType -eq $row.Type -and (Get-DnsFullRecordFingerprint $_) -ceq $row.Data})
        if ($live.Count -ne 1) {throw "Removal target changed/ambiguous: $($row.Name).$($row.Zone) $($row.Type)"}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Kind='UnrelatedRecordRemoval';Record=$row} | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        try {
            Remove-DnsServerResourceRecord -ComputerName localhost -ZoneName $row.Zone -InputObject $live[0] -Force -ErrorAction Stop
            $remaining=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $row.Zone -ErrorAction Stop | Where-Object {$_.HostName -eq $row.Name -and $_.RecordType -eq $row.Type -and (Get-DnsFullRecordFingerprint $_) -ceq $row.Data})
            if ($remaining.Count) {throw 'Removed record still exists.'}
            [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Kind='UnrelatedRecordRemoval';Zone=$row.Zone;Name=$row.Name;Type=$row.Type;Data=$row.Data} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
            Write-DnsLog "Removed audited unrelated record: $($row.Name).$($row.Zone) $($row.Type)" SUCCESS
        } catch {
            [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Failed';Kind='UnrelatedRecordRemoval';Zone=$row.Zone;Name=$row.Name;Type=$row.Type;Error=$_.Exception.Message} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
            throw
        }
    }
}
# Ensure a legitimate apex NS exists before removing unknown nameservers.
# SOA stays essential; its complete content is preserved in the audit.
function Ensure-DnsAuthorityNameserver {
    param($ZonePlan,$Configuration,[string]$ActionsPath)
    foreach ($zone in $ZonePlan) {
        $existing=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -ErrorAction Stop | Where-Object {$_.HostName -in @('@','.') -and $_.RecordType -eq 'NS' -and ([string]$_.RecordData.NameServer).TrimEnd('.') -eq $Configuration.HostName})
        if ($existing.Count) {continue}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Kind='AuthorityNS';Zone=$zone.Zone;Target=$Configuration.HostName} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        Add-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -Name '@' -NS -NameServer ($Configuration.HostName+'.') -ErrorAction Stop
        $after=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -ErrorAction Stop | Where-Object {$_.HostName -in @('@','.') -and $_.RecordType -eq 'NS' -and ([string]$_.RecordData.NameServer).TrimEnd('.') -eq $Configuration.HostName})
        if (-not $after.Count) {throw "Nameserver read-back failed: $($zone.Zone)"}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Kind='AuthorityNS';Zone=$zone.Zone;Target=$Configuration.HostName} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
    }
}

# Keep a valid AD SOA master. Repair a poisoned/outside-AD primary without
# deleting the zone or changing its timers/contact data; verify the server's copy.
function Repair-DnsSoaMasters {
    param($ZonePlan,$Configuration,[string]$ActionsPath)
    $known=@(@($Configuration.ControllerNames) + @($Configuration.HostName,"ad-dns.$($Configuration.DomainName)"))
    foreach ($zone in $ZonePlan) {
        $records=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -ErrorAction Stop | Where-Object RecordType -EQ SOA)
        if ($records.Count -ne 1) {throw "Missing/ambiguous SOA; repair zone storage before cleanup: $($zone.Zone)"}
        $old=$records[0]
        if (([string]$old.RecordData.PrimaryServer).TrimEnd('.') -in $known) {continue}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Kind='SOAMaster';Zone=$zone.Zone;Original=$old;Target=$Configuration.HostName} | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        $updated=$old.Clone()
        $updated.RecordData.PrimaryServer=$Configuration.HostName+'.'
        Set-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -OldInputObject $old -NewInputObject $updated -ErrorAction Stop
        $after=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $zone.Zone -ErrorAction Stop | Where-Object RecordType -EQ SOA)
        if ($after.Count -ne 1 -or ([string]$after[0].RecordData.PrimaryServer).TrimEnd('.') -ne $Configuration.HostName) {throw "SOA master read-back failed: $($zone.Zone)"}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Kind='SOAMaster';Zone=$zone.Zone;Target=$Configuration.HostName} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        Write-DnsLog "SOA primary verified: $($zone.Zone) -> $($Configuration.HostName)" SUCCESS
    }
}

# A stopped DNS service prevents zone backup. Save the partial service inventory
# first, and require a separate confirmation before starting anything.
function Enable-DnsRecoveryServices {
    Import-Module ServerManager -ErrorAction Stop
    $role=Get-WindowsFeature -Name DNS -ErrorAction Stop
    if (-not $role.Installed) {
        if ((Read-Host 'DNS role is missing. Type INSTALL DNS to install it without rebooting') -cne 'INSTALL DNS') {throw 'DNS role installation canceled.'}
        $result=Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction Stop
        if (-not $result.Success) {throw 'DNS role installation did not succeed.'}
        if ($result.RestartNeeded -ne 'No') {Write-DnsLog 'Windows reports a restart may be required; this script will not reboot.' WARN}
    }
    Import-Module DnsServer -ErrorAction Stop
    foreach ($name in @('DNS','Netlogon','Kdc','Dnscache','ADWS')) {
        $service=Get-Service -Name $name -ErrorAction Stop
        if ($service.StartType -ne 'Automatic') {Set-Service -Name $name -StartupType Automatic -ErrorAction Stop}
        if ($service.Status -ne 'Running') {Start-Service -Name $name -ErrorAction Stop}
        $after=Get-Service -Name $name -ErrorAction Stop
        if ($after.Status -ne 'Running' -or $after.StartType -ne 'Automatic') {throw "Service needs attention: $name"}
        Write-DnsLog "Service verified: $name running, Automatic." SUCCESS
    }
    if ((Get-Service -Name NTDS -ErrorAction Stop).Status -ne 'Running') {throw 'AD DS is stopped. Repair AD DS before DNS zone recovery.'}
}
# Preserve embedded _msdcs layouts. Create the forest-wide zone only on a forest
# root DC when it is absent and no embedded _msdcs records already serve it.
function Get-DnsManagedZonePlan {
    param($Snapshot,$Configuration)
    $targets=@(
        [PSCustomObject]@{Zone=$Configuration.DomainName;NetworkId='';Scope='Domain'}
        [PSCustomObject]@{Zone=$Configuration.ReverseZone;NetworkId=$Configuration.NetworkId;Scope='Domain'}
    )
    $msdcs="_msdcs.$($Configuration.ForestName)"
    $embedded=@($Snapshot.ZoneRecords | Where-Object ZoneName -EQ $Configuration.DomainName | ForEach-Object {$_.Records} | Where-Object {$_.HostName -like '*._msdcs'})
    if ($Configuration.ForestName -eq $Configuration.DomainName -and
        ($msdcs -in @($Snapshot.Zones.ZoneName) -or -not $embedded.Count)) {
        $targets += [PSCustomObject]@{Zone=$msdcs;NetworkId='';Scope='Forest'}
    }
    foreach ($target in $targets) {
        $existing=@($Snapshot.Zones | Where-Object ZoneName -EQ $target.Zone)
        if ($existing.Count -gt 1) {throw "Ambiguous zone: $($target.Zone)"}
        if ($existing.Count -and ($existing[0].ZoneType -ne 'Primary' -or -not $existing[0].IsDsIntegrated -or $existing[0].IsReadOnly -or $existing[0].IsShutdown)) {
            throw "Zone $($target.Zone) is not a writable, available AD-integrated primary. Inspect its storage before recovery."
        }
        [PSCustomObject]@{Zone=$target.Zone;NetworkId=$target.NetworkId;Scope=$target.Scope;Action=$(if($existing.Count){'Ensure secure updates/unpaused'}else{'Create secure AD-integrated zone'})}
    }
}
function Invoke-DnsManagedZoneChange {
    param($Plan,[string]$ActionsPath)
    foreach ($row in $Plan) {
        $current=@(Get-DnsServerZone -ComputerName localhost -ErrorAction Stop | Where-Object ZoneName -EQ $row.Zone)
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Kind='Zone';Zone=$row.Zone;Action=$row.Action} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        if (-not $current.Count) {
            $options=@{ComputerName='localhost';ReplicationScope=$row.Scope;DynamicUpdate='Secure';ErrorAction='Stop'}
            if ($row.NetworkId) {Add-DnsServerPrimaryZone @options -NetworkId $row.NetworkId}
            else {Add-DnsServerPrimaryZone @options -Name $row.Zone}
        } else {
            if ($row.Action -eq 'Create secure AD-integrated zone') {throw "Zone appeared after preview: $($row.Zone)"}
            if ($current[0].ZoneType -ne 'Primary' -or -not $current[0].IsDsIntegrated -or $current[0].IsReadOnly -or $current[0].IsShutdown) {throw "Zone state changed: $($row.Zone)"}
            if ($current[0].IsPaused) {Resume-DnsServerZone -ComputerName localhost -Name $row.Zone -ErrorAction Stop}
            if ($current[0].DynamicUpdate -ne 'Secure') {Set-DnsServerPrimaryZone -ComputerName localhost -Name $row.Zone -DynamicUpdate Secure -ErrorAction Stop}
        }
        $after=@(Get-DnsServerZone -ComputerName localhost -ErrorAction Stop | Where-Object ZoneName -EQ $row.Zone)
        if ($after.Count -ne 1 -or -not $after[0].IsDsIntegrated -or $after[0].DynamicUpdate -ne 'Secure' -or $after[0].IsPaused) {throw "Zone read-back failed: $($row.Zone)"}
        [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Kind='Zone';Zone=$row.Zone} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
        Write-DnsLog "Zone verified: $($row.Zone), secure AD-integrated updates." SUCCESS
    }
}
# Forwarders are explicit operator input, never guessed from the router address.
function Read-DnsForwarderInput {
    param([string]$ServerAddress)
    $text=Read-Host 'Optional replacement upstream DNS IPs, comma separated (blank keeps existing forwarders)'
    if (-not $text) {return}
    foreach ($value in @($text -split ',' | ForEach-Object {$_.Trim()} | Select-Object -Unique)) {
        $ip=$null
        if (-not [Net.IPAddress]::TryParse($value,[ref]$ip) -or [Net.IPAddress]::IsLoopback($ip) -or
            $ip.ToString() -eq $ServerAddress -or ($ip.IsIPv4MappedToIPv6 -and $ip.MapToIPv4().ToString() -eq $ServerAddress)) {throw "Invalid/self-referencing upstream DNS IP: $value"}
        $v4=if($ip.IsIPv4MappedToIPv6){$ip.MapToIPv4()}else{$ip}
        if ($ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or
            ($v4.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and ($v4.GetAddressBytes()[0] -eq 0 -or $v4.GetAddressBytes()[0] -ge 224))) {throw "Upstream DNS requires a unicast address: $value"}
        $ip.ToString()
    }
}
# Only add the local DC's delegation when a separate forest-root _msdcs zone
# exists. Existing delegation targets remain available for operator review.
function Ensure-DnsMsdcsDelegation {
    param($Configuration,[string]$ActionsPath)
    if ($Configuration.ForestName -ne $Configuration.DomainName) {return}
    $msdcs="_msdcs.$($Configuration.ForestName)"
    if ($msdcs -notin @(Get-DnsServerZone -ComputerName localhost -ErrorAction Stop | Select-Object -ExpandProperty ZoneName)) {return}
    $records=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Configuration.DomainName -ErrorAction Stop)
    $delegation=@($records | Where-Object {$_.HostName -eq '_msdcs' -and $_.RecordType -eq 'NS' -and ([string]$_.RecordData.NameServer).TrimEnd('.') -eq $Configuration.HostName})
    if ($delegation.Count) {return}
    [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Prepared';Kind='Delegation';Zone=$Configuration.DomainName;Target=$Configuration.HostName} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
    Add-DnsServerZoneDelegation -ComputerName localhost -Name $Configuration.DomainName -ChildZoneName '_msdcs' -NameServer $Configuration.HostName -IPAddress $Configuration.ServerAddress -ErrorAction Stop
    $after=@(Get-DnsServerResourceRecord -ComputerName localhost -ZoneName $Configuration.DomainName -ErrorAction Stop | Where-Object {$_.HostName -eq '_msdcs' -and $_.RecordType -eq 'NS' -and ([string]$_.RecordData.NameServer).TrimEnd('.') -eq $Configuration.HostName})
    if (-not $after.Count) {throw 'The _msdcs delegation was not observed after creation.'}
    [PSCustomObject]@{TimestampUtc=[datetime]::UtcNow;Status='Completed';Kind='Delegation';Zone=$Configuration.DomainName;Target=$Configuration.HostName} | ConvertTo-Json -Compress | Add-Content -LiteralPath $ActionsPath -Encoding UTF8 -ErrorAction Stop
}
# Network changes affect only the adapter holding the configured DNS server IP.
# No IP address or gateway is changed; other adapters retain their resolvers.
function Invoke-DnsNetworkRepair {
    param($Snapshot,$Configuration,[bool]$FixClient,[bool]$FixListener,[string[]]$Forwarders)
    $adapters=@($Snapshot.Addresses | Where-Object {$_.IPAddress -eq $Configuration.ServerAddress -and $_.AddressState -eq 'Preferred'})
    if ($adapters.Count -ne 1) {throw "Assign $($Configuration.ServerAddress) to exactly one local IPv4 interface before network repair."}
    if ($FixClient) {
        $index=$adapters[0].InterfaceIndex
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @($Configuration.ServerAddress) -ErrorAction Stop
        $after=Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop
        if (@($after.ServerAddresses).Count -ne 1 -or $after.ServerAddresses[0] -ne $Configuration.ServerAddress) {throw 'Client DNS read-back failed.'}
        Write-DnsLog "Adapter $index DNS verified: $($Configuration.ServerAddress)." SUCCESS
    }
    if ($FixListener) {
        $settings=Get-DnsServerSetting -ComputerName localhost -All -ErrorAction Stop
        $list=@($settings.ListeningIPAddress | ForEach-Object {[string]$_})
        # An empty listener list means all interfaces, already including this IP.
        if ($list.Count -and $Configuration.ServerAddress -notin $list) {
            $settings.ListeningIPAddress=@($list + $Configuration.ServerAddress | Select-Object -Unique)
            Set-DnsServerSetting -ComputerName localhost -InputObject $settings -ErrorAction Stop
            Restart-Service -Name DNS -Force -ErrorAction Stop
        }
        $after=Get-DnsServerSetting -ComputerName localhost -All -ErrorAction Stop
        if (@($after.ListeningIPAddress).Count -and $Configuration.ServerAddress -notin @($after.ListeningIPAddress | ForEach-Object {[string]$_})) {throw 'DNS listener read-back failed.'}
        Write-DnsLog 'DNS listener includes the configured server IP (or all interfaces).' SUCCESS
    }
    if ($Forwarders.Count) {
        Set-DnsServerForwarder -ComputerName localhost -IPAddress $Forwarders -ErrorAction Stop
        $after=@((Get-DnsServerForwarder -ComputerName localhost -ErrorAction Stop).IPAddress | ForEach-Object {[string]$_} | Sort-Object -Unique)
        if (@(Compare-Object @($Forwarders | Sort-Object -Unique) $after).Count) {throw 'Forwarder read-back failed.'}
        Write-DnsLog "Forwarders verified: $($after -join ', ')." SUCCESS
    }
}
# Check native exits on Windows PowerShell too, and keep tool output as evidence.
function Invoke-DnsNativeTool {
    param([string]$Name,[string[]]$ArgumentList,[string]$OutputPath)
    & (Join-Path "$env:SystemRoot\System32" $Name) @ArgumentList 2>&1 | Out-File -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    if ($LASTEXITCODE -ne 0) {throw "$Name failed (exit $LASTEXITCODE); see $OutputPath"}
}
# Real answers are checked independently of stored records, through the DNS
# server IP using DNS-only lookups over default transport and explicit TCP.
function Get-DnsHealthChecks {
    param($Snapshot,$Configuration)
    foreach ($errorText in $Snapshot.Errors) {[PSCustomObject]@{Check='Inventory';Status='Needs attention';Details=$errorText}}
    foreach ($service in $Snapshot.Services) {
        [PSCustomObject]@{Check="Service $($service.Name)";Status=$(if($service.Status -eq 'Running'){'Pass'}else{'Needs attention'});Details="$($service.Status), $($service.StartType)"}
    }
    $local=@($Snapshot.Addresses | Where-Object {$_.IPAddress -eq $Configuration.ServerAddress -and $_.AddressState -eq 'Preferred'})
    [PSCustomObject]@{Check='Server IPv4';Status=$(if($local.Count -eq 1){'Pass'}else{'Needs attention'});Details=$Configuration.ServerAddress}
    foreach ($zoneName in @($Configuration.DomainName,$Configuration.ReverseZone)) {
        $zone=@($Snapshot.Zones | Where-Object ZoneName -EQ $zoneName)
        [PSCustomObject]@{Check="Zone $zoneName";Status=$(if($zone.Count -eq 1 -and $zone[0].IsDsIntegrated -and $zone[0].DynamicUpdate -eq 'Secure' -and -not $zone[0].IsPaused){'Pass'}else{'Needs attention'});Details=$(if($zone.Count){"$($zone[0].ZoneType), secure updates: $($zone[0].DynamicUpdate)"}else{'Missing'})}
        $soa=@($Snapshot.ZoneRecords | Where-Object ZoneName -EQ $zoneName | ForEach-Object {$_.Records} | Where-Object RecordType -EQ SOA)
        $masters=@($soa | ForEach-Object {([string]$_.RecordData.PrimaryServer).TrimEnd('.')})
        $known=@(@($Configuration.ControllerNames) + @($Configuration.HostName,"ad-dns.$($Configuration.DomainName)"))
        [PSCustomObject]@{Check="SOA master $zoneName";Status=$(if($masters.Count -eq 1 -and $masters[0] -in $known){'Pass'}else{'Needs attention'});Details=($masters -join ', ')}
    }
    $listeners=@($Snapshot.Settings.ListeningIPAddress | ForEach-Object {[string]$_})
    [PSCustomObject]@{Check='DNS listen addresses';Status=$(if($Snapshot.Settings -and (-not $listeners.Count -or $Configuration.ServerAddress -in $listeners)){'Pass'}else{'Needs attention'});Details=$(if($listeners.Count){$listeners -join ', '}else{'All interfaces, if server settings were readable'})}
    [PSCustomObject]@{Check='Upstream forwarding';Status='Review';Details="Configured upstream IPs: $(@($Snapshot.Forwarders.IPAddress) -join ', '); external resolution/recursion is not validated by internal-host checks."}
    foreach ($adapter in $local) {
        $resolver=@($Snapshot.Resolvers | Where-Object InterfaceIndex -EQ $adapter.InterfaceIndex)
        [PSCustomObject]@{Check="Client DNS adapter $($adapter.InterfaceIndex)";Status=$(if(@($resolver.ServerAddresses).Count -eq 1 -and $Configuration.ServerAddress -in @($resolver.ServerAddresses)){'Pass'}else{'Needs attention'});Details=(@($resolver.ServerAddresses) -join ', ')}
    }
    $queries=@(
        foreach ($record in $Configuration.Records) {[PSCustomObject]@{Name="$($record.Name).$($Configuration.DomainName)";Type='A';Expected=$record.IPAddress}}
        foreach ($record in $Configuration.PtrRecords) {[PSCustomObject]@{Name="$($record.Name).$($Configuration.ReverseZone)";Type='PTR';Expected=$record.Target}}
        [PSCustomObject]@{Name="_ldap._tcp.dc._msdcs.$($Configuration.DomainName)";Type='SRV';Expected=$Configuration.HostName+'.:389'}
        [PSCustomObject]@{Name="_kerberos._tcp.dc._msdcs.$($Configuration.DomainName)";Type='SRV';Expected=$Configuration.HostName+'.:88'}
    )
    $running=@($Snapshot.Services | Where-Object {$_.Name -eq 'DNS' -and $_.Status -eq 'Running'}).Count -eq 1
    foreach ($query in $queries) {
        Write-DnsLog "Checking $($query.Type) $($query.Name)..."
        foreach ($transport in @('Default','TCP')) {
            $status='Needs attention';$details='DNS service is not running; query skipped.'
            if ($running) {
                try {
                    $options=@{Name=$query.Name;Type=$query.Type;Server=$Configuration.ServerAddress;DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
                    if ($transport -eq 'TCP') {$options.TcpOnly=$true}
                    $answers=@(Resolve-DnsName @options)
                    $values=@(foreach ($answer in $answers) {
                        if ([string]$answer.Type -ne $query.Type) {continue}
                        switch ($query.Type) {
                            'A' {[string]$answer.IPAddress}
                            'PTR' {([string]$answer.NameHost).TrimEnd('.').ToLowerInvariant()+'.'}
                            'SRV' {([string]$answer.NameTarget).TrimEnd('.').ToLowerInvariant()+'.:'+([string]$answer.Port)}
                        }
                    })
                    $expectedPresent=$query.Expected -in $values
                    if ($expectedPresent -and ($query.Type -eq 'SRV' -or @($values | Sort-Object -Unique).Count -eq 1)) {$status='Pass'}
                    $details="Expected $($query.Expected); observed $($values -join ', ')"
                } catch {$details=$_.Exception.Message}
            }
            [PSCustomObject]@{Check="$transport $($query.Type) $($query.Name)";Status=$status;Details=$details}
        }
    }
}
# Recovery always refreshes inventory after service startup and before preview.
# Canceling either confirmation leaves the subsequent phase untouched.
function Invoke-DnsRecovery {
    param($Configuration,[string]$BackupDirectory,[string]$ReportDirectory,[bool]$Rebuild)
    $partial=Get-DnsRecoverySnapshot
    $null=Save-DnsRecoverySnapshot $partial $BackupDirectory 'before-services'
    if ((Read-Host 'Type START DNS SERVICES to enable/start DNS-related services (not AD DS); Enter cancels') -cne 'START DNS SERVICES') {return}
    Enable-DnsRecoveryServices
    $context=Get-DnsDomainContext
    if ($context.DomainName -ne $Configuration.DomainName -or ($Configuration.ContextVerified -and $context.ForestName -ne $Configuration.ForestName) -or $context.HostName -ne $Configuration.HostName) {
        throw 'Detected AD identity differs from the reviewed configuration. Restart and review the actual domain/DC name.'
    }
    $Configuration.ForestName=$context.ForestName
    $Configuration.ControllerNames=@($context.ControllerNames)
    $Configuration.ContextVerified=$true
    $before=Get-DnsRecoverySnapshot
    $backup=Save-DnsRecoverySnapshot $before $BackupDirectory 'before-records'
    if (-not $before.Complete) {throw "DNS backup inventory is incomplete; record changes blocked. $($before.Errors -join '; ')"}
    if ($before.Settings.IsReadOnlyDC) {throw 'Cannot modify DNS on a read-only DC.'}
    if (@($before.Addresses | Where-Object {$_.IPAddress -eq $Configuration.ServerAddress -and $_.AddressState -eq 'Preferred'}).Count -ne 1) {throw 'Configured DNS server IPv4 is not uniquely assigned locally. Records were not changed.'}
    $zonePlan=@(Get-DnsManagedZonePlan $before $Configuration)
    $recordPlan=@(Get-DnsManagedRecordPlan $before $Configuration $Rebuild)
    $exceptions=Read-Host 'Additional exact DNS owner names to retain (comma separated; blank = none; example selector._domainkey)'
    $Configuration.ExtraRetainedNames=@($exceptions -split ',' | ForEach-Object {$_.Trim().TrimEnd('.').ToLowerInvariant()} | Where-Object {$_} | Select-Object -Unique)
    $cleanupPlan=@(Get-DnsUnrelatedRecordPlan $before $Configuration)
    $prefix=Join-Path $ReportDirectory "plan-$([guid]::NewGuid().ToString('N'))"
    $zonePlan | Export-Csv -LiteralPath "$prefix-zones.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $recordPlan | Select-Object Action,Zone,Name,Type,Expected,Existing | Export-Csv -LiteralPath "$prefix-records.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $cleanupPlan | Select-Object Action,Zone,Name,Type,Value,Reason,Data | Export-Csv -LiteralPath "$prefix-cleanup.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $cleanupPlan | Export-Clixml -LiteralPath "$prefix-cleanup.xml" -Depth 12 -ErrorAction Stop
    $zonePlan | Format-Table Action,Zone,Scope -AutoSize | Out-String | Write-Host
    $recordPlan | Format-Table Action,Zone,Name,Type,Expected,Existing -AutoSize | Out-String | Write-Host
    $cleanupPlan | Where-Object Action -EQ Remove | Format-Table Zone,Name,Type,Value,Reason -Wrap | Out-String -Width 180 | Write-Host
    if (@($cleanupPlan | Where-Object {$_.Action -eq 'Remove' -and $_.Type -eq 'TXT'}).Count) {
        Write-DnsLog 'TXT records are listed for removal. Preserve required SPF/DKIM/DMARC owner names with explicit exceptions, or choose audit only.' WARN
    }
    Write-DnsLog "Audited unrelated records scheduled for removal: $(@($cleanupPlan | Where-Object Action -EQ Remove).Count). Full data: $prefix-cleanup.xml and .csv."
    $removeUnrelated=(Read-DnsChoice '[D] Delete the audited unrelated records, [A] Audit them only (default D)' @('D','A') 'D') -eq 'D'
    Write-DnsLog "Verified data snapshot: $($backup.File). Plans: $prefix*.csv"
    $client=(Read-DnsChoice 'Point this server IPv4 adapter DNS at itself? (Y/n)' @('Y','N') 'Y') -eq 'Y'
    $listener=(Read-DnsChoice 'Ensure the DNS listener includes this IP (may briefly restart DNS)? (Y/n)' @('Y','N') 'Y') -eq 'Y'
    $forwarders=@(Read-DnsForwarderInput $Configuration.ServerAddress)
    $phrase=if ($Rebuild) {"REBUILD DNS RECORDS $($Configuration.DomainName)"}else{"REPAIR DNS $($Configuration.DomainName)"}
    if ($removeUnrelated) {$phrase += ' AND REMOVE UNRELATED'}
    Write-DnsLog 'Managed A/PTR records will be repaired/rebuilt. Unrelated record deletion follows the displayed cleanup plan. Zones and the AD forest remain.'
    if ((Read-Host "Type $phrase to apply this plan; Enter cancels") -cne $phrase) {return}
    if ((Get-FileHash -LiteralPath $backup.File -Algorithm SHA256 -ErrorAction Stop).Hash -ne $backup.SHA256) {throw 'Snapshot changed after preview; recovery blocked.'}
    $actions=Join-Path $ReportDirectory "actions-$([guid]::NewGuid().ToString('N')).jsonl"
    $null=New-Item -ItemType File -Path $actions -ErrorAction Stop
    Invoke-DnsNetworkRepair $before $Configuration $client $listener $forwarders
    Invoke-DnsManagedZoneChange $zonePlan $actions
    foreach ($change in $recordPlan) {Invoke-DnsManagedRecordChange $change $actions}
    Ensure-DnsAuthorityNameserver $zonePlan $Configuration $actions
    Repair-DnsSoaMasters $zonePlan $Configuration $actions
    if ($removeUnrelated) {Invoke-DnsUnrelatedRecordRemoval $cleanupPlan $actions}
    Ensure-DnsMsdcsDelegation $Configuration $actions
    # Netlogon owns GUID/site/service records; do not create guessed SRV targets.
    Register-DnsClient -ErrorAction Stop
    Invoke-DnsNativeTool 'nltest.exe' @('/dsregdns') (Join-Path $ReportDirectory "registration-$([guid]::NewGuid().ToString('N')).log")
    $null=Save-DnsRecoverySnapshot (Get-DnsRecoverySnapshot) $BackupDirectory 'after'
    Write-DnsLog "Managed DNS changes finished. Registration is asynchronous; inspect the post-checks. Actions: $actions"
}

# MAIN: elevation/DC checks and private evidence directories precede read-only audit.
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Run elevated on the AD-DNS domain controller.'}
if ((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 2) {throw 'This recovery script targets the AD-DNS domain controller, not MSSQL.'}
$tools=Join-Path $env:SystemDrive 'Tools'
$run="dns-$(Get-Date -Format yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N'))"
Initialize-Directory $tools
Initialize-Directory (Join-Path $tools 'logs') -Private
Initialize-Directory (Join-Path $tools 'backups') -Private
$reports=Join-Path (Join-Path $tools 'logs') $run
$backups=Join-Path (Join-Path $tools 'backups') $run
Initialize-Directory $reports -Private
Initialize-Directory $backups -Private
Start-Transcript -LiteralPath (Join-Path $reports 'transcript.log') -ErrorAction Stop | Out-Null

# Show the shared competition splash before configuration prompts.
$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |                shed-dns.ps1                |
     | ,      ,_ `\_/~\-           |    made for MWCCDC 2026-27' qualifiers     |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black

try {
    try {$context=Get-DnsDomainContext}
    catch {
        Write-DnsLog "Local AD metadata is unavailable: $_. Audit remains available; recovery must verify AD before zone changes." WARN
        $context=[PSCustomObject]@{DomainName=$null;ForestName=$null;HostName=$env:COMPUTERNAME;ControllerNames=@();Verified=$false}
    }
    while ($true) {
        try {$configuration=Read-DnsRecoveryConfiguration $context;break}
        catch {Write-DnsLog "Configuration needs correction: $_. Enter the table again." WARN}
    }
    $configuration | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reports 'configuration.json') -Encoding UTF8 -ErrorAction Stop
    $configuration.Records | Format-Table Name,IPAddress,Canonical -AutoSize | Out-String | Write-Host
    $configuration.PtrRecords | Format-Table IPAddress,Target -AutoSize | Out-String | Write-Host
    while ($true) {
        $snapshot=Get-DnsRecoverySnapshot
        $null=Save-DnsRecoverySnapshot $snapshot $backups 'audit'
        $checks=@(Get-DnsHealthChecks $snapshot $configuration)
        $auditPlan=@(Get-DnsUnrelatedRecordPlan $snapshot $configuration)
        $auditPrefix=Join-Path $reports "record-audit-$([guid]::NewGuid().ToString('N'))"
        $auditPlan | Select-Object Action,Zone,Name,Type,Value,Reason,Data | Export-Csv -LiteralPath "$auditPrefix.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        $auditPlan | Export-Clixml -LiteralPath "$auditPrefix.xml" -Depth 12 -ErrorAction Stop
        Write-DnsLog "$(@($auditPlan | Where-Object Action -EQ Remove).Count) unrelated record(s) found; read-only audit: $auditPrefix.csv"
        $checksPath=Join-Path $reports "checks-$([guid]::NewGuid().ToString('N')).csv"
        $checks | Export-Csv -LiteralPath $checksPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        $checks | Format-Table Check,Status,Details -Wrap | Out-String -Width 180 | Write-Host
        Write-DnsLog "$(@($checks | Where-Object Status -NE 'Pass').Count) checks need attention/review. Report: $checksPath"
        Write-DnsLog 'These are local DNS checks. Verify from another host; review firewall scope with shed-hardening.'
        $choice=Read-DnsChoice '[A] Audit again, [R] Repair, [B] Rebuild managed records, [D] Run dcdiag DNS basic test, [Q] Finish (default Q)' @('A','R','B','D','Q') 'Q'
        if ($choice -eq 'Q') {break}
        try {
            if ($choice -in @('R','B')) {Invoke-DnsRecovery $configuration $backups $reports ($choice -eq 'B')}
            elseif ($choice -eq 'D') {Invoke-DnsNativeTool 'dcdiag.exe' @('/test:DNS','/DnsBasic','/v') (Join-Path $reports "dcdiag-$([guid]::NewGuid().ToString('N')).log")}
        } catch {Write-DnsLog "Recovery/diagnostic needs attention: $_. Earlier changes may remain; review $backups and $reports." ERROR}
    }
} finally {Stop-Transcript -ErrorAction Stop | Out-Null}
