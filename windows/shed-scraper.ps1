#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Collect durable incident-response evidence, then apply an explicitly reviewed action plan.
.DESCRIPTION
Standalone evidence collection. Default execution inventories files and persistence without remediation.
Findings are written incrementally as UTF-8 JSONL, followed by CSV and an empty actions.template.json.
Copy the template, add reviewed finding IDs/fingerprints/actions, then pass -ApplyPlan PATH.
Stale sources are rejected. -QuarantineAll is retired; heuristics do not authorize mutation.
Quarantine never kills processes. It encrypts and authenticates content and alternate streams,
with keys protected by machine DPAPI; keep the protected store on this host for restoration.
Use -RestoreQuarantine MANIFEST or -RestoreBackup BACKUP for explicit, verified restoration.
Task XML cannot export stored passwords; recreating a removed password-based task requires its
original credentials. Prefer DisableTask. Unloaded profile hives and access failures are reported
as incomplete coverage. -DownloadHistoryLimit 0 collects all discovered provenance records.
-FullScan scans TargetDrive while pruning system/tool/evidence paths and reparse points.
Use -WhatIf with a remediation plan. Exit 1 means failed or incomplete work.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [switch]$FullScan, [ValidatePattern('^[A-Za-z]:$')][string]$TargetDrive='C:',
    [string]$ToolsRoot='C:\Tools', [ValidateRange(0,2147483647)][int]$DownloadHistoryLimit=500,
    [string]$BaselinePath, [string]$ApplyPlan, [string]$RestoreQuarantine, [string]$RestoreBackup,
    [switch]$NonInteractive, [switch]$QuarantineAll
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
function Assert-ShedWindows {
    if ($env:OS -ne 'Windows_NT') { throw 'Shed entry points require Windows. Pure helper tests can run on other platforms.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Run 64-bit Windows PowerShell or PowerShell 7.' }
    if ([Environment]::OSVersion.Version.Build -lt 17763) { throw 'Windows Server 2019 / Windows 10 1809 or newer is required.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script in an elevated PowerShell session.'
    }
}

function Test-ShedPathWithin {
    param([string]$Path, [string]$Root)
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $candidate.Equals($parent, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ShedNoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing reparse point in trusted path: $current"
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($parent) { $parent.FullName } else { $null }
    }
}

function Set-ShedPrivateAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$AllowUsersRead)
    Assert-ShedNoReparsePoint $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
    $acl.SetOwner($admins)
    $inheritance = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            ([Security.Principal.SecurityIdentifier]$sid), [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    if ($AllowUsersRead) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            ([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Initialize-ShedRoot {
    param([string]$Root)
    if ($Root -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetPathRoot($Root).TrimEnd('\') -eq $Root.TrimEnd('\')) {
        throw 'ToolsRoot must be a local directory below a drive root.'
    }
    $profileRoot=[Environment]::ExpandEnvironmentVariables([string][Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList','ProfilesDirectory',($env:SystemDrive+'\Users')))
    foreach ($systemPath in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,$profileRoot)) {
        if ($systemPath -and (Test-ShedPathWithin $systemPath $Root)) {throw 'ToolsRoot must not contain a Windows, application, ProgramData or user-profile root.'}
    }
    if (Test-ShedPathWithin $Root $env:SystemRoot) {throw 'ToolsRoot must be outside the Windows directory.'}
    Assert-ShedNoReparsePoint $Root
    # A writable parent must not let an unprivileged process replace the secured tree.
    $ancestor=[IO.Directory]::GetParent([IO.Path]::GetFullPath($Root))
    $replaceRights=[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor.FullName) {
            $parentAcl=Get-Acl -LiteralPath $ancestor.FullName -ErrorAction Stop
            $parentOwner=$parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($parentOwner -notin @('S-1-5-32-544','S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
                throw "ToolsRoot has an untrusted parent owner at $($ancestor.FullName). Use an admin-controlled local path."
            }
            foreach ($rule in $parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band $replaceRights) -and
                    $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18','S-1-3-0') -and $rule.IdentityReference.Value -notlike 'S-1-5-80-*') {
                    throw "ToolsRoot has a replaceable parent: $($ancestor.FullName). Choose a directory directly under an admin-controlled drive root."
                }
            }
        }
        $ancestor=$ancestor.Parent
    }
    if (Test-Path -LiteralPath $Root) {
        $owner = (Get-Acl -LiteralPath $Root -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($owner -notin @('S-1-5-32-544', 'S-1-5-18', $currentSid)) {
            throw "Untrusted owner $owner on $Root. Use a new admin-owned ToolsRoot."
        }
        # Inspect before changing anything; never descend through junctions or links.
        $stack = New-Object 'Collections.Generic.Stack[string]'
        $stack.Push($Root)
        $items = New-Object 'Collections.Generic.List[object]'
        while ($stack.Count) {
            foreach ($child in @(Get-ChildItem -LiteralPath $stack.Pop() -Force -ErrorAction Stop)) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point in tooling tree: $($child.FullName)" }
                $items.Add($child)
                if ($child.PSIsContainer) { $stack.Push($child.FullName) }
            }
        }
        Set-ShedPrivateAcl $Root -AllowUsersRead
        foreach ($child in $items) {
            $public = Test-ShedPathWithin $child.FullName (Join-Path $Root 'bin')
            Set-ShedPrivateAcl $child.FullName -AllowUsersRead:$public
        }
        Assert-ShedExistingPathTrust $Root
        foreach ($child in $items) {
            Assert-ShedExistingPathTrust $child.FullName
        }
    } else {
        $null = New-Item -ItemType Directory -Path $Root -ErrorAction Stop
        Set-ShedPrivateAcl $Root -AllowUsersRead
        if (@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop).Count) {throw 'Unexpected contents appeared in the new workspace; choose a fresh ToolsRoot.'}
    }
    foreach ($name in @('bin', 'downloads', 'logs', 'evidence', 'backups', 'recovery', 'quarantine')) {
        $path = Join-Path $Root $name
        $null = New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop
        Set-ShedPrivateAcl $path -AllowUsersRead:($name -eq 'bin')
    }
}

function Assert-ShedExistingPathTrust {
    param([string]$Path)
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted=@('S-1-5-32-544','S-1-5-18',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {throw "Untrusted owner on cached workspace content: $Path"}
    $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $write) -and $rule.IdentityReference.Value -notin $trusted) {
            throw "Untrusted write permission on cached workspace content: $Path. Use a fresh admin-controlled ToolsRoot."
        }
    }
}

function Write-ShedJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Value)
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).part"
    try {
        [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $Value -Depth 30), (New-Object Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop } }
}

function Read-ShedJson {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function New-ShedContext {
    param([string]$Name, [string]$ToolsRoot = 'C:\Tools', [switch]$Simulation, [switch]$NoTranscript)
    $root = [IO.Path]::GetFullPath($ToolsRoot)
    $requestedRoot=$root
    if ($Simulation) {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('shed-whatif-' + [guid]::NewGuid().ToString('N'))
        foreach ($namePart in @('', 'bin', 'downloads', 'logs', 'evidence', 'backups', 'recovery', 'quarantine')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $root $namePart) -Force -WhatIf:$false
        }
    } else { Initialize-ShedRoot $root }
    $id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $foreground=[ConsoleColor]::Gray; $background=[ConsoleColor]::Black
    try {$foreground=[Console]::ForegroundColor; $background=[Console]::BackgroundColor} catch {Write-Verbose $_}
    $context = [pscustomobject]@{
        Name=$Name; Root=$root; RequestedRoot=$requestedRoot; RunId=$id; HostName=[Environment]::MachineName; Simulation=[bool]$Simulation
        LogPath=(Join-Path $root "logs\$Name-$id.log"); EventsPath=(Join-Path $root "logs\$Name-$id.jsonl")
        Results=(New-Object 'Collections.Generic.List[object]'); TranscriptStarted=$false
        Foreground=$foreground; Background=$background
        Location=(Get-Location).Path; ProcessDirectory=[IO.Directory]::GetCurrentDirectory()
        SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol
    }
    try { [Console]::BackgroundColor='Black'; [Console]::ForegroundColor='White' } catch { Write-Verbose $_ }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not $NoTranscript) {
        try {
            $null = Start-Transcript -Path (Join-Path $root "logs\$Name-$id.transcript.txt") -ErrorAction Stop
            $context.TranscriptStarted = $true
        } catch { Write-Warning "Transcript unavailable; structured logging remains active: $($_.Exception.Message)" }
    }
    Write-ShedLog $context "Starting $Name on $($context.HostName); run $id"
    return $context
}

function Write-ShedEvent {
    param($Context, [string]$Kind, $Data)
    $record = [ordered]@{Utc=[DateTime]::UtcNow.ToString('o'); Host=$Context.HostName; RunId=$Context.RunId; Kind=$Kind; Data=$Data}
    [IO.File]::AppendAllText($Context.EventsPath, (($record | ConvertTo-Json -Depth 30 -Compress) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}

function Write-ShedLog {
    param($Context, [string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level='INFO')
    $line = "[$([DateTime]::UtcNow.ToString('o'))] [$Level] $Message"
    $color = @{INFO='Cyan'; WARN='Yellow'; ERROR='Red'; SUCCESS='Green'}[$Level]
    Write-Host $line -ForegroundColor $color -BackgroundColor Black
    [IO.File]::AppendAllText($Context.LogPath, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

function Add-ShedResult {
    param($Context, [string]$Name, [ValidateSet('Succeeded','Failed','Skipped','RebootRequired','Incomplete')][string]$Status, [string]$Details='')
    $result = [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Name=$Name; Status=$Status; Details=$Details}
    $Context.Results.Add($result)
    Write-ShedEvent $Context 'Result' $result
    $level = if ($Status -eq 'Failed') {'ERROR'} elseif ($Status -in @('Incomplete','RebootRequired')) {'WARN'} elseif ($Status -eq 'Skipped') {'INFO'} else {'SUCCESS'}
    Write-ShedLog $Context "$Name : $Status. $Details" $level
}

function Invoke-ShedStep {
    param($Context, [string]$Name, [scriptblock]$Action, [scriptblock]$Verify, [bool]$Enabled=$true)
    if (-not $Enabled) { Add-ShedResult $Context $Name 'Skipped' 'Not selected or declined by ShouldProcess.'; return }
    try {
        & $Action | Out-Null
        if ($Verify -and -not (& $Verify)) { throw 'The post-change verification did not pass.' }
        Add-ShedResult $Context $Name 'Succeeded'
    } catch { Add-ShedResult $Context $Name 'Failed' $_.Exception.Message }
}

function Get-ShedExitCode {
    param($Context)
    if (@($Context.Results | Where-Object { $_.Status -in @('Failed','Incomplete') }).Count) { return 1 }
    if (@($Context.Results | Where-Object Status -eq 'RebootRequired').Count) { return 3010 }
    return 0
}

function Close-ShedContext {
    param($Context)
    try {
        $Context.Results | Export-Csv -LiteralPath (Join-Path $Context.Root "logs\$($Context.Name)-$($Context.RunId)-results.csv") -NoTypeInformation -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
        $Context.Results | Format-Table Name,Status,Details -Wrap | Out-Host
        Write-ShedLog $Context "Results: $($Context.EventsPath); exit code $(Get-ShedExitCode $Context)"
    } finally {
        try {if ($Context.TranscriptStarted) { Stop-Transcript -ErrorAction Stop | Out-Null }}
        finally {
            [Net.ServicePointManager]::SecurityProtocol = $Context.SecurityProtocol
            try {[IO.Directory]::SetCurrentDirectory($Context.ProcessDirectory); Set-Location -LiteralPath $Context.Location -ErrorAction Stop}
            finally {try { [Console]::ForegroundColor=$Context.Foreground; [Console]::BackgroundColor=$Context.Background } catch { Write-Verbose $_ }}
        }
    }
}

function ConvertTo-ShedNativeArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows CommandLineToArgvW / CRT quoting, including quotes and trailing slashes.
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-ShedNative {
    param([string]$FilePath, [string[]]$ArgumentList=@(), [int[]]$SuccessCodes=@(0), [string]$WorkingDirectory=([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($FilePath))), [int]$TimeoutSeconds=1800, [switch]$AllowFailure)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$FilePath; $info.Arguments=(@($ArgumentList | ForEach-Object { ConvertTo-ShedNativeArgument $_ }) -join ' ')
    $info.WorkingDirectory=$WorkingDirectory; $info.UseShellExecute=$false
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true; $info.CreateNoWindow=$true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "Could not start $FilePath" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $exception=New-Object TimeoutException("Timed out waiting for $FilePath (PID $($process.Id)); it may still be running. The installation pipeline must stop.")
            $exception.Data['ProcessStillRunning']=$true
            throw $exception
        }
        $process.WaitForExit()
        $result = [pscustomobject]@{ExitCode=$process.ExitCode; StdOut=$stdout.GetAwaiter().GetResult(); StdErr=$stderr.GetAwaiter().GetResult()}
        if (-not $AllowFailure -and $result.ExitCode -notin $SuccessCodes) {
            throw "$FilePath exited $($result.ExitCode): $($result.StdErr) $($result.StdOut)"
        }
        return $result
    } finally { $process.Dispose() }
}

function Get-ShedFileEvidence {
    param([Parameter(Mandatory)][string]$Path)
    Assert-ShedNoReparsePoint $Path
    $before = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($before.PSIsContainer) { throw "Expected a file: $Path" }
    $length=$before.Length; $modified=$before.LastWriteTimeUtc
    $hash = (Get-FileHash -LiteralPath $before.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    $after = Get-Item -LiteralPath $before.FullName -Force -ErrorAction Stop
    if ($length -ne $after.Length -or $modified -ne $after.LastWriteTimeUtc) { throw "File changed during collection: $Path" }
    $signatureStatus='NotChecked'; $publisher=''
    if ($after.Extension -in @('.exe','.dll','.msi','.msix','.msixbundle','.appx','.appxbundle','.ps1','.psm1')) {
        $command = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
        if ($command) {
            $signature = Get-AuthenticodeSignature -LiteralPath $after.FullName -ErrorAction Stop
            $signatureStatus = [string]$signature.Status
            if ($signature.SignerCertificate) { $publisher=$signature.SignerCertificate.Subject }
        }
    }
    $ownerSid=''; $ownerError=''
    if ($env:OS -eq 'Windows_NT') {
        try {$ownerSid=(Get-Acl -LiteralPath $after.FullName -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value}
        catch {$ownerError=$_.Exception.Message}
    }
    [pscustomobject]@{Path=$after.FullName; Sha256=$hash; Length=$length; CreationUtc=$after.CreationTimeUtc.ToString('o'); LastWriteUtc=$modified.ToString('o'); Signature=$signatureStatus; Publisher=$publisher; OwnerSid=$ownerSid; OwnerReadError=$ownerError}
}

function Assert-ShedArtifact {
    param([string]$Path, [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Sha256, [string]$PublisherPattern='')
    $evidence = Get-ShedFileEvidence $Path
    if ($evidence.Sha256 -ne $Sha256) { throw "SHA-256 mismatch: $Path" }
    if ($PublisherPattern -and ($evidence.Signature -ne 'Valid' -or $evidence.Publisher -notmatch $PublisherPattern)) {
        throw "Expected publisher/signature not verified: $Path ($($evidence.Signature), $($evidence.Publisher))"
    }
    return $evidence
}

function Get-ShedVerifiedDownload {
    param($Context, [string]$Uri, [string]$Destination, [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Sha256, [string]$PublisherPattern='')
    if (([uri]$Uri).Scheme -ne 'https') { throw 'Verified downloads require HTTPS.' }
    Assert-ShedNoReparsePoint $Destination
    if (-not (Test-ShedPathWithin $Destination (Join-Path $Context.Root 'downloads'))) { throw 'Download destination must be inside the protected downloads directory.' }
    if (Test-Path -LiteralPath $Destination) {
        try { $null = Assert-ShedArtifact $Destination $Sha256 $PublisherPattern; return $Destination }
        catch { Write-ShedLog $Context "Cached artifact rejected: $Destination" 'WARN' }
    }
    $temporary = "$Destination.$([guid]::NewGuid().ToString('N')).part"
    # Retain the original extension so Authenticode can identify the artifact format.
    $temporary += [IO.Path]::GetExtension($Destination)
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $temporary -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        $null = Assert-ShedArtifact $temporary $Sha256 $PublisherPattern
        if (Test-Path -LiteralPath $Destination) { [IO.File]::Replace($temporary, $Destination, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Destination) }
        Set-ShedPrivateAcl $Destination
        return $Destination
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop } }
}

function Test-ShedSecureStringEqual {
    param([Security.SecureString]$First, [Security.SecureString]$Second)
    if ($First.Length -ne $Second.Length) { return $false }
    $left=[IntPtr]::Zero; $right=[IntPtr]::Zero
    try {
        $left=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $right=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        $different=0
        for ($index=0; $index -lt $First.Length; $index++) {
            $different = $different -bor ([Runtime.InteropServices.Marshal]::ReadInt16($left,$index*2) -bxor [Runtime.InteropServices.Marshal]::ReadInt16($right,$index*2))
        }
        return $different -eq 0
    } finally {
        if ($left -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($left) }
        if ($right -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($right) }
    }
}

function Get-ShedProtectedSidSet {
    param([string[]]$ScoringSids=@(), [string[]]$BuiltInSids=@(), [string]$OperatorSid, [string[]]$ServiceSids=@())
    $set = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in (@($ScoringSids) + @($BuiltInSids) + @($OperatorSid) + @($ServiceSids))) {
        if ($sid) { $null=$set.Add($sid) }
    }
    return ,$set
}

function Get-ShedSession {
    param($SenderInfo)
    if ($env:SSH_CONNECTION) { return [pscustomobject]@{Transport='SSH'; Remote=$true; Peer=($env:SSH_CONNECTION -split '\s+')[0]; Session=$env:SSH_CONNECTION} }
    if ($SenderInfo) { return [pscustomobject]@{Transport='WinRM'; Remote=$true; Peer=''; Session=[string]$SenderInfo.ConnectionString} }
    if ($env:SESSIONNAME -match '^RDP-') { return [pscustomobject]@{Transport='RDP'; Remote=$true; Peer=''; Session=$env:SESSIONNAME} }
    if ($env:SESSIONNAME -and $env:SESSIONNAME -ne 'Console') { return [pscustomobject]@{Transport='Unknown'; Remote=$true; Peer=''; Session=$env:SESSIONNAME} }
    return [pscustomobject]@{Transport='Console'; Remote=$false; Peer=''; Session='Console'}
}

function Test-ShedAddressScope {
    param([string]$Address, [string[]]$Scopes)
    $client=[Net.IPAddress]::Parse($Address)
    $expanded=New-Object 'Collections.Generic.List[string]'
    foreach ($scope in $Scopes) {
        if ($scope -eq 'Any') {return $true}
        if ($scope -eq 'LocalSubnet') {
            foreach ($entry in @(Get-NetIPAddress -AddressState Preferred -ErrorAction Stop)) {$expanded.Add("$($entry.IPAddress)/$($entry.PrefixLength)")}
        } else {$expanded.Add($scope)}
    }
    foreach ($scope in $expanded) {
        $parts=$scope -split '/'; $network=[Net.IPAddress]::Parse($parts[0])
        $left=$client.GetAddressBytes(); $right=$network.GetAddressBytes()
        if ($left.Length -ne $right.Length) {continue}
        $bits=if ($parts.Count -eq 2) {[int]$parts[1]} else {$left.Length*8}
        if ($bits -lt 0 -or $bits -gt $left.Length*8) {throw "Invalid network prefix: $scope"}
        $matchesNetwork=$true
        for ($index=0; $index -lt $left.Length; $index++) {
            $used=[Math]::Min(8,[Math]::Max(0,$bits-$index*8))
            $mask=if ($used -eq 0) {0} else {(255 -shl (8-$used)) -band 255}
            if (($left[$index] -band $mask) -ne ($right[$index] -band $mask)) {$matchesNetwork=$false;break}
        }
        if ($matchesNetwork) {return $true}
    }
    return $false
}

function Get-ShedFiles {
    param([string[]]$Roots, [string[]]$Extensions=@(), [string[]]$ExcludeRoots=@(), $Context,
        [Collections.Generic.HashSet[string]]$Seen=(New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)))
    $stack = New-Object 'Collections.Generic.Stack[string]'
    foreach ($root in $Roots) { if ($root -and (Test-Path -LiteralPath $root)) { $stack.Push([IO.Path]::GetFullPath($root)) } }
    while ($stack.Count) {
        $path=$stack.Pop()
        if (-not $Seen.Add($path)) { continue }
        $excluded=$false
        foreach ($excludedRoot in $ExcludeRoots) { if (Test-ShedPathWithin $path $excludedRoot) { $excluded=$true; break } }
        if ($excluded) {if ($Context) {Write-ShedEvent $Context Coverage @{Path=$path;Status='ExcludedByPolicy'}}; continue }
        try {
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                if ($Context) { Write-ShedEvent $Context 'Coverage' @{Path=$path; Status='SkippedReparsePoint'} }
                continue
            }
            if ($item.PSIsContainer) {
                foreach ($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) { $stack.Push($child.FullName) }
            } elseif (-not $Extensions.Count -or $item.Extension -in $Extensions) { Write-Output $item }
        } catch {
            if ($Context) { Add-ShedResult $Context "Coverage: $path" 'Incomplete' $_.Exception.Message }
            else { Write-Error -ErrorRecord $_ -ErrorAction Continue }
        }
    }
}

function Split-ShedCommand {
    param([AllowEmptyString()][string]$Command, [string]$ProfilePath='')
    $expanded=$Command.Trim()
    if ($ProfilePath) {
        foreach ($mapping in @(@('%USERPROFILE%',$ProfilePath), @('%APPDATA%',(Join-Path $ProfilePath 'AppData\Roaming')), @('%LOCALAPPDATA%',(Join-Path $ProfilePath 'AppData\Local')))) {
            $replacement=$mapping[1]
            $expanded=[regex]::Replace($expanded,[regex]::Escape($mapping[0]),[Text.RegularExpressions.MatchEvaluator]{$replacement},[Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $expanded=[Environment]::ExpandEnvironmentVariables($expanded)
    $executable=''; $arguments=''; $ambiguous=$false
    if ($expanded -match '^"([^"]+)"(?:\s+(.*))?$') { $executable=$matches[1]; if ($matches.ContainsKey(2)) { $arguments=$matches[2] } }
    elseif ($expanded -match '^(\S+)(?:\s+(.*))?$') {
        $executable=$matches[1]; if ($matches.ContainsKey(2)) { $arguments=$matches[2] }
        $ambiguous=($executable -notmatch '\.(exe|com|cmd|bat|ps1|vbs|js)$' -and $arguments -match '\.(exe|com)\b')
    }
    [pscustomobject]@{Raw=$Command; Expanded=$expanded; Executable=$executable; Arguments=$arguments; Ambiguous=$ambiguous}
}

function Get-ShedFingerprint {
    param($Value)
    $canonical=ConvertTo-ShedCanonicalValue $Value
    $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $canonical -Depth 30 -Compress))
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','') }
    finally { $algorithm.Dispose() }
}

function ConvertTo-ShedCanonicalValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value) {return $null}
    # Pipeline output can wrap strings as PSObjects (for example Join-Path).
    # Handle scalar values before inspecting adapted PSObject properties such as Length.
    if ($Value -is [string]) {return [string]$Value}
    if ($Value -is [DateTime]) {return $Value.ToUniversalTime().ToString('o')}
    if ($Value.GetType().IsValueType) {return $Value.PSObject.BaseObject}
    if ($Value -is [Collections.IDictionary]) {
        $ordered=[ordered]@{}; [string[]]$keys=@($Value.Keys); [Array]::Sort($keys,[StringComparer]::Ordinal)
        foreach ($key in $keys) {$ordered[$key]=ConvertTo-ShedCanonicalValue $Value[$key]}
        return $ordered
    }
    if ($Value -is [pscustomobject]) {
        $ordered=[ordered]@{}; [string[]]$keys=@($Value.PSObject.Properties.Name); [Array]::Sort($keys,[StringComparer]::Ordinal)
        foreach ($key in $keys) {$ordered[$key]=ConvertTo-ShedCanonicalValue $Value.$key}
        return $ordered
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=New-Object 'Collections.Generic.List[object]'
        foreach ($item in $Value) {$items.Add((ConvertTo-ShedCanonicalValue $item))}
        return ,$items.ToArray()
    }
    return $Value
}

function Get-ShedProperty {
    param($Object, [string]$Name, $Default='')
    if ($Object -is [Collections.IDictionary] -and $Object.Contains($Name)) {return $Object[$Name]}
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) {return $Object.$Name}
    return $Default
}

function New-ShedAudit {
    param($Context, [string]$BaselinePath='')
    $directory=Join-Path $Context.Root "evidence\$($Context.RunId)"
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop -WhatIf:$false
    $baseline=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($BaselinePath) {foreach ($hash in @((Read-ShedJson $BaselinePath).Fingerprints)) {$null=$baseline.Add([string]$hash)}}
    $audit=[pscustomobject]@{Context=$Context; Directory=$directory; FindingsPath=(Join-Path $directory 'findings.jsonl'); Count=0; Baseline=$baseline}
    [IO.File]::WriteAllText($audit.FindingsPath,'',(New-Object Text.UTF8Encoding($false)))
    return $audit
}

function Add-ShedFinding {
    param($Audit, [string]$Category, $Source, $Evidence, [string]$Severity='INFO', [string]$OwnerSid='')
    $Source=ConvertTo-ShedCanonicalValue $Source
    $fileEvidence=Get-ShedProperty $Evidence File $null
    $fileOwner=Get-ShedProperty $fileEvidence OwnerSid
    if ($fileOwner) {$OwnerSid=$fileOwner}
    $fingerprint=Get-ShedFingerprint $Source
    $known=$Audit.Baseline.Contains($fingerprint)
    if ($known) {$Severity='INFO'}
    $record=[pscustomobject]@{
        SchemaVersion=1; Id=[guid]::NewGuid().ToString('N'); Utc=[DateTime]::UtcNow.ToString('o')
        Host=$Audit.Context.HostName; RunId=$Audit.Context.RunId; OwnerSid=$OwnerSid
        Category=$Category; Severity=$Severity; BaselineMatched=$known; Fingerprint=$fingerprint; Source=$Source; Evidence=$Evidence
    }
    [IO.File]::AppendAllText($Audit.FindingsPath,($record | ConvertTo-Json -Depth 30 -Compress)+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
    $Audit.Count++
    $fileHash=if ($Source -is [Collections.IDictionary] -and $Source.Contains('Sha256')) {$Source['Sha256']} else {Get-ShedProperty $Source Sha256 'N/A'}
    Write-ShedLog $Audit.Context "Finding $($record.Id) [$Category/$Severity] SHA256=$fileHash; fingerprint=$fingerprint"
}

function Complete-ShedAudit {
    param($Audit)
    # JSONL is authoritative and already durable. CSV is a derived, interruption-safe convenience export.
    Get-Content -LiteralPath $Audit.FindingsPath -Encoding UTF8 -ErrorAction Stop | ForEach-Object {
        $record=$_ | ConvertFrom-Json -ErrorAction Stop
        [pscustomobject]@{Id=$record.Id; Utc=$record.Utc; Host=$record.Host; OwnerSid=$record.OwnerSid; Category=$record.Category; Severity=$record.Severity; Fingerprint=$record.Fingerprint;
            Source=($record.Source | ConvertTo-Json -Depth 30 -Compress); Evidence=($record.Evidence | ConvertTo-Json -Depth 30 -Compress)}
    } | Export-Csv -LiteralPath (Join-Path $Audit.Directory 'findings.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $template=[ordered]@{SchemaVersion=1; Host=$Audit.Context.HostName; RunId=$Audit.Context.RunId; FindingsPath=$Audit.FindingsPath;
        FindingsSha256=(Get-FileHash -LiteralPath $Audit.FindingsPath -Algorithm SHA256 -ErrorAction Stop).Hash; Actions=@()}
    Write-ShedJson (Join-Path $Audit.Directory 'actions.template.json') $template
    Write-ShedLog $Audit.Context "Collected $($Audit.Count) findings. Review findings.jsonl and copy selected Id/Fingerprint/Action entries into actions.template.json."
}

function Get-ShedCommandEvidence {
    param([string]$Command, [string]$ProfilePath='')
    $parsed=Split-ShedCommand $Command $ProfilePath
    $target=$parsed.Executable
    $file=$null
    # Never resolve UNC targets or execute a command to discover its path.
    if ($target -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $target -PathType Leaf)) {$file=Get-ShedFileEvidence $target}
    $launcher=$target -match '(^|[\\/])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)(\.exe)?$'
    $payload=$parsed.Arguments -match '(?i)(-enc\b|-encodedcommand\b|\.ps1\b|\.vbs\b|\.hta\b|https?://|AppData|\\Temp\\)'
    [pscustomobject]@{Command=$parsed; ExecutableEvidence=$file; Launcher=$launcher; PayloadIndicator=$payload; ReviewRequired=($launcher -or $payload -or $parsed.Ambiguous -or -not $file)}
}

function Get-ShedRegistryValueRecord {
    param([string]$KeyPath, [string]$ValueName)
    $key=Get-Item -LiteralPath $KeyPath -ErrorAction Stop
    try {
        if ($ValueName -notin $key.GetValueNames()) {throw "Registry value no longer exists: $KeyPath [$ValueName]"}
        [pscustomobject]@{Type='RegistryValue'; KeyPath=$KeyPath; ValueName=$ValueName; ValueKind=[string]$key.GetValueKind($ValueName);
            Value=$key.GetValue($ValueName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
    } finally {$key.Dispose()}
}

function Get-ShedProfileInventory {
    $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop)
    foreach ($userProfile in $profiles) {
        if (-not $userProfile.LocalPath) {continue}
        [pscustomobject]@{Sid=[string]$userProfile.SID; Path=[string]$userProfile.LocalPath; Loaded=[bool]$userProfile.Loaded}
    }
}

function Get-ShedStartupInventory {
    param($Audit, $Profiles)
    $machine='Registry::HKEY_LOCAL_MACHINE'
    $roots=New-Object 'Collections.Generic.List[object]'
    $roots.Add(@{Key=$machine; Sid=''; Profile=''})
    $profileMap=@{}; foreach ($userProfile in $Profiles) {$profileMap[$userProfile.Sid]=$userProfile.Path}
    foreach ($key in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop)) {
        if ($key.PSChildName -match '^S-1-\d+(?:-\d+)+$') {
            $sid=$key.PSChildName
            $profilePath=if ($profileMap.ContainsKey($sid)) {$profileMap[$sid]} else {''}
            $roots.Add(@{Key="Registry::HKEY_USERS\$sid"; Sid=$sid; Profile=$profilePath})
        }
        $key.Dispose()
    }
    foreach ($userProfile in $Profiles) {
        if (-not $userProfile.Loaded) {Add-ShedResult $Audit.Context "Unloaded registry hive: $($userProfile.Sid)" Incomplete 'Profile filesystem is inspected; registry hive was not mounted or modified.'}
    }
    $suffixes=@('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Software\Microsoft\Internet Explorer\TypedURLs',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths')
    foreach ($root in $roots) {
        foreach ($suffix in $suffixes) {
            $path=$root.Key+'\'+$suffix
            if (-not (Test-Path -LiteralPath $path)) {continue}
            try {
                $key=Get-Item -LiteralPath $path -ErrorAction Stop
                try {$names=@($key.GetValueNames())} finally {$key.Dispose()}
                foreach ($name in $names) {
                    if ($suffix -like '*\Winlogon' -and $name -notin @('Shell','Userinit','Taskman','VmApplet')) {continue}
                    $source=Get-ShedRegistryValueRecord $path $name
                    $history=$suffix -match 'TypedURLs|TypedPaths'
                    $evidence=if ($source.Value -is [string]) {Get-ShedCommandEvidence $source.Value $root.Profile} else {$null}
                    Add-ShedFinding $Audit $(if ($history) {'BrowserHistory'} else {'RegistryStartup'}) $source $evidence $(if ($history) {'INFO'} else {'HIGH'}) $root.Sid
                }
            } catch {Add-ShedResult $Audit.Context "Registry coverage: $path" Incomplete $_.Exception.Message}
        }
    }
    $folders=@(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    foreach ($userProfile in $Profiles) {$folders+=@(Join-Path $userProfile.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')}
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) {continue}
        Assert-ShedNoReparsePoint $folder
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction Stop)) {
            try {
                $evidence=Get-ShedFileEvidence $file.FullName
                $source=[ordered]@{Type='File'; Path=$file.FullName; Sha256=$evidence.Sha256}
                $shortcut=$null; $shell=$null; $link=$null
                if ($file.Extension -eq '.lnk') {
                    try {
                        $shell=New-Object -ComObject WScript.Shell
                        $link=$shell.CreateShortcut($file.FullName)
                        $shortcut=[pscustomobject]@{Target=$link.TargetPath; Arguments=$link.Arguments; WorkingDirectory=$link.WorkingDirectory;
                            Assessment=(Get-ShedCommandEvidence ('"'+$link.TargetPath+'" '+$link.Arguments))}
                    } finally {
                        if ($link) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)}
                        if ($shell) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
                    }
                }
                Add-ShedFinding $Audit StartupFolder $source @{File=$evidence; Shortcut=$shortcut} HIGH
            } catch {Add-ShedResult $Audit.Context "Startup coverage: $($file.FullName)" Incomplete $_.Exception.Message}
        }
    }
}

function Get-ShedTaskRecord {
    param($Task)
    $xml=Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop
    [pscustomobject]@{Type='ScheduledTask'; TaskName=$Task.TaskName; TaskPath=$Task.TaskPath; Xml=[string]$xml}
}

function Get-ShedTaskDefinitionFingerprint {
    param([string]$Xml, [switch]$IgnoreEnabled)
    $document=New-Object Xml.XmlDocument
    $document.PreserveWhitespace=$false; $document.LoadXml($Xml)
    if ($IgnoreEnabled) {
        foreach ($node in @($document.SelectNodes("//*[local-name()='Settings']/*[local-name()='Enabled']"))) {[void]$node.ParentNode.RemoveChild($node)}
    }
    return Get-ShedFingerprint @{Xml=$document.OuterXml}
}

function Get-ShedTaskInventory {
    param($Audit)
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        try {
            $source=Get-ShedTaskRecord $task
            $actions=@(foreach ($action in $task.Actions) {
                $execute=Get-ShedProperty $action Execute
                $arguments=Get-ShedProperty $action Arguments
                $classId=Get-ShedProperty $action ClassId
                $comTargets=New-Object 'Collections.Generic.List[object]'
                if ($classId) {
                    foreach ($server in @('InprocServer32','LocalServer32')) {
                        $key="Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\$classId\$server"
                        if (Test-Path -LiteralPath $key) {$comTargets.Add((Get-ShedRegistryValueRecord $key ''))}
                        $sid=Get-ShedProperty $task.Principal UserId
                        if ($sid -match '^S-1-') {
                            $userKey="Registry::HKEY_USERS\$sid\Software\Classes\CLSID\$classId\$server"
                            if (Test-Path -LiteralPath $userKey) {$comTargets.Add((Get-ShedRegistryValueRecord $userKey ''))}
                        }
                    }
                }
                [pscustomobject]@{Execute=$execute; Arguments=$arguments; WorkingDirectory=(Get-ShedProperty $action WorkingDirectory); ClassId=$classId; ComTargets=$comTargets.ToArray(); Assessment=(Get-ShedCommandEvidence ('"'+$execute+'" '+$arguments))}
            })
            # Names and task folders are inventory fields, never proof of trust.
            $severity=if (@($actions | Where-Object {$_.Assessment.ReviewRequired -or $_.ClassId}).Count) {'HIGH'} else {'INFO'}
            Add-ShedFinding $Audit ScheduledTask $source @{State=[string]$task.State; Actions=$actions; Principal=$task.Principal.UserId} $severity
        } catch {Add-ShedResult $Audit.Context "Task coverage: $($task.TaskPath)$($task.TaskName)" Incomplete $_.Exception.Message}
    }
}

function ConvertTo-ShedCimRecord {
    param($Instance)
    $properties=[ordered]@{}
    $types=[ordered]@{}
    foreach ($property in @($Instance.CimInstanceProperties | Sort-Object Name)) {
        $value=$property.Value
        $types[$property.Name]=[string]$property.CimType
        if ($property.CimType -eq 'Reference' -and $null -ne $value) {
            $keys=[ordered]@{}
            foreach ($key in @($value.CimInstanceProperties | Where-Object { $_.Flags -band [Microsoft.Management.Infrastructure.CimFlags]::Key } | Sort-Object Name)) {$keys[$key.Name]=$key.Value}
            if (-not $keys.Count) {throw 'Cannot preserve the keys of a WMI reference.'}
            $value=[ordered]@{ReferenceClass=$value.CimSystemProperties.ClassName; Namespace=$value.CimSystemProperties.Namespace; Keys=$keys}
        }
        $properties[$property.Name]=$value
    }
    [pscustomobject]@{Type='WmiObject'; Namespace='root\subscription'; ClassName=$Instance.CimSystemProperties.ClassName; Properties=$properties; PropertyTypes=$types}
}

function ConvertFrom-ShedCimProperties {
    param($Source)
    $properties=@{}
    foreach ($property in $Source.Properties.PSObject.Properties) {
        $value=$property.Value; $type=Get-ShedProperty $Source.PropertyTypes $property.Name
        if ($type -eq 'Reference' -and $null -ne $value) {
            $keys=@{}; foreach ($key in $value.Keys.PSObject.Properties) {$keys[$key.Name]=$key.Value}
            $value=New-CimInstance -ClassName $value.ReferenceClass -Namespace $value.Namespace -Property $keys -Key @($keys.Keys) -ClientOnly -ErrorAction Stop
        } elseif ($type -eq 'UInt8Array' -and $null -ne $value) {$value=[byte[]]$value}
        elseif ($type -eq 'StringArray' -and $null -ne $value) {$value=[string[]]$value}
        $properties[$property.Name]=$value
    }
    return $properties
}

function Get-ShedWmiInventory {
    param($Audit)
    $all=New-Object 'Collections.Generic.List[object]'
    foreach ($class in @('__EventFilter','__EventConsumer','__FilterToConsumerBinding')) {
        foreach ($instance in @(Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction Stop)) {
            $all.Add($instance)
            $source=ConvertTo-ShedCimRecord $instance
            Add-ShedFinding $Audit WmiSubscription $source @{Note='Inspect the complete filter / consumer / binding relationship before changing it.'} HIGH
        }
    }
    $all | Export-Clixml -LiteralPath (Join-Path $Audit.Directory 'wmi-subscription.xml') -Depth 20 -ErrorAction Stop
}

function Get-ShedHistoryInventory {
    param($Audit, $Profiles, [int]$DownloadHistoryLimit=500)
    $patterns='wget|curl|Invoke-WebRequest|\biwr\b|certutil|bitsadmin|downloadstring|\biex\b|frombase64string|encodedcommand|\-enc\b|tcpclient|nc\.exe|ncat|socat|mimikatz|chisel|ngrok|ligolo|cobaltstrike|meterpreter'
    $count=0; $capped=$false
    foreach ($userProfile in $Profiles) {
        foreach ($relative in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt','AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt')) {
            $path=Join-Path $userProfile.Path $relative
            if (-not (Test-Path -LiteralPath $path)) {continue}
            try {
                Assert-ShedNoReparsePoint $path
                $number=0
                foreach ($line in [IO.File]::ReadLines($path)) {
                    $number++
                    if ($line -match $patterns) {Add-ShedFinding $Audit PSHistory @{Type='History'; Path=$path; Line=$number; Text=$line} $null HIGH $userProfile.Sid}
                }
            } catch {Add-ShedResult $Audit.Context "History coverage: $path" Incomplete $_.Exception.Message}
        }
        $downloads=Join-Path $userProfile.Path Downloads
        foreach ($file in Get-ShedFiles -Roots @($downloads) -Context $Audit.Context) {
            $count++
            if ($DownloadHistoryLimit -gt 0 -and $count -gt $DownloadHistoryLimit) {$capped=$true; continue}
            try {
                $streams=@(Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop | Where-Object Stream -eq 'Zone.Identifier')
                if (-not $streams.Count) {continue}
                $zone=Get-Content -LiteralPath $file.FullName -Stream Zone.Identifier -Raw -ErrorAction Stop
                $evidence=Get-ShedFileEvidence $file.FullName
                Add-ShedFinding $Audit DownloadOrigin @{Type='File'; Path=$file.FullName; Sha256=$evidence.Sha256} @{File=$evidence; ZoneIdentifier=$zone} INFO $userProfile.Sid
            } catch {Add-ShedResult $Audit.Context "Download provenance: $($file.FullName)" Incomplete $_.Exception.Message}
        }
    }
    if ($capped) {Add-ShedResult $Audit.Context 'Download history limit' Incomplete "$count files discovered; provenance limited to $DownloadHistoryLimit. Set -DownloadHistoryLimit 0 for no cap."}
}

function Get-ShedFilesystemInventory {
    param($Audit, $Profiles, [bool]$FullScan, [string]$TargetDrive='C:')
    $extensions=@('.ps1','.psm1','.psd1','.exe','.dll','.bat','.cmd','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.scr','.elf','.bin','.jar','.py','.com','.aspx','.ashx','.asmx','.asp','.php','.jsp','.jspx','.config')
    $roots=@($env:ProgramData,(Join-Path $env:SystemRoot Temp),(Join-Path $env:SystemRoot Debug),($TargetDrive+'\Temp'),($TargetDrive+'\PerfLogs'),(Join-Path $env:PUBLIC '.'),'C:\inetpub\wwwroot')
    foreach ($userProfile in $Profiles) {foreach ($child in @('AppData\Local','AppData\Roaming','Desktop','Downloads')) {$roots+=@(Join-Path $userProfile.Path $child)}}
    if ($FullScan) {$roots=@($TargetDrive+'\')}
    $excluded=@($Audit.Context.Root,$PSScriptRoot,(Join-Path $env:SystemRoot WinSxS),(Join-Path $env:SystemRoot servicing),(Join-Path $env:SystemRoot Installer),(Join-Path $env:SystemRoot Microsoft.NET),(Join-Path $env:SystemRoot assembly))
    foreach ($file in Get-ShedFiles -Roots $roots -Extensions $extensions -ExcludeRoots $excluded -Context $Audit.Context) {
        try {
            $evidence=Get-ShedFileEvidence $file.FullName
            $reasons=New-Object 'Collections.Generic.List[string]'
            if ($file.FullName -match '(?i)[\\/](AppData|Temp|PerfLogs|ProgramData)[\\/]|[\\/]Users[\\/]Public[\\/]') {$reasons.Add('Writable-location triage indicator')}
            if ($evidence.Signature -in @('NotSigned','HashMismatch','NotTrusted','UnknownError')) {$reasons.Add("Signature: $($evidence.Signature)")}
            $severity=if ($reasons.Count) {'SUSPICIOUS'} else {'INFO'}
            Add-ShedFinding $Audit Filesystem @{Type='File'; Path=$file.FullName; Sha256=$evidence.Sha256} @{File=$evidence; Reasons=$reasons.ToArray()} $severity
        } catch {Add-ShedResult $Audit.Context "File coverage: $($file.FullName)" Incomplete $_.Exception.Message}
    }
}

function Protect-ShedFile {
    param([string]$Source, [string]$Destination, [byte[]]$Key, [byte[]]$IV)
    $aes=[Security.Cryptography.Aes]::Create(); $inputStream=$null; $outputStream=$null; $crypto=$null
    try {
        $aes.Key=$Key; $aes.IV=$IV
        $inputStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $outputStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $crypto=New-Object Security.Cryptography.CryptoStream($outputStream,$aes.CreateEncryptor(),[Security.Cryptography.CryptoStreamMode]::Write)
        $inputStream.CopyTo($crypto); $crypto.FlushFinalBlock()
    } finally {if ($crypto) {$crypto.Dispose()}; if ($outputStream) {$outputStream.Dispose()}; if ($inputStream) {$inputStream.Dispose()}; $aes.Dispose()}
}

function Unprotect-ShedFile {
    param([string]$Source, [string]$Destination, [byte[]]$Key, [byte[]]$IV)
    $aes=[Security.Cryptography.Aes]::Create(); $inputStream=$null; $outputStream=$null; $crypto=$null
    try {
        $aes.Key=$Key; $aes.IV=$IV
        $inputStream=[IO.File]::OpenRead($Source)
        $crypto=New-Object Security.Cryptography.CryptoStream($inputStream,$aes.CreateDecryptor(),[Security.Cryptography.CryptoStreamMode]::Read)
        $outputStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $crypto.CopyTo($outputStream)
    } finally {if ($outputStream) {$outputStream.Dispose()}; if ($crypto) {$crypto.Dispose()}; if ($inputStream) {$inputStream.Dispose()}; $aes.Dispose()}
}

function Get-ShedHmac {
    param([string]$Path, [byte[]]$Key, [byte[]]$IV=@())
    $hmac=New-Object Security.Cryptography.HMACSHA256(,$Key); $stream=$null
    try {
        $stream=[IO.File]::OpenRead($Path)
        if ($IV.Length) {[void]$hmac.TransformBlock($IV,0,$IV.Length,$IV,0)}
        $buffer=New-Object byte[] 65536
        while (($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {[void]$hmac.TransformBlock($buffer,0,$read,$buffer,0)}
        [void]$hmac.TransformFinalBlock((New-Object byte[] 0),0,0)
        return [Convert]::ToBase64String($hmac.Hash)
    }
    finally {if ($stream) {$stream.Dispose()}; $hmac.Dispose()}
}

function Get-ShedStreamHash {
    param([string]$Path)
    $algorithm=[Security.Cryptography.SHA256]::Create(); $stream=$null
    try {$stream=[IO.File]::OpenRead($Path); return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','')}
    finally {if ($stream) {$stream.Dispose()};$algorithm.Dispose()}
}

function Invoke-ShedQuarantine {
    param($Context, [string]$Path, [string]$ExpectedSha256, [string]$Reason)
    foreach ($root in @($Context.Root,$PSScriptRoot,(Join-Path $env:SystemRoot System32),(Join-Path $env:SystemRoot WinSxS))) {
        if (Test-ShedPathWithin $Path $root) {throw "Protected runtime/system path cannot be quarantined: $Path"}
    }
    $file=Get-ShedFileEvidence $Path
    if ($file.Sha256 -ne $ExpectedSha256) {throw 'File identity changed since review.'}
    $acl=(Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl
    $attributes=[int][IO.File]::GetAttributes($Path)
    $directory=Join-Path $Context.Root ('quarantine\'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    Set-ShedPrivateAcl $directory
    $cipher=Join-Path $directory 'payload.aes'; $manifestPath=Join-Path $directory 'manifest.json'; $verification=Join-Path $directory 'verify.tmp'
    $material=New-Object byte[] 64; $iv=New-Object byte[] 16; $rng=[Security.Cryptography.RandomNumberGenerator]::Create(); $key=$null; $macKey=$null
    try {
        $rng.GetBytes($material); $rng.GetBytes($iv)
        $key=[byte[]]$material[0..31]; $macKey=[byte[]]$material[32..63]
        Protect-ShedFile $Path $cipher $key $iv
        $mac=Get-ShedHmac $cipher $macKey $iv
        $streams=New-Object 'Collections.Generic.List[object]'
        foreach ($stream in @(Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop | Where-Object {$_.Stream -notin @(':$DATA','$DATA')})) {
            if ($stream.Stream -match '[:\\/\x00]') {throw 'Unsupported alternate-stream name; original retained.'}
            $streamPath=$Path+':'+$stream.Stream
            $streamHash=Get-ShedStreamHash $streamPath
            $streamIv=New-Object byte[] 16; $rng.GetBytes($streamIv)
            $streamCipher=Join-Path $directory ('stream-'+[guid]::NewGuid().ToString('N')+'.aes')
            Protect-ShedFile $streamPath $streamCipher $key $streamIv
            $streamMac=Get-ShedHmac $streamCipher $macKey $streamIv
            Unprotect-ShedFile $streamCipher $verification $key $streamIv
            if ((Get-ShedStreamHash $verification) -ne $streamHash) {throw 'Alternate-stream verification failed; original retained.'}
            Remove-Item -LiteralPath $verification -Force -ErrorAction Stop
            $streams.Add(@{Name=$stream.Stream;Sha256=$streamHash;CipherPath=$streamCipher;IV=[Convert]::ToBase64String($streamIv);HmacSha256=$streamMac})
        }
        $wrapped=[Security.Cryptography.ProtectedData]::Protect($material,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        $manifest=[pscustomobject]@{SchemaVersion=1; Host=$Context.HostName; Utc=[DateTime]::UtcNow.ToString('o'); Status='CopiedNotRemoved';
            OriginalPath=$file.Path; Sha256=$file.Sha256; OriginalAcl=$acl; CreationUtc=$file.CreationUtc; LastWriteUtc=$file.LastWriteUtc;
            CipherPath=$cipher; ProtectedKey=[Convert]::ToBase64String($wrapped); IV=[Convert]::ToBase64String($iv); HmacSha256=$mac; Reason=$Reason; Attributes=$attributes; Streams=$streams.ToArray()}
        Write-ShedJson $manifestPath $manifest
        Unprotect-ShedFile $cipher $verification $key $iv
        if ((Get-FileHash -LiteralPath $verification -Algorithm SHA256 -ErrorAction Stop).Hash -ne $file.Sha256) {throw 'Quarantine round-trip verification failed; original retained.'}
        Remove-Item -LiteralPath $verification -Force -ErrorAction Stop
        if ((Get-ShedFileEvidence $Path).Sha256 -ne $file.Sha256) {throw 'Original changed during quarantine; original retained.'}
        foreach ($stream in $streams) {if ((Get-ShedStreamHash ($Path+':'+$stream.Name)) -ne $stream.Sha256) {throw 'An alternate stream changed during quarantine; original retained.'}}
        # Failure here leaves the encrypted evidence and CopiedNotRemoved record. Never kill a process.
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) {throw 'Original still exists after removal.'}
        $manifest.Status='Quarantined'; Write-ShedJson $manifestPath $manifest
        Write-ShedEvent $Context Quarantine $manifest
        return $manifestPath
    } finally {
        if (Test-Path -LiteralPath $verification) {Remove-Item -LiteralPath $verification -Force -ErrorAction Stop}
        [Array]::Clear($material,0,$material.Length)
        if ($key) {[Array]::Clear($key,0,$key.Length)}; if ($macKey) {[Array]::Clear($macKey,0,$macKey.Length)}
        $rng.Dispose()
    }
}

function Restore-ShedQuarantine {
    param($Context, [string]$ManifestPath, $Caller)
    $dataRoot=Get-ShedProperty $Context RequestedRoot $Context.Root
    if (-not (Test-ShedPathWithin $ManifestPath (Join-Path $dataRoot quarantine))) {throw 'Restore manifest must be in the protected quarantine store.'}
    Assert-ShedNoReparsePoint $ManifestPath
    $manifest=Read-ShedJson $ManifestPath
    if ($manifest.Host -ne $Context.HostName) {throw 'DPAPI quarantine belongs to a different host.'}
    if (-not (Test-ShedPathWithin $manifest.CipherPath (Split-Path -Parent $ManifestPath))) {throw 'Cipher path is outside its quarantine record.'}
    Assert-ShedNoReparsePoint $manifest.CipherPath; Assert-ShedNoReparsePoint $manifest.OriginalPath
    if (Test-Path -LiteralPath $manifest.OriginalPath) {throw 'Restore destination exists; no file will be overwritten.'}
    if (-not $Caller.ShouldProcess($manifest.OriginalPath,'Decrypt and restore reviewed quarantine record')) {return}
    $material=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($manifest.ProtectedKey),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    $temporary=Join-Path (Split-Path -Parent $ManifestPath) ('restore-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $stagedStreams=New-Object 'Collections.Generic.List[object]'
    $temporaryPaths=New-Object 'Collections.Generic.List[string]'
    $temporaryPaths.Add($temporary)
    $published=$false
    $key=$null; $macKey=$null
    try {
        $key=[byte[]]$material[0..31]; $macKey=[byte[]]$material[32..63]
        $iv=[Convert]::FromBase64String($manifest.IV)
        if ((Get-ShedHmac $manifest.CipherPath $macKey $iv) -cne $manifest.HmacSha256) {throw 'Encrypted evidence authentication failed.'}
        Unprotect-ShedFile $manifest.CipherPath $temporary $key $iv
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256 -ErrorAction Stop).Hash -ne $manifest.Sha256) {throw 'Restored content hash mismatch.'}
        # Authenticate and decrypt every stream before creating the restore destination.
        foreach ($stream in $manifest.Streams) {
            if ($stream.Name -match '[:\\/\x00]' -or -not (Test-ShedPathWithin $stream.CipherPath (Split-Path -Parent $ManifestPath))) {throw 'Invalid alternate-stream manifest.'}
            Assert-ShedNoReparsePoint $stream.CipherPath
            $streamIv=[Convert]::FromBase64String($stream.IV)
            if ((Get-ShedHmac $stream.CipherPath $macKey $streamIv) -cne $stream.HmacSha256) {throw 'Alternate-stream authentication failed.'}
            $streamTemporary=Join-Path (Split-Path -Parent $ManifestPath) ('restore-stream-'+[guid]::NewGuid().ToString('N')+'.tmp')
            $temporaryPaths.Add($streamTemporary)
            Unprotect-ShedFile $stream.CipherPath $streamTemporary $key $streamIv
            if ((Get-ShedStreamHash $streamTemporary) -ne $stream.Sha256) {throw 'Alternate-stream restoration hash mismatch.'}
            $stagedStreams.Add(@{Name=$stream.Name;Path=$streamTemporary})
        }
        Assert-ShedNoReparsePoint $manifest.OriginalPath
        [IO.File]::Copy($temporary,$manifest.OriginalPath,$false)
        $published=$true
        foreach ($stream in $stagedStreams) {
            $inputStream=$null; $outputStream=$null
            try {
                $inputStream=[IO.File]::OpenRead($stream.Path)
                $outputStream=[IO.File]::Open(($manifest.OriginalPath+':'+$stream.Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $inputStream.CopyTo($outputStream)
            } finally {if ($inputStream) {$inputStream.Dispose()};if ($outputStream) {$outputStream.Dispose()}}
        }
        $acl=New-Object Security.AccessControl.FileSecurity
        $acl.SetSecurityDescriptorSddlForm($manifest.OriginalAcl)
        Set-Acl -LiteralPath $manifest.OriginalPath -AclObject $acl -ErrorAction Stop
        [IO.File]::SetCreationTimeUtc($manifest.OriginalPath,[DateTime]::Parse($manifest.CreationUtc).ToUniversalTime())
        [IO.File]::SetLastWriteTimeUtc($manifest.OriginalPath,[DateTime]::Parse($manifest.LastWriteUtc).ToUniversalTime())
        [IO.File]::SetAttributes($manifest.OriginalPath,[IO.FileAttributes]$manifest.Attributes)
        $manifest.Status='Restored'; Write-ShedJson $ManifestPath $manifest
        Add-ShedResult $Context 'Quarantine restore' Succeeded $manifest.OriginalPath
    } catch {
        if ($published) {
            $manifest.Status='RestoreIncomplete'
            Write-ShedJson $ManifestPath $manifest
        }
        throw
    } finally {
        foreach ($path in $temporaryPaths) {if (Test-Path -LiteralPath $path) {Remove-Item -LiteralPath $path -Force -ErrorAction Stop}}
        [Array]::Clear($material,0,$material.Length)
        if ($key) {[Array]::Clear($key,0,$key.Length)}
        if ($macKey) {[Array]::Clear($macKey,0,$macKey.Length)}
    }
}

function Get-ShedCurrentSource {
    param($Source)
    switch ($Source.Type) {
        File {return [pscustomobject]@{Type='File'; Path=$Source.Path; Sha256=(Get-ShedFileEvidence $Source.Path).Sha256}}
        RegistryValue {return Get-ShedRegistryValueRecord $Source.KeyPath $Source.ValueName}
        ScheduledTask {return Get-ShedTaskRecord (Get-ScheduledTask -TaskName $Source.TaskName -TaskPath $Source.TaskPath -ErrorAction Stop)}
        WmiObject {
            $expected=Get-ShedFingerprint $Source
            foreach ($instance in @(Get-CimInstance -Namespace $Source.Namespace -ClassName $Source.ClassName -ErrorAction Stop)) {
                $record=ConvertTo-ShedCimRecord $instance
                if ((Get-ShedFingerprint $record) -eq $expected) {return $record}
            }
            throw 'WMI object changed or disappeared since review.'
        }
        default {throw "This inventory category cannot be remediated: $($Source.Type)"}
    }
}

function Open-ShedRegistryKey {
    param([string]$Path)
    if ($Path -notmatch '^Registry::HKEY_(LOCAL_MACHINE|USERS)\\(.+)$') {throw 'Unsupported registry hive in remediation plan.'}
    $hive=if ($matches[1] -eq 'USERS') {[Microsoft.Win32.RegistryHive]::Users} else {[Microsoft.Win32.RegistryHive]::LocalMachine}
    $subkey=$matches[2]
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]::Registry64)
    try {$key=$base.OpenSubKey($subkey,$true); if (-not $key) {throw 'Registry key is unavailable.'}; return $key} finally {$base.Dispose()}
}

function Restore-ShedPersistence {
    param($Context, [string]$BackupPath, $Caller)
    $dataRoot=Get-ShedProperty $Context RequestedRoot $Context.Root
    if (-not (Test-ShedPathWithin $BackupPath (Join-Path $dataRoot backups))) {throw 'Backup must be inside the protected backups directory.'}
    Assert-ShedNoReparsePoint $BackupPath
    $backup=Read-ShedJson $BackupPath
    if ($backup.Host -ne $Context.HostName) {throw 'Backup belongs to a different host.'}
    $source=$backup.Source
    if (-not $Caller.ShouldProcess($BackupPath,'Restore persistence definition from selected backup')) {return}
    switch ($source.Type) {
        RegistryValue {
            $key=Open-ShedRegistryKey $source.KeyPath
            try {
                $value=switch ($source.ValueKind) {'Binary' {,([byte[]]$source.Value)} 'MultiString' {,([string[]]$source.Value)} 'DWord' {[int]$source.Value} 'QWord' {[long]$source.Value} default {$source.Value}}
                $key.SetValue($source.ValueName,$value,([Microsoft.Win32.RegistryValueKind]$source.ValueKind))
            } finally {$key.Dispose()}
        }
        ScheduledTask {
            $existing=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -eq $source.TaskName -and $_.TaskPath -eq $source.TaskPath})
            if ($existing.Count) {
                if ($backup.Action -ne 'DisableTask' -or $existing.Count -ne 1) {throw 'Restore destination task already exists; it was not overwritten.'}
                $current=Get-ShedTaskRecord $existing[0]
                if ((Get-ShedTaskDefinitionFingerprint $current.Xml -IgnoreEnabled) -ne (Get-ShedTaskDefinitionFingerprint $source.Xml -IgnoreEnabled)) {throw 'The task definition changed; review it before restoring.'}
                $document=New-Object Xml.XmlDocument; $document.LoadXml($source.Xml)
                $enabled=$document.SelectSingleNode("//*[local-name()='Settings']/*[local-name()='Enabled']")
                if (-not $enabled -or $enabled.InnerText -ne 'false') {Enable-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -ErrorAction Stop | Out-Null}
                else {Disable-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -ErrorAction Stop | Out-Null}
            } else {Register-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -Xml $source.Xml -ErrorAction Stop | Out-Null}
        }
        WmiObject {
            $properties=ConvertFrom-ShedCimProperties $source
            New-CimInstance -Namespace $source.Namespace -ClassName $source.ClassName -Property $properties -ErrorAction Stop | Out-Null
        }
        default {throw 'Use RestoreQuarantine for files.'}
    }
    $restored=Get-ShedCurrentSource $source
    if ((Get-ShedFingerprint $restored) -ne (Get-ShedFingerprint $source)) {throw 'Restored persistence definition did not match its backup.'}
    Add-ShedResult $Context 'Persistence definition restore' Succeeded $BackupPath
}

function Invoke-ShedActionPlan {
    param($Context, [string]$PlanPath, $Caller)
    $plan=Read-ShedJson $PlanPath
    if ($plan.SchemaVersion -ne 1 -or $plan.Host -ne $Context.HostName) {throw 'Action plan schema or host does not match.'}
    Assert-ShedNoReparsePoint $plan.FindingsPath
    if ((Get-FileHash -LiteralPath $plan.FindingsPath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $plan.FindingsSha256) {throw 'The evidence file changed after the plan was created.'}
    $wanted=@{}; foreach ($action in @($plan.Actions)) {if ($wanted.ContainsKey($action.Id)) {throw 'Duplicate action Id in plan.'}; $wanted[$action.Id]=$action}
    $findings=@{}
    foreach ($line in [IO.File]::ReadLines($plan.FindingsPath)) {
        $record=$line | ConvertFrom-Json -ErrorAction Stop
        if ($wanted.ContainsKey($record.Id)) {
            if ($findings.ContainsKey($record.Id)) {throw 'Duplicate finding Id in evidence.'}
            $findings[$record.Id]=$record
        }
    }
    foreach ($action in @($plan.Actions)) {
        try {
            if (-not $findings.ContainsKey($action.Id)) {throw 'Action Id was not found in the reviewed evidence.'}
            $finding=$findings[$action.Id]
            if ($finding.Host -ne $Context.HostName -or $finding.RunId -ne $plan.RunId -or $action.Fingerprint -ne $finding.Fingerprint) {throw 'Finding identity does not match the reviewed action.'}
            $source=Get-ShedCurrentSource $finding.Source
            if ((Get-ShedFingerprint $source) -ne $finding.Fingerprint) {throw 'Source changed since review; collect and review fresh evidence.'}
            if (-not $Caller.ShouldProcess("$($finding.Category) $($action.Id)",$action.Action)) {Add-ShedResult $Context $action.Id Skipped; continue}
            $backup=[pscustomobject]@{Host=$Context.HostName; Utc=[DateTime]::UtcNow.ToString('o'); Action=$action.Action; Source=$source; FindingId=$finding.Id; Fingerprint=$finding.Fingerprint}
            $backupPath=Join-Path $Context.Root "backups\$($Context.RunId)-$($finding.Id).json"
            Write-ShedJson $backupPath $backup
            if ($action.Action -in @('Quarantine','DeleteFile') -and $source.Type -eq 'File') {
                $manifest=Invoke-ShedQuarantine $Context $source.Path $source.Sha256 "Reviewed action $($action.Action); finding $($finding.Id)"
                Add-ShedResult $Context $finding.Id Succeeded "Encrypted evidence and restore manifest: $manifest"
                continue
            }
            switch ($action.Action) {
                RemoveRegistryValue {
                    if ($source.Type -ne 'RegistryValue') {throw 'Action/type mismatch.'}
                    $key=Open-ShedRegistryKey $source.KeyPath
                    try {$key.DeleteValue($source.ValueName,$true); if ($source.ValueName -in $key.GetValueNames()) {throw 'Registry value still exists.'}} finally {$key.Dispose()}
                }
                DisableTask {
                    if ($source.Type -ne 'ScheduledTask') {throw 'Action/type mismatch.'}
                    Disable-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -ErrorAction Stop | Out-Null
                    if ((Get-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -ErrorAction Stop).State -ne 'Disabled') {throw 'Task did not become disabled.'}
                }
                RemoveTask {
                    if ($source.Type -ne 'ScheduledTask') {throw 'Action/type mismatch.'}
                    Unregister-ScheduledTask -TaskName $source.TaskName -TaskPath $source.TaskPath -Confirm:$false -ErrorAction Stop
                    if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -eq $source.TaskName -and $_.TaskPath -eq $source.TaskPath}).Count) {throw 'Task still exists after removal.'}
                }
                {$_ -in @('RemoveWmiBinding','RemoveWmiConsumer','RemoveWmiFilter')} {
                    if ($source.Type -ne 'WmiObject') {throw 'Action/type mismatch.'}
                    if ($action.Action -eq 'RemoveWmiBinding' -and $source.ClassName -ne '__FilterToConsumerBinding') {throw 'Select a binding object for RemoveWmiBinding.'}
                    if ($action.Action -eq 'RemoveWmiFilter' -and $source.ClassName -ne '__EventFilter') {throw 'Select an event filter for RemoveWmiFilter.'}
                    if ($action.Action -eq 'RemoveWmiConsumer' -and $source.ClassName -notlike '*EventConsumer') {throw 'Select an event consumer for RemoveWmiConsumer.'}
                    if ($action.Action -ne 'RemoveWmiBinding') {
                        $name=Get-ShedProperty $source.Properties Name
                        $bindings=@(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)
                        if (@($bindings | Where-Object {(Get-ShedProperty $_.Filter Name) -eq $name -or (Get-ShedProperty $_.Consumer Name) -eq $name}).Count) {throw 'Remove the reviewed related binding first; the filter/consumer remains active.'}
                    }
                    $removed=0
                    foreach ($instance in @(Get-CimInstance -Namespace $source.Namespace -ClassName $source.ClassName -ErrorAction Stop)) {
                        if ((Get-ShedFingerprint (ConvertTo-ShedCimRecord $instance)) -eq $finding.Fingerprint) {$instance | Remove-CimInstance -ErrorAction Stop; $removed++}
                    }
                    if ($removed -ne 1) {throw 'The selected WMI instance was not removed exactly once.'}
                }
                default {throw "Unsupported action: $($action.Action)"}
            }
            Add-ShedResult $Context $finding.Id Succeeded "Action $($action.Action); original definition: $backupPath"
        } catch {Add-ShedResult $Context $action.Id Failed $_.Exception.Message}
    }
}

$context=$null; $audit=$null; $exitCode=1; $caller=$PSCmdlet
try {
    Assert-ShedWindows
    if ($QuarantineAll) {throw '-QuarantineAll was retired. Collect evidence, review actions.template.json and use -ApplyPlan.'}
    if (@($ApplyPlan,$RestoreQuarantine,$RestoreBackup | Where-Object {$_}).Count -gt 1) {throw 'Choose one of ApplyPlan, RestoreQuarantine or RestoreBackup.'}
    if ($NonInteractive -and ($ApplyPlan -or $RestoreQuarantine -or $RestoreBackup) -and -not $PSBoundParameters.ContainsKey('Confirm')) {
        # The plan itself is explicit authorization; do not allow a hidden confirmation prompt in unattended runs.
        $ConfirmPreference='None'
    }
    $context=New-ShedContext -Name scraper -ToolsRoot $ToolsRoot -Simulation:$WhatIfPreference -NoTranscript
$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-scraper.ps1               |
     | ,      ,_ `\_/~\-           |      made for MWCCDC 2026-27' regionals    |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black
    if ($ApplyPlan) {Invoke-ShedActionPlan $context $ApplyPlan $caller}
    elseif ($RestoreQuarantine) {Restore-ShedQuarantine $context $RestoreQuarantine $caller}
    elseif ($RestoreBackup) {Restore-ShedPersistence $context $RestoreBackup $caller}
    else {
        $audit=New-ShedAudit $context $BaselinePath
        $profiles=@(Get-ShedProfileInventory)
        foreach ($stage in @('History','Startup','Tasks','WMI','Filesystem')) {
            try {
                switch ($stage) {
                    History {Get-ShedHistoryInventory $audit $profiles $DownloadHistoryLimit}
                    Startup {Get-ShedStartupInventory $audit $profiles}
                    Tasks {Get-ShedTaskInventory $audit}
                    WMI {Get-ShedWmiInventory $audit}
                    Filesystem {Get-ShedFilesystemInventory $audit $profiles ([bool]$FullScan) $TargetDrive}
                }
                Add-ShedResult $context "$stage collection" Succeeded
            } catch {Add-ShedResult $context "$stage collection" Incomplete $_.Exception.Message}
        }
    }
    $exitCode=Get-ShedExitCode $context
} catch {
    if ($context) {Add-ShedResult $context 'Scraper interrupted' Failed $_.Exception.Message} else {Write-Error -ErrorRecord $_ -ErrorAction Continue}
    $exitCode=1
} finally {
    if ($audit) {try {Complete-ShedAudit $audit} catch {Add-ShedResult $context 'Evidence export' Failed $_.Exception.Message; $exitCode=1}}
    if ($context) {try {Close-ShedContext $context} catch {Write-Error -ErrorRecord $_ -ErrorAction Continue; $exitCode=1}}
}
exit $exitCode
