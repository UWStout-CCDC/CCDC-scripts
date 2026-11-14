#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install selected tools from reviewed, hash-locked artifacts and verify installed state.
.DESCRIPTION
Standalone installer with an embedded, reviewed package catalog; no lockfile is required.
Default tools include RunAsTrustedInstaller (RunAsTI64.exe) and Timeline Explorer.
All downloads require their pinned SHA-256. Mutable vendor URLs fail closed after upstream updates;
review a new artifact and update the embedded catalog before accepting a changed download.
Portable tools are published under ToolsRoot\bin; RunAsTrustedInstaller is installed, never launched.
Timeline Explorer includes its nested TimelineExplorer folder. Docker is opt-in with -Docker
or -Components Docker; automatic restarts are disabled. Public Npcap is interactive; unattended
OEM installation requires both -NpcapOemPath and -NpcapOemSha256.
WinGet, when available, only downloads pinned artifacts; verified direct downloads provide fallback.
Local companion scripts are copied when present; they are never downloaded from a mutable branch.
Use -WhatIf to inspect. Exit codes: 0 verified, 1 failed/incomplete, 3010 restart required.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [ValidateSet('Firefox','7Zip','FirewallControl','Malwarebytes','Sysinternals','Npcap','Docker','RunAsTrustedInstaller','TimelineExplorer')]
    [string[]]$Components=@('Firefox','7Zip','FirewallControl','Malwarebytes','Sysinternals','Npcap','RunAsTrustedInstaller','TimelineExplorer'),
    [switch]$Docker, [switch]$NonInteractive, [switch]$SkipWinget,
    [string]$NpcapOemPath, [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$NpcapOemSha256,
    [string]$ToolsRoot='C:\Tools'
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

function Read-ShedPackageLock {
    # Reviewed official sources and digests travel with this standalone script.
    $lock=@'
{
  "SchemaVersion": 1,
  "ReviewedDate": "2026-11-13",
  "WingetManifestCommit": "d4ba473606cda2b1a04e2b3a02851abca279253d",
  "Packages": [
    {
      "Name": "Firefox",
      "Id": "Mozilla.Firefox",
      "Version": "160.0",
      "Kind": "Exe",
      "Uri": "https://download-installer.cdn.mozilla.net/pub/firefox/releases/160.0/win64/en-US/Firefox%20Setup%20160.0.exe",
      "Sha256": "8732312EE2D7960C6EA830A4E0D3C0FF5FE0B10856DAB44E2C432FCDEB63FF63",
      "PublisherPattern": "Mozilla Corporation",
      "Arguments": [
        "/S",
        "/PreventRebootRequired=true"
      ],
      "DisplayNamePattern": "^Mozilla Firefox",
      "ExecutableRelativePath": "Mozilla Firefox\\firefox.exe",
      "SourceManifest": "https://raw.githubusercontent.com/microsoft/winget-pkgs/d4ba473606cda2b1a04e2b3a02851abca279253d/manifests/m/Mozilla/Firefox/160.0/Mozilla.Firefox.installer.yaml",
      "SourceManifestSha256": "6c1cbd01f5c91e3e9bf14358da31c331e21d504559450cfe498575fcd52e6d52"
    },
    {
      "Name": "7Zip",
      "Id": "7zip.7zip",
      "Version": "26.06",
      "Kind": "Msi",
      "Uri": "https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi",
      "Sha256": "6DC822569E777D9A3ECD5FFCBC22B55600AF87E6C5D9810A64E8566CF5A4AF9F",
      "PublisherPattern": "",
      "Arguments": [],
      "DisplayNamePattern": "^7-Zip",
      "ExecutableRelativePath": "7-Zip\\7z.exe",
      "SourceManifest": "https://raw.githubusercontent.com/microsoft/winget-pkgs/d4ba473606cda2b1a04e2b3a02851abca279253d/manifests/7/7zip/7zip/26.06/7zip.7zip.installer.yaml",
      "SourceManifestSha256": "9826689b28f1a7018a957227fa01444b5ceadfe225b2fbdef7f5379951b089bc"
    },
    {
      "Name": "FirewallControl",
      "Id": "BiniSoft.WindowsFirewallControl",
      "Version": "6.39.0.0",
      "Kind": "Exe",
      "Uri": "https://www.binisoft.org/download/wfc6setup.exe",
      "Sha256": "88C81C92DF17A9B28EF5FCBEDEC1FFFDD85ED5EB79957330B3ABD5B279E01230",
      "PublisherPattern": "Malwarebytes|BiniSoft",
      "Arguments": [
        "-run",
        "-close",
        "-install",
        "-update"
      ],
      "DisplayNamePattern": "^Windows Firewall Control",
      "ExecutableRelativePath": "Malwarebytes\\Windows Firewall Control\\wfc.exe",
      "SourceManifest": "https://raw.githubusercontent.com/microsoft/winget-pkgs/d4ba473606cda2b1a04e2b3a02851abca279253d/manifests/b/BiniSoft/WindowsFirewallControl/6.39.0.0/BiniSoft.WindowsFirewallControl.installer.yaml",
      "SourceManifestSha256": "a5c9786cab38dc745f61c3f31dceec6980160abf572ab660f7798e4a82aedd6b"
    },
    {
      "Name": "Malwarebytes",
      "Id": "Malwarebytes.Malwarebytes",
      "Version": "5.7.3.376",
      "Kind": "Exe",
      "Uri": "https://data-cdn.mbamupdates.com/web/mb5-setup-consumer/offline/mb5-setup-consumer-5.7.3.376-167.0.5780-1.0.115771.exe",
      "Sha256": "BE06E457881269992D5D8B57F2303F9BB3A73F25ECA301B801BFD46B0B049BDB",
      "PublisherPattern": "Malwarebytes",
      "Arguments": [
        "/VERYSILENT",
        "/NORESTART"
      ],
      "DisplayNamePattern": "^Malwarebytes",
      "ExecutableRelativePath": "Malwarebytes\\Anti-Malware\\mbam.exe",
      "SourceManifest": "https://raw.githubusercontent.com/microsoft/winget-pkgs/d4ba473606cda2b1a04e2b3a02851abca279253d/manifests/m/Malwarebytes/Malwarebytes/5.7.3.376/Malwarebytes.Malwarebytes.installer.yaml",
      "SourceManifestSha256": "94dc9ba235df635f21a33017ac2323b30b8e8a04852a29be2987e2118cb98630"
    },
    {
      "Name": "Sysinternals",
      "Id": "Microsoft.Sysinternals.Suite",
      "Version": "2026-10-15",
      "Kind": "Archive",
      "Uri": "https://download.sysinternals.com/files/SysinternalsSuite.zip",
      "Sha256": "E1E75DE5CDB12116B0A4ECA83725DC7C7A1645266196025CBE5CA6C167161AED",
      "PublisherPattern": "",
      "Arguments": [],
      "DisplayNamePattern": "",
      "ExecutableRelativePath": "Autoruns64.exe",
      "SourceManifest": "https://raw.githubusercontent.com/microsoft/winget-pkgs/d4ba473606cda2b1a04e2b3a02851abca279253d/manifests/m/Microsoft/Sysinternals/Suite/2026-10-15/Microsoft.Sysinternals.Suite.installer.yaml",
      "SourceManifestSha256": "dc16893e9987ed80cd36fec3ab0c78d72edf4ddd41e51a4d008569b06479c295"
    },
    {
      "Name": "Npcap",
      "Id": "Npcap",
      "Version": "1.90",
      "Kind": "Npcap",
      "Uri": "https://npcap.com/dist/npcap-1.90.exe",
      "Sha256": "682b57e1c05ef375931975c9d6ded40888f4bfdf9f4b11571e654f962f1199b6",
      "PublisherPattern": "Insecure\\.Com|Nmap Software",
      "Arguments": [
        "/winpcap_mode=yes",
        "/admin_only=yes",
        "/no_kill=yes"
      ],
      "DisplayNamePattern": "^Npcap",
      "ExecutableRelativePath": "",
      "SourceManifest": "https://npcap.com/dist/npcap-1.90.exe",
      "SourceManifestSha256": "682b57e1c05ef375931975c9d6ded40888f4bfdf9f4b11571e654f962f1199b6"
    },
    {
      "Name": "Docker",
      "Id": "Docker",
      "Version": "29.9.3",
      "Kind": "Docker",
      "Uri": "https://download.docker.com/win/static/stable/x86_64/docker-29.9.3.zip",
      "Sha256": "7c4ff7bbb31579046cd34dd8b91f7cbd3ab3482a1a85330170be726ef792d751",
      "PublisherPattern": "",
      "Arguments": [],
      "DisplayNamePattern": "",
      "ExecutableRelativePath": "docker.exe",
      "PayloadSha256": {
        "docker.exe": "82b011a6c253c6c6a273891133fbf8c76f0a909483f5c34e6dcb7ebc98b91dd5",
        "dockerd.exe": "3ce3b65813dee1d4ca4859d86c40cc1cccace541c412d18c0a0346e2e1236963"
      },
      "SourceManifest": "https://download.docker.com/win/static/stable/x86_64/",
      "SourceManifestSha256": ""
    },
    {
      "Name": "RunAsTrustedInstaller",
      "Id": "",
      "Version": "2.3.2",
      "Kind": "Portable",
      "Uri": "https://github.com/fafalone/RunAsTrustedInstaller/releases/download/v2.3.2/RunAsTI64.exe",
      "Sha256": "92A75D619744FC9559D50EAC77537C89A829FF63DE23162D6D63FCA15CA947DE",
      "PublisherPattern": "",
      "Arguments": [],
      "DisplayNamePattern": "",
      "ExecutableRelativePath": "RunAsTI64.exe",
      "SourceManifest": "https://github.com/fafalone/RunAsTrustedInstaller/releases/tag/v2.3.2"
    },
    {
      "Name": "TimelineExplorer",
      "Id": "",
      "Version": "2026.10.0",
      "Kind": "Archive",
      "Uri": "https://download.ericzimmermanstools.com/net/TimelineExplorer.zip",
      "Sha256": "DFB9C3055FEABAF57C05D0D380AC17E1F050B2628136CAF8BA7BE963FD3FED3E",
      "PublisherPattern": "",
      "PayloadPublisherPattern": "(?:^|,\\s*)(?:CN|O)=ZimTech LLC(?:,|$)",
      "Arguments": [],
      "DisplayNamePattern": "",
      "ExecutableRelativePath": "TimelineExplorer\\TimelineExplorer.exe",
      "SourceManifest": "https://ericzimmerman.github.io/"
    }
  ]
}
'@ | ConvertFrom-Json -ErrorAction Stop
    if ($lock.SchemaVersion -ne 1) {throw 'Unsupported package lock schema.'}
    $names=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($package in $lock.Packages) {
        if (-not $names.Add($package.Name)) {throw 'Duplicate package in embedded catalog.'}
        if ($package.Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or ([uri]$package.Uri).Scheme -ne 'https') {throw "Unpinned artifact in embedded catalog: $($package.Name)"}
        if ($package.Kind -notin @('Exe','Msi','Archive','Portable','Npcap','Docker')) {throw 'Unsupported installer kind.'}
        if ($package.Kind -eq 'Docker') {
            foreach ($name in @('docker.exe','dockerd.exe')) {if ($package.PayloadSha256.$name -notmatch '^[a-fA-F0-9]{64}$') {throw 'Docker executable hash missing.'}}
        }
    }
    return $lock
}

function Compare-ShedVersion {
    param([string]$Actual, [string]$Required)
    $left=@([regex]::Matches($Actual,'\d+') | ForEach-Object {[long]$_.Value})
    $right=@([regex]::Matches($Required,'\d+') | ForEach-Object {[long]$_.Value})
    if (-not $left.Count -or -not $right.Count) {throw 'Cannot compare nonnumeric package versions.'}
    for ($index=0; $index -lt [Math]::Max($left.Count,$right.Count); $index++) {
        $a=if ($index -lt $left.Count) {$left[$index]} else {0}
        $b=if ($index -lt $right.Count) {$right[$index]} else {0}
        if ($a -gt $b) {return 1}; if ($a -lt $b) {return -1}
    }
    return 0
}

function Get-ShedWinget {
    $candidates=New-Object 'Collections.Generic.List[string]'
    $command=Get-Command winget.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($command) {$candidates.Add($command.Source)}
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        foreach ($package in @(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction Stop | Sort-Object Version -Descending)) {
            $candidates.Add((Join-Path $package.InstallLocation winget.exe))
        }
    }
    foreach ($path in $candidates) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {continue}
        try {
            Assert-ShedNoReparsePoint $path
            $signature=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)(?:CN|O)=Microsoft Corporation(?:,|$)') {continue}
            $null=Invoke-ShedNative $path @('--version') -TimeoutSeconds 30
            return $path
        } catch {Write-Verbose "WinGet candidate rejected: $path : $($_.Exception.Message)"}
    }
    return $null
}

function Test-ShedPackageInstalled {
    param($Package, $Context)
    if ($Package.Kind -in @('Archive','Portable')) {
        $directory=Join-Path $Context.Root ('bin\'+$Package.Name)
        $receiptPath=Join-Path $directory '.shed-installed.json'
        if (-not (Test-Path -LiteralPath $receiptPath)) {return $false}
        $receipt=Read-ShedJson $receiptPath
        if (-not (Test-Path -LiteralPath (Join-Path $directory $Package.ExecutableRelativePath) -PathType Leaf)) {return $false}
        if ($receipt.ArtifactSha256 -ne $Package.Sha256) {return $false}
        foreach ($entry in $receipt.Files) {
            $path=Join-Path $directory $entry.RelativePath
            if (-not (Test-ShedPathWithin $path $directory) -or -not (Test-Path -LiteralPath $path)) {return $false}
            if ((Get-ShedFileEvidence $path).Sha256 -ne $entry.Sha256) {return $false}
        }
        return $receipt.Files.Count -gt 0
    }
    if ($Package.Kind -eq 'Docker') {
        $service=Get-Service docker -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -ne 'Running') {return $false}
        $directory=Join-Path $env:ProgramFiles Docker
        foreach ($name in @('docker.exe','dockerd.exe')) {
            $path=Join-Path $directory $name
            if (-not (Test-Path -LiteralPath $path)) {return $false}
            if ((Get-ShedFileEvidence $path).Sha256 -ne $Package.PayloadSha256.$name) {return $false}
        }
        $result=Invoke-ShedNative (Join-Path $directory docker.exe) @('version','--format','{{.Server.Version}}') -TimeoutSeconds 45 -AllowFailure
        return $result.ExitCode -eq 0 -and (Compare-ShedVersion $result.StdOut $Package.Version) -ge 0
    }
    if ($Package.Kind -eq 'Npcap') {
        $driver=Get-CimInstance Win32_SystemDriver -Filter "Name='npcap'" -ErrorAction SilentlyContinue
        if (-not $driver) {return $false}
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            if (-not (Test-Path -LiteralPath $root)) {continue}
            foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                try {
                    $version=$key.GetValue('DisplayVersion'); $name=$key.GetValue('DisplayName')
                    if ($name -match '^Npcap' -and $version -and (Compare-ShedVersion $version $Package.Version) -ge 0) {return $true}
                } finally {if ($null -ne $key) {$key.Dispose()}}
            }
        }
        return $false
    }
    $entries=New-Object 'Collections.Generic.List[object]'
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) {continue}
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            try {
                $name=$key.GetValue('DisplayName'); $version=$key.GetValue('DisplayVersion')
                if ($name -and $version -and $name -match $Package.DisplayNamePattern -and (Compare-ShedVersion $version $Package.Version) -ge 0) {$entries.Add(@{Name=$name; Version=$version})}
            } finally {if ($null -ne $key) {$key.Dispose()}}
        }
    }
    if (-not $entries.Count) {return $false}
    $candidates=@((Join-Path $env:ProgramFiles $Package.ExecutableRelativePath))
    if (${env:ProgramFiles(x86)}) {$candidates+=@(Join-Path ${env:ProgramFiles(x86)} $Package.ExecutableRelativePath)}
    if ($Package.Name -eq 'FirewallControl') {
        $candidates+=@((Join-Path $env:ProgramFiles 'Windows Firewall Control\wfc.exe'))
        if (${env:ProgramFiles(x86)}) {$candidates+=@(Join-Path ${env:ProgramFiles(x86)} 'Windows Firewall Control\wfc.exe')}
    }
    foreach ($path in $candidates) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {continue}
        $evidence=Get-ShedFileEvidence $path
        if ($Package.PublisherPattern -and ($evidence.Signature -ne 'Valid' -or $evidence.Publisher -notmatch $Package.PublisherPattern)) {continue}
        if ($Package.Name -eq 'Malwarebytes' -and (Get-Service MBAMService -ErrorAction Stop).Status -ne 'Running') {return $false}
        if ($Package.Name -eq 'FirewallControl' -and (Get-Service wfcs -ErrorAction Stop).Status -ne 'Running') {return $false}
        return $true
    }
    return $false
}

function Expand-ShedArchive {
    param([string]$Path, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) {throw 'Archive extraction requires a fresh destination.'}
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive=[IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($entry in $archive.Entries) {
            $relative=$entry.FullName.Replace('\',[string][IO.Path]::DirectorySeparatorChar).Replace('/',[string][IO.Path]::DirectorySeparatorChar)
            $target=[IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if (-not (Test-ShedPathWithin $target $Destination) -or [IO.Path]::IsPathRooted($relative) -or $entry.FullName -match '^[A-Za-z]:') {throw 'Archive entry escapes its destination.'}
            if (($entry.ExternalAttributes -shr 16 -band 61440) -eq 40960) {throw 'Archive contains a symbolic link.'}
        }
    } finally {$archive.Dispose()}
    [IO.Compression.ZipFile]::ExtractToDirectory($Path,$Destination)
}

function Install-ShedArchive {
    param($Context, $Package, [string]$ArchivePath)
    $staging=Join-Path $Context.Root ('downloads\extract-'+[guid]::NewGuid().ToString('N'))
    $destination=Join-Path $Context.Root ('bin\'+$Package.Name)
    $previous=Join-Path $Context.Root ('backups\'+$Package.Name+'-'+[guid]::NewGuid().ToString('N'))
    try {
        if ($Package.Kind -eq 'Portable') {
            $null=New-Item -ItemType Directory -Path $staging -ErrorAction Stop
            $null=Assert-ShedArtifact $ArchivePath $Package.Sha256 $Package.PublisherPattern
            Copy-Item -LiteralPath $ArchivePath -Destination (Join-Path $staging $Package.ExecutableRelativePath) -ErrorAction Stop
        } else {Expand-ShedArchive $ArchivePath $staging}
        if (-not (Test-Path -LiteralPath (Join-Path $staging $Package.ExecutableRelativePath))) {throw 'Expected archive executable is absent.'}
        if ($Package.PSObject.Properties['PayloadPublisherPattern'] -and $Package.PayloadPublisherPattern) {
            $payload=Get-ShedFileEvidence (Join-Path $staging $Package.ExecutableRelativePath)
            if ($payload.Signature -ne 'Valid' -or $payload.Publisher -notmatch $Package.PayloadPublisherPattern) {throw 'Archive executable publisher validation failed.'}
        }
        $files=@(Get-ShedFiles -Roots @($staging) | ForEach-Object {
            $evidence=Get-ShedFileEvidence $_.FullName
            [pscustomobject]@{RelativePath=$_.FullName.Substring($staging.Length).TrimStart('\','/'); Sha256=$evidence.Sha256}
        })
        Write-ShedJson (Join-Path $staging '.shed-installed.json') @{ArtifactSha256=$Package.Sha256; Files=$files}
        if (Test-Path -LiteralPath $destination) {Move-Item -LiteralPath $destination -Destination $previous -ErrorAction Stop}
        try {Move-Item -LiteralPath $staging -Destination $destination -ErrorAction Stop}
        catch {if (Test-Path -LiteralPath $previous) {Move-Item -LiteralPath $previous -Destination $destination -ErrorAction Stop}; throw}
        Set-ShedPrivateAcl $destination -AllowUsersRead
        foreach ($file in Get-ShedFiles -Roots @($destination)) {Set-ShedPrivateAcl $file.FullName -AllowUsersRead}
        if (-not (Test-ShedPackageInstalled $Package $Context)) {throw 'Published archive did not pass receipt validation.'}
    } finally {if (Test-Path -LiteralPath $staging) {Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop}}
}

function Install-ShedDocker {
    param($Context, $Package, [string]$ArchivePath)
    # Feature enablement is local and explicitly forbids an automatic restart.
    if (Get-Module -ListAvailable -Name ServerManager) {
        Import-Module ServerManager -ErrorAction Stop
        $feature=Get-WindowsFeature Containers -ErrorAction Stop
        if (-not $feature.Installed) {
            $result=Install-WindowsFeature Containers -Restart:$false -ErrorAction Stop
            if (-not $result.Success) {throw 'Containers feature installation failed.'}
            if ($result.RestartNeeded -eq 'Yes') {return 3010}
        }
    } elseif (Get-Command Enable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $feature=Get-WindowsOptionalFeature -Online -FeatureName Containers -ErrorAction Stop
        if ($feature.State -ne 'Enabled') {
            $result=Enable-WindowsOptionalFeature -Online -FeatureName Containers -NoRestart -ErrorAction Stop
            if ($result.RestartNeeded) {return 3010}
        }
    } else {
        throw 'Neither ServerManager nor OptionalFeature cmdlets are available to enable Containers.'
    }
    $staging=Join-Path $Context.Root ('downloads\docker-'+[guid]::NewGuid().ToString('N'))
    try {
        Expand-ShedArchive $ArchivePath $staging
        foreach ($name in @('docker.exe','dockerd.exe')) {$null=Assert-ShedArtifact (Join-Path $staging "docker\$name") $Package.PayloadSha256.$name}
        if (Get-Service docker -ErrorAction SilentlyContinue) {throw 'An existing nonmatching Docker service requires a planned upgrade; it was left intact.'}
        $directory=Join-Path $env:ProgramFiles Docker
        Assert-ShedNoReparsePoint $directory
        $null=New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
        foreach ($name in @('docker.exe','dockerd.exe')) {
            Copy-Item -LiteralPath (Join-Path $staging "docker\$name") -Destination (Join-Path $directory $name) -Force -ErrorAction Stop
            $null=Assert-ShedArtifact (Join-Path $directory $name) $Package.PayloadSha256.$name
        }
        $config=Join-Path $env:ProgramData 'docker\config'
        Assert-ShedNoReparsePoint $config
        $null=New-Item -ItemType Directory -Path $config -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath (Join-Path $config daemon.json))) {Write-ShedJson (Join-Path $config daemon.json) @{hosts=@('npipe://')}}
        $null=Invoke-ShedNative (Join-Path $directory dockerd.exe) @('--register-service','--service-name','docker')
        Set-Service docker -StartupType Automatic -ErrorAction Stop; Start-Service docker -ErrorAction Stop
        if (-not (Test-ShedPackageInstalled $Package $Context)) {throw 'Docker service/server health check failed.'}
        return 0
    } finally {if (Test-Path -LiteralPath $staging) {Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop}}
}

function Invoke-ShedPackageInstall {
    param($Context, $Package, [string]$WingetPath, [bool]$NonInteractive, [string]$NpcapOemPath='', [string]$NpcapOemSha256='')
    try {
        if (Test-ShedPackageInstalled $Package $Context) {Add-ShedResult $Context $Package.Name Succeeded 'Installed state already meets the reviewed lock; no reinstall.'; return}
        if ($Package.Kind -eq 'Npcap' -and $NonInteractive -and -not $NpcapOemPath) {Add-ShedResult $Context Npcap Incomplete 'Public Npcap requires interactive installation; supply a reviewed OEM path and SHA-256 for silent mode.'; return}
        $extension=if ($Package.Kind -in @('Archive','Docker')) {'.zip'} elseif ($Package.Kind -eq 'Msi') {'.msi'} else {'.exe'}
        $destination=Join-Path $Context.Root ("downloads\$($Package.Name)-$($Package.Version)$extension")
        $prefetched=$false
        if ($WingetPath -and $Package.Kind -in @('Exe','Msi')) {
            $stage=Join-Path $Context.Root ('downloads\winget-'+[guid]::NewGuid().ToString('N'))
            $null=New-Item -ItemType Directory -Path $stage -ErrorAction Stop
            $cleanupStage=$true
            try {
                # WinGet metadata cannot substitute its own hash for the reviewed lock.
                # It only downloads; execution always follows our artifact validation.
                $result=Invoke-ShedNative $WingetPath @('download','--id',$Package.Id,'--exact','--version',$Package.Version,'--source','winget','--scope','machine','--download-directory',$stage,'--accept-package-agreements','--accept-source-agreements','--disable-interactivity') -AllowFailure
                Write-ShedEvent $Context Installer @{Package=$Package.Name; Method='WinGetDownload'; ExitCode=$result.ExitCode; StdOut=$result.StdOut; StdErr=$result.StdErr}
                foreach ($candidate in Get-ShedFiles -Roots @($stage) -Extensions @($extension) -Context $Context) {
                    if ((Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -ne $Package.Sha256) {continue}
                    $null=Assert-ShedArtifact $candidate.FullName $Package.Sha256 $Package.PublisherPattern
                    $publish=$destination+'.'+[guid]::NewGuid().ToString('N')+$extension
                    try {
                        [IO.File]::Copy($candidate.FullName,$publish,$false)
                        $null=Assert-ShedArtifact $publish $Package.Sha256 $Package.PublisherPattern
                        if (Test-Path -LiteralPath $destination) {[IO.File]::Replace($publish,$destination,[NullString]::Value)} else {[IO.File]::Move($publish,$destination)}
                        Set-ShedPrivateAcl $destination; $prefetched=$true
                    } finally {if (Test-Path -LiteralPath $publish) {Remove-Item -LiteralPath $publish -Force -ErrorAction Stop}}
                    break
                }
            } catch {
                if ($_.Exception.Data.Contains('ProcessStillRunning')) {$cleanupStage=$false}
                throw
            } finally {if ($cleanupStage) {Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop}}
            if (-not $prefetched) {Write-ShedLog $Context "WinGet did not supply the exact locked artifact for $($Package.Name); using its reviewed HTTPS URL." WARN}
        }
        if (-not $prefetched) {
            if ($Package.Kind -eq 'Npcap' -and $NpcapOemPath) {
                $null=Assert-ShedArtifact $NpcapOemPath $NpcapOemSha256 $Package.PublisherPattern
                Copy-Item -LiteralPath $NpcapOemPath -Destination $destination -Force -ErrorAction Stop
                $null=Assert-ShedArtifact $destination $NpcapOemSha256 $Package.PublisherPattern
            } else {$null=Get-ShedVerifiedDownload $Context $Package.Uri $destination $Package.Sha256 $Package.PublisherPattern}
        }
        $code=0
        switch ($Package.Kind) {
            Archive {Install-ShedArchive $Context $Package $destination}
            Portable {Install-ShedArchive $Context $Package $destination}
            Docker {$code=Install-ShedDocker $Context $Package $destination}
            Msi {
                $log=Join-Path $Context.Root "logs\$($Package.Name)-$($Context.RunId)-msi.log"
                $result=Invoke-ShedNative "$env:SystemRoot\System32\msiexec.exe" @('/i',$destination,'/qn','/norestart','/L*v',$log) -SuccessCodes @(0,3010)
                $code=$result.ExitCode
            }
            default {
                $arguments=@($Package.Arguments)
                if ($Package.Kind -eq 'Npcap' -and $NpcapOemPath) {$arguments=@('/S')+$arguments}
                $result=Invoke-ShedNative $destination $arguments -SuccessCodes @(0,3010)
                $code=$result.ExitCode
                Write-ShedEvent $Context Installer @{Package=$Package.Name; Method='VerifiedDirect'; ExitCode=$code; StdOut=$result.StdOut; StdErr=$result.StdErr}
            }
        }
        if ($code -eq 3010) {Add-ShedResult $Context $Package.Name RebootRequired 'Restart is required before final health verification; rerun afterward. No restart was initiated.'}
        elseif (Test-ShedPackageInstalled $Package $Context) {Add-ShedResult $Context $Package.Name Succeeded 'Installed state verified.'}
        else {throw 'Installer returned success but the installed-state check failed.'}
    } catch {
        Add-ShedResult $Context $Package.Name Failed $_.Exception.Message
        if ($_.Exception.Data.Contains('ProcessStillRunning')) {throw}
    }
}

function Merge-ShedPath {
    param([string]$Current, [string[]]$Additions)
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $entries=New-Object 'Collections.Generic.List[string]'
    foreach ($entry in @($Current -split ';') + @($Additions)) {
        if (-not $entry.Trim()) {continue}
        $normalized=[Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"')).TrimEnd('\','/')
        if ($seen.Add($normalized)) {$entries.Add($entry.Trim())}
    }
    return $entries -join ';'
}

function Set-ShedToolPath {
    param($Context, [string[]]$Directories)
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$true)
    try {
        $raw=[string]$key.GetValue('Path','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind=$key.GetValueKind('Path')
        foreach ($directory in $Directories) {Assert-ShedNoReparsePoint $directory; if (-not (Test-ShedPathWithin $directory (Join-Path $Context.Root bin))) {throw 'Only protected executable directories are added to PATH.'}}
        $merged=Merge-ShedPath $raw $Directories
        if ($merged -ne $raw) {$key.SetValue('Path',$merged,$kind)}
        # Keep the current process's already expanded machine/user entries. Never inject raw %...% tokens.
        $env:Path=Merge-ShedPath $env:Path $Directories
    } finally {if ($null -ne $key) {$key.Dispose()}}
}

function Copy-ShedBundle {
    param($Context, [string]$SourceDirectory)
    $destination=Join-Path $Context.Root 'bin\Shed'
    if ([IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\') -eq $destination.TrimEnd('\')) {return}
    $staging=Join-Path $Context.Root ('downloads\bundle-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $staging -ErrorAction Stop
    try {
        foreach ($name in @('shed-hardening.ps1','shed-installs.ps1','shed-scraper.ps1')) {
            $source=Join-Path $SourceDirectory $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {Write-ShedLog $Context "Companion script absent locally: $name" WARN; continue}
            $file=Get-Item -LiteralPath $source -ErrorAction Stop
            Assert-ShedNoReparsePoint $file.FullName
            $target=Join-Path $staging $file.Name
            Copy-Item -LiteralPath $file.FullName -Destination $target -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) {throw 'Local bundle copy hash mismatch.'}
        }
        $previous=Join-Path $Context.Root ('backups\Shed-'+$Context.RunId)
        if (Test-Path -LiteralPath $destination) {Move-Item -LiteralPath $destination -Destination $previous -ErrorAction Stop}
        try {Move-Item -LiteralPath $staging -Destination $destination -ErrorAction Stop}
        catch {if (Test-Path -LiteralPath $previous) {Move-Item -LiteralPath $previous -Destination $destination -ErrorAction Stop}; throw}
        Set-ShedPrivateAcl $destination -AllowUsersRead
        foreach ($file in Get-ShedFiles -Roots @($destination)) {Set-ShedPrivateAcl $file.FullName -AllowUsersRead}
    } finally {if (Test-Path -LiteralPath $staging) {Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop}}
}

$context=$null; $exitCode=1
try {
    Assert-ShedWindows
    if ([bool]$NpcapOemPath -ne [bool]$NpcapOemSha256) {throw 'Supply both NpcapOemPath and NpcapOemSha256.'}
    $lock=Read-ShedPackageLock
    $context=New-ShedContext -Name installs -ToolsRoot $ToolsRoot -Simulation:$WhatIfPreference
$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-installs.ps1              |
     | ,      ,_ `\_/~\-           |   made for MWCCDC 2026-27' invitationals   |
     >/'>/ ~|||`\( ,~\-            |                                            |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black
    if ($Docker) {$Components+=@('Docker')}
    $winget=$null
    if (-not $SkipWinget -and -not $WhatIfPreference) {
        try {$winget=Get-ShedWinget} catch {Write-ShedLog $context "WinGet unavailable: $($_.Exception.Message)" WARN}
        if (-not $winget) {Add-ShedResult $context 'WinGet bootstrap' Skipped 'Using verified direct installers. No Gallery trust changes or unsupported portable extraction.'}
    }
    foreach ($name in @($Components | Select-Object -Unique)) {
        $package=@($lock.Packages | Where-Object Name -eq $name)
        if ($package.Count -ne 1) {Add-ShedResult $context $name Failed 'Selected component missing from embedded catalog.'; continue}
        if ($PSCmdlet.ShouldProcess("$name $($package[0].Version)",'Install hash-locked component and verify resulting state')) {
            Invoke-ShedPackageInstall $context $package[0] $winget ([bool]$NonInteractive) $NpcapOemPath $NpcapOemSha256
        } else {Add-ShedResult $context $name Skipped 'Not applied.'}
    }
    if ($PSCmdlet.ShouldProcess((Join-Path $ToolsRoot 'bin\Shed'),'Copy complete local Shed bundle with hash verification')) {
        Invoke-ShedStep $context 'Local Shed bundle' {Copy-ShedBundle $context $PSScriptRoot}
    }
    if (-not $WhatIfPreference) {
        $directories=@()
        foreach ($name in @('Sysinternals','RunAsTrustedInstaller','TimelineExplorer')) {
            $package=@($lock.Packages | Where-Object Name -eq $name)[0]
            if (Test-ShedPackageInstalled $package $context) {$directory=Join-Path $context.Root ('bin\'+$name); if ($name -eq 'TimelineExplorer') {$directory=Join-Path $directory TimelineExplorer}; $directories+=@($directory)}
        }
        if ($directories.Count -and $PSCmdlet.ShouldProcess('Machine PATH','Add validated tool directories')) {Invoke-ShedStep $context 'Tool PATH' {Set-ShedToolPath $context $directories}}
    }
    $exitCode=Get-ShedExitCode $context
} catch {
    if ($context) {Add-ShedResult $context 'Installer interrupted' Failed $_.Exception.Message} else {Write-Error -ErrorRecord $_ -ErrorAction Continue}
    $exitCode=1
} finally {if ($context) {try {Close-ShedContext $context} catch {Write-Error -ErrorRecord $_ -ErrorAction Continue; $exitCode=1}}}
exit $exitCode
