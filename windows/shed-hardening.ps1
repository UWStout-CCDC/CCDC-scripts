#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Role-aware Windows hardening with staged AD rotation and remote-access recovery.
.DESCRIPTION
Standalone Windows hardening; no companion modules or configuration files are required.
Windows Server 2019 / Windows 10 1809+, x64, elevated PowerShell 5.1 or 7.
Account/service disablement and scoring lockout exemptions require explicit switches.
ScoringUsers accepts an array; the current operator, built-ins and service identities are protected.
Kerberos rotation is separate: -KrbtgtStage First, then Second after the effective ticket lifetime
and replication checks. Normal hardening never rotates krbtgt.
Remote runs arm timed SYSTEM rollback before changing management policy. Reconnect using the
reported transport and -ConfirmRemoteAccess ID -ManagementClientAddress CLIENT_IP to commit.
Manual management restore: -RecoveryMode Rollback -RecoveryStatePath STATE_JSON.
Add -RestoreCommitted only to explicitly restore a completed snapshot. Recovery restores
management/firewall state; password resets and other security settings are separate changes.
Use -WhatIf to inspect without applying host policy. Exit 1 means failed or incomplete work.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [ValidateSet('Auto','DC','DNS','MSSQL','Standalone')][string]$Role='Auto',
    [Alias('DefaultScoringUsers')][string[]]$ScoringUsers=@(),
    [string[]]$TrustedNetworks=@('Any'), [string[]]$ManagementAddresses=@('Any'),
    [ValidateRange(1,65535)][int[]]$SqlPorts=@(), [Security.SecureString]$AdministratorPassword,
    [switch]$SkipPasswordChange, [switch]$DisableNonScoringUsers, [switch]$DisableUnneededServices,
    [switch]$ExemptScoringLockout, [ValidateSet('None','First','Second')][string]$KrbtgtStage='None',
    [ValidatePattern('^[a-f0-9]{32}$')][string]$ConfirmRemoteAccess,
    [Net.IPAddress]$ManagementClientAddress,
    [ValidateRange(5,60)][int]$RollbackMinutes=15, [string]$ToolsRoot='C:\Tools',
    [switch]$NonInteractive, [switch]$OpenNetworkSettings, [switch]$Kerb,
    [ValidateSet('None','Rollback','Finalize')][string]$RecoveryMode='None',
    [string]$RecoveryStatePath, [switch]$RestoreCommitted
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

function Get-ShedHostRoles {
    param([string]$Role='Auto')
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $services=@(Get-CimInstance Win32_Service -ErrorAction Stop)
    $dc=($os.ProductType -eq 2)
    $dns=@($services | Where-Object Name -eq 'DNS').Count -gt 0
    $sql=@($services | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' })
    if ($Role -ne 'Auto') {
        if (($Role -eq 'DC') -ne $dc) { throw 'The requested role conflicts with actual domain-controller status.' }
        $dns=($Role -in @('DC','DNS')); if ($Role -ne 'MSSQL' -and -not $dc) { $sql=@() }
    }
    [pscustomobject]@{IsDC=$dc; IsDNS=$dns; IsSQL=($sql.Count -gt 0 -or $Role -eq 'MSSQL'); SqlServices=@($sql); Services=$services}
}

function Get-ShedFirewallPlan {
    param($Roles, [string[]]$TrustedNetworks=@('Any'), [string[]]$ManagementAddresses=@('Any'), [int[]]$SqlPorts=@(1433), [int]$RdpPort=3389, [int[]]$WinRMPorts=@(5985))
    $plan=New-Object 'Collections.Generic.List[object]'
    $plan.Add(@{Name='Shed-ICMP'; Protocol='ICMPv4'; IcmpType='8'; RemoteAddress=$TrustedNetworks})
    $plan.Add(@{Name='Shed-DHCP'; Protocol='UDP'; LocalPort=@('67','68'); RemoteAddress=$TrustedNetworks})
    $plan.Add(@{Name='Shed-NTP'; Protocol='UDP'; LocalPort=@('123'); RemoteAddress=$TrustedNetworks})
    if ($Roles.IsDNS) {
        foreach ($protocol in @('TCP','UDP')) { $plan.Add(@{Name="Shed-DNS-$protocol"; Protocol=$protocol; LocalPort=@('53'); RemoteAddress=$TrustedNetworks; Service='DNS'}) }
    }
    if ($Roles.IsDC) {
        foreach ($protocol in @('TCP','UDP')) {
            $plan.Add(@{Name="Shed-Kerberos-$protocol"; Protocol=$protocol; LocalPort=@('88','464'); RemoteAddress=$TrustedNetworks})
        }
        $plan.Add(@{Name='Shed-LDAP-TCP'; Protocol='TCP'; LocalPort=@('389','636','3268','3269'); RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-LDAP-UDP'; Protocol='UDP'; LocalPort=@('389'); RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-SMB'; Protocol='TCP'; LocalPort=@('445'); RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-RPC-Mapper'; Protocol='TCP'; LocalPort=@('RPC-EPMap'); Program="$env:SystemRoot\System32\svchost.exe"; Service='RpcSs'; RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-AD-RPC'; Protocol='TCP'; LocalPort=@('RPC'); Program="$env:SystemRoot\System32\lsass.exe"; RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-DFSR-RPC'; Protocol='TCP'; LocalPort=@('RPC'); Service='DFSR'; RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-ADWS'; Protocol='TCP'; LocalPort=@('9389'); Service='ADWS'; RemoteAddress=$TrustedNetworks})
        if ($WinRMPorts.Count) { $plan.Add(@{Name='Shed-WinRM'; Protocol='TCP'; LocalPort=@($WinRMPorts | ForEach-Object {[string]$_}); Service='WinRM'; RemoteAddress=$ManagementAddresses}) }
    }
    if ($Roles.IsSQL) {
        foreach ($protocol in @('TCP','UDP')) { $plan.Add(@{Name="Shed-RDP-$protocol"; Protocol=$protocol; LocalPort=@([string]$RdpPort); RemoteAddress=$ManagementAddresses}) }
        $plan.Add(@{Name='Shed-SQL'; Protocol='TCP'; LocalPort=@($SqlPorts | ForEach-Object {[string]$_}); RemoteAddress=$TrustedNetworks})
        $plan.Add(@{Name='Shed-SQL-Browser'; Protocol='UDP'; LocalPort=@('1434'); RemoteAddress=$TrustedNetworks; Service='SQLBrowser'})
    }
    foreach ($port in @(22,23)) { $plan.Add(@{Name="Shed-Block-$port"; Protocol='TCP'; LocalPort=@([string]$port); RemoteAddress=@('Any'); Action='Block'}) }
    return $plan.ToArray()
}

function Resolve-ShedAccounts {
    param([string[]]$Names, [bool]$IsDC, [string]$Server)
    $resolved=New-Object 'Collections.Generic.List[object]'
    foreach ($name in @($Names | ForEach-Object { $_ -split ',' } | ForEach-Object {$_.Trim()} | Where-Object {$_} | Select-Object -Unique)) {
        $account=if ($IsDC) { Get-ADUser -Identity $name -Server $Server -Properties Enabled -ErrorAction Stop } else { Get-LocalUser -Name $name -ErrorAction Stop }
        $sid=if ($IsDC) {$account.SID.Value} else {$account.SID.Value}
        $resolved.Add([pscustomobject]@{Name=$name; SID=$sid; Account=$account})
    }
    return $resolved.ToArray()
}

function Get-ShedTicketLifetime {
    param($Context)
    $path=Join-Path $Context.Root "backups\kerberos-policy-$($Context.RunId).inf"
    $null=Invoke-ShedNative "$env:SystemRoot\System32\secedit.exe" @('/export','/mergedpolicy','/cfg',$path,'/areas','SECURITYPOLICY','/quiet')
    $content=Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    $ticket=[regex]::Match($content,'(?m)^\s*MaxTicketAge\s*=\s*(\d+)\s*$')
    $service=[regex]::Match($content,'(?m)^\s*MaxServiceAge\s*=\s*(\d+)\s*$')
    $skew=[regex]::Match($content,'(?m)^\s*MaxClockSkew\s*=\s*(\d+)\s*$')
    if (-not $ticket.Success -or -not $service.Success -or -not $skew.Success) { throw 'Cannot establish effective Kerberos ticket lifetimes and clock tolerance; refusing rotation.' }
    # Zero means tickets never expire; a finite automatic wait cannot make that safe.
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0fce5b92-bcc1-4b96-9c2b-56397c3f144f
    if ([double]$ticket.Groups[1].Value -eq 0 -or [double]$service.Groups[1].Value -eq 0) {throw 'Nonexpiring Kerberos tickets require manual reconciliation before rotation.'}
    return [TimeSpan]::FromMinutes([Math]::Max([double]$ticket.Groups[1].Value*60,[double]$service.Groups[1].Value)+[double]$skew.Groups[1].Value)
}

function Test-ShedKrbtgtReplication {
    param([string]$Identity, [int]$Version, [string]$Domain)
    $controllers=@(Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop | Where-Object {-not $_.IsReadOnly})
    if (-not $controllers.Count) { throw 'No writable DCs could be enumerated.' }
    foreach ($controller in $controllers) {
        $account=Get-ADUser -Identity $Identity -Server $controller.HostName -Properties 'msDS-KeyVersionNumber' -ErrorAction Stop
        if ([int]$account.'msDS-KeyVersionNumber' -ne $Version) { return $false }
        $partners=@(Get-ADReplicationPartnerMetadata -Target $controller.HostName -Scope Server -ErrorAction Stop)
        if (@($partners | Where-Object LastReplicationResult -ne 0).Count) { return $false }
    }
    return $true
}

function Invoke-ShedKrbtgtStage {
    param($Context, [ValidateSet('First','Second')][string]$Stage, $Caller)
    $domain=Get-ADDomain -ErrorAction Stop
    $identity=$domain.DomainSID.Value + '-502'
    $journalRoot=if ($Context.PSObject.Properties['RequestedRoot']) {$Context.RequestedRoot} else {$Context.Root}
    $path=Join-Path $journalRoot "recovery\krbtgt-$($domain.DomainSID.Value).json"
    if (Test-Path -LiteralPath $path) {Assert-ShedNoReparsePoint $path; Assert-ShedExistingPathTrust $path}
    $state=if (Test-Path -LiteralPath $path) { Read-ShedJson $path } else {$null}
    $server=if ($state) {$state.Server} else {$domain.PDCEmulator}
    $writable=@(Get-ADDomainController -Filter * -Server $domain.DNSRoot -ErrorAction Stop | Where-Object {-not $_.IsReadOnly})
    if ($server -notin @($writable | ForEach-Object HostName)) {throw 'The journal server is not a writable DC in this domain.'}
    if ($state -and ($state.Identity -ne $identity -or $state.Phase -notin @('FirstPending','FirstComplete','SecondPending','SecondComplete'))) {throw 'Invalid krbtgt journal identity or phase.'}
    $account=Get-ADUser -Identity $identity -Server $server -Properties 'msDS-KeyVersionNumber',PasswordLastSet -ErrorAction Stop
    $version=[int]$account.'msDS-KeyVersionNumber'
    $lifetime=Get-ShedTicketLifetime $Context
    if ($state -and $state.Phase -like '*Pending') {
        if ($version -eq [int]$state.ExpectedVersion) {
            $state.Phase=$state.Phase.Replace('Pending','Complete')
            $state.ResetUtc=$account.PasswordLastSet.ToUniversalTime().ToString('o')
            if (-not ($Context.PSObject.Properties['Simulation'] -and $Context.Simulation)) {Write-ShedJson $path $state}
        } else { throw 'An interrupted reset has ambiguous state. Reconcile the recorded key version before another reset.' }
    }
    if ($Stage -eq 'First' -and $state -and $state.Phase -ne 'SecondComplete') {
        if ($version -ne [int]$state.ExpectedVersion) {throw 'krbtgt changed outside the recorded first stage; reconcile the journal before proceeding.'}
        if (-not (Test-ShedKrbtgtReplication $identity $version $domain.DNSRoot)) { throw 'The recorded first reset has not replicated cleanly to every writable DC.' }
        Add-ShedResult $Context 'krbtgt first stage' 'Succeeded' "Existing first stage verified; no password reset repeated. State: $path"
        return
    }
    if ($Stage -eq 'Second') {
        if ($state -and $state.Phase -eq 'SecondComplete') {
            if (-not (Test-ShedKrbtgtReplication $identity ([int]$state.ExpectedVersion) $domain.DNSRoot)) { throw 'Second reset has not replicated to all writable DCs.' }
            Add-ShedResult $Context 'krbtgt second stage' 'Succeeded' 'Already completed and replicated; no reset repeated.'
            return
        }
        if (-not $state -or $state.Phase -ne 'FirstComplete' -or $state.Identity -ne $identity) { throw 'A recorded, verified first reset is required.' }
        if ($version -ne [int]$state.ExpectedVersion) { throw 'krbtgt changed outside this recorded rotation; reconcile before proceeding.' }
        $required=[Math]::Max($lifetime.TotalSeconds,[double]$state.WaitSeconds)
        $due=[DateTime]::Parse($state.ResetUtc).ToUniversalTime().AddSeconds($required)
        if ([DateTime]::UtcNow -lt $due) { throw "Second reset is not permitted before $($due.ToString('o'))." }
    }
    if (-not (Test-ShedKrbtgtReplication $identity $version $domain.DNSRoot)) { throw 'DC key versions or replication health do not agree before the reset.' }
    if (-not $Caller.ShouldProcess("$identity on $server", "Reset krbtgt, $Stage stage")) { Add-ShedResult $Context 'krbtgt' 'Skipped'; return }
    $state=[pscustomobject]@{Identity=$identity; Server=$server; Phase=($Stage+'Pending'); ExpectedVersion=($version+1); ResetUtc=[DateTime]::UtcNow.ToString('o'); WaitSeconds=$lifetime.TotalSeconds}
    Write-ShedJson $path $state # Journal before the irreversible reset; interruption cannot silently repeat it.
    $random=New-Object byte[] 64; $generator=[Security.Cryptography.RandomNumberGenerator]::Create()
    $password=New-Object Security.SecureString
    $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    try { $generator.GetBytes($random); foreach ($value in $random) {$password.AppendChar($alphabet[[int]$value -band 63])}; $password.MakeReadOnly() }
    finally { [Array]::Clear($random,0,$random.Length); $generator.Dispose() }
    try { Set-ADAccountPassword -Identity $identity -Server $server -NewPassword $password -Reset -ErrorAction Stop }
    finally { if ($password) {$password.Dispose()} }
    $account=Get-ADUser -Identity $identity -Server $server -Properties 'msDS-KeyVersionNumber',PasswordLastSet -ErrorAction Stop
    if ([int]$account.'msDS-KeyVersionNumber' -ne $state.ExpectedVersion) { throw 'Unexpected key version after reset; journal remains pending.' }
    $state.Phase=$Stage+'Complete'; $state.ResetUtc=$account.PasswordLastSet.ToUniversalTime().ToString('o')
    Write-ShedJson $path $state
    $status=if (Test-ShedKrbtgtReplication $identity $state.ExpectedVersion $domain.DNSRoot) {'Succeeded'} else {'Incomplete'}
    Add-ShedResult $Context "krbtgt $Stage stage" $status "State saved at $path; the other stage requires a separate invocation."
}

function Get-ShedPsoSettings {
    param($Source)
    return @{
        ComplexityEnabled=[bool]$Source.ComplexityEnabled; PasswordHistoryCount=[int]$Source.PasswordHistoryCount
        MinPasswordLength=[int]$Source.MinPasswordLength; MinPasswordAge=[TimeSpan]$Source.MinPasswordAge
        MaxPasswordAge=[TimeSpan]$Source.MaxPasswordAge; ReversibleEncryptionEnabled=[bool]$Source.ReversibleEncryptionEnabled
        LockoutDuration=[TimeSpan]$Source.LockoutDuration; LockoutObservationWindow=[TimeSpan]$Source.LockoutObservationWindow
        LockoutThreshold=0
    }
}

function Set-ShedScoringPolicy {
    param($Context, $ScoringAccounts, [string]$Server, [bool]$Exempt, $Caller)
    $legacy=@(Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'CCDC-Exempt-Scoring-Lockout'" -Server $Server -Properties AppliesTo -ErrorAction Stop)
    $subjects=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($Exempt) { foreach ($account in $ScoringAccounts) {$null=$subjects.Add($account.SID)} }
    if ($legacy.Count) {
        $legacy | Export-Clixml -LiteralPath (Join-Path $Context.Root "backups\legacy-pso-$($Context.RunId).xml") -Depth 10 -ErrorAction Stop
        foreach ($subject in @($legacy[0].AppliesTo)) {
            $object=Get-ADObject -Identity $subject -Server $Server -Properties objectClass -ErrorAction Stop
            if ($object.ObjectClass -eq 'group') {
                foreach ($member in @(Get-ADGroupMember -Identity $subject -Recursive -Server $Server -ErrorAction Stop | Where-Object objectClass -eq 'user')) {$null=$subjects.Add($member.SID.Value)}
            } else {$null=$subjects.Add((Get-ADUser -Identity $subject -Server $Server -ErrorAction Stop).SID.Value)}
        }
        if (-not $Caller.ShouldProcess($legacy[0].DistinguishedName,'Replace legacy weakened scoring PSO')) { return }
        Remove-ADFineGrainedPasswordPolicy -Identity $legacy[0] -Server $Server -Confirm:$false -ErrorAction Stop
    }
    foreach ($sid in $subjects) {
        $user=Get-ADUser -Identity $sid -Server $Server -ErrorAction Stop
        $source=Get-ADUserResultantPasswordPolicy -Identity $user -Server $Server -ErrorAction Stop
        if (-not $source) {$source=Get-ADDefaultDomainPasswordPolicy -Server $Server -ErrorAction Stop}
        $settings=Get-ShedPsoSettings $source
        $name='Shed-Scoring-NoLockout-' + ($sid -split '-')[-1]
        $existing=@(Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -Server $Server -ErrorAction Stop)
        if (-not $Caller.ShouldProcess($user.SamAccountName,'Apply lockout-only exemption preserving password controls')) {continue}
        if ($existing.Count) {
            Set-ADFineGrainedPasswordPolicy -Identity $existing[0] @settings -Server $Server -ErrorAction Stop
        } else {
            $precedence=1000
            if ($source.PSObject.Properties['Precedence']) {
                if ($source.Precedence -le 1) {throw "Cannot deterministically supersede precedence-1 policy for $($user.SamAccountName). Existing stronger controls remain in force."}
                $precedence=[int]$source.Precedence-1
            }
            New-ADFineGrainedPasswordPolicy -Name $name -Precedence $precedence @settings -Server $Server -ErrorAction Stop | Out-Null
        }
        Add-ADFineGrainedPasswordPolicySubject -Identity $name -Subjects $user -Server $Server -ErrorAction Stop
        $effective=Get-ADUserResultantPasswordPolicy -Identity $user -Server $Server -ErrorAction Stop
        if (-not $effective -or $effective.Name -ne $name -or $effective.LockoutThreshold -ne 0) {throw "Exemption did not become effective for $($user.SamAccountName)."}
        foreach ($field in @('ComplexityEnabled','PasswordHistoryCount','MinPasswordLength','MinPasswordAge','MaxPasswordAge','ReversibleEncryptionEnabled')) {
            if ($effective.$field -ne $settings[$field]) {throw "Password setting $field changed unexpectedly for $($user.SamAccountName)."}
        }
        Add-ShedResult $Context "Scoring exemption: $($user.SamAccountName)" 'Succeeded' 'Password controls retained; resultant policy verified.'
    }
}

function Save-ShedManagementState {
    param($Context, $Services, [string[]]$DesiredTransports, $Session, [int]$RollbackMinutes=15, [string[]]$ManagementAddresses=@('LocalSubnet'))
    foreach ($existing in @(Get-ChildItem -LiteralPath (Join-Path $Context.Root recovery) -Filter state.json -File -Recurse -ErrorAction Stop)) {
        if ((Read-ShedJson $existing.FullName).Status -eq 'Pending') {throw "A management recovery transaction is still pending: $($existing.FullName)"}
    }
    $id=[guid]::NewGuid().ToString('N'); $directory=Join-Path $Context.Root "recovery\$id"
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $firewall=Join-Path $directory 'firewall.wfw'
    $null=Invoke-ShedNative "$env:SystemRoot\System32\netsh.exe" @('advfirewall','export',$firewall)
    if (-not (Test-Path -LiteralPath $firewall) -or (Get-Item -LiteralPath $firewall).Length -eq 0) {throw 'Firewall snapshot was not produced.'}
    $registry=New-Object 'Collections.Generic.List[object]'
    foreach ($spec in @(
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','UserAuthentication'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','SecurityLayer'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','MinEncryptionLevel'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','MaxIdleTime'))) {
        $key=Get-Item -LiteralPath $spec[0] -ErrorAction SilentlyContinue
        $exists=$key -and $spec[1] -in @($key.GetValueNames())
        $registry.Add(@{Path=$spec[0]; Name=$spec[1]; Exists=[bool]$exists; Value=$(if ($exists) {$key.GetValue($spec[1])} else {$null})})
    }
    $wsmanBackup=''
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN') {
        $wsmanBackup=Join-Path $directory 'wsman.reg'
        $null=Invoke-ShedNative "$env:SystemRoot\System32\reg.exe" @('export','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN',$wsmanBackup,'/y')
    }
    $managedNames=@('WinRM','TermService','sshd','ssh-agent','TlntSvr','AnyDesk','TeamViewer','uvnc_service','tightvnc','tvnserver','rustdesk','Spooler','RemoteRegistry','DiagTrack','PeerDistSvc','SharedAccess','lltdsvc','SSDPSRV','upnphost','WbioSrvc','SNMPTRAP')
    $serviceSnapshot=@(foreach ($service in @($Services | Where-Object {$_.Name -in $managedNames})) {
        $key=Get-Item -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name) -ErrorAction Stop
        try {[pscustomobject]@{Name=$service.Name;StartMode=$service.StartMode;State=$service.State;DelayedAutoStart=$key.GetValue('DelayedAutoStart',0)}} finally {$key.Dispose()}
    })
    $state=[pscustomobject]@{Id=$id; Host=[Environment]::MachineName; Status='Pending'; CreatedUtc=[DateTime]::UtcNow.ToString('o'); DeadlineUtc=[DateTime]::UtcNow.AddMinutes($RollbackMinutes).ToString('o');
        Firewall=$firewall; Services=$serviceSnapshot; Registry=$registry.ToArray(); WSManBackup=$wsmanBackup;
        DesiredTransports=$DesiredTransports; ManagementAddresses=$ManagementAddresses; OriginalTransport=$Session.Transport; DeferredServices=@(); GuardRules=@(); RollbackTask="Shed-Rollback-$id"; FinalizeTask="Shed-Finalize-$id"}
    $statePath=Join-Path $directory 'state.json'; Write-ShedJson $statePath $state
    $runner=Join-Path $directory 'shed-hardening.ps1'
    Assert-ShedNoReparsePoint $script:ShedSourcePath
    if ((Get-FileHash -LiteralPath $script:ShedSourcePath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $script:ShedSourceSha256) {throw 'The hardening source changed during this run.'}
    Copy-Item -LiteralPath $script:ShedSourcePath -Destination $runner -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $runner -Algorithm SHA256 -ErrorAction Stop).Hash -ne $script:ShedSourceSha256) {throw 'Recovery script copy hash mismatch.'}
    Set-ShedPrivateAcl $runner
    if ($Session.Remote) {
        $runner=Join-Path $directory 'shed-hardening.ps1'
        $arguments=@('-NoProfile','-NonInteractive','-File',$runner,'-RecoveryMode','Rollback','-RecoveryStatePath',$statePath,'-ToolsRoot',$Context.Root) | ForEach-Object {ConvertTo-ShedNativeArgument $_}
        $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ($arguments -join ' ')
        $trigger=New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes($RollbackMinutes))
        $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $null=Register-ScheduledTask -TaskName $state.RollbackTask -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop
        $recovery=[pscustomobject]@{State=$state;Path=$statePath}
        Add-ShedSessionGuard $recovery $Session
    }
    [pscustomobject]@{State=$state; Path=$statePath}
}

function Confirm-ShedRemoteAccess {
    param($Context, [ValidatePattern('^[a-f0-9]{32}$')][string]$Id, $Session, $Caller, [string]$ClientAddress='')
    $path=Join-Path $Context.RequestedRoot "recovery\$Id\state.json"
    Assert-ShedNoReparsePoint $path
    $state=Read-ShedJson $path
    if ($state.Host -ne [Environment]::MachineName -or $state.Status -ne 'Pending') {throw 'Recovery state does not match a pending run on this host.'}
    if ($Session.Transport -ne 'Console' -and $Session.Transport -notin $state.DesiredTransports) {throw 'Reconnect using an intended management transport or use the local console before confirming.'}
    if ($Session.Transport -ne 'Console') {
        if ($Session.Peer) {$ClientAddress=$Session.Peer}
        if (-not $ClientAddress) {throw 'Supply -ManagementClientAddress with this connection client IP to verify the permanent management scope.'}
        if (-not (Test-ShedAddressScope $ClientAddress $state.ManagementAddresses)) {throw 'The client address is outside the permanent management scope. The temporary recovery rule remains in place.'}
    }
    if ([DateTime]::UtcNow -ge [DateTime]::Parse($state.DeadlineUtc).ToUniversalTime().AddMinutes(-1)) {throw 'Recovery deadline is too close or has expired; allow rollback before retrying.'}
    if (-not $Caller.ShouldProcess($Id,'Confirm replacement access and run deferred local cleanup')) {return}
    $runner=Join-Path (Split-Path -Parent $path) 'shed-hardening.ps1'
    $arguments=@('-NoProfile','-NonInteractive','-File',$runner,'-RecoveryMode','Finalize','-RecoveryStatePath',$path,'-ToolsRoot',$Context.RequestedRoot) | ForEach-Object {ConvertTo-ShedNativeArgument $_}
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ($arguments -join ' ')
    $null=Register-ScheduledTask -TaskName $state.FinalizeTask -Action $action -User SYSTEM -RunLevel Highest -Force -ErrorAction Stop
    Start-ScheduledTask -TaskName $state.FinalizeTask -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    Write-ShedLog $Context 'Waiting for the local continuation; recovery remains armed until it commits.'
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $current=Read-ShedJson $path
        if ($current.Status -eq 'Committed') {Add-ShedResult $Context 'Remote continuation' Succeeded "Local cleanup committed: $path";return}
        if ($current.Status -eq 'RolledBack') {Add-ShedResult $Context 'Remote continuation' Failed 'Management changes were rolled back.';return}
    }
    Add-ShedResult $Context 'Remote continuation' 'Incomplete' "Local cleanup started. Inspect $path for Committed status; rollback stays armed until cleanup succeeds."
}

function Add-ShedSessionGuard {
    param($Recovery,$Session)
    $ports=switch ($Session.Transport) {'RDP' {3389} 'WinRM' {5985;5986} 'SSH' {22} default {throw 'Cannot protect an unidentified management transport.'}}
    if ($Session.Transport -eq 'RDP') {$ports=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop).PortNumber)}
    if ($Session.Transport -eq 'SSH') {$ports=@([int](($Session.Session -split '\s+')[3]))}
    if ($Session.Transport -eq 'WinRM' -and $Session.Session) {
        $endpoint=$null
        if ([uri]::TryCreate($Session.Session,[UriKind]::Absolute,[ref]$endpoint)) {$ports=@($endpoint.Port)}
    }
    $guard='Shed-Session-'+$Recovery.State.Id
    New-NetFirewallRule -Name $guard -DisplayName $guard -Group 'Shed Session Recovery' -Direction Inbound -Protocol TCP -LocalPort $ports -RemoteAddress $(if ($Session.Peer) {@($Session.Peer)} else {@('Any')}) -Action Allow -Profile Any -ErrorAction Stop | Out-Null
    $Recovery.State.GuardRules=@($guard); Write-ShedJson $Recovery.Path $Recovery.State
}

function Set-ShedFirewall {
    param($Context, $Plan, $Recovery, $Session)
    $desired=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $Plan) {
        if ($rule.ContainsKey('Service') -and -not (Get-Service -Name $rule.Service -ErrorAction SilentlyContinue)) {continue}
        # Preserve the transport carrying this run until a replacement session confirms access.
        if ($Session.Remote -and (($Session.Transport -eq 'SSH' -and $rule.Name -eq 'Shed-Block-22') -or $Session.Transport -eq 'Unknown')) {continue}
        $null=$desired.Add($rule.Name)
        $parameters=@{DisplayName=$rule.Name; Group='Shed Managed'; Direction='Inbound'; Action='Allow'; Enabled='True'; Profile='Any'}
        foreach ($key in $rule.Keys) {$parameters[$key]=$rule[$key]}
        $existing=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $rule.Name)
        if ($existing.Count) {$existing | Remove-NetFirewallRule -ErrorAction Stop}
        New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null
    }
    if ($Session.Remote -and -not @($Recovery.State.GuardRules).Count) {
        $ports=switch ($Session.Transport) {'RDP' {3389} 'WinRM' {5985;5986} 'SSH' {22} default {22;3389;5985;5986}}
        # RDP's actual configured port is used even for a nonstandard listener.
        if ($Session.Transport -eq 'RDP') {$ports=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop).PortNumber)}
        $guard='Shed-Session-' + $Recovery.State.Id
        $scope=if ($Session.Peer) {@($Session.Peer)} else {@('Any')}
        New-NetFirewallRule -Name $guard -DisplayName $guard -Group 'Shed Session Recovery' -Direction Inbound -Protocol TCP -LocalPort $ports -RemoteAddress $scope -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        $Recovery.State.GuardRules=@($guard); Write-ShedJson $Recovery.Path $Recovery.State
    }
    $legacyNames=@('ICMP-In','DHCP-In','NTP-In','DNS-UDP-In','DNS-TCP-In','WinRM-HTTP-In','WinRM-HTTPS-In','AD-LDAP-TCP','AD-CLDAP-UDP','AD-SMB-TCP','AD-RPC-EPMAP','AD-Kerberos-TCP','AD-Kerberos-UDP','AD-Kpasswd-TCP','AD-Kpasswd-UDP','RDP-TCP-In','RDP-UDP-In','MSSQL-TCP-In','MSSQL-UDP-In','Block-SSH','Block-Telnet') | ForEach-Object {'CCDC-'+$_}
    foreach ($old in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)) {
        if (($old.Group -eq 'Shed Managed' -and -not $desired.Contains($old.Name)) -or $old.DisplayName -in $legacyNames) {
            $old | Remove-NetFirewallRule -ErrorAction Stop
        }
    }
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -ErrorAction Stop
    foreach ($profileState in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        if ($profileState.Enabled -ne 'True' -or $profileState.DefaultInboundAction -ne 'Block') {throw 'Effective firewall profile does not enforce the requested enabled/default-block state.'}
    }
    $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)
    $inventory=@(foreach ($rule in $active) {
        $ports=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget)
        $addresses=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object LocalAddress,RemoteAddress)
        $applications=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object Program,Package)
        $services=@($rule | Get-NetFirewallServiceFilter -ErrorAction Stop | Select-Object Service)
        [pscustomobject]@{Name=$rule.Name; DisplayName=$rule.DisplayName; Group=$rule.Group; Action=[string]$rule.Action; Direction=[string]$rule.Direction; Profile=[string]$rule.Profile; Ports=$ports; Addresses=$addresses; Applications=$applications; Services=$services}
    })
    Write-ShedJson (Join-Path $Context.Root "backups\effective-firewall-$($Context.RunId).json") $inventory
    foreach ($name in $desired) {
        $effective=@($active | Where-Object Name -eq $name)
        $requested=@($Plan | Where-Object Name -eq $name)[0]
        $action=if ($requested.ContainsKey('Action')) {$requested.Action} else {'Allow'}
        if ($effective.Count -ne 1 -or $effective[0].Action -ne $action -or $effective[0].Direction -ne 'Inbound') {throw "Managed firewall rule is not uniquely active with its requested action: $name"}
    }
    $unmanaged=@($active | Where-Object { $_.Direction -eq 'Inbound' -and $_.Group -notin @('Shed Managed','Shed Session Recovery') })
    Write-ShedLog $Context "$($unmanaged.Count) other active inbound rules retained; review effective-firewall JSON for broad allows and conflicting blocks." 'WARN'
}

function Invoke-ShedRecovery {
    param([ValidateSet('Rollback','Finalize')][string]$Mode, [string]$StatePath, [switch]$RestoreCommitted)
Assert-ShedNoReparsePoint $StatePath
$lock=$null; $state=$null
try {
    $lock=[IO.File]::Open("$StatePath.lock",[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $state=Read-ShedJson $StatePath
    if ($state.Host -ne [Environment]::MachineName) {throw 'Recovery state belongs to another host.'}
    if ($state.Status -ne 'Pending' -and -not ($Mode -eq 'Rollback' -and $RestoreCommitted -and $state.Status -eq 'Committed')) {
        foreach ($task in @($state.RollbackTask,$state.FinalizeTask)) {if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop}}
        return 0
    }
    if ($Mode -eq 'Rollback') {
        $null=Invoke-ShedNative "$env:SystemRoot\System32\netsh.exe" @('advfirewall','import',$state.Firewall)
        foreach ($value in $state.Registry) {
            if ($value.Exists) {
                $null=New-Item -Path $value.Path -Force -ErrorAction Stop
                New-ItemProperty -Path $value.Path -Name $value.Name -Value $value.Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            } elseif (Test-Path -LiteralPath $value.Path) {
                $key=Get-Item -LiteralPath $value.Path -ErrorAction Stop
                if ($value.Name -in $key.GetValueNames()) {Remove-ItemProperty -LiteralPath $value.Path -Name $value.Name -ErrorAction Stop}
            }
        }
        if ($state.WSManBackup) {
            if (-not (Test-Path -LiteralPath $state.WSManBackup)) {throw 'WinRM registry recovery snapshot is missing.'}
            if ((Get-Service WinRM -ErrorAction Stop).Status -ne 'Stopped') {Stop-Service WinRM -Force -ErrorAction Stop}
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN') {
                $null=Invoke-ShedNative "$env:SystemRoot\System32\reg.exe" @('delete','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN','/f')
            }
            $null=Invoke-ShedNative "$env:SystemRoot\System32\reg.exe" @('import',$state.WSManBackup)
        }
        foreach ($service in $state.Services) {
            $startup=switch ($service.StartMode) {'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {throw "Unknown service mode: $($service.StartMode)"}}
            if ($service.State -eq 'Running' -and $startup -eq 'Disabled') {Set-Service $service.Name -StartupType Manual -ErrorAction Stop}
            else {Set-Service $service.Name -StartupType $startup -ErrorAction Stop}
            if ($service.State -eq 'Running') {Start-Service $service.Name -ErrorAction Stop}
            elseif ((Get-Service $service.Name -ErrorAction Stop).Status -ne 'Stopped') {Stop-Service $service.Name -ErrorAction Stop}
            Set-Service $service.Name -StartupType $startup -ErrorAction Stop
            New-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name) -Name DelayedAutoStart -Value ([int]$service.DelayedAutoStart) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        $state.Status='RolledBack'
    } else {
        if ([DateTime]::UtcNow -ge [DateTime]::Parse($state.DeadlineUtc).ToUniversalTime()) {throw 'Deadline passed; leaving rollback armed.'}
        foreach ($name in $state.DeferredServices) {
            if ($name -eq 'WinRM') {Disable-PSRemoting -Force -ErrorAction Stop}
            if ($name -eq 'TermService') {Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -ErrorAction Stop}
            Stop-Service -Name $name -Force -ErrorAction Stop
            Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
            if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Stopped') {throw "Deferred service remains running: $name"}
            if ($name -eq 'sshd') {
                New-NetFirewallRule -Name 'Shed-Block-22' -DisplayName 'Shed-Block-22' -Group 'Shed Managed' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Block -Profile Any -ErrorAction Stop | Out-Null
            }
        }
        foreach ($name in $state.GuardRules) {Get-NetFirewallRule -Name $name -ErrorAction Stop | Remove-NetFirewallRule -ErrorAction Stop}
        $state.Status='Committed'
    }
    Write-ShedJson $StatePath $state
    foreach ($task in @($state.RollbackTask,$state.FinalizeTask)) {
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop}
    }
} catch {
    [IO.File]::AppendAllText((Join-Path (Split-Path -Parent $StatePath) 'recovery-errors.log'),"$([DateTime]::UtcNow.ToString('o')) $($_.Exception.Message)`r`n")
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    return 1
} finally {if ($lock) {$lock.Dispose()}}

return 0
}

$context=$null; $exitCode=1; $caller=$PSCmdlet
try {
    Assert-ShedWindows
    $script:ShedSourcePath=$PSCommandPath
    $script:ShedSourceSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($RecoveryMode -ne 'None') {
        if (-not $RecoveryStatePath -or -not (Test-ShedPathWithin $RecoveryStatePath (Join-Path $ToolsRoot recovery))) {throw 'RecoveryStatePath must be within ToolsRoot\recovery.'}
        Assert-ShedExistingPathTrust $ToolsRoot
        Assert-ShedNoReparsePoint $RecoveryStatePath
        $recoveryAncestor=[IO.Path]::GetFullPath($RecoveryStatePath)
        while (Test-ShedPathWithin $recoveryAncestor $ToolsRoot) {
            Assert-ShedExistingPathTrust $recoveryAncestor
            $recoveryAncestor=Split-Path -Parent $recoveryAncestor
            if (-not $recoveryAncestor) {break}
        }
        if ($caller.ShouldProcess($RecoveryStatePath,"Apply management recovery: $RecoveryMode")) {
            $exitCode=Invoke-ShedRecovery $RecoveryMode $RecoveryStatePath -RestoreCommitted:$RestoreCommitted
        } else {$exitCode=0}
        exit $exitCode
    }
    $context=New-ShedContext -Name hardening -ToolsRoot $ToolsRoot -Simulation:$WhatIfPreference
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
    $remotingSender=Get-Variable PSSenderInfo -ValueOnly -ErrorAction SilentlyContinue
    $session=Get-ShedSession $remotingSender
    if ($ConfirmRemoteAccess) {
        Confirm-ShedRemoteAccess $context $ConfirmRemoteAccess $session $caller ([string]$ManagementClientAddress)
    } else {
        $roles=Get-ShedHostRoles $Role
        Write-ShedLog $context "DC=$($roles.IsDC); DNS=$($roles.IsDNS); SQL=$($roles.IsSQL); transport=$($session.Transport)"
        if ($session.Transport -eq 'Unknown') {throw 'Cannot identify the current management transport; use the local console.'}
        if ($Kerb) {Write-ShedLog $context '-Kerb is retained for compatibility; essential DC Kerberos rules are always included.' WARN}
        $server=''; $domain=$null
        if ($roles.IsDC) {Import-Module ActiveDirectory -ErrorAction Stop; $domain=Get-ADDomain -ErrorAction Stop; $server=$domain.PDCEmulator}
        else {Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop}
        if ($KrbtgtStage -ne 'None') {
            if (-not $roles.IsDC) {throw 'krbtgt rotation requires a writable DC.'}
            if ((Get-ADDomainController -Identity $env:COMPUTERNAME -Server $server -ErrorAction Stop).IsReadOnly) {throw 'Run krbtgt rotation from a writable DC, not an RODC.'}
            Invoke-ShedKrbtgtStage $context $KrbtgtStage $caller
        } else {
            if (-not $NonInteractive -and -not $WhatIfPreference) {
                $answer=Read-Host "Scoring usernames, comma-separated (Enter keeps: $($ScoringUsers -join ', '))"
                if ($answer.Trim()) {$ScoringUsers=@($answer -split ',' | ForEach-Object {$_.Trim()})}
            }
            $scoring=@(Resolve-ShedAccounts $ScoringUsers $roles.IsDC $server)
            $operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $allUsers=if ($roles.IsDC) {@(Get-ADUser -Filter * -Server $server -Properties Enabled,PasswordLastSet,LastLogonDate -ErrorAction Stop)} else {@(Get-LocalUser -ErrorAction Stop)}
            $admin=@($allUsers | Where-Object {$_.SID.Value -match '-500$'})
            if ($admin.Count -ne 1) {throw 'The built-in RID-500 Administrator could not be identified uniquely.'}
            $builtIns=@($allUsers | Where-Object {$_.SID.Value -match '-(500|501|502|503|504)$'} | ForEach-Object {$_.SID.Value})
            $serviceSids=New-Object 'Collections.Generic.List[string]'
            $unresolvedIdentities=New-Object 'Collections.Generic.List[string]'
            $serviceNames=@($roles.Services.StartName)
            foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {if ($task.Principal.UserId) {$serviceNames+=@($task.Principal.UserId)}}
            foreach ($name in @($serviceNames | Select-Object -Unique)) {
                if ($name -and $name -notin @('LocalSystem','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService')) {
                    try {
                        $sid=if ($name -match '^S-1-') {$name} else {([Security.Principal.NTAccount]$name).Translate([Security.Principal.SecurityIdentifier]).Value}
                        $serviceSids.Add($sid)
                    } catch {$unresolvedIdentities.Add($name); Write-ShedLog $context "Unresolved service/task identity: $name. Review before bulk account disablement." WARN}
                }
            }
            $protected=Get-ShedProtectedSidSet -ScoringSids @($scoring | ForEach-Object SID) -BuiltInSids $builtIns -OperatorSid $operatorSid -ServiceSids $serviceSids.ToArray()
            if ($DisableNonScoringUsers -and $unresolvedIdentities.Count) {throw "Resolve service/task identities before bulk disablement: $($unresolvedIdentities -join ', ')"}
            $allUsers | Select-Object Name,Enabled,SID,PasswordLastSet | Format-Table -AutoSize | Out-Host
            $groupSid=if ($roles.IsDC) {$domain.DomainSID.Value+'-512'} else {'S-1-5-32-544'}
            $members=if ($roles.IsDC) {@(Get-ADGroupMember -Identity $groupSid -Recursive -Server $server -ErrorAction Stop)} else {@(Get-LocalGroupMember -SID $groupSid -ErrorAction Stop)}
            Write-ShedEvent $context AdministrativeGroup @($members | Select-Object Name,SID,ObjectClass)
            if ($WhatIfPreference) {
                $null=$caller.ShouldProcess([Environment]::MachineName,'Apply role-aware hardening after a management snapshot')
                Add-ShedResult $context 'Hardening plan' Skipped 'WhatIf: no host policy, account, service or firewall changes.'
            } elseif ($caller.ShouldProcess([Environment]::MachineName,'Snapshot management state and apply hardening')) {
                $desired=@(); if ($roles.IsDC) {$desired+='WinRM'}; if ($roles.IsSQL) {$desired+='RDP'}
                if ($session.Remote -and $desired.Count -eq 0) {throw 'This profile has no replacement management transport; run from the console.'}
                $recovery=Save-ShedManagementState $context $roles.Services $desired $session $RollbackMinutes $ManagementAddresses
                Write-ShedLog $context "Management recovery state: $($recovery.Path)"
                if (-not $SkipPasswordChange) {
                    $password=$AdministratorPassword
                    if (-not $password -and -not $NonInteractive) {
                        do {
                            $password=Read-Host "New password for $($admin[0].Name) (RID 500)" -AsSecureString
                            $confirmation=Read-Host 'Confirm password' -AsSecureString
                            $same=Test-ShedSecureStringEqual $password $confirmation; $confirmation.Dispose()
                            if (-not $same -or $password.Length -eq 0) {$password.Dispose(); $password=$null; Write-Warning 'Passwords differ or are empty.'}
                        } while (-not $password)
                    }
                    if ($password) {
                        Invoke-ShedStep $context 'Administrator password' {
                            if ($roles.IsDC) {Set-ADAccountPassword -Identity $admin[0].SID -Server $server -NewPassword $password -Reset -ErrorAction Stop}
                            else {Set-LocalUser -SID $admin[0].SID -Password $password -ErrorAction Stop}
                        } -Enabled:($caller.ShouldProcess($admin[0].SID.Value,'Reset Administrator through a secure account API'))
                        if (-not $AdministratorPassword) {$password.Dispose()}; $password=$null
                        if ($roles.IsDC -and $context.Results[$context.Results.Count-1].Status -eq 'Succeeded') {
                            Invoke-ShedStep $context 'DSRM synchronization' {
                                $result=Invoke-ShedNative "$env:SystemRoot\System32\ntdsutil.exe" @('set dsrm password',"sync from domain account $($admin[0].SamAccountName)",'q','q')
                                if ($result.StdOut -notmatch 'success' -or $result.StdOut -match 'fail|error') {throw "DSRM sync was not verified: $($result.StdOut)"}
                            }
                        }
                    } else {Add-ShedResult $context 'Administrator password' Skipped 'No SecureString supplied for noninteractive execution.'}
                } else {Add-ShedResult $context 'Administrator password' Skipped 'Explicit SkipPasswordChange.'}
                if ($roles.IsDC) {
                    Invoke-ShedStep $context 'WinRM management' {
                        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
                        if ($PSVersionTable.PSEdition -eq 'Core') {
                            $null=Invoke-ShedNative "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile','-NonInteractive','-Command','Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop')
                        }
                        Set-Service WinRM -StartupType Automatic -ErrorAction Stop; Start-Service WinRM -ErrorAction Stop
                        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
                        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
                        Set-Item WSMan:\localhost\Client\Auth\Basic -Value $false -Force -ErrorAction Stop
                        Set-Item WSMan:\localhost\Service\CbtHardeningLevel -Value Relaxed -Force -ErrorAction Stop
                        Test-WSMan -ComputerName $env:COMPUTERNAME -Authentication Default -ErrorAction Stop | Out-Null
                    }
                    if ($context.Results[$context.Results.Count-1].Status -ne 'Succeeded') {throw 'Replacement WinRM failed verification; recovery remains armed.'}
                }
                if ($roles.IsSQL) {
                    Invoke-ShedStep $context 'RDP management' {
                        $ts='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; $tcp="$ts\WinStations\RDP-Tcp"
                        Set-ItemProperty $ts -Name fDenyTSConnections -Value 0 -ErrorAction Stop
                        foreach ($setting in @(@('UserAuthentication',1),@('SecurityLayer',2),@('MinEncryptionLevel',3))) {Set-ItemProperty $tcp -Name $setting[0] -Value $setting[1] -ErrorAction Stop}
                        $policy='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; $null=New-Item -Path $policy -Force -ErrorAction Stop
                        New-ItemProperty $policy -Name MaxIdleTime -Value 900000 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                        Set-Service TermService -StartupType Automatic -ErrorAction Stop; Start-Service TermService -ErrorAction Stop
                    }
                    if ($context.Results[$context.Results.Count-1].Status -ne 'Succeeded') {throw 'Replacement RDP failed configuration; recovery remains armed.'}
                }
                $rdpPort=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop).PortNumber
                if ($roles.IsSQL -and -not $SqlPorts.Count) {
                    $pids=@($roles.SqlServices | Where-Object ProcessId -gt 0 | Select-Object -ExpandProperty ProcessId)
                    $SqlPorts=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.OwningProcess -in $pids -and -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.LocalAddress))} | Select-Object -ExpandProperty LocalPort -Unique)
                    if (-not $SqlPorts.Count) {throw 'No SQL listener detected; supply the actual -SqlPorts.'}
                }
                $winrmPorts=@()
                if ($roles.IsDC) {
                    foreach ($listener in @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop)) {$winrmPorts+=@(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop | Where-Object Name -eq Port | ForEach-Object {[int]$_.Value})}
                    if (-not $winrmPorts.Count) {throw 'No configured WinRM listener found.'}
                }
                $plan=@(Get-ShedFirewallPlan $roles $TrustedNetworks $ManagementAddresses $SqlPorts $rdpPort $winrmPorts)
                Write-ShedJson (Join-Path $context.Root "backups\firewall-plan-$($context.RunId).json") $plan
                Set-ShedFirewall $context $plan $recovery $session
                Add-ShedResult $context 'Role firewall' Succeeded 'Managed rules verified; other effective rules inventoried.'
                if ($roles.IsSQL -and -not @(Get-NetTCPConnection -State Listen -LocalPort $rdpPort -ErrorAction Stop).Count) {throw 'RDP is not listening; recovery remains armed.'}
                $disable=@('sshd','ssh-agent','TlntSvr','AnyDesk','TeamViewer','uvnc_service','tightvnc','tvnserver','rustdesk')
                if (-not $roles.IsDC) {$disable+='WinRM'}; if (-not $roles.IsSQL) {$disable+='TermService'}
                if ($DisableUnneededServices) {$disable+=@('Spooler','RemoteRegistry','DiagTrack','PeerDistSvc','SharedAccess','lltdsvc','SSDPSRV','upnphost','WbioSrvc','SNMPTRAP')}
                foreach ($name in @($disable | Select-Object -Unique)) {
                    if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {continue}
                    $transport=switch ($name) {'sshd' {'SSH'} 'ssh-agent' {'SSH'} 'WinRM' {'WinRM'} 'TermService' {'RDP'} default {''}}
                    if ($session.Remote -and ($transport -eq $session.Transport -or $session.Transport -eq 'Unknown')) {
                        $recovery.State.DeferredServices+=@($name); Write-ShedJson $recovery.Path $recovery.State
                        Add-ShedResult $context "Disable $name" Skipped 'Deferred until replacement access is confirmed.'; continue
                    }
                    Invoke-ShedStep $context "Disable $name" {
                        if ($name -eq 'WinRM') {Disable-PSRemoting -Force -ErrorAction Stop}
                        if ($name -eq 'TermService') {Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -ErrorAction Stop}
                        Stop-Service $name -Force -ErrorAction Stop; Set-Service $name -StartupType Disabled -ErrorAction Stop
                    } {(Get-Service $name -ErrorAction Stop).Status -eq 'Stopped' -and (Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop).StartMode -eq 'Disabled'} -Enabled:($caller.ShouldProcess($name,'Stop and disable service'))
                }
                if ($DisableNonScoringUsers) {
                    if (-not $scoring.Count) {throw 'Bulk disablement requires explicit resolved ScoringUsers.'}
                    $candidates=@($allUsers | Where-Object {$_.Enabled -and -not $protected.Contains($_.SID.Value)})
                    $candidates | Select-Object Name,SID | Format-Table -AutoSize | Out-Host
                    Write-ShedJson (Join-Path $context.Root "backups\account-disable-plan-$($context.RunId).json") @($candidates | Select-Object Name,SID,Enabled)
                    $approved=$NonInteractive -or (Read-Host "Type DISABLE $($candidates.Count) to apply this account plan") -ceq "DISABLE $($candidates.Count)"
                    if ($approved) {
                        foreach ($user in $candidates) {
                            Invoke-ShedStep $context "Disable user $($user.Name)" {
                                if ($roles.IsDC) {Disable-ADAccount -Identity $user.SID -Server $server -ErrorAction Stop}
                                else {Disable-LocalUser -SID $user.SID -ErrorAction Stop}
                            } {
                                if ($roles.IsDC) {-not (Get-ADUser -Identity $user.SID -Server $server -ErrorAction Stop).Enabled}
                                else {-not (Get-LocalUser -SID $user.SID -ErrorAction Stop).Enabled}
                            } -Enabled:($caller.ShouldProcess($user.SID.Value,'Disable account in reviewed plan'))
                        }
                    } else {Add-ShedResult $context 'Account disable plan' Skipped 'Exact plan not confirmed.'}
                }
                $dormantPattern=if ($roles.IsDC) {'-501$'} else {'-(501|503|504)$'}
                foreach ($guest in @($allUsers | Where-Object {$_.SID.Value -match $dormantPattern -and $_.Enabled -and $_.SID.Value -notin @($scoring | ForEach-Object SID) -and $_.SID.Value -ne $operatorSid})) {
                    Invoke-ShedStep $context "Dormant built-in: $($guest.Name)" {
                        if ($roles.IsDC) {Disable-ADAccount -Identity $guest.SID -Server $server -ErrorAction Stop}
                        else {Disable-LocalUser -SID $guest.SID -ErrorAction Stop}
                    } -Enabled:($caller.ShouldProcess($guest.SID.Value,'Disable Guest'))
                }
                if ($roles.IsDC) {
                    $exempt = if ($PSBoundParameters.ContainsKey('ExemptScoringLockout')) { [bool]$ExemptScoringLockout } else { $true }
                    Invoke-ShedStep $context 'Scoring password policies' {Set-ShedScoringPolicy $context $scoring $server $exempt $caller}
                    Invoke-ShedStep $context 'Account lockout' {Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -Server $server -LockoutThreshold 10 -LockoutDuration (New-TimeSpan -Minutes 15) -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction Stop}
                } else {Invoke-ShedStep $context 'Account lockout' {$null=Invoke-ShedNative "$env:SystemRoot\System32\net.exe" @('accounts','/lockoutthreshold:10','/lockoutduration:15','/lockoutwindow:15')}}
                if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
                    Invoke-ShedStep $context 'Defender baseline' {Set-MpPreference -DisableRealtimeMonitoring $false -PUAProtection Enabled -ErrorAction Stop} {(Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled}
                } else {Add-ShedResult $context 'Defender baseline' Skipped 'Defender cmdlets absent; inspect active endpoint protection.'}
                Invoke-ShedStep $context 'SMB signing' {
                    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
                    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
                } {(Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature -and (Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature}
                Get-NetIPConfiguration -ErrorAction Stop | Format-List | Out-Host
                $hosts=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
                Write-ShedEvent $context HostsOverrides @(Get-Content -LiteralPath $hosts -ErrorAction Stop | Where-Object {$_ -notmatch '^\s*(#|$)'})
                if ($OpenNetworkSettings -and -not $NonInteractive) {Start-Process ncpa.cpl -ErrorAction Stop | Out-Null}
                if ($session.Remote) {
                    Add-ShedResult $context 'Management recovery' Incomplete "Reconnect using $($desired -join ' or ') and run .\shed-hardening.ps1 -ToolsRoot '$ToolsRoot' -ConfirmRemoteAccess $($recovery.State.Id) -ManagementClientAddress <client-IP>. Rollback: $($recovery.State.DeadlineUtc)."
                } else {$recovery.State.Status='Committed'; Write-ShedJson $recovery.Path $recovery.State}
            } else {Add-ShedResult $context Hardening Skipped Declined}
        }
    }
    $exitCode=Get-ShedExitCode $context
} catch {
    if ($context) {Add-ShedResult $context 'Hardening interrupted' Failed $_.Exception.Message} else {Write-Error -ErrorRecord $_ -ErrorAction Continue}
    $exitCode=1
} finally {if ($context) {try {Close-ShedContext $context} catch {Write-Error -ErrorRecord $_ -ErrorAction Continue; $exitCode=1}}}
exit $exitCode
