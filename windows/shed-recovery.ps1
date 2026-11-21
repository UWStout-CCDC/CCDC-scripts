#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Interactive AD-DNS service baseline and recovery draft.
.DESCRIPTION
Launch in a fresh elevated Windows PowerShell session:
  powershell.exe -NoLogo -NoProfile -File C:\Tools\shed-recovery.ps1
Enter finishes. Audit/capture/compare do not change services. Capture a baseline
only after independently verifying that the host is healthy, then keep a copy
and its SHA-256 off this server. A locally stored hash is not proof of origin.
Recovery requires a matching host baseline and a SHA-256 from that trusted copy.
Only startup mode and starting a stopped service are supported. Executable,
account, parameters, dependencies, ACL and file-hash drift block recovery.
This first draft supports AD-DNS only. SQL/AD ACL/database/binary repair is deferred.
.NOTES
Version: 1.2
Release: Post-invitationals updates.
Reports: C:\Tools\logs\recovery-<run>. Baselines/pre-change snapshots/actions
are kept there with Administrators/SYSTEM access. No automatic rollback/restart.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-RecoveryLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level='INFO')
    $color = @{INFO='White';WARN='Yellow';ERROR='Red';SUCCESS='Green'}[$Level]
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $color -BackgroundColor Black
}
function Read-RecoveryChoice {
    param([string]$Prompt, [string[]]$Choices, [string]$Default='F')
    do {
        $value = (Read-Host "$Prompt (Enter = $Default)").Trim().ToUpperInvariant()
        if (-not $value) { $value=$Default }
    } while ($value -notin $Choices)
    return $value
}

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

# Fixed service scope. Optional role services retain their captured running/stopped state.
function Get-RecoveryServiceNames {
    @('NTDS','DNS','Netlogon','Kdc','W32Time','ADWS','WinRM','Dnscache','LanmanServer','CertSvc','WAS','W3SVC')
}
function Get-RecoveryRegistryValues {
    param([string]$Path, [string[]]$Exclude=@())
    $key=Get-Item -LiteralPath $Path -ErrorAction Stop
    $values=[ordered]@{}
    foreach ($name in @($key.GetValueNames() | Sort-Object)) {
        if ($name -in $Exclude) { continue }
        $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($value -is [byte[]]) { $value=[Convert]::ToBase64String($value) }
        $label=if($name -eq ''){'(Default)'}else{$name}
        if ($values.Contains($label)) { throw 'Ambiguous registry value names.' }
        $values[$label]=[ordered]@{Kind=[string]$key.GetValueKind($name);Value=$value}
    }
    return $values
}
function Get-RecoveryBinaryEvidence {
    param([string]$Path, [hashtable]$Cache)
    $expanded=[Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)) { $expanded=Join-Path $env:SystemRoot $expanded.Substring(12) }
    if (-not [IO.Path]::IsPathRooted($expanded) -or $expanded.StartsWith('\\')) { throw "Binary path must be a local absolute path: $Path" }
    $expanded=[IO.Path]::GetFullPath($expanded)
    if ($Cache.ContainsKey($expanded)) { return $Cache[$expanded] }
    if (-not (Test-TrustedPath $expanded)) { throw "Binary path has unsafe ownership/permissions or links: $expanded" }
    $item=Get-Item -LiteralPath $expanded -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 128MB) { throw "Unexpected service binary: $expanded" }
    $record=[PSCustomObject]@{Path=$expanded;SHA256=(Get-FileHash -LiteralPath $expanded -Algorithm SHA256 -ErrorAction Stop).Hash}
    $Cache[$expanded]=$record
    return $record
}
function Get-RecoverySnapshot {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($os.ProductType -ne 2) { throw 'This draft supports AD-DNS domain controllers only.' }
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $machine=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop
    $all=@(Get-CimInstance Win32_Service -ErrorAction Stop)
    if (@($all | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' }).Count) { throw 'Mixed AD/SQL roles are outside this draft.' }
    $cache=@{}
    $records=@(foreach ($name in Get-RecoveryServiceNames) {
        $service=@($all | Where-Object Name -EQ $name)
        $required=$name -notin @('CertSvc','WAS','W3SVC')
        $row=[ordered]@{Name=$name;Required=$required;Exists=($service.Count -eq 1);State='Absent';Start=-1;Delayed=0;Config=$null;Files=@();Error=''}
        try {
            if ($service.Count -gt 1 -or ($required -and -not $service.Count)) { throw 'Required service missing or identity ambiguous.' }
            if ($service.Count) {
                $s=$service[0]; $path="HKLM:\SYSTEM\CurrentControlSet\Services\$name"
                $key=Get-Item -LiteralPath $path -ErrorAction Stop
                if ('Start' -notin $key.GetValueNames()) { throw 'Startup value missing.' }
                $row.State=[string]$s.State; $row.Start=[int]$key.GetValue('Start')
                $delayed=$key.GetValue('DelayedAutoStart',0)
                $row.Delayed=if($row.Start -eq 2){[int]$delayed}else{0}
                $parameters="$path\Parameters"
                $parameterValues=[ordered]@{}
                $parameterAcl=''
                if (Test-Path -LiteralPath $parameters -ErrorAction Stop) {
                    $parameterValues=Get-RecoveryRegistryValues $parameters
                    $parameterAcl=(Get-Acl -LiteralPath $parameters -ErrorAction Stop).Sddl
                }
                $row.Config=[ordered]@{
                    PathName=[string]$s.PathName; Account=[string]$s.StartName; ServiceType=[string]$s.ServiceType
                    Registry=Get-RecoveryRegistryValues $path @('Start','DelayedAutoStart')
                    Parameters=$parameterValues; RegistryAcl=(Get-Acl -LiteralPath $path -ErrorAction Stop).Sddl
                    ParametersAcl=$parameterAcl
                    Dependencies=@((Get-Service -Name $name -ErrorAction Stop).RequiredServices.Name | Sort-Object)
                }
                $command=[Environment]::ExpandEnvironmentVariables([string]$s.PathName).Trim()
                $exe=if($command -match '^"([^"\r\n]+\.exe)"(?:\s|$)'){$Matches[1]}
                    elseif($command -match '^([^\s"]+\.exe)(?:\s|$)'){$Matches[1]}
                    else{throw 'Ambiguous/unquoted executable path; manual review required.'}
                $files=@(Get-RecoveryBinaryEvidence $exe $cache)
                if ($parameterValues.Contains('ServiceDll')) {
                    $files+=Get-RecoveryBinaryEvidence ([string]$parameterValues['ServiceDll'].Value) $cache
                }
                $row.Files=$files
            }
        } catch { $row.Error=[string]$_ }
        [PSCustomObject]$row
    })
    [PSCustomObject]@{
        SchemaVersion=1;ScriptVersion='1.2';CapturedAtUtc=[DateTime]::UtcNow.ToString('o')
        Host=[PSCustomObject]@{ComputerName=[string]$computer.Name;Domain=[string]$computer.Domain;MachineGuid=[string]$machine.MachineGuid;Build=[string]$os.BuildNumber;Role='AD-DNS'}
        Complete=(@($records | Where-Object Error).Count -eq 0); Services=$records
    }
}
function Save-RecoverySnapshot {
    param($Snapshot, [string]$Directory, [string]$Label)
    $path=Join-Path $Directory "$Label-$([guid]::NewGuid().ToString('N')).json"
    $Snapshot | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    $read=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($read.Services.Count -ne $Snapshot.Services.Count -or $read.Host.MachineGuid -cne $Snapshot.Host.MachineGuid) { throw 'Snapshot read-back failed.' }
    [PSCustomObject]@{Path=$path;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}
}
# Canonical comparison includes every registry/parameter value and file hash.
# These snapshots come from this schema, whose object property order is stable.
function Get-RecoveryServiceFingerprint {
    param($Service, [switch]$IncludeRuntime)
    $value=[ordered]@{Name=$Service.Name;Exists=$Service.Exists;Config=$Service.Config;Files=@($Service.Files);Error=$Service.Error}
    if ($IncludeRuntime) { $value.Start=$Service.Start; $value.Delayed=$Service.Delayed; $value.State=$Service.State }
    $value | ConvertTo-Json -Depth 18 -Compress
}
function Assert-RecoveryBaseline {
    param($Baseline, $Current)
    if ($Baseline.SchemaVersion -ne 1 -or $Baseline.Complete -ne $true) { throw 'Baseline schema is unsupported or capture was incomplete.' }
    foreach ($field in @('ComputerName','Domain','MachineGuid','Build','Role')) {
        if ([string]::IsNullOrWhiteSpace([string]$Baseline.Host.$field) -or $Baseline.Host.$field -cne $Current.Host.$field) { throw "Baseline belongs to a different host/build/role ($field mismatch)." }
    }
    $names=@(Get-RecoveryServiceNames)
    if (@($Baseline.Services).Count -ne $names.Count) { throw 'Baseline service scope is incomplete.' }
    foreach ($name in $names) {
        $row=@($Baseline.Services | Where-Object Name -CEQ $name)
        if ($row.Count -ne 1) { throw "Baseline missing or duplicate service: $name" }
        $row=$row[0]
        $required=$name -notin @('CertSvc','WAS','W3SVC')
        if ($row.Error -or ($required -and ($row.Exists -ne $true -or $row.State -ne 'Running' -or $row.Start -notin @(2,3))) -or
            ($row.Exists -and (-not $row.Config -or -not @($row.Files).Count))) { throw "Baseline is not eligible as a healthy reference: $name" }
        if ($row.Exists) {
            if ($row.Start -notin @(2,3,4) -or $row.Delayed -notin @(0,1) -or $row.State -notin @('Running','Stopped')) { throw "Invalid startup values: $name" }
            foreach ($file in $row.Files) {
                if (-not $file.Path -or $file.SHA256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "Invalid binary evidence: $name" }
            }
        }
    }
}
function Read-RecoveryBaseline {
    param([string]$Path, [string]$ExpectedHash, $Current)
    if ($ExpectedHash -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Enter the 64-character SHA-256 saved independently from the healthy host.' }
    if (-not (Test-TrustedPath $Path)) { throw 'Baseline path must have trusted ownership/permissions and no links.' }
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 2MB) { throw 'Invalid baseline file size/type.' }
    # Hash the actual bytes parsed, so replacing the file between hashing and
    # deserializing cannot substitute a different baseline in this operation.
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','') } finally { $sha.Dispose() }
    if ($hash -ine $ExpectedHash) { throw 'Baseline SHA-256 does not match the independently saved hash.' }
    $baseline=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
    Assert-RecoveryBaseline $baseline $Current
    return $baseline
}
function Get-RecoveryPlan {
    param($Baseline, $Current)
    Assert-RecoveryBaseline $Baseline $Current
    $id=0
    foreach ($expected in $Baseline.Services) {
        $id++
        $observed=@($Current.Services | Where-Object Name -CEQ $expected.Name)
        $reason=''; $action='Report only'
        if ($observed.Count -ne 1) { $reason='Current service is missing or ambiguous.' }
        else {
            $observed=$observed[0]
            if ($observed.Error) { $reason="Current collection failed: $($observed.Error)" }
            elseif (-not $expected.Exists -or -not $observed.Exists) { $reason='Service installation changed or optional service absent.' }
            elseif ((Get-RecoveryServiceFingerprint $expected) -cne (Get-RecoveryServiceFingerprint $observed)) {
                $reason='Binary/hash, account, registry, parameters, dependencies or ACL changed. Starting it is blocked.'
            } elseif ($observed.State -notin @('Running','Stopped')) { $reason='Service is in a transitional/unsupported state; rescan.' }
            elseif ($expected.State -eq 'Running' -and $expected.Start -in @(2,3) -and
                ($expected.Start -ne $observed.Start -or $expected.Delayed -ne $observed.Delayed -or $observed.State -ne 'Running')) {
                $action='Restore startup / start'; $reason='Launch configuration and recorded binaries match baseline.'
            } elseif ($expected.State -ne $observed.State -or $expected.Start -ne $observed.Start -or $expected.Delayed -ne $observed.Delayed) {
                $reason='Captured optional service state is not an eligible start repair; review manually.'
            } else { $action='No change'; $reason='Matches baseline.' }
        }
        [PSCustomObject]@{ID=$id;Name=$expected.Name;Action=$action;ExpectedStart=$expected.Start;ExpectedDelayed=$expected.Delayed;CurrentStart=$observed.Start;CurrentState=$observed.State;Details=$reason}
    }
}
function Add-RecoveryAction {
    param([string]$Path, [string]$Status, $Data)
    [PSCustomObject]@{TimeUtc=[DateTime]::UtcNow.ToString('o');Status=$Status;Data=$Data} |
        ConvertTo-Json -Depth 18 -Compress | Add-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}
function Set-RecoveryStartup {
    param([string]$Name, [int]$Start, [int]$Delayed)
    if ($Name -cnotin @(Get-RecoveryServiceNames) -or $Start -notin @(2,3) -or $Delayed -notin @(0,1)) { throw 'Unsupported service/startup repair.' }
    $mode=if($Start -eq 3){'demand'}elseif($Delayed -eq 1){'delayed-auto'}else{'auto'}
    $output=& "$env:SystemRoot\System32\sc.exe" config $Name 'start=' $mode 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Service configuration exit $LASTEXITCODE`: $output" }
}
function Start-RecoveryService {
    param([string]$Name)
    $service=Get-Service -Name $Name -ErrorAction Stop
    if (@($service.RequiredServices | Where-Object Status -NE Running).Count) { throw 'A dependency is stopped. Review and recover dependencies separately first.' }
    if ([string]$service.Status -ne 'Stopped') { throw 'Service is no longer stopped; rescan.' }
    Start-Service -InputObject $service -ErrorAction Stop
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
}
function Invoke-RecoveryServiceRepair {
    param($Baseline, $Preview, [int]$ID, [string]$Directory)
    $plan=@(Get-RecoveryPlan $Baseline $Preview)
    $selected=@($plan | Where-Object ID -EQ $ID)
    if ($selected.Count -ne 1 -or $selected[0].Action -ne 'Restore startup / start') { throw 'Select an eligible startup/start repair ID.' }
    $name=$selected[0].Name
    $selected | Format-List | Out-String | Write-Host
    if ((Read-Host "Type REPAIR $name to restore startup and start if stopped") -cne "REPAIR $name") { return }
    $journal=Join-Path $Directory 'actions.jsonl'
    $prepared=$false; $saved=$null
    try {
        $fresh=Get-RecoverySnapshot
        $previous=@($Preview.Services | Where-Object Name -CEQ $name)[0]
        $current=@($fresh.Services | Where-Object Name -CEQ $name)[0]
        if ((Get-RecoveryServiceFingerprint $previous -IncludeRuntime) -cne (Get-RecoveryServiceFingerprint $current -IncludeRuntime)) { throw 'Service changed since preview. Rescan before changing it.' }
        $eligible=@(Get-RecoveryPlan $Baseline $fresh | Where-Object Name -CEQ $name)[0]
        if ($eligible.Action -ne 'Restore startup / start') { throw 'Service is no longer eligible.' }
        $saved=Save-RecoverySnapshot $fresh $Directory 'before-repair'
        $data=[PSCustomObject]@{Name=$name;BeforeSnapshot=$saved;Before=$current;Requested=$eligible}
        Add-RecoveryAction $journal Prepared $data
        $prepared=$true
        if ($current.Start -ne $eligible.ExpectedStart -or $current.Delayed -ne $eligible.ExpectedDelayed) {
            Set-RecoveryStartup $name $eligible.ExpectedStart $eligible.ExpectedDelayed
        }
        # Verify config and startup again before starting any code.
        $verify=Get-RecoverySnapshot
        $verified=@($verify.Services | Where-Object Name -CEQ $name)[0]
        $expected=@($Baseline.Services | Where-Object Name -CEQ $name)[0]
        if ($verified.Error -or (Get-RecoveryServiceFingerprint $expected) -cne (Get-RecoveryServiceFingerprint $verified) -or
            $verified.Start -ne $expected.Start -or $verified.Delayed -ne $expected.Delayed) { throw 'Configuration/startup verification failed; service start skipped.' }
        if ($verified.State -eq 'Stopped') { Start-RecoveryService $name }
        elseif ($verified.State -ne 'Running') { throw 'Unexpected service state; rescan.' }
        $after=Get-RecoverySnapshot
        $result=@($after.Services | Where-Object Name -CEQ $name)[0]
        if ($result.State -ne 'Running' -or $result.Start -ne $expected.Start -or $result.Delayed -ne $expected.Delayed -or
            (Get-RecoveryServiceFingerprint $expected) -cne (Get-RecoveryServiceFingerprint $result)) { throw 'Final service verification failed.' }
        $afterFile=Save-RecoverySnapshot $after $Directory 'after-repair'
        Add-RecoveryAction $journal Completed ([PSCustomObject]@{Name=$name;Snapshot=$afterFile})
        Write-RecoveryLog "$name is running with verified startup. Application/scoring health still requires a separate test." SUCCESS
    } catch {
        if ($prepared) { Add-RecoveryAction $journal Failed ([PSCustomObject]@{Name=$name;Error=[string]$_;BeforeSnapshot=$saved}) }
        throw
    }
}

# Main execution begins here; the function library above is safe to extract for tests.
if ($args.Count) { throw 'Run shed-recovery.ps1 without arguments and answer the prompts.' }
if ($env:OS -ne 'Windows_NT') { throw 'Live recovery requires Windows AD-DNS. The mocked tests can run on macOS.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in an elevated Windows PowerShell session.' }
} finally { $identity.Dispose() }
$tools=Join-Path $env:SystemDrive 'Tools'
Initialize-Directory $tools
Initialize-Directory (Join-Path $tools 'logs') -Private
$directory=Join-Path (Join-Path $tools 'logs') "recovery-$(Get-Date -Format yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N'))"
Initialize-Directory $directory -Private
Start-Transcript -LiteralPath (Join-Path $directory 'transcript.log') -ErrorAction Stop | Out-Null
try {
$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |             shed-recovery.ps1              |
     | ,      ,_ `\_/~\-           |    made for MWCCDC 2026-27' qualifiers     |
     >/'>/ ~|||`\( ,~\-            |     v1.2 - post-invitationals updates      |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black
    Write-RecoveryLog "Reports and recovery records: $directory"
    Write-RecoveryLog 'AD-DNS service draft. Audit and compare are read-only; each repair needs a separate confirmation.'
    while ($true) {
        Write-Host "`n== Service recovery ==" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host '  [A] Audit current services'
        Write-Host '  [C] Capture a healthy-host baseline'
        Write-Host '  [V] Compare with a trusted baseline (preview only)'
        Write-Host '  [R] Preview and select one startup/start repair'
        Write-Host '  [F] Finish'
        $choice=Read-RecoveryChoice 'Choice' @('A','C','V','R','F')
        if ($choice -eq 'F') { break }
        try {
            $current=Get-RecoverySnapshot
            $saved=Save-RecoverySnapshot $current $directory 'audit'
            $current.Services | Format-Table Name,Exists,State,Start,Delayed,Error -Wrap -AutoSize | Out-String | Write-Host
            Write-RecoveryLog "Current snapshot: $($saved.Path)"
            Write-RecoveryLog 'Startup values: 2 = Automatic; 3 = Manual; 4 = Disabled. Delayed=1 adds Automatic delayed start.'
            if ($choice -eq 'A') { continue }
            if ($choice -eq 'C') {
                Assert-RecoveryBaseline $current $current
                Write-RecoveryLog 'Running services do not establish a healthy host. Verify DNS, AD, WinRM, time and scoring, and investigate persistence before using this capture as a recovery reference.' WARN
                if ((Read-Host 'Type HEALTHY to designate this snapshot as your independently verified healthy baseline') -cne 'HEALTHY') { continue }
                $baselineFile=Save-RecoverySnapshot $current $directory 'healthy-baseline'
                Write-RecoveryLog "Baseline: $($baselineFile.Path)" SUCCESS
                Write-RecoveryLog "SHA-256: $($baselineFile.SHA256)" SUCCESS
                Write-RecoveryLog 'Keep the baseline and hash off this server. A hash stored beside a compromised file does not establish trust.' WARN
                continue
            }
            $path=(Read-Host 'Path to your trusted healthy-baseline JSON (Enter cancels)').Trim().Trim('"')
            if (-not $path) { continue }
            $hash=(Read-Host 'SHA-256 from your independently saved healthy capture').Trim()
            $baseline=Read-RecoveryBaseline $path $hash $current
            $plan=@(Get-RecoveryPlan $baseline $current)
            $planPath=Join-Path $directory "plan-$([guid]::NewGuid()).csv"
            $plan | Export-Csv -LiteralPath $planPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            $plan | Format-Table ID,Name,Action,CurrentState,CurrentStart,ExpectedStart,Details -Wrap -AutoSize | Out-String | Write-Host
            Write-RecoveryLog "Saved preview: $planPath"
            if ($choice -ne 'R') { continue }
            $text=Read-Host 'Exact repair ID (Enter cancels)'
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $id=0
            if (-not [int]::TryParse($text,[ref]$id)) { throw 'Enter one numeric repair ID.' }
            Invoke-RecoveryServiceRepair $baseline $current $id $directory
        } catch { Write-RecoveryLog "Review/repair incomplete: $_" ERROR }
    }
    Write-RecoveryLog "Session finished. Reports: $directory"
} finally { Stop-Transcript | Out-Null }
