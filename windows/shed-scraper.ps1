#Requires -RunAsAdministrator
<#
.SYNOPSIS
Interactive, audit-first inventory of files and Windows persistence points.
.DESCRIPTION
Run without arguments. Collection never deletes files, changes startup entries,
removes WMI subscriptions, disables tasks, or stops processes/services. Reports
are saved before an optional review menu. Blank answers keep everything.
Shortcuts, images, links, Windows/application files, validly signed files, and
files referenced by processes/services/autoruns/tasks are not quarantined.
Quarantine, task disablement, and IFEO Debugger removal require separate, exact
confirmations and recovery records. Launch with powershell.exe -NoProfile -File
to avoid loading potentially poisoned profiles.
.NOTES
Version: 1.2
Release: Post-invitationals updates.

READING GUIDE
  Helpers below handle logging, path/evidence checks, dependency refresh, and the
  optional action menu. Main execution starts at the elevation/directory setup.
  Collection stages 1-6 inventory dependencies, history/downloads, startup,
  tasks, WMI, and selected filesystem locations. During collection, timestamped
  activity updates in the console and audit.log show the stage, elapsed scan time,
  finding count, and current operation. Reports are saved along the way.

DEFAULTS AND ACTIONS
  Collection is read-only with respect to audited items, but creates report and
  recovery directories. File scope defaults to user/temp hotspots; final menus
  default to Finish. Choosing REVIEW or seeing a REVIEW label changes nothing.
  Each eligible file/task needs its ID plus QUARANTINE <ID> or DISABLE <ID>.
  Shortcuts/images are not quarantine candidates. WMI and most registry values
  stay report-only. A separate reviewed action can remove one IFEO Debugger value.

REPORTS AND RECOVERY
  C:\Tools\logs\scraper-<run> holds audit.log, findings.csv/findings.xml,
  actions.jsonl, and task XML backups. C:\Tools\Quarantine\scraper-<run> holds
  moved files and verified recovery copies. The JSON-lines manifest records the
  original path, recovery paths, hash, and action outcome. There is no automatic
  purge or restore. Old quarantine folders are not scanned or rewritten.

INTERPRETING RESULTS
  Unsigned, downloaded, or unfamiliar is not the same as malicious. References
  and signatures are point-in-time guardrails, not proof a file is never needed.
  Reports may contain full commands/history/WMI script text for IR review.
  New report/recovery directories allow Administrators and SYSTEM only. Linked
  workspace paths or directories owned by an untrusted principal stop startup.
.EXAMPLE
.\shed-scraper.ps1
#>
if ($args.Count -gt 0) {
    throw 'Run .\shed-scraper.ps1 without arguments and answer the prompts. Automatic/bulk quarantine is not supported.'
}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Write status to both the console and audit.log; count read/action warning messages.
# Findings themselves are stored separately so a large inventory need not flood the console.
# Each downloaded script can display its own headings without a companion module.
function Write-RunHeading {
    param([string]$Title)
    Write-Host
    Write-Host "== $Title ==" -ForegroundColor Cyan -BackgroundColor Black
}

function Write-ScraperLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO')
    $colors = @{ INFO = 'White'; WARN = 'Yellow'; ERROR = 'Red'; SUCCESS = 'Green' }
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $line -ForegroundColor $colors[$Level] -BackgroundColor Black
    Add-Content -LiteralPath $script:ReportLog -Value $line -Encoding UTF8 -ErrorAction Stop
    if ($Level -in @('WARN', 'ERROR')) { $script:ReadOrActionErrors++ }
}

# Progress reflects work reached on the scan thread. A slow Windows call leaves
# its operation visible until it returns. Rate-limit output inside large loops.
function Write-ScraperActivity {
    param([string]$Detail, [string]$Stage, [switch]$Immediate)
    if (-not $script:ScanTimer -or -not $script:ScanTimer.IsRunning) { return }
    $elapsed = $script:ScanTimer.Elapsed
    if ($Stage) {
        $script:ScanStage = $Stage
        Write-RunHeading $Stage
    } elseif (-not $Immediate -and ($elapsed - $script:LastActivity).TotalSeconds -lt 5) {
        return
    }
    $script:LastActivity = $elapsed
    Write-ScraperLog ("{0} | {1:hh\:mm\:ss} elapsed | {2} findings | {3}" -f $script:ScanStage, $elapsed, $script:Findings.Count, $Detail)
}

# Return one validated menu answer, using the displayed default for Enter.
# Unknown answers reprompt and never implicitly select a destructive operation.
function Read-ScraperChoice {
    param([string[]]$Prompt, [string[]]$Choices, [string]$Default)
    Write-Host
    foreach ($line in $Prompt) { Write-Host $line }
    $question = if ($Default) { "Choice (Enter = $Default)" } else { 'Choice' }
    while ($true) {
        $answer = (Read-Host $question).Trim()
        if (-not $answer) { $answer = $Default }
        if ($answer -in $Choices) { return $answer }
        Write-Host "Choose one of $($Choices -join ', ')." -ForegroundColor Yellow -BackgroundColor Black
    }
}

# Append an inventory record with a run-local ID and return that record.
# Severity is a review label, not an instruction to quarantine or disable anything.
function Add-ScraperFinding {
    param([string]$Category, [string]$Name, [string]$Path, [string]$Details,
        [string]$Severity = 'INFO', [string]$Hash = '', [string]$Signature = '', [string]$Signer = '')
    # IDs are generated once for this run and remain attached to their original
    # record. Callers use $null when they do not need the returned object.
    $finding = [PSCustomObject]@{
        ID = $script:Findings.Count + 1; Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category = $Category; Severity = $Severity; Name = $Name; Path = $Path
        Hash = $Hash; Signature = $Signature; Signer = $Signer; Details = $Details; Action = 'Reported only'
    }
    $script:Findings.Add($finding)
    return $finding
}

# Checkpoint the full finding list to CSV and CLIXML, including action outcomes.
# These writes affect report files only, not the audited items.
function Save-ScraperReports {
    Write-ScraperActivity 'Saving CSV and XML reports' -Immediate
    $script:Findings | Export-Csv -LiteralPath $script:FindingsCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $script:Findings | Export-Clixml -LiteralPath $script:FindingsXml -ErrorAction Stop
}

# Append one JSON-lines recovery/audit event: Prepared, Completed, or Failed.
# Prepared records are written before mutation so recovery paths survive an interruption.
function Add-ScraperAction {
    param([string]$Kind, [string]$Status, [object]$Data)
    [PSCustomObject]@{
        Timestamp = Get-Date -Format o; Kind = $Kind; Status = $Status; Data = $Data
    } | ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $script:ActionsFile -Encoding UTF8 -ErrorAction Stop
}

# Normalize a path/reference for conservative Windows-style comparisons.
# This expands environment variables and normalizes case/slashes; it does not open/execute a target.
function Get-ScraperPathKey {
    param([string]$Path)
    [Environment]::ExpandEnvironmentVariables($Path).Replace('/', '\').TrimEnd('\').ToLowerInvariant()
}

# Check a directory boundary, not just a text prefix, so C:\WindowsBackup
# is not mistaken for C:\Windows. Used for protected roots and scan exclusions.
function Test-ScraperPathWithin {
    param([string]$Path, [string]$Root)
    if (-not $Root) { return $false }
    $pathKey = Get-ScraperPathKey $Path
    $rootKey = Get-ScraperPathKey $Root
    return $pathKey -eq $rootKey -or $pathKey.StartsWith($rootKey + '\', [StringComparison]::OrdinalIgnoreCase)
}

# Read the file/directory and its ancestor attributes to detect link traversal.
# Return true for reparse points or provider-reported links; do not follow or alter them.
function Test-ScraperLinkedPath {
    param([string]$Path)
    # Check every ancestor, not just the file: never walk through a junction.
    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $current.LinkType) { return $true }
        $current = if ($current -is [IO.DirectoryInfo]) { $current.Parent } else { $current.Directory }
    }
    return $false
}

# Read SHA-256 and Authenticode metadata without executing the file.
# An unavailable signature becomes Unknown, which blocks later quarantine.
function Get-ScraperFileEvidence {
    param([string]$Path)
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $signature = 'Unknown'
    $signer = ''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig) {
            $signature = [string]$sig.Status
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        }
    } catch { Write-ScraperLog "Could not read signature for $Path`: $_" 'WARN' }
    [PSCustomObject]@{ Hash = $hash; Signature = $signature; Signer = $signer }
}

# Re-enumerate profiles and startup folders because shortcuts can change while
# an operator is reviewing a file. Only the initial pass writes findings.
function Update-ScraperStartupReferences {
    param($Context, [switch]$CollectFindings)
    try {
        $profileDirs = Get-ChildItem -LiteralPath $Context.UsersRoot -Directory -Force -ErrorAction Stop |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
        $directories = @($Context.CommonStartup) + @($profileDirs | ForEach-Object {
            Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        })
        foreach ($directory in $directories) {
            if ($CollectFindings) { Write-ScraperActivity "Reading startup folder $directory" }
            if ($directory -notin $Context.ProtectedRoots) { $Context.ProtectedRoots += $directory }
            try { $files = @(Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction Stop) }
            catch [System.Management.Automation.ItemNotFoundException] { continue }
            catch {
                $Context.DependenciesComplete = $false
                Write-ScraperLog "Could not inventory startup folder ${directory}: $_. File quarantine is blocked." 'WARN'
                continue
            }
            foreach ($file in $files) {
                $Context.References.Add($file.FullName)
                if ($file.Extension -eq '.lnk') {
                    $shell = $null
                    $shortcut = $null
                    try {
                        $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
                        $shortcut = $shell.CreateShortcut($file.FullName)
                        if ([string]::IsNullOrWhiteSpace($shortcut.TargetPath)) { throw "Unresolved target: $($file.FullName)" }
                        $Context.References.Add([Environment]::ExpandEnvironmentVariables("$($shortcut.TargetPath) $($shortcut.Arguments)"))
                    } catch {
                        $Context.DependenciesComplete = $false
                        Write-ScraperLog "Could not read startup shortcut $($file.FullName): $_. File quarantine is blocked." 'WARN'
                    } finally {
                        if ($shortcut -and [Runtime.InteropServices.Marshal]::IsComObject($shortcut)) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
                        if ($shell -and [Runtime.InteropServices.Marshal]::IsComObject($shell)) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
                    }
                }
                if ($CollectFindings) {
                    $null = Add-ScraperFinding 'StartupFolder' $file.Name $file.FullName 'Startup entry (report only).'
                }
            }
        }
    } catch {
        $Context.DependenciesComplete = $false
        Write-ScraperLog "Startup dependency check incomplete: $_. File quarantine is blocked." 'WARN'
    }
}

# Refresh process/service/task/startup/WMI references around a selected action.
# Retain old references conservatively; any refresh error leaves quarantine blocked for this run.
function Update-ScraperDependencies {
    param($Context)
    # Refresh immediately around a reviewed action. Old references are retained
    # conservatively, even if an observed task/process has since disappeared.
    Update-ScraperStartupReferences $Context
    try {
        foreach ($class in @('Win32_Process', 'Win32_Service')) {
            foreach ($item in @(Get-CimInstance -ClassName $class -ErrorAction Stop)) {
                foreach ($reference in @($item.ExecutablePath, $item.CommandLine, $item.PathName)) {
                    if ($reference) { $Context.References.Add([Environment]::ExpandEnvironmentVariables($reference)) }
                }
            }
        }
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($action in $task.Actions) { $Context.References.Add("$($action.Execute) $($action.Arguments)") }
        }
        foreach ($key in $Context.RegistryKeys) {
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $properties = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    $Context.References.Add([Environment]::ExpandEnvironmentVariables([string]$property.Value))
                }
            }
        }
        foreach ($class in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
            foreach ($item in @(Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction Stop)) {
                foreach ($reference in @($item.ExecutablePath, $item.CommandLineTemplate, $item.ScriptText)) {
                    if ($reference) { $Context.References.Add([Environment]::ExpandEnvironmentVariables([string]$reference)) }
                }
            }
        }
    } catch {
        $Context.DependenciesComplete = $false
        Write-ScraperLog "Dependency refresh failed: $_. File quarantine is blocked." 'WARN'
    }
}

# Return Allowed/Reason after checking category, extension, paths, links,
# dependency references, signatures, and the collected hash. This function never moves a file.
function Get-ScraperQuarantineDecision {
    param($Finding, $Context)
    $reason = ''
    try {
        if ($Finding.Category -ne 'Filesystem') { $reason = 'Only reviewed filesystem findings can be quarantined.' }
        $file = Get-Item -LiteralPath $Finding.Path -Force -ErrorAction Stop
        # An execution extension alone is not evidence of malware. This list only
        # limits which explicitly reviewed files can be moved; images/shortcuts/data cannot.
        # This is an action allowlist, not a malware detection list. A file
        # passing this gate still requires all protections and explicit confirmation.
        $allowed = @('.exe', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.jar', '.py')
        if ($file.PSIsContainer -or $file.Extension.ToLowerInvariant() -notin $allowed) { $reason = 'Shortcuts, images, modules, and other non-executable data are report-only.' }
        if (Test-ScraperLinkedPath $file.FullName) { $reason = 'Link, junction, or linked ancestor: report-only.' }
        foreach ($root in $Context.ProtectedRoots) {
            if (Test-ScraperPathWithin $file.FullName $root) { $reason = "Protected system/application/startup/report directory: $root"; break }
        }
        if ((Get-ScraperPathKey $file.FullName) -eq (Get-ScraperPathKey $Context.ScriptPath)) { $reason = 'The running scraper is protected.' }
        if (-not $Context.DependenciesComplete) { $reason = 'Dependency inventory is incomplete; file quarantine is blocked for this run.' }
        $fileKey = Get-ScraperPathKey $file.FullName
        $namePattern = '(?i)(?<![\w.])' + [regex]::Escape($file.Name) + '(?=$|[\s"'';,])'
        # Full paths and filename-only commands both protect the file. This may
        # block an unrelated same-named item, which is preferable to removing a dependency.
        foreach ($reference in $Context.References) {
            $referenceKey = Get-ScraperPathKey $reference
            if ($referenceKey.Contains($fileKey) -or $reference -match $namePattern) {
                $reason = 'Referenced by a process, service, task, startup entry, or WMI subscription; investigate separately.'
                break
            }
        }
        if (-not $Finding.Hash -or $Finding.Signature -eq 'Unknown') { $reason = 'Original hash/signature evidence is unavailable.' }
        # A valid signature is not proof of benign behavior. This tool simply
        # leaves signed files to manual investigation rather than risking removal.
        if ($Finding.Signature -eq 'Valid') { $reason = 'Validly signed file: report-only.' }
        if ($reason) { return [PSCustomObject]@{ Allowed = $false; Reason = $reason } }
        $evidence = Get-ScraperFileEvidence $file.FullName
        if ($evidence.Hash -ne $Finding.Hash) { $reason = 'File changed since collection; rescan before taking action.' }
        elseif ($evidence.Signature -in @('Valid', 'Unknown')) { $reason = 'Current signature is valid or cannot be verified; report-only.' }
    } catch { $reason = "Cannot safely inspect file: $($_.Exception.Message)" }
    [PSCustomObject]@{ Allowed = (-not [bool]$reason); Reason = $reason }
}

# Move one eligible file only after exact ID confirmation and fresh checks.
# Create/hash a recovery copy, save its manifest, then move/hash the original under a unique name.
function Invoke-ScraperQuarantine {
    param($Finding, $Context, [string]$QuarantineDirectory)
    Update-ScraperDependencies $Context
    $decision = Get-ScraperQuarantineDecision $Finding $Context
    if (-not $decision.Allowed) { Write-ScraperLog "Kept $($Finding.Path): $($decision.Reason)" 'WARN'; return }
    $Finding | Format-List ID, Name, Path, Hash, Signature, Signer, Details | Out-String | Write-Host
    if ((Read-Host "Type QUARANTINE $($Finding.ID) to move ONLY this file; Enter keeps it") -cne "QUARANTINE $($Finding.ID)") { return }
    $data = $null
    try {
        # Recheck after the operator has had time to review the evidence.
        Update-ScraperDependencies $Context
        $decision = Get-ScraperQuarantineDecision $Finding $Context
        if (-not $decision.Allowed) { throw $decision.Reason }
        # Two recovery files are intentional: a verified copy exists before the
        # original is moved. GUID names prevent same-name files overwriting each other.
        $dest = Join-Path $QuarantineDirectory ("$([guid]::NewGuid())-$([IO.Path]::GetFileName($Finding.Path)).quarantine")
        $backup = "$dest.backup"
        [IO.File]::Copy($Finding.Path, $backup, $false)
        if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256 -ErrorAction Stop).Hash -ne $Finding.Hash) { throw 'Recovery-copy hash does not match the collected file.' }
        $data = [PSCustomObject]@{ ID = $Finding.ID; OriginalPath = $Finding.Path; QuarantinePath = $dest; RecoveryCopy = $backup; Hash = $Finding.Hash }
        # A verified recovery copy and its original path must be recorded first.
        Add-ScraperAction 'Quarantine' 'Prepared' $data
        Update-ScraperDependencies $Context
        $decision = Get-ScraperQuarantineDecision $Finding $Context
        if (-not $decision.Allowed) { throw $decision.Reason }
        Move-Item -LiteralPath $Finding.Path -Destination $dest -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction Stop).Hash -ne $Finding.Hash) { throw 'Moved-file verification failed; retain both recovery files for investigation.' }
        $Finding.Action = 'Quarantined (recovery copy retained)'
        Add-ScraperAction 'Quarantine' 'Completed' $data
        Write-ScraperLog "Quarantined ONLY $($Finding.Path). Original path and recovery files: $script:ActionsFile" 'SUCCESS'
    } catch {
        $Finding.Action = "Action needs review: $($_.Exception.Message)"
        if ($data) { Add-ScraperAction 'Quarantine' 'Failed' ([PSCustomObject]@{ Operation = $data; Error = $_.Exception.Message }) }
        Write-ScraperLog "Quarantine incomplete for $($Finding.Path): $_" 'ERROR'
    }
}

# Resolve a task by literal name AND folder, not a wildcard-capable name query.
# Fail if it no longer resolves uniquely, preventing accidental changes to another task.
function Get-ScraperExactTask {
    param([string]$Name, [string]$Path)
    # Match literal properties; wildcard-capable task-path queries are unsuitable
    # when an operator has selected exactly one finding.
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $Name -and $_.TaskPath -eq $Path })
    if ($tasks.Count -ne 1) { throw 'The selected task no longer resolves to exactly one task. Rescan before taking action.' }
    return $tasks[0]
}

# For one confirmed non-platform task, require unchanged XML and a validated
# definition backup before disabling it. Keep the task definition; never unregister or stop it.
function Invoke-ScraperTaskDisable {
    param($Finding, [string]$BackupDirectory)
    if ($Finding.Category -ne 'ScheduledTask') { Write-ScraperLog 'Select a scheduled-task finding.' 'WARN'; return }
    $task = $script:TaskTargets[$Finding.ID]
    if (-not $task -or $task.TaskPath -like '\Microsoft\*') {
        Write-ScraperLog 'Platform tasks and unavailable task definitions are report-only.' 'WARN'; return
    }
    $Finding | Format-List ID, Name, Path, Details | Out-String | Write-Host
    if ((Read-Host "Type DISABLE $($Finding.ID) to disable ONLY this task; Enter keeps it") -cne "DISABLE $($Finding.ID)") { return }
    $data = $null
    try {
        $current = Get-ScraperExactTask $task.TaskName $task.TaskPath
        # Compare the current definition with the collected one after the user
        # has reviewed it; do not act on an entry changed in the meantime.
        $xml = Export-ScheduledTask -InputObject $current -ErrorAction Stop
        if (-not $task.Definition -or $xml -cne $task.Definition) { throw 'Task definition changed or its original XML was unavailable; rescan before taking action.' }
        $backupPath = Join-Path $BackupDirectory "task-$($Finding.ID)-$([guid]::NewGuid()).xml"
        Set-Content -LiteralPath $backupPath -Value $xml -Encoding Unicode -ErrorAction Stop
        $null = [xml](Get-Content -LiteralPath $backupPath -Raw -ErrorAction Stop)
        $data = [PSCustomObject]@{ ID = $Finding.ID; TaskName = $task.TaskName; TaskPath = $task.TaskPath; PreviousState = [string]$current.State; DefinitionBackup = $backupPath }
        Add-ScraperAction 'DisableTask' 'Prepared' $data
        # Disable future scheduling only; do not unregister the task or terminate
        # any already-running instance. Read back its state before reporting success.
        Disable-ScheduledTask -InputObject $current -ErrorAction Stop | Out-Null
        $after = Get-ScraperExactTask $task.TaskName $task.TaskPath
        if ([string]$after.State -ne 'Disabled') { throw "Observed task state: $($after.State)" }
        $Finding.Action = 'Task disabled (definition retained)'
        Add-ScraperAction 'DisableTask' 'Completed' $data
        Write-ScraperLog "Disabled ONLY $($task.TaskPath)$($task.TaskName); XML backup: $backupPath" 'SUCCESS'
    } catch {
        $Finding.Action = "Action needs review: $($_.Exception.Message)"
        if ($data) { Add-ScraperAction 'DisableTask' 'Failed' ([PSCustomObject]@{ Operation = $data; Error = $_.Exception.Message }) }
        Write-ScraperLog "Task disablement incomplete: $_" 'ERROR'
    }
}

# Walk requested roots iteratively, pruning exclusions and skipping linked paths.
# Yield only requested extensions and visit overlapping directories once; no files are changed.
function Get-ScraperFiles {
    param([string[]]$Roots, [string[]]$ExcludedRoots, [string[]]$Extensions)
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    # A stack avoids recursive function calls. The visited set deduplicates
    # parents/children reached through overlapping requested scan roots.
    $pending = [Collections.Generic.Stack[string]]::new()
    foreach ($root in $Roots) { $pending.Push($root) }
    while ($pending.Count) {
        $directory = $pending.Pop()
        if (-not $visited.Add((Get-ScraperPathKey $directory))) { continue }
        if (@($ExcludedRoots | Where-Object { Test-ScraperPathWithin $directory $_ }).Count) { continue }
        Write-ScraperActivity "Reading folder $directory"
        try {
            if (Test-ScraperLinkedPath $directory) { Write-ScraperLog "Skipped linked directory: $directory"; continue }
            $children = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
        } catch { Write-ScraperLog "Could not enumerate $directory`: $_" 'WARN'; continue }
        foreach ($item in $children) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType) { continue }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            elseif ($item.Extension.ToLowerInvariant() -in $Extensions) { $item }
        }
    }
}

# Run optional per-item review after reports are saved. Enter finishes.
# Q/T require one numeric finding ID and then a separate exact action confirmation.
function Start-ScraperReview {
    param($Context, [string]$QuarantineDirectory, [string]$TaskBackupDirectory)
    while ($true) {
        $choice = Read-ScraperChoice -Prompt @(
            'Review findings'
            '  [L] List findings'
            '  [Q] Review one file for quarantine'
            '  [T] Review one scheduled task for disablement'
            '  [D] Review one IFEO Debugger value for removal'
            '  [F] Finish'
        ) -Choices @('L', 'Q', 'T', 'D', 'F') -Default 'F'
        if ($choice -eq 'F') { return }
        if ($choice -eq 'L') { $script:Findings | Format-Table ID, Category, Severity, Name, Path -AutoSize -Wrap | Out-String | Write-Host; continue }
        $idInput = Read-Host 'Exact finding ID (blank cancels)'
        $id = 0
        if (-not [int]::TryParse($idInput, [ref]$id)) { continue }
        $finding = $script:Findings | Where-Object ID -EQ $id | Select-Object -First 1
        if (-not $finding) { Write-Host 'No finding has that ID.'; continue }
        if ($choice -eq 'Q') { Invoke-ScraperQuarantine $finding $Context $QuarantineDirectory }
        elseif ($choice -eq 'D') { Invoke-ScraperDebuggerRemoval $finding }
        else { Invoke-ScraperTaskDisable $finding $TaskBackupDirectory }
        Save-ScraperReports
    }
}

# Draft defensive coverage for launch hijacks and policy sabotage. All collection
# is read-only; only the separate IFEO action below can remove one reviewed value.
function Read-ScraperRegistryEvidence {
    param($Context, [string]$Path, [string[]]$ValueNames = @())
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in @($key.GetValueNames())) {
            if ($ValueNames.Count -and $name -notin $ValueNames) { continue }
            $kind = [string]$key.GetValueKind($name)
            $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $text = if ($value -is [array]) { $value -join ' | ' } else { [string]$value }
            $Context.References.Add($text)
            $finding = Add-ScraperFinding 'RegistryPolicy' $name $Path "$kind`: $text" 'REVIEW'
            # Only IFEO Debugger values qualify. Never offer entire-key deletion,
            # security-package removal, or automated AppLocker/WDAC removal.
            if ($name -eq 'Debugger' -and $kind -in @('String','ExpandString') -and
                $key.Name -match '^HKEY_LOCAL_MACHINE\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\') {
                $finding.Category = 'IFEODebugger'
                $script:RegistryTargets[$finding.ID] = [PSCustomObject]@{Path=$Path; Name=$name; Value=$value; Kind=$kind}
            }
        }
    } catch {
        $Context.DependenciesComplete = $false
        $null = Add-ScraperFinding 'CollectionGap' 'Registry read failed' $Path ([string]$_) 'WARN'
    }
}

function Get-ScraperLaunchEvidence {
    param($Context)
    Write-ScraperActivity 'Reading executable launch and security policy hooks' -Stage 'Launch hijacks and policy sabotage'
    foreach ($base in @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')) {
        foreach ($suffix in @(
            'Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
            'Microsoft\Windows NT\CurrentVersion\SilentProcessExit',
            'Microsoft\Active Setup\Installed Components',
            'Policies\Microsoft\Windows\Safer\CodeIdentifiers',
            'Policies\Microsoft\Windows\SrpV2'
        )) {
            $root = "$base\$suffix"
            try {
                if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) { continue }
                Read-ScraperRegistryEvidence $Context $root
                $count = 0
                foreach ($key in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop)) {
                    $count++
                    if ($count -gt 2000) { throw 'More than 2000 policy keys: inspect this subtree separately.' }
                    Read-ScraperRegistryEvidence $Context $key.PSPath
                }
            } catch {
                $Context.DependenciesComplete = $false
                $null = Add-ScraperFinding 'CollectionGap' 'Policy enumeration failed' $root ([string]$_) 'WARN'
            }
        }
        Read-ScraperRegistryEvidence $Context "$base\Microsoft\Windows NT\CurrentVersion\Windows" @('AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs')
    }
    foreach ($spec in @(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Names=@('BootExecute')},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'; Names=@()},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Names=@('Security Packages','Authentication Packages','Notification Packages','RunAsPPL','LimitBlankPasswordUse')},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Names=@('UseLogonCredential')},
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'; Names=@()},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'; Names=@('Type','NtpServer')},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Names=@('LDAPServerIntegrity','LdapEnforceChannelBinding','TCP/IP Port')},
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Names=@('PortNumber','SecurityLayer','UserAuthentication')}
    )) { Read-ScraperRegistryEvidence $Context $spec.Path $spec.Names }
    foreach ($hive in @('HKLM:', 'HKCU:')) {
        Read-ScraperRegistryEvidence $Context "$hive\Software\Microsoft\Command Processor" @('AutoRun')
        foreach ($suffix in @('ScriptBlockLogging','ModuleLogging','Transcription')) {
            Read-ScraperRegistryEvidence $Context "$hive\Software\Policies\Microsoft\Windows\PowerShell\$suffix"
        }
    }
    # No profile is dot-sourced. A valid Microsoft signature alone cannot detect
    # cmd.exe copied over utilman.exe; compare embedded OriginalFilename too.
    foreach ($name in @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe')) {
        $path = Join-Path $env:SystemRoot "System32\$name"
        try {
            if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { continue }
            if (Test-ScraperLinkedPath $path) { throw 'Linked system binary requires offline inspection.' }
            $file = Get-Item -LiteralPath $path -ErrorAction Stop
            $evidence = Get-ScraperFileEvidence $path
            $original = [string]$file.VersionInfo.OriginalFilename
            $severity = if ($evidence.Signature -ne 'Valid' -or [IO.Path]::GetFileName($original) -ine $name) { 'WARN' } else { 'INFO' }
            $null = Add-ScraperFinding 'SystemBinary' $name $path "Embedded original filename: $original. A signature is not proof this is the correct binary. Use trusted Windows servicing media/SFC for recovery." $severity $evidence.Hash $evidence.Signature $evidence.Signer
        } catch { $null = Add-ScraperFinding 'CollectionGap' $name $path ([string]$_) 'WARN' }
    }
    $profileDirs = @((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0'))
    try {
        if ($env:ProgramFiles) { $profileDirs += @(Get-ChildItem -LiteralPath (Join-Path $env:ProgramFiles 'PowerShell') -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) }
        foreach ($profile in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop)) {
            if ($profile.LocalPath) {
                $profileDirs += (Join-Path $profile.LocalPath 'Documents\WindowsPowerShell'), (Join-Path $profile.LocalPath 'Documents\PowerShell')
            }
        }
        foreach ($directory in @($profileDirs | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $directory -ErrorAction Stop)) { continue }
            if (Test-ScraperLinkedPath $directory) { throw "Linked profile directory skipped: $directory" }
            foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*profile.ps1' -File -Force -ErrorAction Stop)) {
                if (Test-ScraperLinkedPath $file.FullName) { continue }
                if ($file.Length -gt 1MB) { throw "Profile too large for this draft: $($file.FullName)" }
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                $Context.References.Add([string]$content)
                $evidence = Get-ScraperFileEvidence $file.FullName
                $null = Add-ScraperFinding 'PowerShellProfile' $file.Name $file.FullName $content 'REVIEW' $evidence.Hash $evidence.Signature $evidence.Signer
            }
        }
    } catch { $Context.DependenciesComplete = $false; $null = Add-ScraperFinding 'CollectionGap' 'PowerShell profiles' 'Profiles' ([string]$_) 'WARN' }
    try {
        $output = & "$env:SystemRoot\System32\bitsadmin.exe" /list /allusers /verbose 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "BITS enumeration exit $LASTEXITCODE`: $output" }
        $Context.References.Add($output)
        $null = Add-ScraperFinding 'BITS' 'All-user jobs and notification commands' 'BITS' $output 'REVIEW'
    } catch { $Context.DependenciesComplete = $false; $null = Add-ScraperFinding 'CollectionGap' 'BITS inventory' 'BITS' ([string]$_) 'WARN' }
    foreach ($log in @('Security','System','Application','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational')) {
        try {
            $info = Get-WinEvent -ListLog $log -ErrorAction Stop
            $severity = if (-not $info.IsEnabled -or $info.MaximumSizeInBytes -lt 32MB) { 'REVIEW' } else { 'INFO' }
            $null = Add-ScraperFinding 'EventLogConfiguration' $log $log "Enabled=$($info.IsEnabled); MaxBytes=$($info.MaximumSizeInBytes); Records=$($info.RecordCount); Mode=$($info.LogMode). Small/empty logs are review leads, not proof of tampering." $severity
        } catch { $null = Add-ScraperFinding 'CollectionGap' $log $log ([string]$_) 'WARN' }
    }
    try {
        $output = & "$env:SystemRoot\System32\auditpol.exe" /get /category:* /r 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw $output }
        $null = Add-ScraperFinding 'AuditPolicy' 'Effective audit policy' 'auditpol' $output 'REVIEW'
    } catch { $null = Add-ScraperFinding 'CollectionGap' 'Audit policy' 'auditpol' ([string]$_) 'WARN' }
    Write-ScraperLog 'Other users\profile hives, redirected Documents, credential-provider COM registrations, and offline/rootkit integrity remain outside this draft coverage.' 'WARN'
}

function Invoke-ScraperDebuggerRemoval {
    param($Finding)
    if ($Finding.Category -ne 'IFEODebugger' -or -not $script:RegistryTargets.ContainsKey($Finding.ID)) {
        Write-ScraperLog 'Only a collected IFEO Debugger value can use this action.' 'WARN'; return
    }
    $target = $script:RegistryTargets[$Finding.ID]
    $Finding | Format-List ID,Name,Path,Details | Out-String | Write-Host
    if ((Read-Host "Type REMOVE DEBUGGER $($Finding.ID) to remove ONLY this value (legitimate debuggers also use IFEO)") -cne "REMOVE DEBUGGER $($Finding.ID)") { return }
    try {
        $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
        $current = $key.GetValue($target.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($current -cne $target.Value -or [string]$key.GetValueKind($target.Name) -ne $target.Kind) { throw 'Value changed since collection. Rescan before changing it.' }
        $data = [PSCustomObject]@{ID=$Finding.ID; Path=$target.Path; Name=$target.Name; Value=$current; Kind=$target.Kind}
        # Durable write before removal, including unexpanded value and registry type.
        Add-ScraperAction 'RemoveIFEODebugger' 'Prepared' $data
        Remove-ItemProperty -LiteralPath $target.Path -Name $target.Name -ErrorAction Stop
        $after = Get-Item -LiteralPath $target.Path -ErrorAction Stop
        if ($target.Name -in @($after.GetValueNames())) { throw 'Debugger value remains after removal.' }
        $Finding.Action = 'IFEO Debugger value removed; key retained'
        Add-ScraperAction 'RemoveIFEODebugger' 'Completed' $data
        Write-ScraperLog 'Debugger value removed and verified. Recovery value/type are in actions.jsonl.' 'SUCCESS'
    } catch {
        $Finding.Action = "Removal needs review: $_"
        Write-ScraperLog $Finding.Action 'ERROR'
    }
}

# Direct AD permissions survive group cleanup. Preserve and report all ACEs on
# these high-impact objects; never remove delegates based on a guessed allowlist.
function Get-ScraperRoleEvidence {
    param($Context)
    Write-ScraperActivity 'Reading direct AD/SQL permissions' -Stage 'Role-specific compromise review'
    $dc = Get-Service NTDS -ErrorAction SilentlyContinue
    if ($dc) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $domain = Get-ADDomain -Server localhost -ErrorAction Stop
            foreach ($dn in @($domain.DistinguishedName, "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)")) {
                $object = Get-ADObject -Identity $dn -Server localhost -Properties nTSecurityDescriptor -ErrorAction Stop
                $acl = $object.nTSecurityDescriptor
                if (-not $acl) { throw "No readable security descriptor on $dn" }
                $detail = $acl.Access | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,ObjectType,InheritedObjectType,InheritanceType,IsInherited | ConvertTo-Json -Depth 4
                $null = Add-ScraperFinding 'ADPermissions' $dn $dn "Review delegation, GenericAll/WriteDacl/WriteOwner, and replication extended rights. Group removal does not revoke these ACEs.`n$detail" 'REVIEW'
            }
            foreach ($name in @('SYSVOL','NETLOGON')) {
                $share = Get-SmbShare -Name $name -ErrorAction Stop
                $acl = Get-Acl -LiteralPath $share.Path -ErrorAction Stop
                $null = Add-ScraperFinding 'ShareACL' $name $share.Path ($acl.Sddl) 'REVIEW'
            }
        } catch { $null = Add-ScraperFinding 'CollectionGap' 'AD permissions/SYSVOL' 'AD' ([string]$_) 'WARN' }
    }
    # SQL Windows and SQL logins are separate databases of identities. Use only
    # fixed SELECT statements, integrated authentication, and short query timeouts.
    $sqlRoot = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    try {
        if (-not (Test-Path -LiteralPath $sqlRoot -ErrorAction Stop)) { return }
        $instances = Get-Item -LiteralPath $sqlRoot -ErrorAction Stop
        foreach ($name in $instances.GetValueNames()) {
            $instanceId = [string]$instances.GetValue($name)
            $path = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer"
            foreach ($suffix in @('','\Parameters','\SuperSocketNetLib\Tcp','\SuperSocketNetLib\Tcp\IPAll')) {
                Read-ScraperRegistryEvidence $Context "$path$suffix"
            }
            $auditSql = Read-ScraperChoice -Prompt @(
                "Query SQL instance $name using integrated authentication?"
                'The queries are SELECT-only, but existing server LOGON triggers can run when connecting.'
                '  [Y] Connect and collect role/database/job/trigger metadata'
                '  [N] Keep registry evidence only'
            ) -Choices @('Y','N') -Default 'N'
            if ($auditSql -ne 'Y') {
                $null = Add-ScraperFinding 'CollectionGap' "SQL instance $name metadata skipped" $path 'Connection-based review was declined. SQL permissions/jobs/triggers remain unverified.' 'REVIEW'
                continue
            }
            $connection = $null
            try {
                $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
                $builder.DataSource = if ($name -eq 'MSSQLSERVER') { '.' } else { ".\$name" }
                $builder.IntegratedSecurity = $true; $builder.ConnectTimeout = 3
                $builder.ApplicationName = 'Blue team read-only review'
                $connection = New-Object System.Data.SqlClient.SqlConnection $builder.ConnectionString
                $connection.Open()
                $queries = [ordered]@{
                    Databases = 'SELECT name,state_desc,user_access_desc,is_read_only FROM sys.databases'
                    ServerRoles = 'SELECT r.name AS role_name,m.name AS member_name,m.type_desc,m.is_disabled FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id=rm.role_principal_id JOIN sys.server_principals m ON m.principal_id=rm.member_principal_id'
                    Config = "SELECT name,value,value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled','show advanced options')"
                    Triggers = 'SELECT t.name,t.is_disabled,t.type_desc,m.definition FROM sys.server_triggers t LEFT JOIN sys.server_sql_modules m ON m.object_id=t.object_id'
                    AgentJobs = 'SELECT j.name,j.enabled,s.step_id,s.subsystem,s.command FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON s.job_id=j.job_id'
                }
                foreach ($entry in $queries.GetEnumerator()) {
                    $command = $connection.CreateCommand()
                    try {
                        $command.CommandTimeout = 5; $command.CommandText = $entry.Value
                        $reader = $command.ExecuteReader()
                        try { $table = New-Object System.Data.DataTable; $table.Load($reader) } finally { $reader.Dispose() }
                        $records = @(foreach ($row in $table.Rows) {
                            $fields = [ordered]@{}
                            foreach ($column in $table.Columns) { $fields[$column.ColumnName] = $row[$column.ColumnName] }
                            [PSCustomObject]$fields
                        })
                        $null = Add-ScraperFinding 'SQLReview' "$name/$($entry.Key)" $builder.DataSource ($records | ConvertTo-Json -Depth 5) 'REVIEW'
                    } catch { $null = Add-ScraperFinding 'CollectionGap' "$name/$($entry.Key)" 'SQL' ([string]$_) 'WARN' }
                    finally { $command.Dispose() }
                }
                $null = Add-ScraperFinding 'SQLReview' 'Metadata visibility' $builder.DataSource 'Results are limited to the current Windows login permissions. Empty results are not proof that no hidden logins, jobs, or triggers exist.' 'REVIEW'
            } catch { $null = Add-ScraperFinding 'CollectionGap' "SQL instance $name" $path ([string]$_) 'WARN' }
            finally { if ($connection) { $connection.Dispose() } }
        }
    } catch { $null = Add-ScraperFinding 'CollectionGap' 'SQL instances' $sqlRoot ([string]$_) 'WARN' }
}

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

# Startup and all collection below are read-only with respect to audited items.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run in an elevated Windows PowerShell session.' }
# MAIN EXECUTION: all action helpers are defined, but none are invoked during
# collection. New directories/files below are the reports and recovery workspace.
$toolsDirectory = Join-Path $env:SystemDrive 'Tools'
$runName = "scraper-$(Get-Date -Format yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$reportDirectory = Join-Path (Join-Path $toolsDirectory 'logs') $runName
$quarantineDirectory = Join-Path (Join-Path $toolsDirectory 'Quarantine') $runName
$taskBackupDirectory = Join-Path $reportDirectory 'task-backups'
# Protect evidence before collecting full command lines or making recovery copies.
Initialize-Directory $toolsDirectory
Initialize-Directory (Split-Path $reportDirectory -Parent) -Private
Initialize-Directory (Split-Path $quarantineDirectory -Parent) -Private
foreach ($directory in @($reportDirectory, $quarantineDirectory, $taskBackupDirectory)) {
    Initialize-Directory $directory -Private
}
$script:ReportLog = Join-Path $reportDirectory 'audit.log'
$script:FindingsCsv = Join-Path $reportDirectory 'findings.csv'
$script:FindingsXml = Join-Path $reportDirectory 'findings.xml'
$script:ActionsFile = Join-Path $reportDirectory 'actions.jsonl'
$null = New-Item -ItemType File -Path $script:ActionsFile
$script:Findings = [Collections.Generic.List[object]]::new()
$script:TaskTargets = @{}
$script:RegistryTargets = @{}
$script:ReadOrActionErrors = 0
# Context carries the protected directories and observed dependency references.
# DependenciesComplete is a sticky safety flag: a failed dependency read blocks quarantine.
$context = [PSCustomObject]@{
    UsersRoot = Join-Path $env:SystemDrive 'Users'
    CommonStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
    ScriptPath = $PSCommandPath; DependenciesComplete = $true; RegistryKeys = @()
    References = [Collections.Generic.List[string]]::new()
    ProtectedRoots = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData, $toolsDirectory) + @($env:PSModulePath -split ';') | Where-Object { $_ }
}
$splash = @'

            ___                    +--------------------------------------------+
    `=/~~~~~   ~\                  |              shed-scraper.ps1              |
     | ,      ,_ `\_/~\-           |    made for MWCCDC 2026-27' qualifiers     |
     >/'>/ ~|||`\( ,~\-            |     v1.2 - post-invitationals updates      |
     |  |   `||   \;               |                                            |
\\\\//\\\/TX\\//\\\\|//            |  <------------ that's kayne                |
                                   +--------------------------------------------+
'@
Write-Host $splash -ForegroundColor Red -BackgroundColor Black
Write-ScraperLog 'Collection is read-only. Review individual findings after the reports are saved.'
Write-ScraperLog "Reports: $reportDirectory"

# 1. Capture live dependency references; never stop processes or services.
$script:ScanTimer = [Diagnostics.Stopwatch]::StartNew()
Write-ScraperActivity 'Reading process and service lists' -Stage 'Running processes and services'
foreach ($class in @('Win32_Process', 'Win32_Service')) {
    try {
        Write-ScraperActivity "Querying $class" -Immediate
        $instances = @(Get-CimInstance -ClassName $class -ErrorAction Stop)
        foreach ($item in $instances) {
            if ($class -eq 'Win32_Service') {
                $detail = $item | Select-Object Name,DisplayName,PathName,StartName,StartMode,State | ConvertTo-Json -Compress
                $null = Add-ScraperFinding 'ServiceConfiguration' $item.Name $item.PathName $detail 'REVIEW'
            }
            $references = if ($class -eq 'Win32_Process') { @($item.ExecutablePath, $item.CommandLine) } else { @($item.PathName) }
            foreach ($reference in $references) { if ($reference) { $context.References.Add([Environment]::ExpandEnvironmentVariables($reference)) } }
        }
    } catch { $context.DependenciesComplete = $false; Write-ScraperLog "Dependency inventory failed for $class`: $_. File quarantine will be blocked." 'WARN' }
}

# 2. Collect command history and download provenance; do not modify either.
Write-ScraperActivity 'Listing user profiles' -Stage 'Command history and downloads'
# These keyword matches find commands worth reading, including legitimate
# administration/downloads. Matches are never executed or removed from history.
$historyPattern = '(?i)\b(wget|curl|Invoke-WebRequest|iwr|certutil|bitsadmin|downloadstring|iex|frombase64string|encodedcommand|tcpclient|ncat|socat|mimikatz|chisel|ngrok|ligolo|meterpreter)\b|(?:^|\s)-enc(?:odedcommand)?\b'
$usersRoot = Join-Path $env:SystemDrive 'Users'
$profiles = @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
foreach ($profile in $profiles) {
    Write-ScraperActivity "Reading profile $($profile.Name)"
    $historyPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $lineNumber = 0
            foreach ($line in @(Get-Content -LiteralPath $historyPath -ErrorAction Stop)) {
                $lineNumber++
                if ($lineNumber % 1000 -eq 0) { Write-ScraperActivity "Reading $($profile.Name) history, line $lineNumber" }
                if ($line -match $historyPattern) { $null = Add-ScraperFinding 'PSHistory' $profile.Name "$historyPath : $lineNumber" "Command needs context: $line" 'REVIEW' }
            }
        } catch { Write-ScraperLog "Could not read history $historyPath`: $_" 'WARN' }
    }
    $downloads = Join-Path $profile.FullName 'Downloads'
    if (Test-Path -LiteralPath $downloads) {
        Get-ScraperFiles @($downloads) @() @('.exe', '.ps1', '.bat', '.cmd', '.lnk', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico') | ForEach-Object {
            $file = $_
            Write-ScraperActivity "Checking download metadata for $($file.Name)"
            try {
                # Zone.Identifier is optional NTFS download-origin metadata.
                # Its presence says where a file came from, not whether it is malicious.
                $zone = Get-Content -LiteralPath $file.FullName -Stream Zone.Identifier -ErrorAction Stop
                $null = Add-ScraperFinding 'DownloadProvenance' $file.Name $file.FullName ($zone -join ' | ')
            } catch { } # Most local files have no Zone.Identifier stream.
        }
    }
}
foreach ($key in @('HKCU:\Software\Microsoft\Internet Explorer\TypedURLs', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths')) {
    if (-not (Test-Path -LiteralPath $key)) { continue }
    try {
        $properties = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -match '^(url\d+|path\d+)$') {
                $null = Add-ScraperFinding 'BrowserHistory' $property.Name $key ([string]$property.Value)
            }
        }
    } catch { Write-ScraperLog "Could not read browser/path history $key`: $_" 'WARN' }
}
Save-ScraperReports

# 3. Inventory registry/startup items; all remain in place, including .lnk/images.
Write-ScraperActivity 'Reading startup registry entries' -Stage 'Startup entries and files'
# Inspect machine and current-user autoruns, including 32-bit application keys
# and login shell settings. Other users' registry hives are not mounted here.
$startupKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$context.RegistryKeys = $startupKeys
foreach ($key in $startupKeys) {
    Write-ScraperActivity "Reading $key"
    if (-not (Test-Path -LiteralPath $key)) { continue }
    try {
        $properties = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            if ($key -like '*\Winlogon' -and $property.Name -notin @('Shell', 'Userinit')) { continue }
            $context.References.Add([Environment]::ExpandEnvironmentVariables([string]$property.Value))
            $null = Add-ScraperFinding 'RegistryStartup' $property.Name $key ([string]$property.Value) 'REVIEW'
        }
    } catch { $context.DependenciesComplete = $false; Write-ScraperLog "Could not read startup key $key`: $_" 'WARN' }
}
Update-ScraperStartupReferences $context -CollectFindings
Save-ScraperReports

# 4. Inventory ALL task paths. Names such as Microsoft are not proof of trust.
Write-ScraperActivity 'Listing scheduled tasks' -Stage 'Scheduled tasks'
try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $taskNumber = 0
    foreach ($task in $tasks) {
        $taskNumber++
        Write-ScraperActivity "Task $taskNumber of $($tasks.Count): $($task.TaskPath)$($task.TaskName)" -Immediate:($taskNumber -eq 1)
        $actions = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
        foreach ($action in $actions) { if ($action) { $context.References.Add($action) } }
        $details = "State: $($task.State); Principal: $($task.Principal.UserId); Actions: $($actions -join ' | ')"
        # Microsoft-folder tasks are still inventoried. The folder is used only
        # as a conservative optional-action boundary, not as proof the task is trustworthy.
        $severity = if (($actions -join ' ') -match $historyPattern -or $task.TaskPath -notlike '\Microsoft\*') { 'REVIEW' } else { 'INFO' }
        $finding = Add-ScraperFinding 'ScheduledTask' $task.TaskName "$($task.TaskPath)$($task.TaskName)" $details $severity
        $definition = $null
        try { $definition = Export-ScheduledTask -InputObject $task -ErrorAction Stop }
        catch { Write-ScraperLog "Could not snapshot XML for $($finding.Path): $_. This task cannot be disabled through review." 'WARN' }
        $script:TaskTargets[$finding.ID] = [PSCustomObject]@{ TaskName = $task.TaskName; TaskPath = $task.TaskPath; Definition = $definition }
    }
} catch { $context.DependenciesComplete = $false; Write-ScraperLog "Could not fully inventory tasks: $_" 'WARN' }

# 5. WMI subscriptions are report-only. Legitimate management tools use these too.
# Consumers are the action, filters describe the event, and bindings connect
# them. Record all three kinds so an IR review can reconstruct the subscription.
Write-ScraperActivity 'Reading subscription definitions' -Stage 'WMI subscriptions'
foreach ($class in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__EventFilter', '__FilterToConsumerBinding')) {
    try {
        Write-ScraperActivity "Querying $class" -Immediate
        foreach ($item in @(Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction Stop)) {
            $details = $item | Select-Object Name, ExecutablePath, CommandLineTemplate, ScriptingEngine, ScriptText, Query, Filter, Consumer | ConvertTo-Json -Compress -Depth 4
            foreach ($reference in @($item.ExecutablePath, $item.CommandLineTemplate, $item.ScriptText, $item.Query)) {
                if ($reference) { $context.References.Add([Environment]::ExpandEnvironmentVariables([string]$reference)) }
            }
            $null = Add-ScraperFinding 'WMI' ([string]$item.Name) "root\subscription:$class" $details 'REVIEW'
        }
    } catch { $context.DependenciesComplete = $false; Write-ScraperLog "Could not inventory WMI $class`: $_" 'WARN' }
}
Save-ScraperReports

Get-ScraperLaunchEvidence $context
Get-ScraperRoleEvidence $context
Save-ScraperReports

# 6. Walk selected locations without following links or collecting the same file twice.
# File-scope selection affects the final filesystem walk only; history,
# provenance, startup, task, and WMI collection above has already completed.
$script:ScanTimer.Stop()
Write-RunHeading 'File inventory scope'
$scope = Read-ScraperChoice -Prompt @(
    'Where should the read-only file inventory look?'
    '  [H] User and temporary folders'
    '  [F] Entire system drive'
    '  [C] One folder of your choice'
    '  [S] Skip file inventory'
) -Choices @('H', 'F', 'C', 'S') -Default 'H'
$roots = @()
if ($scope -eq 'F') { $roots = @("$env:SystemDrive\") }
elseif ($scope -eq 'C') {
    $custom = Read-Host 'Full path to one folder (blank skips file inventory)'
    if ($custom) { $roots = @((Get-Item -LiteralPath $custom -Force -ErrorAction Stop).FullName) }
} elseif ($scope -eq 'H') {
    $roots = @((Join-Path $env:SystemRoot 'Temp'), (Join-Path $env:SystemDrive 'Temp'), (Join-Path $env:SystemDrive 'PerfLogs'), $env:ProgramData)
    foreach ($profile in $profiles) {
        $roots += @('Desktop', 'Downloads', 'AppData\Local', 'AppData\Roaming') | ForEach-Object { Join-Path $profile.FullName $_ }
    }
}
$script:ScanTimer.Start()
Write-ScraperActivity "Checking $($roots.Count) selected scan roots" -Stage 'File inventory'
$roots = @($roots | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
# Prune bulky OS stores and the tools/report/quarantine tree before descent.
# Files outside these exclusions may still be protected from any later quarantine.
$excluded = @($toolsDirectory, (Join-Path $env:SystemRoot 'WinSxS'), (Join-Path $env:SystemRoot 'servicing'), (Join-Path $env:SystemRoot 'Installer'))
$extensions = @('.exe', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.jar', '.py')
$fileCount = 0
$firstFileSeen = $false
# Process each match as the directory walk yields it, including on a full-drive scan.
Get-ScraperFiles $roots $excluded $extensions | ForEach-Object {
    $file = $_
    Write-ScraperActivity "$fileCount files inventoried. Inspecting $($file.FullName)" -Immediate:(-not $firstFileSeen)
    $firstFileSeen = $true
    try {
        $evidence = Get-ScraperFileEvidence $file.FullName
        # REVIEW only changes report categorization. It never automatically
        # selects this file for quarantine or bypasses the protection checks.
        $severity = if ($evidence.Signature -eq 'Valid') { 'INFO' } else { 'REVIEW' }
        $null = Add-ScraperFinding 'Filesystem' $file.Name $file.FullName "Size: $($file.Length); signature is context, not a malware verdict." $severity $evidence.Hash $evidence.Signature $evidence.Signer
        $fileCount++
    } catch { Write-ScraperLog "Could not inspect file $($file.FullName): $_" 'WARN' }
}
Save-ScraperReports
$script:ScanTimer.Stop()
Write-RunHeading 'Audit results'
Write-ScraperLog "Collection complete: $($script:Findings.Count) findings, including $fileCount inventoried files. Reports saved before any review actions."
$script:Findings | Group-Object Category | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host
# OPTIONAL ACTION PHASE: all inventory reports are already on disk. Finish
# (the default) exits without modifying audited files, registry entries, or tasks.
$review = Read-ScraperChoice -Prompt @(
    'After collection'
    '  [F] Finish audit'
    '  [R] Review individual findings'
) -Choices @('F', 'R') -Default 'F'
if ($review -eq 'R') { Start-ScraperReview $context $quarantineDirectory $taskBackupDirectory }
Save-ScraperReports
Write-RunHeading 'Scraper reports'
Write-ScraperLog "Read or action warnings and errors: $script:ReadOrActionErrors"
Write-ScraperLog "Findings: $script:FindingsCsv"
Write-ScraperLog "Actions and recovery paths: $script:ActionsFile"
Write-ScraperLog "Audit log: $script:ReportLog"
Read-Host 'Press Enter to exit'
