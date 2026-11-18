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
Quarantine and task disablement require separate, exact confirmations and backups.
.EXAMPLE
.\shed-scraper.ps1
#>
if ($args.Count -gt 0) {
    throw 'Run .\shed-scraper.ps1 without arguments and answer the prompts. Automatic/bulk quarantine is not supported.'
}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-ScraperLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $line
    Add-Content -LiteralPath $script:ReportLog -Value $line -Encoding UTF8 -ErrorAction Stop
    if ($Level -in @('WARN', 'ERROR')) { $script:ReadOrActionErrors++ }
}

function Read-ScraperChoice {
    param([string]$Prompt, [string[]]$Choices, [string]$Default)
    while ($true) {
        $answer = (Read-Host $Prompt).Trim()
        if (-not $answer) { $answer = $Default }
        if ($answer -in $Choices) { return $answer }
        Write-Host "Enter one of: $($Choices -join ', ')."
    }
}

function Add-ScraperFinding {
    param([string]$Category, [string]$Name, [string]$Path, [string]$Details,
        [string]$Severity = 'INFO', [string]$Hash = '', [string]$Signature = '', [string]$Signer = '')
    $finding = [PSCustomObject]@{
        ID = $script:Findings.Count + 1; Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category = $Category; Severity = $Severity; Name = $Name; Path = $Path
        Hash = $Hash; Signature = $Signature; Signer = $Signer; Details = $Details; Action = 'Reported only'
    }
    $script:Findings.Add($finding)
    return $finding
}

function Save-ScraperReports {
    $script:Findings | Export-Csv -LiteralPath $script:FindingsCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $script:Findings | Export-Clixml -LiteralPath $script:FindingsXml -ErrorAction Stop
}

function Add-ScraperAction {
    param([string]$Kind, [string]$Status, [object]$Data)
    [PSCustomObject]@{
        Timestamp = Get-Date -Format o; Kind = $Kind; Status = $Status; Data = $Data
    } | ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $script:ActionsFile -Encoding UTF8 -ErrorAction Stop
}

function Get-ScraperPathKey {
    param([string]$Path)
    [Environment]::ExpandEnvironmentVariables($Path).Replace('/', '\').TrimEnd('\').ToLowerInvariant()
}

function Test-ScraperPathWithin {
    param([string]$Path, [string]$Root)
    if (-not $Root) { return $false }
    $pathKey = Get-ScraperPathKey $Path
    $rootKey = Get-ScraperPathKey $Root
    return $pathKey -eq $rootKey -or $pathKey.StartsWith($rootKey + '\', [StringComparison]::OrdinalIgnoreCase)
}

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

function Update-ScraperDependencies {
    param($Context)
    # Refresh immediately around a reviewed action. Old references are retained
    # conservatively, even if an observed task/process has since disappeared.
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

function Get-ScraperQuarantineDecision {
    param($Finding, $Context)
    $reason = ''
    try {
        if ($Finding.Category -ne 'Filesystem') { $reason = 'Only reviewed filesystem findings can be quarantined.' }
        $file = Get-Item -LiteralPath $Finding.Path -Force -ErrorAction Stop
        # An execution extension alone is not evidence of malware. This list only
        # limits which explicitly reviewed files can be moved; images/shortcuts/data cannot.
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
        foreach ($reference in $Context.References) {
            $referenceKey = Get-ScraperPathKey $reference
            if ($referenceKey.Contains($fileKey) -or $reference -match $namePattern) {
                $reason = 'Referenced by a process, service, task, startup entry, or WMI subscription; investigate separately.'
                break
            }
        }
        if (-not $Finding.Hash -or $Finding.Signature -eq 'Unknown') { $reason = 'Original hash/signature evidence is unavailable.' }
        if ($Finding.Signature -eq 'Valid') { $reason = 'Validly signed file: report-only.' }
        if ($reason) { return [PSCustomObject]@{ Allowed = $false; Reason = $reason } }
        $evidence = Get-ScraperFileEvidence $file.FullName
        if ($evidence.Hash -ne $Finding.Hash) { $reason = 'File changed since collection; rescan before taking action.' }
        elseif ($evidence.Signature -in @('Valid', 'Unknown')) { $reason = 'Current signature is valid or cannot be verified; report-only.' }
    } catch { $reason = "Cannot safely inspect file: $($_.Exception.Message)" }
    [PSCustomObject]@{ Allowed = (-not [bool]$reason); Reason = $reason }
}

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

function Get-ScraperExactTask {
    param([string]$Name, [string]$Path)
    # Match literal properties; wildcard-capable task-path queries are unsuitable
    # when an operator has selected exactly one finding.
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $Name -and $_.TaskPath -eq $Path })
    if ($tasks.Count -ne 1) { throw 'The selected task no longer resolves to exactly one task. Rescan before taking action.' }
    return $tasks[0]
}

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
        $xml = Export-ScheduledTask -InputObject $current -ErrorAction Stop
        if (-not $task.Definition -or $xml -cne $task.Definition) { throw 'Task definition changed or its original XML was unavailable; rescan before taking action.' }
        $backupPath = Join-Path $BackupDirectory "task-$($Finding.ID)-$([guid]::NewGuid()).xml"
        Set-Content -LiteralPath $backupPath -Value $xml -Encoding Unicode -ErrorAction Stop
        $null = [xml](Get-Content -LiteralPath $backupPath -Raw -ErrorAction Stop)
        $data = [PSCustomObject]@{ ID = $Finding.ID; TaskName = $task.TaskName; TaskPath = $task.TaskPath; PreviousState = [string]$current.State; DefinitionBackup = $backupPath }
        Add-ScraperAction 'DisableTask' 'Prepared' $data
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

function Get-ScraperFiles {
    param([string[]]$Roots, [string[]]$ExcludedRoots, [string[]]$Extensions)
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending = [Collections.Generic.Stack[string]]::new()
    foreach ($root in $Roots) { $pending.Push($root) }
    while ($pending.Count) {
        $directory = $pending.Pop()
        if (-not $visited.Add((Get-ScraperPathKey $directory))) { continue }
        if (@($ExcludedRoots | Where-Object { Test-ScraperPathWithin $directory $_ }).Count) { continue }
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

function Start-ScraperReview {
    param($Context, [string]$QuarantineDirectory, [string]$TaskBackupDirectory)
    while ($true) {
        $choice = Read-ScraperChoice -Prompt '[L] List findings, [Q] Review one file for quarantine, [T] Review one task for disablement, [F] Finish (default F)' -Choices @('L', 'Q', 'T', 'F') -Default 'F'
        if ($choice -eq 'F') { return }
        if ($choice -eq 'L') { $script:Findings | Format-Table ID, Category, Severity, Name, Path -AutoSize | Out-String | Write-Host; continue }
        $idInput = Read-Host 'Exact finding ID (blank cancels)'
        $id = 0
        if (-not [int]::TryParse($idInput, [ref]$id)) { continue }
        $finding = $script:Findings | Where-Object ID -EQ $id | Select-Object -First 1
        if (-not $finding) { Write-Host 'No finding has that ID.'; continue }
        if ($choice -eq 'Q') { Invoke-ScraperQuarantine $finding $Context $QuarantineDirectory }
        else { Invoke-ScraperTaskDisable $finding $TaskBackupDirectory }
        Save-ScraperReports
    }
}

# Startup and all collection below are read-only with respect to audited items.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run in an elevated Windows PowerShell session.' }
$toolsDirectory = Join-Path $env:SystemDrive 'Tools'
$runName = "scraper-$(Get-Date -Format yyyyMMdd-HHmmss)-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$reportDirectory = Join-Path (Join-Path $toolsDirectory 'logs') $runName
$quarantineDirectory = Join-Path (Join-Path $toolsDirectory 'Quarantine') $runName
$taskBackupDirectory = Join-Path $reportDirectory 'task-backups'
New-Item -ItemType Directory -Path $reportDirectory, $quarantineDirectory, $taskBackupDirectory -Force | Out-Null
$script:ReportLog = Join-Path $reportDirectory 'audit.log'
$script:FindingsCsv = Join-Path $reportDirectory 'findings.csv'
$script:FindingsXml = Join-Path $reportDirectory 'findings.xml'
$script:ActionsFile = Join-Path $reportDirectory 'actions.jsonl'
$null = New-Item -ItemType File -Path $script:ActionsFile
$script:Findings = [Collections.Generic.List[object]]::new()
$script:TaskTargets = @{}
$script:ReadOrActionErrors = 0
$context = [PSCustomObject]@{
    ScriptPath = $PSCommandPath; DependenciesComplete = $true; RegistryKeys = @()
    References = [Collections.Generic.List[string]]::new()
    ProtectedRoots = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData, $toolsDirectory) + @($env:PSModulePath -split ';') | Where-Object { $_ }
}
Write-ScraperLog 'Audit-first collection. Unknown, unsigned, downloaded, or startup items are not automatically malicious.'
Write-ScraperLog "Reports: $reportDirectory. No audited items change unless explicitly selected and confirmed later."

# 1. Capture live dependency references; never stop processes or services.
foreach ($class in @('Win32_Process', 'Win32_Service')) {
    try {
        $instances = @(Get-CimInstance -ClassName $class -ErrorAction Stop)
        foreach ($item in $instances) {
            $references = if ($class -eq 'Win32_Process') { @($item.ExecutablePath, $item.CommandLine) } else { @($item.PathName) }
            foreach ($reference in $references) { if ($reference) { $context.References.Add([Environment]::ExpandEnvironmentVariables($reference)) } }
        }
    } catch { $context.DependenciesComplete = $false; Write-ScraperLog "Dependency inventory failed for $class`: $_. File quarantine will be blocked." 'WARN' }
}

# 2. Collect command history and download provenance; do not modify either.
Write-ScraperLog 'Collecting command history and download provenance...'
$historyPattern = '(?i)\b(wget|curl|Invoke-WebRequest|iwr|certutil|bitsadmin|downloadstring|iex|frombase64string|encodedcommand|tcpclient|ncat|socat|mimikatz|chisel|ngrok|ligolo|meterpreter)\b|(?:^|\s)-enc(?:odedcommand)?\b'
$usersRoot = Join-Path $env:SystemDrive 'Users'
$profiles = @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
foreach ($profile in $profiles) {
    $historyPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $lineNumber = 0
            foreach ($line in @(Get-Content -LiteralPath $historyPath -ErrorAction Stop)) {
                $lineNumber++
                if ($line -match $historyPattern) { $null = Add-ScraperFinding 'PSHistory' $profile.Name "$historyPath : $lineNumber" "Command needs context: $line" 'REVIEW' }
            }
        } catch { Write-ScraperLog "Could not read history $historyPath`: $_" 'WARN' }
    }
    $downloads = Join-Path $profile.FullName 'Downloads'
    if (Test-Path -LiteralPath $downloads) {
        foreach ($file in @(Get-ScraperFiles @($downloads) @() @('.exe', '.ps1', '.bat', '.cmd', '.lnk', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico'))) {
            try {
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
Write-ScraperLog 'Inventorying startup entries and files (report-only)...'
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
$startupDirectories = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')) + @($profiles | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
$context.ProtectedRoots += $startupDirectories
foreach ($directory in $startupDirectories) {
    if (-not (Test-Path -LiteralPath $directory)) { continue }
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction Stop)) {
            $context.References.Add($file.FullName)
            if ($file.Extension -eq '.lnk') {
                # Read an existing shortcut as metadata; never call Save or Run.
                $shell = $null
                $shortcut = $null
                try {
                    $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
                    $shortcut = $shell.CreateShortcut($file.FullName)
                    $context.References.Add("$($shortcut.TargetPath) $($shortcut.Arguments)")
                } catch {
                    $context.DependenciesComplete = $false
                    Write-ScraperLog "Could not read startup shortcut target $($file.FullName): $_. File quarantine is blocked." 'WARN'
                } finally {
                    if ($shortcut -and [Runtime.InteropServices.Marshal]::IsComObject($shortcut)) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
                    if ($shell -and [Runtime.InteropServices.Marshal]::IsComObject($shell)) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
                }
            }
            $null = Add-ScraperFinding 'StartupFolder' $file.Name $file.FullName 'Startup presence is inventory only. Shortcuts/images are retained.'
        }
    } catch { $context.DependenciesComplete = $false; Write-ScraperLog "Could not read startup folder $directory`: $_" 'WARN' }
}
Save-ScraperReports

# 4. Inventory ALL task paths. Names such as Microsoft are not proof of trust.
Write-ScraperLog 'Inventorying scheduled tasks (no tasks disabled during collection)...'
try {
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        $actions = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
        foreach ($action in $actions) { if ($action) { $context.References.Add($action) } }
        $details = "State: $($task.State); Principal: $($task.Principal.UserId); Actions: $($actions -join ' | ')"
        $severity = if (($actions -join ' ') -match $historyPattern -or $task.TaskPath -notlike '\Microsoft\*') { 'REVIEW' } else { 'INFO' }
        $finding = Add-ScraperFinding 'ScheduledTask' $task.TaskName "$($task.TaskPath)$($task.TaskName)" $details $severity
        $definition = $null
        try { $definition = Export-ScheduledTask -InputObject $task -ErrorAction Stop }
        catch { Write-ScraperLog "Could not snapshot XML for $($finding.Path): $_. This task cannot be disabled through review." 'WARN' }
        $script:TaskTargets[$finding.ID] = [PSCustomObject]@{ TaskName = $task.TaskName; TaskPath = $task.TaskPath; Definition = $definition }
    }
} catch { $context.DependenciesComplete = $false; Write-ScraperLog "Could not fully inventory tasks: $_" 'WARN' }

# 5. WMI subscriptions are report-only. Legitimate management tools use these too.
foreach ($class in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__EventFilter', '__FilterToConsumerBinding')) {
    try {
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

# 6. Walk selected locations without following links or collecting the same file twice.
$scope = Read-ScraperChoice -Prompt 'File inventory: [H] User/temp hotspots, [F] Full system drive, [C] Custom folder, [S] Skip (default H; collection changes nothing)' -Choices @('H', 'F', 'C', 'S') -Default 'H'
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
$roots = @($roots | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
$excluded = @($toolsDirectory, (Join-Path $env:SystemRoot 'WinSxS'), (Join-Path $env:SystemRoot 'servicing'), (Join-Path $env:SystemRoot 'Installer'))
$extensions = @('.exe', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.jar', '.py')
$fileCount = 0
foreach ($file in Get-ScraperFiles $roots $excluded $extensions) {
    try {
        $evidence = Get-ScraperFileEvidence $file.FullName
        $severity = if ($evidence.Signature -eq 'Valid') { 'INFO' } else { 'REVIEW' }
        $null = Add-ScraperFinding 'Filesystem' $file.Name $file.FullName "Size: $($file.Length); signature is context, not a malware verdict." $severity $evidence.Hash $evidence.Signature $evidence.Signer
        $fileCount++
        if ($fileCount % 250 -eq 0) { Write-ScraperLog "Inventoried $fileCount executable/script files..." }
    } catch { Write-ScraperLog "Could not inspect file $($file.FullName): $_" 'WARN' }
}
Save-ScraperReports
Write-ScraperLog "Collection complete: $($script:Findings.Count) findings. Reports saved before any review actions."
$script:Findings | Group-Object Category | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host
Write-Host 'No audited files, shortcuts, images, registry entries, tasks, processes, services, or WMI objects have been changed.'
$review = Read-ScraperChoice -Prompt '[F] Finish audit, [R] Open optional per-item review (default F)' -Choices @('F', 'R') -Default 'F'
if ($review -eq 'R') { Start-ScraperReview $context $quarantineDirectory $taskBackupDirectory }
Save-ScraperReports
Write-ScraperLog "Finished with $script:ReadOrActionErrors read/action warning(s). Findings: $script:FindingsCsv; actions/recovery paths: $script:ActionsFile"
Read-Host 'Press Enter to exit'
