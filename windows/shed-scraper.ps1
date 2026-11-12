# filesystem scraper:
#   recursively search entire system for
#   .ps1 files, .exe files, secret harmful third options
#       !!! LOG ALL OF THESE FOR IRs !!!
#       prompt user to delete? maybe run this a few times on a VM to find .exes that need to stay
#   maybe scrape IE downloads history and/or wget if available
#   check scheduled tasks
#       !!! LOG ALL OF THESE FOR IRs !!!
#   check startup/run/runOnce folders
#   look into WMI event subscriptions

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$FullScan,
    [switch]$NonInteractive,
    [switch]$QuarantineAll,
    [string]$TargetDrive = "C:"
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
# 0. Privileges, Directories, & Logging Setup
# -----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[!] ERROR: Script must be run as Administrator!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Press Enter to exit..."
    exit 1
}

# Trap terminating errors
trap {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray -BackgroundColor Black
    Write-Host "" -BackgroundColor Black
    Read-Host "Press Enter to exit..."
    break
}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ToolsDir      = "C:\Tools"
$LogsDir       = "$ToolsDir\logs"
$QuarantineDir = "$ToolsDir\Quarantine"
New-Item -ItemType Directory -Force -Path $ToolsDir, $LogsDir, $QuarantineDir | Out-Null
Set-Location -Path $ToolsDir
[System.IO.Directory]::SetCurrentDirectory($ToolsDir)

$timestamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$IRReportFile  = "$LogsDir\IR-Report-$timestamp.txt"
$IRCsvFile     = "$LogsDir\IR-Findings-$timestamp.csv"

# Global findings collection for structured IR reporting
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "ALERT")]$Level = "INFO"
    )
    $timeStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "ALERT"   = "Magenta"
    }
    Write-Host "[$timeStr] [$Level] $Message" -ForegroundColor $colors[$Level] -BackgroundColor Black
    "[$timeStr] [$Level] $Message" | Out-File -FilePath $IRReportFile -Append -Encoding ascii
}

function Add-IRFinding {
    param(
        [string]$Category,
        [string]$ItemName,
        [string]$Path,
        [string]$Details,
        [string]$Hash = "N/A",
        [string]$Severity = "SUSPICIOUS"
    )
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category  = $Category
        ItemName  = $ItemName
        Path      = $Path
        Hash      = $Hash
        Severity  = $Severity
        Details   = $Details
    }
    $script:Findings.Add($finding)
    Write-Log "[IR FINDING] [$Category] $ItemName ($Path) | $Details" "ALERT"
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    try {
        if (-not (Test-Path -LiteralPath $FilePath)) { return }
        $fileName = Split-Path -Leaf $FilePath
        $destPath = "$QuarantineDir\$timestamp`_$fileName.quarantine"
        Move-Item -LiteralPath $FilePath -Destination $destPath -Force -ErrorAction Stop
        Write-Log "QUARANTINED: $FilePath -> $destPath (Reason: $Reason)" "SUCCESS"
    } catch {
        Write-Log "Failed to quarantine ${FilePath}: $_" "ERROR"
    }
}

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

Write-Log "Starting incident response audit on $(hostname)" "INFO"
Write-Log "IR Report Destination: $IRReportFile" "INFO"
Write-Log "Quarantine Directory : $QuarantineDir" "INFO"

# -----------------------------------------------------------------------------
# 1. Scrape Download History, Wget/Curl, & PowerShell History
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " [1/5] Scraping Download History, Web Artifacts & Command Lines"
Write-Host "================================================================================"

# A. PowerShell Console History (inspect for curl, wget, IEX, certutil, reverse shells)
Write-Log "Checking PowerShell history across all user profiles..." "INFO"
$historySuspiciousPatterns = @(
    "wget", "curl", "Invoke-WebRequest", "iwr", "certutil", "bitsadmin",
    "downloadstring", "iex", "frombase64string", "encodedcommand", "-enc",
    "reverse", "tcpclient", "nc.exe", "ncat", "socat", "mimikatz",
    "chisel", "ngrok", "ligolo", "cobaltstrike", "meterpreter"
)

Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | ForEach-Object {
    $userPath = $_.FullName
    $lines = Get-Content -LiteralPath $userPath -ErrorAction SilentlyContinue
    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        foreach ($pattern in $historySuspiciousPatterns) {
            if ($line -match [regex]::Escape($pattern)) {
                Add-IRFinding -Category "PSHistory" -ItemName "Suspicious Command Line" -Path "$userPath : Line $lineNum" -Details $line -Severity "HIGH"
                break
            }
        }
    }
}

# B. Internet Explorer / Legacy Edge Typed URLs
Write-Log "Scraping Internet Explorer / Windows TypedURLs registry keys..." "INFO"
$typedUrlPaths = @(
    "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
)
foreach ($regKey in $typedUrlPaths) {
    if (Test-Path $regKey) {
        $props = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -match '^url\d+|^path\d+' } | ForEach-Object {
                Add-IRFinding -Category "BrowserHistory" -ItemName "TypedURL" -Path "$regKey\$($_.Name)" -Details "$($_.Value)" -Severity "INFO"
            }
        }
    }
}

# C. Zone.Identifier Alternate Data Streams (ADS) in User Downloads (identifies URL origins of downloaded tools)
Write-Log "Auditing downloaded files and Zone.Identifier provenance (HostUrl)..." "INFO"
Get-ChildItem -Path "C:\Users\*\Downloads" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
    $filePath = $_.FullName
    try {
        $zoneContent = Get-Content -LiteralPath "${filePath}:Zone.Identifier" -ErrorAction SilentlyContinue
        if ($zoneContent) {
            $hostUrl = ($zoneContent | Select-String -Pattern "HostUrl=(.*)").Matches.Groups[1].Value
            $referrer = ($zoneContent | Select-String -Pattern "ReferrerUrl=(.*)").Matches.Groups[1].Value
            $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Add-IRFinding -Category "DownloadedFile" -ItemName $_.Name -Path $filePath -Hash $hash -Details "Origin Host: $hostUrl | Referrer: $referrer" -Severity "SUSPICIOUS"
        }
    } catch {}
}

# -----------------------------------------------------------------------------
# 2. Check Startup Folders, Run, & RunOnce Registry Persistence
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " [2/5] Checking Startup Folders & Registry Run / RunOnce Keys"
Write-Host "================================================================================"

$startupRegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($regPath in $startupRegistryPaths) {
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | ForEach-Object {
                if ($_.Name -notmatch '^PS.*') {
                    $val = "$($_.Value)"
                    $targetPath = $val
                    if ($val -match '"([^"]+)"') { $targetPath = $matches[1] }
                    elseif ($val -match '^([^\s]+)') { $targetPath = $matches[1] }
                    
                    $hash = "N/A"
                    if (Test-Path -LiteralPath $targetPath) {
                        $hash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    }

                    # Classify severity: filter out common standard system/tray processes
                    $knownGoodPatterns = @(
                        'SecurityHealthSystray.exe',
                        'OneDrive.exe',
                        'vmtoolsd.exe',
                        'VBoxTray.exe'
                    )
                    $isKnownGood = $false
                    foreach ($good in $knownGoodPatterns) {
                        if ($val -like "*$good*") {
                            $isKnownGood = $true
                            break
                        }
                    }

                    $severity = if ($isKnownGood) { "INFO" } else { "HIGH" }
                    Add-IRFinding -Category "RegistryStartup" -ItemName $_.Name -Path "$regPath -> $val" -Hash $hash -Details "Entry in $regPath" -Severity $severity

                    if (-not $NonInteractive -and -not $isKnownGood) {
                        $action = Read-Host "Unrecognized Registry Run item found: '$($_.Name)' ($val). Remove registry entry? (y/N)"
                        if ($action -eq 'y' -or $action -eq 'Y') {
                            Remove-ItemProperty -Path $regPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                            Write-Log "Removed registry startup entry: $($_.Name) from $regPath" "SUCCESS"
                        }
                    }
                }
            }
        }
    }
}

# Winlogon Shell & Userinit hijacking checks
$winlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (Test-Path $winlogonPath) {
    $wl = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Shell -and $wl.Shell.Trim().ToLower() -ne "explorer.exe") {
            Add-IRFinding -Category "WinlogonHijack" -ItemName "Shell" -Path "$winlogonPath\Shell" -Details "Abnormal Shell: $($wl.Shell)" -Severity "CRITICAL"
        }
        if ($wl.Userinit -and $wl.Userinit.Trim().ToLower() -notmatch '^c:\\windows\\system32\\userinit\.exe,?$') {
            Add-IRFinding -Category "WinlogonHijack" -ItemName "Userinit" -Path "$winlogonPath\Userinit" -Details "Abnormal Userinit: $($wl.Userinit)" -Severity "CRITICAL"
        }
    }
}

# Startup folders
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
)

Get-ChildItem -Path $startupFolders -File -ErrorAction SilentlyContinue | ForEach-Object {
    $filePath = $_.FullName
    $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    Add-IRFinding -Category "StartupFolder" -ItemName $_.Name -Path $filePath -Hash $hash -Details "File residing in Startup Folder" -Severity "HIGH"
    
    if (-not $NonInteractive) {
        $prompt = Read-Host "Startup file found: '$($_.Name)'. [Q] Quarantine, [D] Delete, [S] Skip (Default: Q)"
        if ($prompt -eq 'd' -or $prompt -eq 'D') {
            Remove-Item -LiteralPath $filePath -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted startup file: $filePath" "SUCCESS"
        } elseif ($prompt -ne 's' -and $prompt -ne 'S') {
            Invoke-QuarantineFile -FilePath $filePath -Reason "Startup folder persistence"
        }
    } elseif ($QuarantineAll) {
        Invoke-QuarantineFile -FilePath $filePath -Reason "Startup folder persistence (Auto)"
    }
}

# -----------------------------------------------------------------------------
# 3. Check Scheduled Tasks Persistence
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " [3/5] Checking Scheduled Tasks for Persistence"
Write-Host "================================================================================"

Write-Log "Auditing non-Microsoft scheduled tasks..." "INFO"
try {
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    # Filter out core Microsoft built-in tasks
    $suspiciousTasks = $allTasks | Where-Object {
        $_.TaskPath -notmatch '^\\Microsoft\\Windows\\' -and
        $_.TaskName -notmatch '^Microsoft' -and
        $_.TaskPath -notmatch '^\\Microsoft\\Office\\'
    }

    foreach ($task in $suspiciousTasks) {
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }
        $actionStr = $actions -join " | "
        
        $targetExe = ($task.Actions | Select-Object -First 1).Execute
        $hash = "N/A"
        if ($targetExe -and (Test-Path -LiteralPath $targetExe)) {
            $hash = (Get-FileHash -LiteralPath $targetExe -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }

        Add-IRFinding -Category "ScheduledTask" -ItemName $task.TaskName -Path $task.TaskPath -Hash $hash -Details "Action: $actionStr | State: $($task.State)" -Severity "HIGH"

        if (-not $NonInteractive) {
            $taskAction = Read-Host "Non-standard task '$($task.TaskName)' detected. [D] Disable, [R] Remove, [S] Skip (Default: D)"
            if ($taskAction -eq 'r' -or $taskAction -eq 'R') {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "Unregistered task: $($task.TaskName)" "SUCCESS"
            } elseif ($taskAction -ne 's' -and $taskAction -ne 'S') {
                Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Disabled task: $($task.TaskName)" "SUCCESS"
            }
        }
    }
} catch {
    Write-Log "Could not audit scheduled tasks: $_" "WARN"
}

# -----------------------------------------------------------------------------
# 4. Check WMI Event Subscriptions (Advanced Red Team Persistence)
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " [4/5] Checking WMI Event Subscriptions"
Write-Host "================================================================================"

Write-Log "Querying root\subscription for WMI Event Consumers and Filters..." "INFO"
try {
    # CommandLineEventConsumers
    $cmdConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $cmdConsumers) {
        Add-IRFinding -Category "WMIConsumer" -ItemName $c.Name -Path "root\subscription:CommandLineEventConsumer" -Details "Command: $($c.CommandLineTemplate) | Executable: $($c.ExecutablePath)" -Severity "CRITICAL"
        if (-not $NonInteractive) {
            $prompt = Read-Host "Suspicious CommandLineEventConsumer '$($c.Name)' found. Remove? (y/N)"
            if ($prompt -eq 'y' -or $prompt -eq 'Y') {
                Remove-CimInstance -InputObject $c -ErrorAction SilentlyContinue
                Write-Log "Removed WMI CommandLineEventConsumer: $($c.Name)" "SUCCESS"
            }
        }
    }

    # ActiveScriptEventConsumers
    $scriptConsumers = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    foreach ($sc in $scriptConsumers) {
        Add-IRFinding -Category "WMIConsumer" -ItemName $sc.Name -Path "root\subscription:ActiveScriptEventConsumer" -Details "ScriptType: $($sc.ScriptingEngine) | Code: $($sc.ScriptText)" -Severity "CRITICAL"
        if (-not $NonInteractive) {
            $prompt = Read-Host "Suspicious ActiveScriptEventConsumer '$($sc.Name)' found. Remove? (y/N)"
            if ($prompt -eq 'y' -or $prompt -eq 'Y') {
                Remove-CimInstance -InputObject $sc -ErrorAction SilentlyContinue
                Write-Log "Removed WMI ActiveScriptEventConsumer: $($sc.Name)" "SUCCESS"
            }
        }
    }

    # Event Filters & Bindings
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    foreach ($b in $bindings) {
        $filterRef   = "$($b.Filter)"
        $consumerRef = "$($b.Consumer)"
        if ($filterRef -notmatch 'SCM Event Log Filter' -and $consumerRef -notmatch 'SCM Event Log Consumer') {
            Add-IRFinding -Category "WMIBinding" -ItemName "FilterToConsumerBinding" -Path "root\subscription" -Details "Filter: $filterRef -> Consumer: $consumerRef" -Severity "HIGH"
        }
    }
} catch {
    Write-Log "Could not query WMI subscriptions: $_" "WARN"
}

# -----------------------------------------------------------------------------
# 5. Recursive Filesystem Scraper (.ps1, .exe, & Secret Harmful 3rd Options)
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " [5/5] Recursive Filesystem Scraper (Scripts, Binaries & Secret Third Options)"
Write-Host "================================================================================"

# "secret harmful third options": batch, vbs, hta, scr, js, ws, dlls in userland, elf, python, jar
$targetExtensions = @(
    "*.ps1", "*.psm1", "*.exe", "*.bat", "*.cmd",
    "*.vbs", "*.vbe", "*.js", "*.jse", "*.wsf",
    "*.hta", "*.scr", "*.elf", "*.bin", "*.jar", "*.py"
)

# Common Red Team drop hotspots vs Full Drive Scan
$searchPaths = @(
    "C:\Users\*\AppData\Local\Temp",
    "C:\Users\*\AppData\Roaming",
    "C:\Users\*\AppData\Local",
    "C:\Windows\Temp",
    "C:\Temp",
    "C:\PerfLogs",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\System32\Tasks",
    "C:\Windows\Debug",
    "C:\Users\*\Desktop",
    "C:\Users\*\Downloads"
)

if ($FullScan) {
    Write-Log "FullScan enabled. Expanding search to entire $TargetDrive drive (excluding Windows Component Store)..." "WARN"
    $searchPaths = @("$TargetDrive\")
} else {
    Write-Log "Targeting high-probability malware drop directories (Hotspots)..." "INFO"
}

# Folders to explicitly skip during recursive traversal (legitimate high-density OS folders)
$excludeDirs = @(
    "*\Windows\WinSxS*",
    "*\Windows\servicing*",
    "*\Windows\Installer*",
    "*\Microsoft.NET*",
    "*\Windows\assembly*"
)

$scannedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

foreach ($pathPattern in $searchPaths) {
    # Resolve wildcards in paths
    $resolvedPaths = Resolve-Path $pathPattern -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
    foreach ($rPath in $resolvedPaths) {
        Write-Log "Scanning directory: $rPath" "INFO"
        try {
            Get-ChildItem -LiteralPath $rPath -Include $targetExtensions -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $item = $_
                $skip = $false
                foreach ($ex in $excludeDirs) {
                    if ($item.FullName -like $ex) { $skip = $true; break }
                }
                if (-not $skip) {
                    $scannedFiles.Add($item)
                }
            }
        } catch {}
    }
}

Write-Log "Total candidate files discovered: $($scannedFiles.Count)" "INFO"

# Analyze each candidate file
$suspiciousFiles = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($file in $scannedFiles) {
    try {
        $filePath = $file.FullName
        $ext = $file.Extension.ToLower()

        # Check digital signature for binaries (.exe, .dll) and scripts (.ps1)
        $sigStatus = "Unsigned"
        if ($ext -in @(".exe", ".dll", ".ps1")) {
            $sig = Get-AuthenticodeSignature -LiteralPath $filePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq "Valid") {
                # Skip trusted Microsoft / Windows signed binaries located in standard Program Files / System32
                if ($sig.SignerCertificate.Subject -match "Microsoft" -and ($filePath -like "C:\Program Files*" -or $filePath -like "C:\Windows\System32*")) {
                    continue
                }
                $sigStatus = "Valid: $($sig.SignerCertificate.Subject)"
            }
        }

        # Check SHA256 Hash
        $hashObj = Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        $hash = if ($hashObj) { $hashObj.Hash } else { "N/A" }

        # Flag reasons
        $reason = @()
        if ($ext -in @(".bat", ".cmd", ".vbs", ".hta", ".scr", ".js")) {
            $reason += "Scripting/Execution Format ($ext)"
        }
        if ($filePath -match 'AppData|Temp|PerfLogs|Public|ProgramData') {
            $reason += "Writable Hotspot Location"
        }
        if ($sigStatus -eq "Unsigned" -and $ext -in @(".exe", ".ps1")) {
            $reason += "Unsigned Binary/Script"
        }

        $reasonStr = if ($reason.Count -gt 0) { $reason -join ", " } else { "General Audit" }

        Add-IRFinding -Category "Filesystem" -ItemName $file.Name -Path $filePath -Hash $hash -Details "Size: $($file.Length) bytes | Sig: $sigStatus | Flags: $reasonStr" -Severity "SUSPICIOUS"

        $suspiciousFiles.Add([PSCustomObject]@{
            File    = $file
            Hash    = $hash
            Reason  = $reasonStr
            Sig     = $sigStatus
        })
    } catch {}
}

# Triage & Remediation for Suspicious Files
if ($suspiciousFiles.Count -gt 0) {
    Write-Host "`n--------------------------------------------------------------------------------"
    Write-Host "Suspicious Files Discovered: $($suspiciousFiles.Count)" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------------------------"

    if (-not $NonInteractive) {
        $actionChoice = Read-Host "Action for discovered files: [Q] Quarantine suspicious files, [I] Interactively review each, [S] Skip / Keep all (Default: Q)"
        if ([string]::IsNullOrWhiteSpace($actionChoice)) { $actionChoice = "Q" }

        if ($actionChoice -eq 'Q' -or $actionChoice -eq 'q') {
            foreach ($s in $suspiciousFiles) {
                Invoke-QuarantineFile -FilePath $s.File.FullName -Reason $s.Reason
            }
        } elseif ($actionChoice -eq 'I' -or $actionChoice -eq 'i') {
            foreach ($s in $suspiciousFiles) {
                Write-Host "`nFile: $($s.File.FullName)" -ForegroundColor Cyan
                Write-Host "Size: $($s.File.Length) bytes | Hash: $($s.Hash)" -ForegroundColor DarkCyan
                Write-Host "Flags: $($s.Reason)" -ForegroundColor Yellow
                $userAction = Read-Host "[Q] Quarantine, [D] Delete permanently, [S] Skip (Default: Q)"
                if ($userAction -eq 'd' -or $userAction -eq 'D') {
                    Remove-Item -LiteralPath $s.File.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted file: $($s.File.FullName)" "SUCCESS"
                } elseif ($userAction -ne 's' -and $userAction -ne 'S') {
                    Invoke-QuarantineFile -FilePath $s.File.FullName -Reason $s.Reason
                }
            }
        }
    } elseif ($QuarantineAll) {
        foreach ($s in $suspiciousFiles) {
            Invoke-QuarantineFile -FilePath $s.File.FullName -Reason "$($s.Reason) (Auto)"
        }
    }
}

# -----------------------------------------------------------------------------
# 6. Export Structured IR Reports & Final Summary
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================"
Write-Host " Incident Response Audit Summary"
Write-Host "================================================================================"

# Export findings to CSV for easy parsing by IR teams
try {
    $script:Findings | Export-Csv -Path $IRCsvFile -NoTypeInformation -Encoding ascii
    Write-Log "Structured CSV findings exported to $IRCsvFile" "SUCCESS"
} catch {
    Write-Log "Could not export CSV findings: $_" "WARN"
}

Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " Total Suspicious Findings Logged: $($script:Findings.Count)" -ForegroundColor Yellow
Write-Host " Full Text IR Report Log        : $IRReportFile" -ForegroundColor Cyan
Write-Host " Structured CSV Findings File   : $IRCsvFile" -ForegroundColor Cyan
Write-Host " Quarantine Safe Folder         : $QuarantineDir" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

Write-Log "Filesystem and persistence scraper finished successfully." "SUCCESS"
Write-Host "`n[+] Scraping complete. Review $IRReportFile for competition IR submissions." -ForegroundColor Green
if (-not $NonInteractive) { Read-Host "Press Enter to exit..." }
