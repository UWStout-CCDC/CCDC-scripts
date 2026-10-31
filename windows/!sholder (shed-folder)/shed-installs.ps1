# tools installer:
#   install winget (use 2019 for 2019) (detect OS ?)
#   install Sysinternals :3333333
#   install firefox
#   install Docker if on non-AD server

#Requires -RunAsAdministrator
[CmdletBinding()]

$InstallDir = "C:\Tools"
$DownloadsDir = "$InstallDir\downloads"
$LogsDir = "$InstallDir\logs"
$dl = $DownloadsDir

# global preferences to stop catch errors and hide progress bars
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# TLS 1.2 to "fix downloads" - claude
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Create install directory for tools
Write-Host "Creating install directory at $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir, $LogsDir, $DownloadsDir | Out-Null

# Log everything from CLI to file
Start-Transcript -Path "$LogsDir\install-$(Get-Date -f yyyyMMdd-HHmmss).log"

# chud code past here

# try/catch for winget install

$Downloads = @(
    @{ Name = 'Docker';  Url = 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1' }
    # @{ Name = 'tool'; Url = 'https://example.com/tool.zip' }
)

try {
    # Bootstrap winget if not installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        try {
            Write-Host "[+] Downloading winget and its dependencies..."
            Invoke-WebRequest 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile "$dl\VCLibs.appx" -UseBasicParsing
            Invoke-WebRequest 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile "$dl\UIXaml.appx" -UseBasicParsing
            Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile "$dl\winget.msixbundle" -UseBasicParsing

            Write-Host "[+] Installing winget..."
            Add-AppxPackage -Path "$dl\winget.msixbundle" -DependencyPath "$dl\VCLibs.appx", "$dl\UIXaml.appx"

            # winget installs per-user, so add its folder to this session's PATH
            $env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
        }
        catch {
            Write-Warning "Could not install winget: $_"
        }
    }

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    $wingetPath = if ($wingetCmd) { $wingetCmd.Source } else { $null }



    # JOB QUEUE: Launch all installs and downloads concurrently
    #----------------------------------------------------------
    $Jobs = [System.Collections.Generic.List[PSObject]]::new()

    # 1. Winget package install jobs
    if ($wingetPath) {
        $packages = @('Microsoft.Sysinternals.Suite', 'Mozilla.Firefox')

        foreach ($id in $packages) {
            Write-Host "[+] Queuing winget install job for: $id" -ForegroundColor Cyan
            $job = Start-Job -Name "Install-$id" -ScriptBlock {
                param($pkgId, $exePath)
                $ErrorActionPreference = 'Stop'
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                # Ensure path is available in the background job process
                if ($env:Path -notlike "*$env:LOCALAPPDATA\Microsoft\WindowsApps*") {
                    $env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
                }

                Write-Host "[*] [$pkgId] Starting installation via winget..."

                # Retry up to 3 times in case of transient installer/database locks
                $maxRetries = 3
                $retryDelay = 5
                $installed = $false
                $lastCode = 0

                for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                    Write-Host "[*] [$pkgId] (Attempt $attempt/$maxRetries) Running winget install..."
                    & $exePath install --id $pkgId --exact --source winget --silent `
                        --accept-package-agreements --accept-source-agreements

                    $lastCode = $LASTEXITCODE
                    if ($lastCode -eq 0) {
                        Write-Host "[✓] [$pkgId] Successfully installed!"
                        $installed = $true
                        break
                    }
                    else {
                        if ($attempt -lt $maxRetries) {
                            Write-Warning "[-] [$pkgId] Winget returned code $lastCode. Retrying in ${retryDelay}s..."
                            Start-Sleep -Seconds $retryDelay
                        }
                    }
                }

                if (-not $installed) {
                    throw "winget exited with code $lastCode for $pkgId"
                }
            } -ArgumentList $id, $wingetPath

            $Jobs.Add($job)
        }
    }
    else {
        Write-Warning "winget unavailable, skipping Sysinternals and Firefox."
    }

    # 2. Standalone file download jobs
    foreach ($d in $Downloads) {
        Write-Host "[+] Queuing download job for: $($d.Name)" -ForegroundColor Cyan
        $job = Start-Job -Name "Download-$($d.Name)" -ScriptBlock {
            param($name, $url, $destDir, $targetInstallDir)
            $ErrorActionPreference = 'Stop'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $filename = Split-Path -Leaf $url
            if (-not $filename -or $filename -notlike "*.*") {
                $filename = "$name.dat"
            }
            $outFile = Join-Path $destDir $filename

            Write-Host "[*] [$name] Downloading from $url to $outFile..."
            Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -TimeoutSec 300
            Write-Host "[✓] [$name] Download complete."

            # If it's a zip file, unpack it
            if ($filename -like "*.zip") {
                $extractPath = Join-Path $targetInstallDir $name
                Write-Host "[*] [$name] Extracting archive to $extractPath..."
                Expand-Archive -Path $outFile -DestinationPath $extractPath -Force
                Write-Host "[✓] [$name] Archive extracted."
            }
        } -ArgumentList $d.Name, $d.Url, $DownloadsDir, $InstallDir

        $Jobs.Add($job)
    }

    # MONITORING: Track running jobs and notify as each finishes
    # -----------------------------------------------------------
    if ($Jobs.Count -gt 0) {
        Write-Host "`n[+] Launched $($Jobs.Count) install/download job(s) in parallel. Waiting for completion..." -ForegroundColor Cyan
        $Jobs | Format-Table Id, Name, State -AutoSize | Out-String | Write-Host

        $completedIds = [System.Collections.Generic.HashSet[int]]::new()
        $jobResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        while ($completedIds.Count -lt $Jobs.Count) {
            foreach ($j in $Jobs) {
                if (-not $completedIds.Contains($j.Id)) {
                    $current = Get-Job -Id $j.Id
                    if ($current.State -ne 'Running' -and $current.State -ne 'NotStarted') {
                        $completedIds.Add($j.Id) | Out-Null

                        $outputLines = $null
                        $isFailed = ($current.State -eq 'Failed')
                        $errMsg = $null

                        try {
                            $outputLines = Receive-Job -Job $current -ErrorAction Stop
                        }
                        catch {
                            $isFailed = $true
                            $errMsg = $_.Exception.Message
                        }

                        if (-not $isFailed -and $current.State -eq 'Completed') {
                            Write-Host "`n[✓] Job '$($current.Name)' completed successfully!" -ForegroundColor Green
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $current.Name
                                Status  = "Success"
                                Details = "Completed"
                            })
                        }
                        else {
                            if (-not $errMsg) {
                                $errMsg = if ($current.ChildJobs.JobStateInfo.Reason) {
                                    $current.ChildJobs.JobStateInfo.Reason.Message
                                } else {
                                    "Exited with state $($current.State)"
                                }
                            }
                            Write-Host "`n[✗] Job '$($current.Name)' failed: $errMsg" -ForegroundColor Red
                            $jobResults.Add([PSCustomObject]@{
                                JobName = $current.Name
                                Status  = "Failed"
                                Details = $errMsg
                            })
                        }

                        if ($outputLines) {
                            Write-Host "--- Output from $($current.Name) ---" -ForegroundColor DarkGray
                            $outputLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                            Write-Host "------------------------------------" -ForegroundColor DarkGray
                        }
                    }
                }
            }
            Start-Sleep -Milliseconds 800
        }

        # -----------------------------------------------------------
        # NOTIFY: Final summary and notification alerts
        # -----------------------------------------------------------
        $successCount = ($jobResults | Where-Object { $_.Status -eq 'Success' }).Count
        $failCount = ($jobResults | Where-Object { $_.Status -eq 'Failed' }).Count
        $totalCount = $jobResults.Count

        Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
        Write-Host "               ALL INSTALL JOBS COMPLETE" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan
        $jobResults | Format-Table -AutoSize | Out-String | Write-Host

        $timestamp = Get-Date -Format "HH:mm:ss"

        if ($failCount -eq 0) {
            $notifyTitle = "CCDC Installs - All Done!"
            $notifyMessage = "[$timestamp] All $totalCount installs finished successfully."
            Write-Host "[NOTIFY] $notifyMessage" -ForegroundColor Green

            # Audio notification (victory chime)
            try {
                [System.Console]::Beep(800, 150)
                [System.Console]::Beep(1000, 150)
                [System.Console]::Beep(1200, 250)
            } catch {}
        }
        else {
            $notifyTitle = "CCDC Installs - Finished with Errors"
            $notifyMessage = "[$timestamp] Installs complete: $successCount succeeded, $failCount failed."
            Write-Host "[NOTIFY] $notifyMessage" -ForegroundColor Red

            # Audio notification (warning beeps)
            try {
                [System.Console]::Beep(500, 250)
                Start-Sleep -Milliseconds 100
                [System.Console]::Beep(500, 250)
            } catch {}
        }
        Write-Host ("=" * 60) + "`n" -ForegroundColor Cyan

        # Windows desktop notification (balloon tip)
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Information
            $balloon.BalloonTipTitle = $notifyTitle
            $balloon.BalloonTipText = $notifyMessage
            $balloon.BalloonTipIcon = if ($failCount -eq 0) { [System.Windows.Forms.ToolTipIcon]::Info } else { [System.Windows.Forms.ToolTipIcon]::Warning }
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(10000)
        } catch {}

        # Cleanup jobs
        $Jobs | ForEach-Object { Remove-Job -Job $_ -Force -ErrorAction SilentlyContinue }
    }
    else {
        Write-Host "[-] No jobs queued to run." -ForegroundColor Yellow
    }

    Write-Host "[done]"
}
finally {
    Stop-Transcript
}