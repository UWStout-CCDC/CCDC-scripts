# Firefox
$installFirefox = Read-Host "Do you want to install Firefox? (yes/no)"
if ($installFirefox -eq "yes") {
    Start-Job -ScriptBlock {
        $firefoxInstallerPath = "$env:TEMP\FirefoxInstaller.exe"
        Write-Host "Downloading Firefox installer..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US", $firefoxInstallerPath)

        Write-Host "Installing Firefox..."
        Start-Process -FilePath $firefoxInstallerPath -ArgumentList "/S" -Wait
    }
}

# ClamAV
$installClamAV = Read-Host "Do you want to install ClamAV? (yes/no)"
if ($installClamAV -eq "yes") {
    Start-Job -ScriptBlock {
        $clamavInstallerPath = "$env:TEMP\clamav-win-x64.msi"
        Write-Host "Downloading ClamAV installer..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.msi", $clamavInstallerPath)

        Write-Host "Installing ClamAV..."
        Start-Process -FilePath $clamavInstallerPath -ArgumentList "/quiet /norestart" -Wait

        # Configure ClamAV for regular scans
        Write-Host "Scheduling ClamAV scans..."
        $clamAVConfigPath = "C:\Program Files\ClamAV\clamd.conf"
        Set-Content -Path $clamAVConfigPath -Value 'LogFile "C:\Program Files\ClamAV\clamd.log"'
        schtasks /create /sc minute /mo 15 /tn "ClamAV Scan" /tr "C:\Program Files\ClamAV\clamscan.exe -r C:\" /st 00:00
    }
}

# Wireshark
$installWireshark = Read-Host "Do you want to install Wireshark? (yes/no)"
if ($installWireshark -eq "yes") {
    Start-Job -ScriptBlock {
        $wiresharkIntallerPath = "$env:TEMP\Wireshark-4.4.1-x64.exe"
        Write-Host "Downloading Wireshark..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://2.na.dl.wireshark.org/win64/Wireshark-4.4.1-x64.exe", $wiresharkIntallerPath)

        Write-Host "Installing Wireshark..."
        Start-Process -FilePath $wiresharkIntallerPath -ArgumentList "/S" -Wait
    }
}

# Sysinternals
$installSysinternals = Read-Host "Do you want to install Sysinternals tools? (yes/no)"
if ($installSysinternals -eq "yes") {
    Start-Job -ScriptBlock {
        Write-Host "Downloading Sysinternals..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", "$env:TEMP\Autoruns.zip")
        $webClient.DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", "$env:TEMP\ProcessExplorer.zip")
        $webClient.DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", "$env:TEMP\ProcessMonitor.zip")
        $webClient.DownloadFile("https://download.sysinternals.com/files/TCPView.zip", "$env:TEMP\TCPView.zip")

        Write-Host "Installing Sysinternals..."
        New-Item -Path "C:\Sysinternals" -ItemType Directory
        Expand-Archive -Path "$env:TEMP\Autoruns.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "$env:TEMP\ProcessExplorer.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "$env:TEMP\ProcessMonitor.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "$env:TEMP\TCPView.zip" -DestinationPath "C:\Sysinternals"
        Write-Host "Sysinternals installed to C:\Sysinternals"
    }
}
