# Firefox
$installFirefox = Read-Host "Do you want to install Firefox? (yes/no)"
if ($installFirefox -eq "yes") {
    Start-Job -ScriptBlock {
        $firefoxInstallerPath = "C:\CCDC\tools-Windows\FirefoxInstaller.exe"
        Write-Host "Installing Firefox..."
        Start-Process -FilePath $firefoxInstallerPath -ArgumentList "/quiet" -Wait
    }
}

# ClamAV
$installClamAV = Read-Host "Do you want to install ClamAV? (yes/no)"
if ($installClamAV -eq "yes") {
    Start-Job -ScriptBlock {
        $clamavInstallerPath = "C:\CCDC\tools-Windows\combined.msi"
        Write-Host "Installing ClamAV..."
        Start-Process -FilePath $clamavInstallerPath -ArgumentList "/quiet /norestart" -Wait
        # Configure ClamAV for regular scans
        Write-Host "Scheduling ClamAV scans..."
        $clamAVPath = "C:\Program Files\ClamAV\"
        # Copy the example configuration files and prepare them for use
        Copy-Item -Path "$clamAVPath\conf_examples\freshclam.conf.sample" -Destination "$clamAVPath\freshclam.conf"
        Copy-Item -Path "$clamAVPath\conf_examples\clamd.conf.sample" -Destination "$clamAVPath\clamd.conf"
        (Get-Content -Path "$clamAVPath\freshclam.conf") -replace '^Example', '' | Set-Content -Path "$clamAVPath\freshclam.conf"
        (Get-Content -Path "$clamAVPath\clamd.conf") -replace '^Example', '' | Set-Content -Path "$clamAVPath\clamd.conf"
        Set-Content -Path "$clamAVPath\clamd.conf" -Value 'LogFile "C:\Program Files\ClamAV\clamd.log"'
        # update the virus definitions
        Start-Process -FilePath "C:\Program Files\ClamAV\freshclam.exe"
        schtasks /create /sc minute /mo 15 /tn "ClamAV Scan" /tr "C:\Program Files\ClamAV\clamscan.exe -r C:\" /st 00:00
    }
}

# NPCAP (Required for Wireshark)
$installNpcap = Read-Host "Do you want to install NPCAP? (yes/no)"
if ($installNpcap -eq "yes") {
    Start-Job -ScriptBlock {
        $npcapInstallerPath = "C:\CCDC\tools-Windows\npcap-1.80.exe"
        Write-Host "Installing NPCAP..."
        Start-Process -FilePath $npcapInstallerPath -Wait
    }
}

# Wireshark
$installWireshark = Read-Host "Do you want to install Wireshark? (yes/no)"
if ($installWireshark -eq "yes") {
    Start-Job -ScriptBlock {
        $wiresharkIntallerPath = "C:\CCDC\tools-Windows\Wireshark-4.4.3-x64.exe"
        Write-Host "Installing Wireshark..."
        Start-Process -FilePath $wiresharkIntallerPath -ArgumentList "/S" -Wait
    }
}

# Sysinternals
$installSysinternals = Read-Host "Do you want to install Sysinternals tools? (yes/no)"
if ($installSysinternals -eq "yes") {
    Start-Job -ScriptBlock {
        Write-Host "Installing Sysinternals..."
        New-Item -Path "C:\Sysinternals" -ItemType Directory
        Expand-Archive -Path "C:\CCDC\tools-Windows\Autoruns.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "C:\CCDC\tools-Windows\ProcessExplorer.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "C:\CCDC\tools-Windows\ProcessMonitor.zip" -DestinationPath "C:\Sysinternals"
        Expand-Archive -Path "C:\CCDC\tools-Windows\TCPView.zip" -DestinationPath "C:\Sysinternals"
        Write-Host "Sysinternals installed to C:\Sysinternals"
    }
}

# Remove script from startup
$entryName = "MyStartupScript"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName

# Wait for all jobs to complete
Get-Job | Wait-Job

# Set execution policy back to Restricted
Write-Host "Setting execution policy back to Restricted..."
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Restricted -Force

$scriptPath = "C:\CCDC\tools-Windows\Win-Update.ps1"
$entryName = "Windows Update Script"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

# Restart the computer
Write-Host "Restarting Computer"
Restart-Computer