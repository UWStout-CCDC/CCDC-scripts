# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Create directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir $ccdcPath -Force
mkdir "$ccdcPath\DNS" -Force
mkdir $toolsPath -Force

# Ask if tools should be downloaded
$downloadTools = Read-Host "Do you want to download the necessary tools? (yes/no)"
if ($downloadTools -eq "yes") {
    # Download necessary tools
    $tools = @(
        @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
        @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" }
    )

    foreach ($tool in $tools) {
        Write-Host "Downloading $($tool.Name)..."
        Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
    }
} else {
    Write-Host "Skipping download of tools."
}

# Initialize the global jobs array
$global:jobs = @()

function Start-LoggedJob {
    param (
        [string]$JobName,
        [scriptblock]$ScriptBlock
    )
    
    $job = Start-Job -Name $JobName -ScriptBlock $ScriptBlock
    $global:jobs += @($job)  # Ensure the job is added as an array element
    Write-Host "Started job: $JobName"
}

# Sync system time
Start-LoggedJob -JobName "Synchronize System Time" -ScriptBlock {
    tzutil /s "Central Standard Time"
    w32tm /resync
}

# Set strong password policies
Start-LoggedJob -JobName "Set Password Policies" -ScriptBlock { net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 }

# Disable unnecessary services
$servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
foreach ($service in $servicesToDisable) {
    Start-LoggedJob -JobName "Disable Service: $service" -ScriptBlock {
        param ($service)
        Write-Host "Disabling service: $service"
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
    } -ArgumentList $service
}

# Additional test jobs
Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -PUAProtection Enabled
}

Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
}

Start-LoggedJob -JobName "Disable SMBv1" -ScriptBlock {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
}

# Monitor jobs
while ($global:jobs.Count -gt 0) {
    foreach ($job in $global:jobs) {
        if ($job.State -eq 'Completed') {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - $($job.Name) has completed."
            $job | Receive-Job
            Remove-Job -Job $job
            $global:jobs = $global:jobs | Where-Object { $_.Id -ne $job.Id }
        }
    }
    Start-Sleep -Seconds 5
}

Write-Host "All jobs have completed."