# Variables
$tftpd64Path = "C:\CCDC\windows-tools\tftpd64.exe"  # Replace with the actual path to your Tftpd64 executable
$rootDirectory = "C:\TftpRoot"  # Set your desired TFTP root directory
$networkInterface = "Ethernet0"  # Name of the network interface to use
$logFile = "C:\CCDC\windows-tools\tftpd64_setup.log"

# Function to log messages
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logEntry
}

# Create the TFTP root directory if it doesn't exist
if (!(Test-Path $rootDirectory)) {
    New-Item -Path $rootDirectory -ItemType Directory
    Write-Log "Created TFTP root directory: $rootDirectory"
}

# Check if Tftpd64 service is already installed
$service = Get-Service -Name "Tftpd64" -ErrorAction SilentlyContinue
if ($service) {
    Write-Log "Tftpd64 service is already installed."
} else {
    # Register Tftpd64 as a Windows service
    $serviceArgs = @(
        "-install",
        "-svcname", "Tftpd64",
        "-startup=auto",
        "-DisplayName", "Tftpd64 Service",
        "-desc", "TFTP server using tftpd64"
    )
    Start-Process -FilePath $tftpd64Path -ArgumentList $serviceArgs -Wait
    Write-Log "Registered Tftpd64 as a Windows service."
}

# Configure Tftp settings within the service 
$configArgs = @(
    "-config",
    "-if", $networkInterface,
    "-root", $rootDirectory
)
Start-Process -FilePath $tftpd64Path -ArgumentList $configArgs -Wait
Write-Log "Configured Tftpd64 with root directory: $rootDirectory on interface: $networkInterface"

# Start the Tftpd64 service
Start-Service -Name "Tftpd64"
Write-Log "Started Tftpd64 service."

# Configure Windows Firewall to allow TFTP traffic
$firewallRule = Get-NetFirewallRule -DisplayName "Allow TFTP" -ErrorAction SilentlyContinue
if (!$firewallRule) {
    New-NetFirewallRule -DisplayName "Allow TFTP" -Direction Inbound -Protocol UDP -LocalPort 69 -Action Allow
    Write-Log "Configured Windows Firewall to allow TFTP traffic on port 69."
} else {
    Write-Log "Windows Firewall rule for TFTP traffic already exists."
}

Write-Output "Tftpd64 service configured with root directory: $($rootDirectory) on interface: $($networkInterface)"
Write-Log "Tftpd64 setup complete."