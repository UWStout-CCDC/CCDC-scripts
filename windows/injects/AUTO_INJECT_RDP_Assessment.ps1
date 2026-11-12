# AUTO_INJECT_RDP_Assessment.ps1
# Assess and harden Remote Desktop Protocol (RDP) configuration
# Inject ID: RDP01

Write-Host "`n===== RDP Security Assessment =====" -ForegroundColor Cyan

# Check RDP Status
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

if ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "[!] RDP is Enabled" -ForegroundColor Yellow
} else {
    Write-Host "[+] RDP is Disabled" -ForegroundColor Green
}

# Check Network Level Authentication
$nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

if ($nla.UserAuthentication -eq 1) {
    Write-Host "[+] NLA is Enabled" -ForegroundColor Green
} else {
    Write-Host "[!] NLA is Disabled" -ForegroundColor Red
}

# Check RDP Firewall Rules
Write-Host "`n===== RDP Firewall Rules =====" -ForegroundColor Cyan

$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "RemoteDesktop*" -or
        $_.DisplayGroup -eq "Remote Desktop"
    }

if ($rules) {
    $rules |
        Select-Object DisplayName, Enabled, Direction, Action |
        Format-Table -AutoSize
} else {
    Write-Host "[!] No standard RDP firewall rules found." -ForegroundColor Yellow
}

# Check Allowed Source IPs
Write-Host "`n===== Allowed RDP Source IPs =====" -ForegroundColor Cyan

$allowedRules = $rules | Where-Object {
    $_.Enabled -eq "True" -and
    $_.Direction -eq "Inbound" -and
    $_.Action -eq "Allow"
}

if ($allowedRules) {
    $allowedRules |
        Get-NetFirewallAddressFilter |
        Select-Object RemoteAddress |
        Format-Table -AutoSize
} else {
    Write-Host "[+] No enabled inbound RDP allow rules found." -ForegroundColor Green
}

# Check Scored Windows Services
Write-Host "`n===== Scored Windows Services =====" -ForegroundColor Cyan

$services = @(
    "WinRM",
    "DNS"
)

foreach ($service in $services) {
    $status = Get-Service -Name $service -ErrorAction SilentlyContinue

    if ($status) {
        Write-Host "$service : $($status.Status)"
    } else {
        Write-Host "$service : Not Installed"
    }
}

# Recommendations
Write-Host "`n===== Hardening Recommendations =====" -ForegroundColor Cyan

Write-Host "- Disable RDP if it is not required."
Write-Host "- Enable NLA if RDP is required."
Write-Host "- Restrict RDP to trusted source IP addresses."
Write-Host "- Do not disable DNS or WinRM services used for scoring."
Write-Host "- Do not modify unrelated Windows Firewall rules."

Write-Host "`nAssessment Complete." -ForegroundColor Green