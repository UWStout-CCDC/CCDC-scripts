# Define the URL for the DoD GPOs
$gpoUrl = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_October_2024.zip"

# Define the local path to save the GPOs
$gpoPath = "$env:TEMP\DoD_GPOs.zip"

# Download the DoD GPOs
Write-Host "Downloading DoD GPOs..."
Invoke-WebRequest -Uri $gpoUrl -OutFile $gpoPath

# Extract the GPOs
Write-Host "Extracting DoD GPOs..."
Expand-Archive -Path $gpoPath -DestinationPath "$env:TEMP\DoD_GPOs"

# Define the path to the specific GPO folder
$gpoFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\GPOs"
$wmiFilterFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\WMI Filter"

# Import the GPOs
Write-Host "Importing DoD GPOs..."
$gpoSubFolders = Get-ChildItem -Path $gpoFolder -Directory

foreach ($gpoSubFolder in $gpoSubFolders) {
    $gpoName = $gpoSubFolder.Name
    Write-Host "Importing GPO: $gpoName"
    Import-GPO -BackupGpoName $gpoName -Path $gpoSubFolder.FullName
}

# Apply WMI filters if they exist
if (Test-Path $wmiFilterFolder) {
    Write-Host "Applying WMI Filters..."
    $wmiFilterFiles = Get-ChildItem -Path $wmiFilterFolder -Filter "*.xml"
    foreach ($wmiFilterFile in $wmiFilterFiles) {
        Write-Host "Importing WMI Filter: $($wmiFilterFile.Name)"
        Import-WmiFilter -Path $wmiFilterFile.FullName
    }
}

# Apply the GPOs
Write-Host "Applying DoD GPOs..."
gpupdate /force

Write-Host "DoD GPOs have been downloaded, imported, and applied successfully."