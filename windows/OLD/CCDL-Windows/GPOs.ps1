$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"

# Download Group Policy
$tools = @(
    @{ Name = "Windows Defender GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Defender-gpos.zip"; Path = "$toolsPath\Defender-gpos.zip" },
    @{ Name = "Firefox GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox-gpos.zip"; Path = "$toolsPath\Firefox-gpos.zip" },
    @{ Name = "Edge GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/MS-Edge-gpos.zip"; Path = "$toolsPath\MS-Edge-gpos.zip" },
    @{ Name = "Windows 10 GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Windows-10-gpos.zip"; Path = "$toolsPath\Windows-10-gpos.zip" },
    @{ Name = "Windows 2019 GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Windows-2019-gpos.zip"; Path = "$toolsPath\Windows-2019-gpos.zip" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}

# Unzip the GPOs
foreach ($tool in $tools) {
    if ($tool.Path -like "*.zip") {
        $destinationPath = "$([System.IO.Path]::GetDirectoryName($tool.Path))\$($tool.Name)"
        Write-Host "Extracting $($tool.Name) to $destinationPath..."
        Expand-Archive -Path $tool.Path -DestinationPath $destinationPath -Force
    }
}

# Define the path to the specific GPO folder
#$gpoFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\GPOs"
#$wmiFilterFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\WMI Filter"
$gpoFolders = @()

# Select the GPOs based on the OS and server role
$productName = (Get-ComputerInfo).WindowsProductName
if ($productName -eq "Windows Server 2019 Standard") {
    if ((Get-WindowsFeature -Name AD-Domain-Services).installed) {
        $gpoFolders = @(
            # @{ Name = 'Defender'; Path = "$toolsPath\Windows Defender GPOs"},
            # @{ Name = 'Firefox'; Path = "$toolsPath\Firefox GPOs"},
            # @{ Name = 'Edge'; Path = "$toolsPath\Edge GPOs"},
            @{ Name = 'Windows 2019 DC'; Path = "$toolsPath\Windows 2019 GPOs"; Id = "515BB8D8-8316-445B-8EDF-590B1B434EC8"}
        )
    } else {
        $gpoFolders = @(
            # @{ Name = 'Defender'; Path = "$toolsPath\Windows Defender GPOs"},
            # @{ Name = 'Firefox'; Path = "$toolsPath\Firefox GPOs"},
            # @{ Name = 'Edge'; Path = "$toolsPath\Edge GPOs"},
            @{ Name = 'Windows 2019 MS'; Path = "$toolsPath\Windows 2019 GPOs"; Id = "314F919C-F030-469C-89C4-6B65CE42AC9D"}
        )
    }
}
else {
    $gpoFolders = @(
        # @{ Name = 'Defender'; Path = "$toolsPath\Windows Defender GPOs"},
        # @{ Name = 'Firefox'; Path = "$toolsPath\Firefox GPOs"},
        # @{ Name = 'Edge'; Path = "$toolsPath\Edge GPOs"},
        @{ Name = 'Windows 10'; Path = "$toolsPath\Windows 10 GPOs"; Id = "11CEE829-941A-4704-B7DC-2880B3D3710E"}
    )
}

# Import the GPOs
Write-Host "Importing DoD GPOs..."
foreach ($gpoFolder in $gpoFolders) {
    $gpoName = $gpoFolder.Name
    Write-Host "Importing GPO: $gpoName"
    New-GPO -Name $gpoFolder.Name
    $gpoId = (Get-GPO -Name $gpoFolder.Name).Id
    Import-GPO -BackupId $gpoFolder.Id -Path $gpoFolder.Path -TargetGuid $gpoId
    # Link the GPO to the domain and enforce it
    Write-Host "GPO has been created, enforce on the next boot."
}

# Apply WMI filters if they exist
# if (Test-Path $wmiFilterFolder) {
#     Write-Host "Applying WMI Filters..."
#     $wmiFilterFiles = Get-ChildItem -Path $wmiFilterFolder -Filter "*.xml"
#     foreach ($wmiFilterFile in $wmiFilterFiles) {
#         Write-Host "Importing WMI Filter: $($wmiFilterFile.Name)"
#         Import-WmiFilter -Path $wmiFilterFile.FullName
#     }
# }

# Apply the GPOs
Write-Host "Applying DoD GPOs..."
gpupdate /force

Write-Host "DoD GPOs have been downloaded, imported, and applied successfully."