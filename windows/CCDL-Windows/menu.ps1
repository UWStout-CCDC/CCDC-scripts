Function Show-Menu {
    Write-Host "====================="
    Write-Host " DNS and AD Management Menu"
    Write-Host "====================="
    Write-Host "1: Secure Directory"
    Write-Host "2: Backup DNS Zones"
    Write-Host "3: Restore DNS Zones"
    Write-Host "4: Backup AD Users"
    Write-Host "5: Restore AD Users"
    Write-Host "6: View and Disable AD Users"
    Write-Host "7: Exit"
    Write-Host "====================="
}

Function Start-DnsRecovery {
    param (
        [Parameter(Mandatory=$True)]
        [Object]$archive
    )
    
    # this cannot be changed, the commands will only load files from this dir
    $dnsRoot = "C:\Windows\System32\dns"

    # Check if required cmdlets are available
    $requiredCmdlets = @("Expand-Archive", "Add-DnsServerPrimaryZone", "Get-ChildItem", "Remove-Item")
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Write-Error "Required cmdlet $cmdlet is not available. Please ensure the necessary modules are installed."
            return
        }
    }

    If (!(Test-Path $archive)) {
        Write-Error "$archive does not exist, check the path and try again"
        return
    }

    Write-Host "Expanding $archive at $dnsRoot" -ForegroundColor Green
    Try {
        Expand-Archive -Path $archive -DestinationPath $dnsRoot -ErrorAction Stop
        Write-Host "Archive expanded successfully." -ForegroundColor Green
    } Catch {
        Write-Error "Failed to expand archive: $_"
        return
    }

    $allFiles = Get-ChildItem $dnsRoot
    $backupFiles = $allFiles | Where-Object {$_.Name -Like "*.dns.bak"}

    If ($backupFiles.Count -eq 0) {
        Write-Error "No backup files found in $dnsRoot"
        return
    }

    ForEach ($file in $backupFiles) {
        $zone = $file.Name.Replace('.dns.bak','')
        Write-Host "Loading $zone from $file..." -ForegroundColor Green
        Try { 
            Add-DnsServerPrimaryZone -ZoneName $zone -ZoneFile $file.Name -LoadExisting -ErrorAction Stop
            Write-Host "Successfully restored $zone" -ForegroundColor Green
        } Catch {
            Write-Warning "Failed to restore $zone $_"
        }
    }

    Write-Host "Removing backup files from $dnsRoot" -ForegroundColor Green
    Try {
        Remove-Item -Path "$dnsRoot\*.dns.bak" -ErrorAction Stop
        Write-Host "Backup files removed successfully." -ForegroundColor Green
    } Catch {
        Write-Error "Failed to remove backup files: $_"
    }
}

Function Backup-DnsZones {
    $backupLocation = "C:\DNS_Backups"
    if (-not (Test-Path $backupLocation)) {
        Write-Host "Creating backup directory at $backupLocation" -ForegroundColor Green
        Try {
            New-Item -Path $backupLocation -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Host "Backup directory created successfully." -ForegroundColor Green
        } Catch {
            Write-Error "Failed to create backup directory: $_"
            return
        }
    }
    $archive = "C:\$(Get-Date -UFormat %Y-%m-%d)-$env:COMPUTERNAME.dns.zip"
    $log = 'C:\DNS_Backups\dns_backup.log'
    Start-Transcript -Path $log -Append

    # Check if required cmdlets are available
    $requiredCmdlets = @("Get-DnsServerZone", "Export-DnsServerZone", "Compress-Archive", "Move-Item", "Remove-Item")
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Write-Error "Required cmdlet $cmdlet is not available. Please ensure the necessary modules are installed."
            Stop-Transcript
            return
        }
    }

    # User variables
    

    # System variables
    $dnsRoot = 'C:\Windows\System32\dns\'
    $primarys = Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' }

    # Use an array to catch bad things and put it in our log
    $failureArray = @()

    ForEach ($z in $primarys) {
        $zone = $z.ZoneName
        # Auto created zones fail to export
        If ($z.IsAutoCreated -eq $false -And $z.ZoneName -notLike "*arpa") {
            Write-Host "Zone $zone" -ForegroundColor Green
            $file = "$zone.dns.bak"
            Write-Host "Exporting $zone to $file" -ForegroundColor Green
            Try {
                Export-DnsServerZone -Name $zone -FileName $file -ErrorAction Stop
                Write-Host "Successfully exported $zone" -ForegroundColor Green
            } Catch {
                Write-Warning "Failed to backup $zone $_"
                $failureArray += $zone
            }
        }
    }

    # Zip and move
    $zipFiles = "$dnsRoot\*.dns.bak"

    Write-Host "Compressing archive $archive" -ForegroundColor Green
    Try {
        Compress-Archive -Path $zipFiles -DestinationPath $archive -ErrorAction Stop
        Write-Host "Archive compressed successfully." -ForegroundColor Green
    } Catch {
        Write-Error "Failed to compress archive: $_"
        $failureArray += "compression failure"
    }

    Write-Host "Moving $archive to $backupLocation" -ForegroundColor Green
    Try {
        Move-Item -Path $archive -Destination $backupLocation -ErrorAction Stop
        Write-Host "Archive moved successfully." -ForegroundColor Green
    } Catch {
        Write-Error "Failed to move archive: $_"
        $failureArray += "move failure"
    }

    Write-Host "Removing backup files from $dnsRoot" -ForegroundColor Green
    Try {
        Remove-Item -Path "$dnsRoot\*.dns.bak" -Recurse -ErrorAction Stop
        Write-Host "Backup files removed successfully." -ForegroundColor Green
    } Catch {
        Write-Error "Failed to remove backup files: $_"
        $failureArray += 'backup dir failed to remove'
    }

    If ($failureArray.Count -gt 0) {
        Write-Host "Failures: $failureArray" -ForegroundColor Red
    } Else {
        Write-Host "Backup completed successfully." -ForegroundColor Green
    }

    Stop-Transcript
}

Function Backup-AdUsers {
    Import-Module DSInternals
    $backupPath = "C:\AD_Backups"
    $logFile = "$backupPath\BackupLog.txt"
    $backupFile = "$backupPath\UsersBackup_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"

    # Function to log messages
    Function Write-Log {
        param ([string]$message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $message" | Tee-Object -FilePath $logFile -Append
    }

    # Ensure backup directory exists
    if (-not (Test-Path $backupPath)) {
        Write-Log "Creating backup directory at $backupPath..."
        Try {
            New-Item -Path $backupPath -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Log "Backup directory created successfully."
        } Catch {
            Write-Log "ERROR: Failed to create backup directory. $_"
            return
        }
    }

    # Export users and password hashes
    Write-Log "Backing up AD users and password hashes..."
    Try {
        $users = Get-ADUser -Filter * -Properties SamAccountName, GivenName, Surname, Name, UserPrincipalName, DistinguishedName, Enabled, Description

        $backupData = @()

        foreach ($user in $users) {
            $ntHash = (Get-ADReplAccount -SamAccountName $user.SamAccountName -Server (Get-ADDomainController).HostName).NTHash
            $backupData += [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                GivenName         = $user.GivenName
                Surname           = $user.Surname
                Name              = $user.Name
                UserPrincipalName = $user.UserPrincipalName
                DistinguishedName = $user.DistinguishedName
                Enabled           = $user.Enabled
                Description       = $user.Description
                NTLMHash          = $ntHash
            }
        }

        $backupData | Export-Csv -Path $backupFile -NoTypeInformation -Force
        Write-Log "Backup completed successfully. File saved at $backupFile"
    } Catch {
        Write-Log "ERROR: Failed to backup users. $_"
    }

    Write-Log "Backup script finished."
}

Function Restore-AdUsers {
    Import-Module DSInternals
    $backupPath = "C:\AD_Backups"
    $logFile = "$backupPath\RestoreLog.txt"
    $latestBackup = Get-ChildItem -Path $backupPath -Filter "UsersBackup_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    # Function to log messages
    Function Write-Log {
        param ([string]$message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $message" | Tee-Object -FilePath $logFile -Append
    }

    if (-not $latestBackup) {
        Write-Log "ERROR: No backup file found. Restore aborted."
        return
    }

    Write-Log "Using backup file: $($latestBackup.FullName)"
    $users = Import-Csv $latestBackup.FullName

    foreach ($user in $users) {
        Try {
            # Check if user already exists
            if (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue) {
                Write-Log "User '$($user.SamAccountName)' already exists. Skipping."
                continue
            }

            # Create user
            New-ADUser -SamAccountName $user.SamAccountName `
                       -GivenName $user.GivenName `
                       -Surname $user.Surname `
                       -Name $user.Name `
                       -UserPrincipalName $user.UserPrincipalName `
                       -Path $user.DistinguishedName `
                       -Enabled $true `
                       -Description $user.Description `
                       -PassThru

            # Restore password hash
            $hashBytes = [Convert]::FromBase64String($user.NTLMHash)
            Set-SamAccountPasswordHash -SamAccountName $user.SamAccountName -NTHash $hashBytes -Server (Get-ADDomainController).HostName
            Write-Log "Restored user: $($user.SamAccountName) with original password."
        } Catch {
            Write-Log "ERROR: Failed to restore user '$($user.SamAccountName)'. $_"
        }
    }

    Write-Log "Restore process completed."
}

# Function to create directories and secure them
Function New-Directories {
    param (
        [Parameter(Mandatory=$True)]
        [String]$path
    )

    # Check if required cmdlets are available
    $requiredCmdlets = @("New-Item", "Get-Acl", "Set-Acl")
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Write-Error "Required cmdlet $cmdlet is not available. Please ensure the necessary modules are installed."
            return
        }
    }

    # Create directory if it doesn't exist
    if (-not (Test-Path $path)) {
        Write-Host "Creating directory at $path" -ForegroundColor Green
        Try {
            New-Item -Path $path -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Host "Directory created successfully." -ForegroundColor Green
        } Catch {
            Write-Error "Failed to create directory: $_"
            return
        }
    }

    # Get the ACL of the directory
    $acl = Get-Acl -Path $path

    # Remove existing permissions
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

    # Create a new rule for Administrators
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)

    # Create a new rule for System
    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ruleSystem)

    # Set the new ACL
    Set-Acl -Path $path -AclObject $acl
}

Function Get-And-Disable-AdUsers {
    $logFile = "C:\AD_Backups\DisableUsersLog.txt"

    # Function to log messages
    Function Write-Log {
        param ([string]$message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $message" | Tee-Object -FilePath $logFile -Append
    }

    Write-Log "Checking required modules..."
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Active Directory module not found. Attempting to install..."
        Try {
            Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature -ErrorAction Stop
            Import-Module ActiveDirectory
            Write-Log "Active Directory module installed successfully."
        } Catch {
            Write-Log "ERROR: Failed to install Active Directory module. $_"
            return
        }
    }

    Write-Log "Fetching all AD users..."
    Try {
        $users = Get-ADUser -Filter * -Properties SamAccountName, Name, Enabled
        Write-Log "Fetched $(($users | Measure-Object).Count) users successfully."
    } Catch {
        Write-Log "ERROR: Failed to fetch AD users. $_"
        return
    }

    Write-Host "List of AD Users:"
    $users | ForEach-Object { Write-Host "$($_.SamAccountName) - $($_.Name) - Enabled: $($_.Enabled)" }

    $userToDisable = Read-Host "Enter the SamAccountName of the user to disable (or press + to return to the menu)"
    if ($userToDisable -eq '+') { return }

    $confirm = Confirm-Action "Are you sure you want to disable the user $userToDisable?"
    if (-not $confirm) { return }

    Write-Log "Attempting to disable user $userToDisable..."
    Try {
        Disable-ADAccount -Identity $userToDisable -ErrorAction Stop
        Write-Log "User $userToDisable disabled successfully."
        Write-Host "User $userToDisable disabled successfully." -ForegroundColor Green
    } Catch {
        Write-Log "ERROR: Failed to disable user $userToDisable. $_"
        Write-Host "ERROR: Failed to disable user $userToDisable. $_" -ForegroundColor Red
    }
}

# inital preparation
Install-PackageProvider -Name NuGet -Force

# Register the PowerShell Gallery as package repository if it is missing for any reason.
if($null -eq (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    Register-PSRepository -Default
    }

    # Download the DSInternals PowerShell module.
    Install-Module -Name DSInternals -Force

Function Confirm-Action {
    param (
        [string]$message
    )
    $confirmation = Read-Host "$message (Y/N)"
    return $confirmation -eq 'Y'
}

Do {
    Show-Menu
    $choice = Read-Host "Enter your choice"

    Switch ($choice) {
        1 {
            $path = Read-Host "Enter the path to secure (or press + to return to the menu)"
            if ($path -eq '+') { continue }
            New-Directories -path $path
             
        }
        2 {
            $confirm = Confirm-Action "Are you sure you want to backup DNS zones?"
            if ($confirm) {
                Backup-DnsZones
            }
             
        }
        3 {
            $archive = Read-Host "Enter the path to the DNS archive (or press + to return to the menu)"
            if ($archive -eq '+') { continue }
            $confirm = Confirm-Action "Are you sure you want to start DNS recovery?"
            if ($confirm) {
                Start-DnsRecovery -archive $archive
            }
             
        }
        4 {
            $confirm = Confirm-Action "Are you sure you want to backup AD users?"
            if ($confirm) {
                Backup-AdUsers
            }
             
        }
        5 {
            $confirm = Confirm-Action "Are you sure you want to restore AD users?"
            if ($confirm) {
                Restore-AdUsers
            }
        }
        6 {
            $confirm = Confirm-Action "Are you sure you want to View and Disable AD Users?"
            if ($confirm) {
                Get-And-Disable-AdUsers
            }
        }
        7 {
            Write-Host "Exiting..."
            Break
        }
        Default {
            Write-Host "Invalid choice, please try again"
             
        }
    }
} While ($choice -ne 7)