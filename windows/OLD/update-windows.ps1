try {
        Set-Service -Name wuauserv -StartupType Automatic
        Write-Host "Installing Windows updates..."
        Start-Sleep -Seconds 60

        $maxRetries = 3
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                Install-WindowsUpdate -AcceptAll -Install
                Write-Host "--------------------------------------------------------------------------------"
                Write-Host "Windows updates installed."
                Write-Host "--------------------------------------------------------------------------------"
                $success = $true
            } catch {
                $retryCount++
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Write-Host "An error occurred while installing Windows updates: $_"
                Write-Host "Retrying... ($retryCount/$maxRetries)"
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Start-Sleep -Seconds 60
            }
        }

        if (-not $success) {
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            Write-Host "Failed to install Windows updates after $maxRetries attempts."
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An unexpected error occurred: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }