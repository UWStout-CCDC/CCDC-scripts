$winget = (Invoke-WebRequest -Uri "https://aka.ms/getwinget" -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
$vclibs = (Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location

Start-Bitstransfer -Source "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -Destination ".\Microsoft.UI.Xaml.2.8.6.msixbundle"
Start-Bitstransfer -Source "$vclibs" -Destination ".\Microsoft.VCLibs.x64.14.00.Desktop.appx"
Start-Bitstransfer -Source "$winget" -Destination ".\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

Add-AppxPackage -Path ".\Microsoft.VCLibs.x64.14.00.Desktop.appx"
Add-AppxPackage -Path ".\Microsoft.UI.Xaml.2.8.6.msixbundle"
Add-AppxPackage -Path ".\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"