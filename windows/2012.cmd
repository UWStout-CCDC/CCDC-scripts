
set ccdcpath="c:\ccdc"
mkdir %ccdcpath% >NUL
icacls %ccdcpath% /inheritancelevel:e >NUL
mkdir %ccdcpath%\ThreatHunting >NUL
mkdir %ccdcpath%\Config >NUL
mkdir %ccdcpath%\Regback >NUL
mkdir %ccdcpath%\Proof >NUL

:: Set IP Addresses
set  EComm=172.20.241.30
set  DNSNTP=172.20.240.20
set  WebMail=172.20.241.40
set  Splunk=172.20.241.20
set  ADDNS=172.20.242.200
set  PAMI=172.20.242.150
set  2016Docker=172.20.240.10
set  UbuntuWeb=172.20.240.20
::set /P Windows10="ENTER WINDOWS 10 IP: "
set  UbuntuWkst=172.20.242.100
set  Internal=%Ecomm%,%DNSNTP%,%WebMail%,%Splunk%,%ADDNS%,%UbuntuWkst%,%PAMI%,%2016Docker%,%UbuntuWeb%
Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo Splunk ip is now %Splunk%
Echo AD/DNS box ip is now %ADDNS%
Echo UbuntuWeb IP is now %UbuntuWeb%
Echo UbuntuWkst is now %UbuntuWkst%
Echo PA MI is now %PAMI%
Echo Docker2016 is now %2016Docker%

:: Set Firewall
netsh advfirewall export %ccdcpath%\firewall.old
netsh advfirewall set allprofiles state on
:: Block by default
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles settings inboundusernotification enable
:: Logging
netsh advfirewall set allprofiles logging filename %ccdcpath%\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 8192
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set global statefulftp disable
netsh advfirewall set global statefulpptp disable

::call :Get_Sysinternals

:: Disable all rules
netsh advfirewall firewall set rule name=all new enable=no
:: New rules
netsh advfirewall firewall add rule name="Allow Pings" protocol=icmpv4:8,any dir=in action=allow enable=yes
netsh advfirewall firewall add rule name="All the Pings!" dir=out action=allow enable=yes protocol=icmpv4:8,any
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="Web OUT" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="DNS OUT" dir=out action=allow enable=no profile=any remoteport=53 protocol=udp remoteip=%DNSNTP%,9.9.9.9
:: netsh advfirewall firewall add rule name="SSH in from any" dir=in action=allow enable=no profile=any localport=22 protocol=tcp
netsh advfirewall firewall add rule name="NTP Allow" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=%DNSNTP% protocol=udp
:: netsh advfirewall firewall add rule name="WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip=%WebMail%,%Splunk%,%DNSNTP%,%EComm%,%UbuntuWkst%,%ADDNS%,%UbuntuWkst% remoteport=22 protocol=tcp

:: Diable IPv6 Teredo tunneling
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled 


:: Disable default accounts
ECHO "Disabling Guest..."
net user Guest /active:no

:: Disable features
ECHO "Disabling features..."
DISM /online /disable-feature /featurename:"TelnetClient"
DISM /online /disable-feature /featurename:"TelnetServer"
DISM /online /disable-feature /featurename:"TFTP"

:: Disable IIS features
DISM /online /disable-feature /featurename:"IIS-WebServerRole"
DISM /online /disable-feature /featurename:"IIS-WebServer"
DISM /online /disable-feature /featurename:"IIS-CommonHttpFeatures"
DISM /online /disable-feature /featurename:"IIS-Security"
DISM /online /disable-feature /featurename:"IIS-RequestFiltering"
DISM /online /disable-feature /featurename:"IIS-StaticContent"
DISM /online /disable-feature /featurename:"IIS-DefaultDocument"
DISM /online /disable-feature /featurename:"IIS-DirectoryBrowsing"
DISM /online /disable-feature /featurename:"IIS-HttpErrors"
DISM /online /disable-feature /featurename:"IIS-HttpRedirect"
DISM /online /disable-feature /featurename:"IIS-WebDAV"
DISM /online /disable-feature /featurename:"IIS-ApplicationDevelopment"
DISM /online /disable-feature /featurename:"IIS-WebSockets"
DISM /online /disable-feature /featurename:"IIS-ApplicationInit"
DISM /online /disable-feature /featurename:"IIS-NetFxExtensibility"
DISM /online /disable-feature /featurename:"IIS-NetFxExtensibility45"
DISM /online /disable-feature /featurename:"IIS-ISAPIExtensions"
DISM /online /disable-feature /featurename:"IIS-ISAPIFilter"
DISM /online /disable-feature /featurename:"IIS-ASPNET"
DISM /online /disable-feature /featurename:"IIS-ASPNET45"
DISM /online /disable-feature /featurename:"IIS-ASP"
DISM /online /disable-feature /featurename:"IIS-CGI"
DISM /online /disable-feature /featurename:"IIS-ServerSideIncludes"
DISM /online /disable-feature /featurename:"IIS-HealthAndDiagnostics"
DISM /online /disable-feature /featurename:"IIS-HttpLogging"
DISM /online /disable-feature /featurename:"IIS-LoggingLibraries"
DISM /online /disable-feature /featurename:"IIS-RequestMonitor"
DISM /online /disable-feature /featurename:"IIS-HttpTracing"
DISM /online /disable-feature /featurename:"IIS-CustomLogging"
DISM /online /disable-feature /featurename:"IIS-ODBCLogging"
DISM /online /disable-feature /featurename:"IIS-CertProvider"
DISM /online /disable-feature /featurename:"IIS-BasicAuthentication"
DISM /online /disable-feature /featurename:"IIS-WindowsAuthentication"
DISM /online /disable-feature /featurename:"IIS-DigestAuthentication"
DISM /online /disable-feature /featurename:"IIS-ClientCertificateMappingAuthentication"
DISM /online /disable-feature /featurename:"IIS-IISCertificateMappingAuthentication"
DISM /online /disable-feature /featurename:"IIS-URLAuthorization"
DISM /online /disable-feature /featurename:"IIS-IPSecurity"
DISM /online /disable-feature /featurename:"IIS-Performance"
DISM /online /disable-feature /featurename:"IIS-HttpCompressionStatic"
DISM /online /disable-feature /featurename:"IIS-HttpCompressionDynamic"
DISM /online /disable-feature /featurename:"IIS-WebServerManagementTools"
DISM /online /disable-feature /featurename:"IIS-ManagementConsole"
DISM /online /disable-feature /featurename:"IIS-LegacySnapIn"
DISM /online /disable-feature /featurename:"IIS-ManagementScriptingTools"
DISM /online /disable-feature /featurename:"IIS-ManagementService"
DISM /online /disable-feature /featurename:"IIS-IIS6ManagementCompatibility"
DISM /online /disable-feature /featurename:"IIS-Metabase"
DISM /online /disable-feature /featurename:"IIS-WMICompatibility"
DISM /online /disable-feature /featurename:"IIS-LegacyScripts"
DISM /online /disable-feature /featurename:"IIS-FTPServer"
DISM /online /disable-feature /featurename:"IIS-FTPSvc"
DISM /online /disable-feature /featurename:"IIS-FTPExtensibility"
DISM /online /disable-feature /featurename:"IIS-HostableWebCore"
DISM /online /disable-feature /featurename:"Microsoft-Windows-Web-Services-for-Management-IIS-Extension"

:: Enable Powershell
DISM /online /enable-feature /featurename:"MicrosoftWindowsPowerShellRoot"
DISM /online /enable-feature /featurename:"MicrosoftWindowsPowerShell"
:: Enable GUI
DISM /online /enable-feature /featurename:"ServerCore-FullServer"
DISM /online /enable-feature /featurename:"MicrosoftWindowsPowerShellV2"
DISM /online /enable-feature /featurename:"Server-Gui-Shell"

:: TODO: See if MSMQ is enabled in the practice arena. It's supposed to help mail servers by holding
:: mail.
:: DISM /online /disable-feature /featurename:"MSMQ"
:: DISM /online /disable-feature /featurename:"MSMQ-Services"
:: DISM /online /disable-feature /featurename:"MSMQ-Server"
:: DISM /online /disable-feature /featurename:"MSMQ-Triggers"
:: DISM /online /disable-feature /featurename:"MSMQ-ADIntegration"
:: DISM /online /disable-feature /featurename:"MSMQ-HTTP"
:: DISM /online /disable-feature /featurename:"MSMQ-Multicast"
:: DISM /online /disable-feature /featurename:"MSMQ-DCOMProxy"
:: DISM /online /disable-feature /featurename:"MSMQ-RoutingServer"

:: Disable Remote Access features
DISM /online /disable-feature /featurename:"Gateway-UI"
DISM /online /disable-feature /featurename:"RemoteAccess"
DISM /online /disable-feature /featurename:"RemoteAccessServer"
DISM /online /disable-feature /featurename:"RasRoutingProtocols"
DISM /online /disable-feature /featurename:"WindowsPowerShellWebAccess"
DISM /online /disable-feature /featurename:"RemoteAccessMgmtTools"
DISM /online /disable-feature /featurename:"RemoteAccessPowerShell"
DISM /online /disable-feature /featurename:"BitLocker-RemoteAdminTool"
DISM /online /disable-feature /featurename:"RemoteAssistance"
DISM /online /disable-feature /featurename:"Remote-Desktop-Services"

:: Disable SMB
DISM /online /disable-feature /featurename:"SmbDirect"
DISM /online /disable-feature /featurename:"SMB1Protocol"
DISM /online /disable-feature /featurename:"SMBBW"
DISM /online /disable-feature /featurename:"SmbWitness"
DISM /online /disable-feature /featurename:"SMBHashGeneration"

:: TODO?
:: DISM /online /disable-feature /featurename:"SBMgr-UI"

DISM /online /disable-feature /featurename:"SNMP"

:: Application server is for running custom business logic. I believe the only scored service is
:: DNS, so this shouldn't be required
DISM /online /disable-feature /featurename:"Application-Server"
DISM /online /disable-feature /featurename:"AS-NET-Framework"
DISM /online /disable-feature /featurename:"Application-Server-WebServer-Support"
DISM /online /disable-feature /featurename:"AS-Ent-Services"
DISM /online /disable-feature /featurename:"Application-Server-TCP-Port-Sharing"
DISM /online /disable-feature /featurename:"Application-Server-WAS-Support"
DISM /online /disable-feature /featurename:"Application-Server-HTTP-Activation"
DISM /online /disable-feature /featurename:"Application-Server-MSMQ-Activation"
DISM /online /disable-feature /featurename:"Application-Server-TCP-Activation"
DISM /online /disable-feature /featurename:"Application-Server-Pipe-Activation"
DISM /online /disable-feature /featurename:"AS-Dist-Transaction"
DISM /online /disable-feature /featurename:"AS-Incoming-Trans"
DISM /online /disable-feature /featurename:"AS-Outgoing-Trans"
DISM /online /disable-feature /featurename:"AS-WS-Atomic"

:: Registry

echo Editing Registry...
echo. > %ccdcpath%\Proof\regproof.txt

:: Just a name thing, but I don't like "redteam" being owner...
echo Change RegisteredOwner: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f

:: Turn on User account control
echo UAC: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
call :RegEdit add %K /v EnableLUA /t REG_DWORD /d 1

:: Disable admin autologon
set K="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
call :RegEdit add %K /v AutoAdminLogon /t REG_DWORD /d 0

echo Legal Banner: >> %ccdcpath%\Proof\regproof.txt
set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\system"
call :RegEdit add %K /v legalnoticecaption /t Reg_SZ /d "Team 12 Legal Notice"
call :RegEdit add %K /v legalnoticetext /t Reg_SZ /d "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED"

:: Windows Updates
:: echo Windows Updates: >> %ccdcpath%\Proof\regproof.txt
:: TODO: Doesn't exist in 2012?
:: set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
:: call :RegEdit add %K /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0
:: set K="HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
:: call :RegEdit add %K /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0

:: TODO: Doesn't exist in 2012?
:: set K="HKLM\SYSTEM\Internet Communication Management\Internet Communication"
:: call :RegEdit add %K /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0

:: TODO: I'm not sure what this does
:: set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
:: call :RegEdit add %K /v NoWindowsUpdate /t Reg_DWORD /d 0

::Autoupdates
echo Windows Auto Updates: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
call :RegEdit add %K /v AUOptions /t REG_DWORD /d 3
call :RegEdit add %K /v IncludeRecommendedUpdates /t REG_DWORD /d 1

::Clear remote registry paths
echo Clear remote registry paths >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths"
call :RegEdit add %K /v Machine /t REG_MULTI_SZ /d ""

set K="HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"
call :RegEdit add %K /v Machine /t REG_MULTI_SZ /d ""

:: Delete the image hijack that kills taskmanager
echo Re-enable task manager: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
call :RegEdit delete %K /v Debugger

echo Re-enable task manager 2: >> %ccdcpath%\Proof\regproof.txt
set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
call :RegEdit delete %K /v DisableTaskMgr

:: THIS PROBABLY HAS TO BE DONE MANUALLY if cmd is disabled, but who does that?!?!?!?!?!
echo Re-enable cmd prompt: >> %ccdcpath%\Proof\regproof.txt
set K="HKCU\Software\Policies\Microsoft\Windows\System"
call :RegEdit delete %K /v DisableCMD

::Enable Windows Defender
echo Re-enable Windows Defender: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
call :RegEdit delete %K /v DisableAntiSpyware

:: Unhide Files
echo Unhide files: >> %ccdcpath%\Proof\regproof.txt
set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
call :RegEdit add %K /v Hidden /t REG_DWORD /d 1

echo unhide system files: >> %ccdcpath%\Proof\regproof.txt
set K="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
call :RegEdit add %K /v ShowSuperHidden /t REG_DWORD /d 1

:: Fix Local Security Authority(LSA)
echo Restrictanonymous: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %K /v restrictanonymous /t REG_DWORD /d 1

echo Restrictanonymoussam: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %K /v restrictanonymoussam /t REG_DWORD /d 1

echo Change everyone includes anonymous: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %K /v everyoneincludesanonymous /t REG_DWORD /d 0

echo Get rid of the ridiculous store plaintext passwords: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"
call :RegEdit add %K /v EnablePlainTextPassword /t REG_DWORD /d 0

:: LMHash is weak
echo Turn off Local Machine Hash: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %K /v NoLMHash /t REG_DWORD /d 1

echo delete use machine id: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit delete %K /v UseMachineID

echo Change notification packages: >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %K /v "Notification Packages" /t REG_MULTI_SZ /d "scecli"

echo Show hidden users in gui: >> %ccdcpath%\Proof\regproof.txt
:: TODO
set K="HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts"
::call :RegEdit delete %K

echo Disable possible backdoors >> %ccdcpath%\Proof\regproof.txt
set K="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
call :RegEdit add %K /v "Debugger" /t REG_SZ /d "systray.exe"

set K="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
call :RegEdit add %K /v Debugger /t REG_SZ /d "systray.exe"

:: TODO set dns forward server to 9.9.9.9
:: netsh interface ipv4 set dnsservers "<?>" static 9.9.9.9 primary

:: TODO set NTP server
:: TODO splunk forwarding
:: TODO Disable remote access
:: TODO Restrict Powershell
:: TODO Update
:: TODO Windows Defender

EXIT /B 0

:: RegEdit <action> <registry> /v <entry> /t <type> /d <value>
:: %~0     %~1      %~2       %~3 %~4    %~5 %~6   %~7 %~8
:RegEdit
if %~3 != /v ( EXIT /B 1 )

REG query %~2 /v %~4 >> %ccdcpath%\Proof\regproof.txt
if %~1 == add (
  if %~5 != /t ( EXIT /B 1 )
  if %~7 != /d ( EXIT /B 1 )
  REG add %~2 /v %~4 /t %~6 /d %~8 /f
) else if %~1 == delete (
  REG delete %~2 /v %~4 /f
)
REG query %~2 /v %~4 >> %ccdcpath%\Proof\regproof.txt

EXIT /B 0

