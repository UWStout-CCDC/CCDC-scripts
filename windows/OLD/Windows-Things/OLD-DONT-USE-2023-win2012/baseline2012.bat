@echo off

:: Notes: This file needs to be copied and pasted into notepad, rather than saving the webpage as
:: text.

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
set  UbuntuWeb=172.20.242.10
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

:: Export exisiting Firewall
netsh advfirewall export %ccdcpath%\firewall.old
netsh advfirewall set allprofiles state on
:: Block by default
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles settings inboundusernotification enable
:: Enable Logging
netsh advfirewall set allprofiles logging filename %ccdcpath%\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 8192
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set global statefulftp disable
netsh advfirewall set global statefulpptp disable

::Disable existing rules
netsh advfirewall firewall set rule name=all new enable=no

::Outbound rules
netsh advfirewall firewall add rule name="Allow Pings out" dir=out action=allow enable=yes protocol=icmpv4:8,any
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="Web OUT" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="NTP OUT" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=any protocol=udp
netsh advfirewall firewall add rule name="Active Directory TCP OUT" dir=out action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any remoteport=any remoteip=any protocol=tcp
netsh advfirewall firewall add rule name="Active Directory UDP OUT" dir=out action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any remoteport=any remoteip=any protocol=udp
netsh advfirewall firewall add rule name="DNS TCP OUT" dir=out action=allow program="C:\Windows\System32\dns.exe" enable=yes profile=any remoteport=any remoteip=any protocol=tcp
netsh advfirewall firewall add rule name="DNS UDP OUT" dir=out action=allow program="C:\Windows\System32\dns.exe" enable=yes profile=any remoteport=any remoteip=any protocol=udp
netsh advfirewall firewall add rule name="DNS OUT" dir=out action=allow enable=yes profile=any remoteport=53 protocol=udp remoteip=%DNSNTP%,9.9.9.9
netsh advfirewall firewall add rule name="DHCP" dir=out action=allow program="C:\Windows\System32\svhost.exe" enable=yes profile=any localport=68 remoteport=67 remoteip=any protocol=udp

::Inbound rules
netsh advfirewall firewall add rule name="NTP in" dir=in action=allow enable=yes profile=any localport=123 remoteip=any protocol=udp
netsh advfirewall firewall add rule name="Allow Pings in" dir=in action=allow enable=yes protocol=icmpv4:8,any 
netsh advfirewall firewall add rule name="DNS IN (UDP)" dir=in action=allow enable=yes profile=any localport=53 protocol=udp
netsh advfirewall firewall add rule name="DNS IN (TDP)" dir=in action=allow enable=yes profile=any localport=53 protocol=tcp
netsh advfirewall firewall add rule name="LDAP TCP IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=389 protocol=tcp
netsh advfirewall firewall add rule name="LDAP UDP IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=389 protocol=udp
netsh advfirewall firewall add rule name="LDAP Global Catalog IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=3268 protocol=tcp
netsh advfirewall firewall add rule name="NETBIOS Resolution IN" dir=in action=allow program="System" enable=yes profile=any localport=138 protocol=udp
netsh advfirewall firewall add rule name="SAM/LSA TCP In" dir=in action=allow program="System" enable=yes profile=any localport=445 protocol=tcp
netsh advfirewall firewall add rule name="SAM/LSA UDP In" dir=in action=allow program="System" enable=yes profile=any localport=445 protocol=udp
netsh advfirewall firewall add rule name="Secure LDAP IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=636 protocol=tcp
netsh advfirewall firewall add rule name="Secure LDAP Global Catalog IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=3269 protocol=tcp
netsh advfirewall firewall add rule name="RPC IN" dir=in action=allow program="C:\Windows\System32\lsass.exe" enable=yes profile=any localport=RPC protocol=tcp
netsh advfirewall firewall add rule name="RPC-EPMAP IN" dir=in action=allow program="C:\Windows\System32\svhost.exe" enable=yes profile=any localport=RPC-EPMap protocol=tcp
netsh advfirewall firewall add rule name="DHCP UDP IN" dir=in action=allow program="C:\Windows\System32\svhost.exe" enable=yes profile=any localport=67,68 protocol=udp
netsh advfirewall firewall add rule name="RPC for DNS IN" dir=in action=allow program="C:\Windows\System32\dns.exe" enable=yes profile=any localport=RPC protocol=tcp

:: Diable IPv6 Teredo tunneling
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled 

:: Disable default accounts
ECHO "Disabling Guest..."
net user Guest /active:no

::Backup GPOs
mkdir c:\ccdc\gpobackup\
powershell -Command "Backup-Gpo -All -Path c:\ccdc\gpobackup"

::Import Group Policy
ECHO "Importing Group Policy..."
powershell -Command "Import-GPO -BackupGPOName 'Audit Policy' -TargetName AuditPolicy -path .\gpo -CreateIfNeeded"
:: powershell -Command "Import-GPO -BackupGPOName 'Password Policy' -TargetName PasswordPolicy -path .\gpo -CreateIfNeeded"
powershell -Command "Import-GPO -BackupGPOName 'Access Control' -TargetName AccessControl -path .\gpo -CreateIfNeeded"
powershell -Command "Import-GPO -BackupGPOName 'AppLocker' -TargetName AppLocker -path .\gpo -CreateIfNeeded"

::Secure DNS
dnscmd /Config /SocketPoolSize 10000
dnscmd /Config /CacheLockingPercent 100

:: Disable features
ECHO "Disabling features..."
DISM /online /disable-feature /featurename:"TelnetClient" /NoRestart
DISM /online /disable-feature /featurename:"TelnetServer" /NoRestart
DISM /online /disable-feature /featurename:"TFTP" /NoRestart

:: Disable IIS features
DISM /online /disable-feature /featurename:"IIS-WebServerRole" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WebServer" /NoRestart
DISM /online /disable-feature /featurename:"IIS-CommonHttpFeatures" /NoRestart
DISM /online /disable-feature /featurename:"IIS-Security" /NoRestart
DISM /online /disable-feature /featurename:"IIS-RequestFiltering" /NoRestart
DISM /online /disable-feature /featurename:"IIS-StaticContent" /NoRestart
DISM /online /disable-feature /featurename:"IIS-DefaultDocument" /NoRestart
DISM /online /disable-feature /featurename:"IIS-DirectoryBrowsing" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpErrors" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpRedirect" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WebDAV" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ApplicationDevelopment" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WebSockets" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ApplicationInit" /NoRestart
DISM /online /disable-feature /featurename:"IIS-NetFxExtensibility" /NoRestart
DISM /online /disable-feature /featurename:"IIS-NetFxExtensibility45" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ISAPIExtensions" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ISAPIFilter" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ASPNET" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ASPNET45" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ASP" /NoRestart
DISM /online /disable-feature /featurename:"IIS-CGI" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ServerSideIncludes" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HealthAndDiagnostics" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpLogging" /NoRestart
DISM /online /disable-feature /featurename:"IIS-LoggingLibraries" /NoRestart
DISM /online /disable-feature /featurename:"IIS-RequestMonitor" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpTracing" /NoRestart
DISM /online /disable-feature /featurename:"IIS-CustomLogging" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ODBCLogging" /NoRestart
DISM /online /disable-feature /featurename:"IIS-CertProvider" /NoRestart
DISM /online /disable-feature /featurename:"IIS-BasicAuthentication" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WindowsAuthentication" /NoRestart
DISM /online /disable-feature /featurename:"IIS-DigestAuthentication" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ClientCertificateMappingAuthentication" /NoRestart
DISM /online /disable-feature /featurename:"IIS-IISCertificateMappingAuthentication" /NoRestart
DISM /online /disable-feature /featurename:"IIS-URLAuthorization" /NoRestart
DISM /online /disable-feature /featurename:"IIS-IPSecurity" /NoRestart
DISM /online /disable-feature /featurename:"IIS-Performance" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpCompressionStatic" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HttpCompressionDynamic" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WebServerManagementTools" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ManagementConsole" /NoRestart
DISM /online /disable-feature /featurename:"IIS-LegacySnapIn" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ManagementScriptingTools" /NoRestart
DISM /online /disable-feature /featurename:"IIS-ManagementService" /NoRestart
DISM /online /disable-feature /featurename:"IIS-IIS6ManagementCompatibility" /NoRestart
DISM /online /disable-feature /featurename:"IIS-Metabase" /NoRestart
DISM /online /disable-feature /featurename:"IIS-WMICompatibility" /NoRestart
DISM /online /disable-feature /featurename:"IIS-LegacyScripts" /NoRestart
DISM /online /disable-feature /featurename:"IIS-FTPServer" /NoRestart
DISM /online /disable-feature /featurename:"IIS-FTPSvc" /NoRestart
DISM /online /disable-feature /featurename:"IIS-FTPExtensibility" /NoRestart
DISM /online /disable-feature /featurename:"IIS-HostableWebCore" /NoRestart
DISM /online /disable-feature /featurename:"Microsoft-Windows-Web-Services-for-Management-IIS-Extension" /NoRestart

:: Disable Remote Access features
DISM /online /disable-feature /featurename:"Gateway-UI" /NoRestart
DISM /online /disable-feature /featurename:"RemoteAccess" /NoRestart
DISM /online /disable-feature /featurename:"RemoteAccessServer" /NoRestart
DISM /online /disable-feature /featurename:"RasRoutingProtocols" /NoRestart
DISM /online /disable-feature /featurename:"WindowsPowerShellWebAccess" /NoRestart
DISM /online /disable-feature /featurename:"RemoteAccessMgmtTools" /NoRestart
DISM /online /disable-feature /featurename:"RemoteAccessPowerShell" /NoRestart
DISM /online /disable-feature /featurename:"BitLocker-RemoteAdminTool" /NoRestart
DISM /online /disable-feature /featurename:"RemoteAssistance" /NoRestart
DISM /online /disable-feature /featurename:"Remote-Desktop-Services" /NoRestart

:: Disable SMB1
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"

DISM /online /disable-feature /featurename:"SmbDirect" /NoRestart
DISM /online /disable-feature /featurename:"SMB1Protocol" /NoRestart
DISM /online /disable-feature /featurename:"SMBBW" /NoRestart
DISM /online /disable-feature /featurename:"SmbWitness" /NoRestart
DISM /online /disable-feature /featurename:"SMBHashGeneration" /NoRestart

DISM /online /disable-feature /featurename:"SNMP" /NoRestart

::Enable SMB2 for GPM
powershell -Command "Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force"

:: Application server is for running custom business logic. I believe the only scored service is
:: DNS, so this shouldn't be required
DISM /online /disable-feature /featurename:"Application-Server" /NoRestart
DISM /online /disable-feature /featurename:"AS-NET-Framework" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-WebServer-Support" /NoRestart
DISM /online /disable-feature /featurename:"AS-Ent-Services" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-TCP-Port-Sharing" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-WAS-Support" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-HTTP-Activation" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-MSMQ-Activation" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-TCP-Activation" /NoRestart
DISM /online /disable-feature /featurename:"Application-Server-Pipe-Activation" /NoRestart
DISM /online /disable-feature /featurename:"AS-Dist-Transaction" /NoRestart
DISM /online /disable-feature /featurename:"AS-Incoming-Trans" /NoRestart
DISM /online /disable-feature /featurename:"AS-Outgoing-Trans" /NoRestart
DISM /online /disable-feature /featurename:"AS-WS-Atomic" /NoRestart



::Backup registry before making modifications
mkdir "c:\ccdc\regbackup"
set regbakpath="c:\ccdc\regbackup"
reg export HKCR %regbakpath%\HKCR.reg /y
reg export HKCU %regbakpath%\HKCU.reg /y
reg export HKLM %regbakpath%\HKLM.reg /y
reg export HKU %regbakpath%\HKU.reg /y
reg export HKCC %regbakpath%\HKCC.reg /y

echo Editing Registry...
echo. > %ccdcpath%\Proof\regproof.txt

:: Just a name thing, but I don't like "redteam" being owner...
echo Change RegisteredOwner: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f


:: Disable admin autologon
set PA="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
call :RegEdit add %PA% /v AutoAdminLogon /t REG_DWORD /d 0

echo Legal Banner: >> %ccdcpath%\Proof\regproof.txt
set PA="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\system"
call :RegEdit add %PA% /v legalnoticecaption /t Reg_SZ /d "Legal Notice"
call :RegEdit add %PA% /v legalnoticetext /t Reg_SZ /d "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED"

:: Turn on User account control
echo UAC: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
call :RegEdit add %PA% /v EnableLUA /t REG_DWORD /d 1

::Autoupdates
echo Windows Auto Updates: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
call :RegEdit add %PA% /v AUOptions /t REG_DWORD /d 3
call :RegEdit add %PA% /v IncludeRecommendedUpdates /t REG_DWORD /d 1

::Clear remote registry paths
echo Clear remote registry paths >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths"
call :RegEdit add %PA% /v Machine /t REG_MULTI_SZ /d ""

set PA="HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"
call :RegEdit add %PA% /v Machine /t REG_MULTI_SZ /d ""

:: Delete the image hijack that kills taskmanager
echo Re-enable task manager: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
call :RegEdit delete %PA% /v Debugger

echo Re-enable task manager 2: >> %ccdcpath%\Proof\regproof.txt
set PA="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
call :RegEdit delete %PA% /v DisableTaskMgr

:: THIS PROBABLY HAS TO BE DONE MANUALLY if cmd is disabled, but who does that?!?!?!?!?!
echo Re-enable cmd prompt: >> %ccdcpath%\Proof\regproof.txt
set PA="HKCU\Software\Policies\Microsoft\Windows\System"
call :RegEdit delete %PA% /v DisableCMD

::Enable Windows Defender
echo Re-enable Windows Defender: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
call :RegEdit delete %PA% /v DisableAntiSpyware

:: Unhide Files
echo Unhide files: >> %ccdcpath%\Proof\regproof.txt
set PA="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
call :RegEdit add %PA% /v Hidden /t REG_DWORD /d 1
echo unhide system files: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add %PA% /v ShowSuperHidden /t REG_DWORD /d 1

:: Fix Local Security Authority(LSA)
set PA="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %PA% /v RunAsPPL /t REG_DWORD /d 1
echo Restrictanonymous: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add %PA% /v restrictanonymous /t REG_DWORD /d 1
echo Restrictanonymoussam: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add %PA% /v restrictanonymoussam /t REG_DWORD /d 1
echo Change everyone includes anonymous: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add %PA% /v everyoneincludesanonymous /t REG_DWORD /d 0
echo delete use machine id: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit delete %PA% /v UseMachineID
echo Change notification packages: >> %ccdcpath%\Proof\regproof.txt
call :RegEdit add %PA% /v "Notification Packages" /t REG_MULTI_SZ /d "scecli"

echo Get rid of the ridiculous store plaintext passwords: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"
call :RegEdit add %PA% /v EnablePlainTextPassword /t REG_DWORD /d 0

:: LMHash is weak
echo Turn off Local Machine Hash: >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SYSTEM\CurrentControlSet\Control\LSA"
call :RegEdit add %PA% /v NoLMHash /t REG_DWORD /d 1

echo Show hidden users in gui: >> %ccdcpath%\Proof\regproof.txt
:: TODO
set PA="HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts"
::call :RegEdit delete %PA%

echo Disable possible backdoors >> %ccdcpath%\Proof\regproof.txt
set PA="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
call :RegEdit add %PA% /v "Debugger" /t REG_SZ /d "systray.exe"

set PA="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
call :RegEdit add %PA% /v Debugger /t REG_SZ /d "systray.exe"

set PA="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
call :RegEdit add %PA% /v SMB1 /t REG_DWORD /d 0
call :RegEdit add %PA% /v SMB2 /t REG_DWORD /d 0

:: Require Ctrl-Alt-Del on login
set PA="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
call :RegEdit add %PA% /v "DisableCAD" /t REG_DWORD /d 0


:: Set NTP server
:: The first 3 commands stop the ntp client, and reset it to default config
net stop w32time
w32tm /unregister
w32tm /register
w32tm /config /manualpeerlist:"172.20.240.20 time.nist.gov",0x8 /syncfromflags:MANUAL
w32tm /config /reliable:yes
net start w32time

:: Disable remote Powershell
:: PS> Disable-PSRemoting -Force
powershell -Command "Disable-PSRemoting -Force"

cmd /k


:: RegEdit <action> <registry> /v <entry> /t <type> /d <value>
:: %~0     %~1      %~2       %~3 %~4    %~5 %~6   %~7 %~8
:RegEdit
if %~3 NEQ /v ( EXIT /B 1 )

ECHO %~2
REG query %2 /v %4 >> %ccdcpath%\Proof\regproof.txt
if "%~1" == "add" (
  if "%5" NEQ "/t" ( EXIT /B 1 )
  if "%7" NEQ "/d" ( EXIT /B 1 )
  REG add %2 /v %4 /t %6 /d %8 /f
) else if "%~1" == "delete" (
  REG delete %2 /v %4 /f
)
REG query %2 /v %4 >> %ccdcpath%\Proof\regproof.txt

EXIT /B 0
