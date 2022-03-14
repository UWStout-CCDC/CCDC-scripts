# Windows from Blue Team Field Manual

## Tools

- Firefox
- [PSTools](https://download.sysinternals.com/files/PSTools.zip)

## DHCP Logging

`HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters:ActivityLogFlag=1`
Logs to `%windir%\System32\Dhcp`

## DNS Logging

    >DNScmd <NAME> /config /loglevel /0x8100F331
    >DNScmd <NAME> /config /LogFileFath <PATH>

## File Integrety !NOT AVAILABLE BY DEFAULT

    >fciv <file>
    >fciv c:\ -r -sha1 -xml <database.xml>
    >fciv -v -sha1 -xml <database.xml>

## User Activity

    >psloggedon \\computername

## AD

List OUs
    >dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXT>
List Workstations, Servers, DCs, OUs
    >netdom query <WORKSTATION|SERVER|DC|OU|PDC|TRUST|FSMO>
Query AD:
    > dsquery <ou|computer|..> [filter]
    filter = OU=[OU],DC=[DOMAIN],..

! TODO

## Services

    <sc <query|config|stop>
    >sc config "<NAME>" start= disabled

## Firewall

Already in script
    PS>Get-Content <LOG FILE>

## Change Password

    >net user <USERNAME> * /domain
    >net user <USERNAME> <NEW PASS>

## DNS / HOST FILE

Flush
    >ipconfig /flushdns
    >nbtstat -R
`HKLM\System\CurrentControlSet\Services\Tcpip\Parameters:DatabasePath=<HOST FILE>`
Host file is just
    <ip> <domain name>
Can set malicious domains to localhost

## AppLocker

I'm not sure if this is necessary or a good idea. It can only be done via GUI

## IPSec

I don't think this will help us

## Misc Reg Keys

See pg 30 to 32

## Patching

    >wusa <MSU FILE>
    ?>wuauclt /detectnow /updatenow

## Features and Updates

Query list of installed packages
    >Get-WindowsPackage -Online
