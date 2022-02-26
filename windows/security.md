# Windows Security

## Group Policy
> Domains > [DOMAIN]
- Groups that can have GPOs created for them

- DG_Readiness_tool ?

AD Users
- PS> Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true}
  - Other filters?
	- PS> Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} | Set-ADUser -PasswordNeverExpires $false
	- 

PS> Disable user that haven't logged in in the last 90 days.
$days = (Get-Date).Adddays(-90)
Get-ADUser -Filter {LastLogonTimeStamp -lt $days -and enabled -eq $true} | Disable-ADAccount

PS> Create ADOU and add computer to it
New-ADOrganizationalUnit -Name "Seattle_Servers"
Get-ADComputer SEA-SVR1 | Move-ADObject -TargetPath "OU=Seattle_Servers,DC=Contoso,DC=com"

## DHCP/DNS

Roles & Features > DHCP | DNS

### Manage DNS

Server Manager > Tools > DNS
  - [Server] > Action > Properties > Forwarders; Forwarding servers
	- [Server] > *; DNS records

## Windows Defender

