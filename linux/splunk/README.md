# Splunk Specific Scripts/Files

## init-splunk.sh Usage
### Download script
```
wget https://tinyurl.com/yx3pmm9m -O init-splunk.sh --no-check-certificate
```

### Make executable and run
```
chmod +x init-splunk.sh
./init-splunk.sh
```

### Script Options
* Manually create backup
```
./init-splunk.sh backup
```
* Restore most recent backup
```
./init-splunk.sh restore
```

## CentOS-Base.repo
* Is used to fix the repos on CentOS 7 systems since they are usually broken.
* Just points the repos to the Cern archives of CentOS repos.
* No longer needed for Splunk as it is now running Oracle Linux 9.2.

## audit.rules
* Is used to apply a baseline of auditd rules once auditd is setup and installed


# List of all current functions in "init-splunk.sh" (as of last commit)
## Security Config Functions
* changePasswords
* createNewAdmin
* updateSystem
* installTools
* lockUnusedAccounts
* secureRootLogin
* setUmask
* restrictUserCreation
* firewallSetup
* securePermissions
* cronAndAtSecurity
* clearPromptCommand
* stopSSH
* setupAIDE
* setDNS
* setLegalBanners
* setupAuditd
* disableUncommonProtocols
* disableCoreDumps
* secureSysctl
* secureGrub
* setSELinuxPolicy
* installGUI
* bulkRemoveServices
* bulkDisableServices
* setupIPv6
* disableRootSSH
* initilizeClamAV

## Splunk Specific Functions
* webUIPassword
* disableSketchyTokens
* disableVulnerableSplunkApps
* fixSplunkXMLParsingRCE
* setSplunkRecievers
* setupPaloApps
* disableDistrubutedSearch
* addMonitorFiles

## List of helper functions
* backup
* restore
* get
* replace
* monitor
* restartSplunk

## List of functions that are not currently being used
* fixCentOSRepos
* init