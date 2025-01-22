Goal here is to modernize the main init script and automate the full setup of the Splunk system

# Things done so far
* Created copy scripts to modify
* Updated iptables
* Created script to install firewall service
* Update the copied init script to use updated parameters
* Updated the order of execution for the copied init
* Started auto-splunk script


# List of things to fix with script
* Refactor main init script to be more efficient with user input
  - Input at beginning
  - Allow for executing system specific scripts based on user selection
* Add general SELinux policy setup automation
* Reorganize the linux scripts repo as needed
  - Will likely need to move scripts around to ensure old scripts are phased out and new scripts are phased in


# Things to automate:
* Fix yum repos if broken (e.g. if they don't work on an update)
* Change default admin password
* Remove all users outside of default admin
* Remove all apps outside of default (if any exist)
* System specific SELinux configs (if any)
* Set up forwarder configs
  - Include directories to monitor (e.g. important linux and windows dirs)
* Patch vulnerabilities
* Install any app packages I want to use
  - Stuff for Palo and AD
* Setup dashboards/searches/alerts
* Create backups
* Install GUI/Browser



TEST EVERYTHING!!!