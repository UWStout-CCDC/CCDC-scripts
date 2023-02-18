# Linux scripts

Scripts to configure various parts of the Linux boxes

## Scripts

Please see the documentation at the beginning of each script for
details about it.

- `pull.sh`: Downloads all of the scripts from this via [raw.githubusercontent.com]
- `log_state.sh`: logs the state of the machine to the `/ccdc` directory
- `iptables.sh`: iptables rules
- `ssh.sh`: configures ssh servers
- `splunk.sh`: installs and configures splunk forwarder
- `users.py`: Configures user accounts
- `packages.py`: configres packages - updates & remove blacklisted packages
- `services.py`: configure services - DNS, Apache, Mail
- `monitor.sh`: Monitors important things all in one command, check monitor.sh for more info
- `init-for-old-centos.sh`: init file for older centos machines without https/tls support

## Log state dumps

For a number of the machines, an example dump from a fresh install has been created,
for potential diffing with the current state of the machines in the competition

- `debian8`: Debian 8.11 - 2021 Qualifier has a Debian 8.5 (TODO)
- `ubuntu14`: Ubuntu 14.04
- `centos6`: CentOS 6 - labeled Splunk
- `centos7`: CentOS 7
- `fedora21`: Fedora 21

## Other files

Most files not explicitly mentioned above are used by one of the scripts.
Exceptions are listed below

- `old/`: Old scripts

## TODO

- User configs
- Package configs
- Service configs
- fakeshell?

## Credits

- `splunk.sh`: Adapted from `makeforwarder.sh` found in UCI-CCDC/CCDC2021
- `monitor.sh`: Adapted from `monpanel` found in JaminB/CCDC
