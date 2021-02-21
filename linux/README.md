# Linux scripts

Scripts to configure various parts of the Linux boxes

## Scripts

- `pull.sh`: Downloads all of the scripts from this via [raw.githubusercontent.com]
- `log_state.sh`: logs the state of the machine to the `/ccdc` directory
- `iptables.sh`: iptables rules
- `ssh.sh`: configures ssh servers
- `users.sh`: Configures user accounts
- `splunk.sh`: installs and configures splunk forwarder
- `packages.py`: configres packages - updates & remove blacklisted packages
- `services.py`: configure services - DNS, Apache, Mail

## Other files

Most files not explicitly mentioned above are used by one of the scripts.
Exceptions are listed below

- `old/`: Old scripts

## Credits

- `splunk.sh`: Adapted from `makeforwarder.sh` found in UCI-CCDC/CCDC2021
