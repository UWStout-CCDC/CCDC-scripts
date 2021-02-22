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
