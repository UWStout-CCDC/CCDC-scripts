# Simple File Monitoring for Linux systems

There are a few tools to identify file modifications. We use multiple, which can
lead to multiple notifactions for the same change, but provides a much higher
level of assurance that at least one will catch a change.

## Usage

This is intended to be installed as a systemd service, and automatically notify
via a few different channels whether a file has changed.

## Implementation

Simple File watching:

```bash
fswatch -0 . | xargs -0 -I{} bash -c 'echo "{}" >> /var/log/fswatch; wall "Modification"'
```

This only notifies when the FS sees a change. This doesn't cover changes while
the system is off (e.g. while reboot, etc). For that, we can use hashing.

```bash
# Generate hashes
sha256sum /var/www/ > /ccdc/log/www_hashes
# Check Hashes
sha256sum -c /var/www/ << /ccdc/log/www_hashed
```

A full solution will start the watcher, and then execute a sha256sum check to
verify the current state.

```bash

fswatch -0 . | xargs -0 -I{} bash -c 'echo "{}" >> /var/log/fswatch; wall "Modification"' &

if sha256sum -c /var/www/ << /ccdc/log/www_hashed
then
  echo "Verified"
else
  wall "Modification"
fi

```

This can be run via systemd, which will keep the task running at all times, and
enable automatic startup on boot. `wall` is used for notification during the
compentition, since we expect to have someone logged into a terminal at all
times.
