# Palo Alto config files

The Palo Alto has the option to configure via a CLI. This can be done
via ssh connection from workstation to Palo Alto.

## Comments

The PA cli doesn't recognize comments, so we have a shell script
to remove them. Since it's a simple script, it only recognizes full line
comments, i.e. the comment needs
to be the first thing on the line (whitespace is fine).

Just run `./prepare.sh [file]` to remove comments.

Our intention is to run the preparation step before the competition,
and have the prepared files ready for download from the github. However,
since it's a simple shell script, as long as the PA is configured from a
linux box, the preparation script can be run on competition day.

## Scripts

These are the scripts that have been prepared:

- `quick_harden`: a script to automatically harden the enviroment by
disabling outside access, and locking down management interfaces
