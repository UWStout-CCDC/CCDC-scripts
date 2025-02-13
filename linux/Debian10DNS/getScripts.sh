get() {
  # only download if the file doesn't exist
  if [[ ! -f "$SCRIPT_DIR/$1" ]]
  then
    mkdir -p $(dirname "$SCRIPT_DIR/$1") 1>&2
    BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
    wget --no-check-certificate "$BASE_URL/$1" -O "$SCRIPT_DIR/$1" 1>&2
  fi
  echo "$SCRIPT_DIR/$1"
}

# Ensure the script is ran as root.
if [ $(whoami) != "root" ];
then
    error 'Must be run as root, exiting!'
    exit 1
fi

# Grab script so it's guarnteed to be in /ccdc/scripts/linux
get linux/init.sh

# Grabs monitor.sh script for monitoring log, process, connections, etc
get linux/monitor.sh
get linux/monitor2.sh

bash $(get linux/log_state.sh)
SPLUNK_SCRIPT=$(get linux/splunk-forward.sh)