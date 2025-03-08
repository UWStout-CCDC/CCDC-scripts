#!/bin/bash
# Diffing Baselines Script

# Define directories
BASE_DIR="/root/DIFFING"
CHANGES_DIR="${BASE_DIR}/CHANGES"
# UNCOMMENT THIS IF YOU DON'T MAKE THEM IN AN INIT SCRIPT LIKE ME
# mkdir -p "${BASE_DIR}" "${CHANGES_DIR}"

# Colors because they make me happy
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Declare an associative array of commands.
declare -A commands
commands[aureport]="aureport -i"
commands[services]="systemctl list-units --type=service --all --no-pager --no-legend | cut -d ' ' -f1 | sort"
commands[port]="ss -tulnp | sort"
commands[connection]="ss -tanp | tail -n +2 | sort"
commands[alias]="alias | sort"
commands[executables]="find /usr/bin /usr/sbin /bin /sbin -type f | sort"
commands[cron]='for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done'
commands[users]="sudo cat /etc/shadow"
commands[rootkit]="sudo chkrootkit"
commands[iptables]="iptables-save | sed -E 's/\[.*?\]//g' | sed '/^#/d' | sort"
commands[free]="free -h"
commands[processes]="ps aux --sort=user,pid"
commands[yum_installed]="rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort"
commands[etc_config]="find /etc -type f -exec sha256sum {} + | sort"

# Loop over each command, capturing and diffing the outputs.
for key in "${!commands[@]}"; do
    echo "Processing ${key} baseline..."
    current_file="${BASE_DIR}/${key}_current.txt"
    previous_file="${BASE_DIR}/${key}_previous.txt"
    diff_file="${CHANGES_DIR}/${key}_diff.txt"

    # If a current baseline exists, move it to previous.
    if [ -f "$current_file" ]; then
        mv "$current_file" "$previous_file"
    fi

    # Run the command and save its output as the new current baseline.
    eval ${commands[$key]} > "$current_file"

    # If a previous baseline exists, perform a unified diff.
    if [ -f "$previous_file" ]; then
        diff -u "$previous_file" "$current_file" > "$diff_file"
        if [ -s "$diff_file" ]; then
            if [[ "$key" == "aureport" || "$key" == "connection" || "$key" == "yum_installed" || "$key" == "processes" || "$key" == "free" ]]; then
                echo -e "${YELLOW}Differences found for ${key} (see ${diff_file}).${NC}"
            else
                echo -e "${RED}Differences found for ${key} (see ${diff_file}).${NC}"
            fi
        else
            echo -e "${GREEN}No differences found for ${key}.${NC}"
            rm -f "$diff_file"
        fi
    else
        echo "No previous baseline for ${key}. Baseline saved as current."
    fi
done

echo "Diffing complete. Baseline files are in ${BASE_DIR} and diffs (if any) in ${CHANGES_DIR}."
