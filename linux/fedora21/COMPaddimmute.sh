echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m      Select Critical Files to Lock (Immutable)     \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1

#!/bin/bash
# Interactive script to set the immutable attribute on selected critical files and directories.
# Run this as root. You can enter "all" to select every item or individual numbers separated by spaces.

# List of critical items to protect (files and directories)
ITEMS=(
    /etc/roundcubemail
    /etc/httpd
    /etc/dovecot
    /etc/postfix
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/gshadow
    /etc/sudoers
    /etc/ssh/sshd_config
    /etc/ssh/ssh_config
    /etc/crontab
    /etc/fstab
    /etc/hosts
    /etc/resolv.conf
    /etc/sysctl.conf
    /etc/selinux/config
)

echo "Select the items you want to lock (make immutable):"
echo "Enter the numbers separated by spaces, or type 'all' to select everything."
echo

# Display the list with numbers
for i in "${!ITEMS[@]}"; do
    printf "%2d) %s\n" "$((i+1))" "${ITEMS[i]}"
done

echo
read -p "Your selection: " selection

# Convert "all" to a list of all indices
if [[ "$selection" =~ ^[Aa][Ll][Ll]$ ]]; then
    indices=($(seq 1 ${#ITEMS[@]}))
else
    # Split the input into an array of numbers
    read -r -a indices <<< "$selection"
fi

echo
echo "Locking down the following items (setting immutable attribute):"
for num in "${indices[@]}"; do
    # Check if the selection is a valid number within the range.
    if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#ITEMS[@]}" ]; then
        echo "Invalid selection: $num. Skipping."
        continue
    fi

    item="${ITEMS[$((num-1))]}"

    # If the item exists, check if it's a file or directory.
    if [ -f "$item" ]; then
        chattr +i "$item" 2>/dev/null && echo "Set immutable on file: $item" || echo "Failed to lock file: $item"
    elif [ -d "$item" ]; then
        chattr -R +i "$item" 2>/dev/null && echo "Set immutable on directory: $item" || echo "Failed to lock directory: $item"
    else
        echo "Item not found: $item"
    fi
done

echo
echo "Selected items have been processed."
