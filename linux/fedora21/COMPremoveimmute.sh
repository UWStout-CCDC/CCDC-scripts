echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m      Select Critical Files to Unlock (Remove Immutable)      \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1

#!/bin/bash
# Interactive script to remove the immutable attribute from selected critical files and directories.
# Run this script as root.
# You can enter "all" to select every item or provide individual numbers separated by spaces.

# List of critical items (files and directories)
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

echo "Select the items you want to unlock (remove immutable attribute):"
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
echo "Unlocking the following items (removing immutable attribute):"
for num in "${indices[@]}"; do
    # Validate the selection is a number within the correct range.
    if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#ITEMS[@]}" ]; then
        echo "Invalid selection: $num. Skipping."
        continue
    fi

    item="${ITEMS[$((num-1))]}"

    # Check if the item exists and then remove the immutable attribute.
    if [ -f "$item" ]; then
        chattr -i "$item" 2>/dev/null && echo "Removed immutability from file: $item" || echo "Failed to unlock file: $item"
    elif [ -d "$item" ]; then
        chattr -R -i "$item" 2>/dev/null && echo "Removed immutability from directory: $item" || echo "Failed to unlock directory: $item"
    else
        echo "Item not found: $item"
    fi
done

echo
echo "Selected items have been processed."
