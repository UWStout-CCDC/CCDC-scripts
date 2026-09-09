#!/bin/bash

# Loop through each user in the system (excluding root)
for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
    if [[ "$user" != "root" ]]; then
        echo "Restoring login access for user: $user"

        # Set home directory permissions back to default
        chmod -R 700 /home/"$user"
    

        # Restore user shell to /bin/bash to allow login
        usermod -s /bin/bash "$user"
    fi
done

echo "Users can now log back in."
