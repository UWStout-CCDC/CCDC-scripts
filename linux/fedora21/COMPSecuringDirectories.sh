#!/usr/bin/env bash
#
# secure-configs.sh
#
# This script sets ownership to root:root, sets restrictive permissions,
# and applies the immutable attribute to critical config directories.
# **Use with caution** — you will need to remove the immutable bit before
# updating or editing these configs in the future.

# A helper function to apply ownership, perms, and immutability.
set_permissions_and_immutable() {
  local dir="$1"

  echo "Applying ownership root:root to $dir ..."
  sudo chown -R root:root "$dir"

  echo "Setting directory permissions to 755 in $dir ..."
  sudo find "$dir" -type d -exec chmod 755 {} \;

  echo "Setting file permissions to 644 in $dir ..."
  sudo find "$dir" -type f -exec chmod 644 {} \;

  echo "Applying immutable attribute (+i) to $dir ..."
  sudo chattr -R +i "$dir"

  echo "Finished securing $dir."
  echo
}

# List of directories we want to process
CONFIG_DIRS=(
  "/etc/roundcubemail"
  "/etc/httpd"
  "/etc/dovecot"
  "/etc/postfix"
)

echo "=================================================="
echo "  Secure Config Directories Script"
echo "  This will apply root-only ownership & perms,"
echo "  then make directories immutable."
echo "=================================================="
echo

# Loop through each directory, prompt user, and apply changes if "y"
for dir in "${CONFIG_DIRS[@]}"; do
  echo "Directory: $dir"
  read -r -p "Is this the correct directory to secure? (y/n): " answer

  if [[ "$answer" =~ ^[Yy]$ ]]; then
    if [[ -d "$dir" ]]; then
      set_permissions_and_immutable "$dir"
    else
      echo "Warning: $dir does not exist on this system. Skipping."
      echo
    fi
  else
    echo "Skipping $dir."
    echo
  fi
done

echo "All done!"

