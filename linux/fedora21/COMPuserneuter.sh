#!/bin/bash

# Fedora user shell toggle script
# Goes through users one by one and asks whether to set them to nologin.
# Restore section is included at the bottom and commented out.

NOLOGIN="/usr/sbin/nologin"
[ -x "$NOLOGIN" ] || NOLOGIN="/sbin/nologin"

if [ ! -x "$NOLOGIN" ]; then
    echo "nologin binary not found."
    exit 1
fi

UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null)
UID_MIN=${UID_MIN:-1000}

echo "Using nologin shell: $NOLOGIN"
echo

awk -F: -v min="$UID_MIN" '
    $3 >= min && $1 != "root" && $1 != "nobody" {
        print $1 ":" $7
    }
' /etc/passwd | while IFS=: read -r user shell; do
    echo "User: $user"
    echo "Current shell: $shell"
    read -rp "Set this user to nologin? (y/N): " ans

    case "$ans" in
        y|Y)
            usermod -s "$NOLOGIN" "$user"
            echo "Changed $user to $NOLOGIN"
            ;;
        *)
            echo "Skipped $user"
            ;;
    esac
    echo
done

echo "Done."

# --------------------------------------------------------------------
# RESTORE SECTION
# Uncomment this block if you want to go through each user and restore
# them to /bin/bash one by one.
# --------------------------------------------------------------------
#
# RESTORE_SHELL="/bin/bash"
#
# awk -F: -v min="$UID_MIN" '
#     $3 >= min && $1 != "root" && $1 != "nobody" {
#         print $1 ":" $7
#     }
# ' /etc/passwd | while IFS=: read -r user shell; do
#     echo "User: $user"
#     echo "Current shell: $shell"
#     read -rp "Restore this user to $RESTORE_SHELL? (y/N): " ans
#
#     case "$ans" in
#         y|Y)
#             usermod -s "$RESTORE_SHELL" "$user"
#             echo "Restored $user to $RESTORE_SHELL"
#             ;;
#         *)
#             echo "Skipped $user"
#             ;;
#     esac
#     echo
# done
#
# echo "Restore complete."
