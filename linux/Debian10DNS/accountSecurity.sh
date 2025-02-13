#gets wanted username
echo "What would you like the admin account to be named?"
read username

PASSWD_SH=$SCRIPT_DIR/linux/passwd.sh
cat <<EOF > $PASSWD_SH
if [[ \$EUID -ne 0 ]]
then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

NOLOGIN=$SCRIPT_DIR/linux/nologin.sh
cat <<EOF > $NOLOGIN
#!/bin/bash
echo "This account is unavailable."
EOF
chmod a=rx $NOLOGIN

#removes the ability to log on of rogue users
awk -F: "{ print \"usermod -s $NOLOGIN \" \$1; print \"passwd -l \" \$1 }" /etc/passwd >> $PASSWD_SH
echo "usermod -s /bin/bash $username" >> $PASSWD_SH
echo "passwd -u $username" >> $PASSWD_SH
echo "usermod -s /bin/bash root" >> $PASSWD_SH
echo "passwd -u root" >> $PASSWD_SH

groupadd wheel
groupadd sudo
cp /etc/sudoers $CCDC_ETC/sudoers
cat <<-EOF > /etc/sudoers
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# User privilege specification
root    ALL=(ALL:ALL) ALL
$username ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
%wheel   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:
#@includedir /etc/sudoers.d
EOF

useradd -G wheel,sudo -m -s /bin/bash -U $username

echo "Set $username's password"
passwd $username
echo "Set root password"
passwd root

# Set permissions
chown -hR $username:$username $CCDC_DIR
# Fix permissions (just in case)
chown root:root /etc/group
chmod a=r,u=rw /etc/group
chown root:root /etc/sudoers
chmod a=,ug=r /etc/sudoers
chown root:root /etc/passwd
chmod a=r,u=rw /etc/passwd
if [ $(getent group shadow) ]; then
    chown root:shadow /etc/shadow
else
    chown root:root /etc/shadow
fi
chmod a=,u=rw,g=r /etc/shadow