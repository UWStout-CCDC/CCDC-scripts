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

apt-get install dnsutils
apt-get install bind9

printf "${GREEN}Configuring Bind9...\n\n${NC}"

# Chrootify
CHROOT_DIR=/var/bind9/chroot

cat <<-EOF > /etc/default/bind9
#
# run resolvconf?
RESOLVCONF=no

# Startup options for the server
OPTIONS="-u bind -t ${CHROOT_DIR}"
EOF

systemctl reenable bind9
systemctl daemon-reload

mkdir -p ${CHROOT_DIR}/{etc,dev,run/named,var/cache/bind,usr/share,/var/log/bind9/}

mknod ${CHROOT_DIR}/dev/null c 1 3
mknod ${CHROOT_DIR}/dev/random c 1 8
mknod ${CHROOT_DIR}/dev/urandom c 1 9
chmod 666 ${CHROOT_DIR}/dev/{null,random,urandom}

cp -r /etc/bind ${CHROOT_DIR}/etc

#ln -s ${CHROOT_DIR}/etc/bind /etc/bind

cp /etc/localtime ${CHROOT_DIR}/etc/
cp -a /usr/share/dns /var/bind9/chroot/usr/share/

touch ${CHROOT_DIR}/var/log/bind9/query.log

chown bind:bind ${CHROOT_DIR}/etc/bind/rndc.key
chown bind:bind ${CHROOT_DIR}/run/named
chown bind:bind ${CHROOT_DIR}/etc/bind
chown bind:bind ${CHROOT_DIR}/var/log/bind9/query.log
chmod 775 ${CHROOT_DIR}/{var/cache/bind,run/named,etc/bind,var/log/bind9/query.log}
chgrp bind ${CHROOT_DIR}/{var/cache/bind,run/named,etc/bind,var/log/bind9/query.log}

# The AppArmor SHOULD look like this:
cat <<-EOF > /etc/apparmor.d/usr.sbin.named

# vim:syntax=apparmor
# Last Modified: Fri Jun  1 16:43:22 2007
#include <tunables/global>

/usr/sbin/named flags=(attach_disconnected) {
    #include <abstractions/base>
    #include <abstractions/nameservice> 
    capability net_bind_service,
    capability setgid,
    capability setuid,
    capability sys_chroot,
    capability sys_resource,    
    # /etc/bind should be read-only for bind
    # /var/lib/bind is for dynamically updated zone (and journal) files.
    # /var/cache/bind is for slave/stub data, since we're not the origin of it.
    # See /usr/share/doc/bind9/README.Debian.gz
    
    ${CHROOT_DIR}/etc/bind/** r,
    ${CHROOT_DIR}/var/** rw,
    ${CHROOT_DIR}/dev/** rw,
    ${CHROOT_DIR}/run/** rw,
    ${CHROOT_DIR}/usr/** r,
    ${CHROOT_DIR}/tmp/** rw,
    ${CHROOT_DIR}/log/bind9/** rw,
    
    # Database file used by allow-new-zones
    /var/cache/bind/_default.nzd-lock rwk,  
    # gssapi
    /etc/krb5.keytab kr,
    /etc/bind/krb5.keytab kr,   
    # ssl
    /etc/ssl/openssl.cnf r, 
    # root hints from dns-data-root
    /usr/share/dns/root.* r,    
    # GeoIP data files for GeoIP ACLs
    /usr/share/GeoIP/** r,  
    # dnscvsutil package
    /var/lib/dnscvsutil/compiled/** rw, 
    # Allow changing worker thread names
    owner @{PROC}/@{pid}/task/@{tid}/comm rw,   
    @{PROC}/net/if_inet6 r,
    @{PROC}/*/net/if_inet6 r,
    @{PROC}/sys/net/ipv4/ip_local_port_range r,
    /usr/sbin/named mr,
    /{,var/}run/named/named.pid w,
    /{,var/}run/named/session.key w,
    # support for resolvconf
    /{,var/}run/named/named.options r,  
    # some people like to put logs in /var/log/named/ instead of having
    # syslog do the heavy lifting.
    /var/log/named/** rw,
    /var/log/named/ rw, 
    # gssapi
    /var/lib/sss/pubconf/krb5.include.d/** r,
    /var/lib/sss/pubconf/krb5.include.d/ r,
    /var/lib/sss/mc/initgroups r,
    /etc/gss/mech.d/ r, 
    # ldap
    /etc/ldap/ldap.conf r,
    /{,var/}run/slapd-*.socket rw,  
    # dynamic updates
    /var/tmp/DNS_* rw,  
    # dyndb backends
    /usr/lib/bind/*.so rm,  
    # Samba DLZ
    /{usr/,}lib/@{multiarch}/samba/bind9/*.so rm,
    /{usr/,}lib/@{multiarch}/samba/gensec/*.so rm,
    /{usr/,}lib/@{multiarch}/samba/ldb/*.so rm,
    /{usr/,}lib/@{multiarch}/ldb/modules/ldb/*.so rm,
    /var/lib/samba/bind-dns/dns.keytab rk,
    /var/lib/samba/bind-dns/named.conf r,
    /var/lib/samba/bind-dns/dns/** rwk,
    /var/lib/samba/private/dns.keytab rk,
    /var/lib/samba/private/named.conf r,
    /var/lib/samba/private/dns/** rwk,
    /etc/samba/smb.conf r,
    /dev/urandom rwmk,
    owner /var/tmp/krb5_* rwk,  
    # Site-specific additions and overrides. See local/README for details.
    #include <local/usr.sbin.named>
}

EOF

systemctl reload apparmor

echo "\$AddUnixListenSocket ${CHROOT_DIR}/dev/log" > /etc/rsyslog.d/bind-chroot.conf

systemctl restart rsyslog
systemctl restart bind9
# Chrootify

rndc querylog

printf "${GREEN}Bind9 Configured!\n\n${NC}"

mkdir /var/ccdc
touch /var/ccdc/monitor.sh
cat > /var/ccdc/monitor.sh << 'EOF'
#!/bin/bash

# >.< Just a little twink in this little world!

if [ $(whoami) != "root" ];then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!"
  exit
fi

find / -name .bashrc > temp4 &
md5sum /etc/passwd /etc/group /etc/profile md5sum /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > temp2
ls -a /etc/ /usr/ /sys/ /home/ /bin/ /etc/ssh/ >> temp2
while true;
do	
	netstat -n -A inet | grep ESTABLISHED > temp
	incoming_ftp=$(cat temp | cut -d ':' -f2 | grep "^21" | wc -l)
	outgoing_ftp=$(cat temp | cut -d ':' -f3 | grep "^21" | wc -l)
	
	incoming_ssh=$(cat temp | cut -d ':' -f2 | grep "^22" | wc -l)
	outgoing_ssh=$(cat temp | cut -d ':' -f3 | grep "^22" | wc -l)

	

	outgoing_telnet=$(cat temp | cut -d ':' -f2 | grep "^23" | wc -l)
	incoming_telnet=$(cat temp | cut -d ':' -f3 | grep "^23" | wc -l)

	incoming_telnet=$(cat temp | cut -d ':' -f2 | grep "^^23" | wc -l)
	outgoing_telnet=$(cat temp | cut -d ':' -f3 | grep "^^23" | wc -l)

	
	echo "ACTIVE NETWORK CONNECTIONS:"
	echo "---------------------------"
	if [ $outgoing_telnet -gt 0 ]; then
		echo $outgoing_telnet successful outgoing telnet connection.
	fi
	
	if [ $incoming_telnet -gt 0 ]; then
		echo $incoming_telnet successful incoming telnet session.
	fi

	if [ $outgoing_ssh -gt 0 ]; then
		echo $outgoing_ssh successful outgoing ssh connection.
	fi
	
	if [ $incoming_ssh -gt 0 ]; then
		echo $incoming_ssh successful incoming ssh session.
	fi
	
	
	if [ $outgoing_ftp -gt 0 ]; then
		echo $outgoing_ftp successful outgoing ftp connection.
	fi
	
	if [ $incoming_ftp -gt 0 ]; then
		echo $incoming_ftp successful incoming ftp session.
	fi

	if [ $incoming_ftp -gt 0 ]; then
		echo $incoming_ftp successful incoming ftp session.
	fi
	cat temp
	sleep 5
	clear

	echo "CURRENT LOGIN SESSIONS:"
	echo "-----------------------"
	w
	echo
	echo "RECENT LOGIN SESSIONS:"
	echo "----------------------"
	last | head -n5
	sleep 5
	clear

	sleepingProcs=$(pstree | grep sleep)
	if [[ ! -z "$sleepingProcs" ]];then
	  echo "SLEEP PROCESSES:"
	  echo "----------------"
	  sleep 5
	  clear
	fi

	#Check for changes to important files.
	
	md5sum /etc/passwd /etc/group /etc/profile md5sum /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > temp3
	ls -a /etc/ /usr/ /sys/ /home/ /bin/ /etc/ssh/ >> temp3
	fileChanges=$(diff temp2 temp3)
	if [[ ! -z "$fileChanges" ]];then
  	  echo CHANGE TRACKER:
	  echo -e "\n"
	  echo "$fileChanges"
	  sleep 5
	  clear
	fi

	echo "CRON JOBS:"
	echo "Found Cronjobs for the following users:"
	echo "---------------------------------------"
	ls /var/spool/cron/crontabs
	echo
	echo "Cronjobs in cron.d:"
	echo "-------------------"
	ls /etc/cron.d/
	sleep 5
	clear

	echo "ALIASES:"
	echo "--------"
	alias
	echo
	echo ".BASHRC LOCATIONS:"
	echo "------------------"
	cat temp4 | while read line
	do
		echo $line
	done
	sleep 5
	clear

	echo "USERS ABLE TO LOGIN:"
	echo "--------------------"
	grep -v -e "/bin/false" -e "/sbin/nologin" /etc/passwd | cut -d ':' -f1
	sleep 5
	clear

	echo "CURRENT PROCESS TREE:"
	echo "---------------------"
	pstree
	sleep 7
	clear
  
  	if type aide > /dev/null
  	then
    		echo "AIDE:"
    		echo "-----------"
		echo "If used on Splunk there will be noise from Splunk logs"
    		aide --check > /aide_log.txt
		head /aide_log.txt
		echo "Use 'vi /aide_log.txt' to get more detailed info" 
		sleep 7
		clear
   	fi
  
done


exit

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

SAVE_FILE="temp_save"
LAST_FILE="temp_last"
touch $SAVE_FILE

verify_packaged_files() {
  # This take a while, should do it in a seperate screen session
  if type dpkg
  then
    dpkg -V
  elif type rpm
  then
    rpm -V
  else
    echo "Unknown Package manager"
  fi
}

locate_added_files() {
  EXTRA_FILES="/ccdc/log/extra_files"
  echo "" > $EXTRA_FILES
  for LINE in $(echo $PATH | sed -e 's/:/\n/g' | head -10)
  do
    for FILE in $(ls -Ap -w 1 $LINE)
    do
      dpkg -S $LINE/$FILE || echo "$LINE/$FILE" >> $EXTRA_FILES
    done
  done
}

while true
do
  mv $SAVE_FILE $LAST_FILE
  # Run checks > $SAVE_FILE

  # List active connections, filters out ports 80, 443, 53, 123
  echo "Active Connections:" >> $SAVE_FILE
	netstat -n -A inet | grep ESTABLISHED | grep -vP ":(80|443|53|123)" >> $SAVE_FILE
  
  echo "\nActive Logins:" >> $SAVE_FILE
  # Manually print header & tell w not to print a header
  echo "USER\tTTY\tFROM\tLOGIN@\tIDLE\tJCPU\tPCPU\tWHAT" >> $SAVE_FILE
	w -h >> $SAVE_FILE

  echo "\nFailed Logins:" >> $SAVE_FILE
	lastb >> $SAVE_FILE

  echo "\nSuccessful Logins:" >> $SAVE_FILE
	last >> $SAVE_FILE
  
  # `pstree` `ps -aux` ??

  echo "\nUser Crontabs:" >> $SAVE_FILE
	ls /var/spool/cron/crontabs >> $SAVE_FILE

  echo "\nSystem Crontabs:" >> $SAVE_FILE
	ls /etc/cron.d/ >> $SAVE_FILE

  echo "\nUsers able to login:" >> $SAVE_FILE
	grep -v -e "/bin/false" -e "/sbin/nologin" /etc/passwd | cut -d ':' -f1 >> $SAVE_FILE

  echo "\nFiles changed:" >> $SAVE_FILE
  aide --check >> $SAVE_FILE

  echo "\nSetuid Files:" >> $SAVE_FILE
  find / -perm /u+s,u+g >> $SAVE_FILE

  # diff will print the full list of changes to stdout, while wall will print across ALL active sessions
  if diff $SAVE_FILE $LAST_FILE
  then
    wall ">>>> Something has changed <<<<"
  fi

  sleep 20
done

EOF

touch /usr/sbin/monitor
chmod +x /usr/sbin/monitor
cp /var/ccdc/monitor.sh /usr/sbin/monitor

cat <<-EOF > /etc/sysctl.conf
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.kexec_restrict = 1
kernel.kptr_restrict = 2
# kernel.modules_disabled = 1
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

cat <<-EOF > /etc/apt/sources.list
# deb cdrom:[Debian GNU/Linux 10.10.0 _Buster_ - Official amd64 NETINST 20210619-16:11]/ buster main

#deb cdrom:[Debian GNU/Linux 10.10.0 _Buster_ - Official amd64 NETINST 20210619-16:11]/ buster main

deb http://deb.debian.org/debian/ buster main
deb-src http://deb.debian.org/debian/ buster main

deb http://security.debian.org/debian-security buster/updates main
deb-src http://security.debian.org/debian-security buster/updates main
EOF

apt-get update
apt-get upgrade

CHROOT_DIR=/var/bind9/chroot

#
#   Manage Logging
#

mkdir -p ${CHROOT_DIR}/tmp/logs/

touch ${CHROOT_DIR}/tmp/logs/dns_queries.msgs
touch ${CHROOT_DIR}/tmp/logs/dns_debug.msgs
touch ${CHROOT_DIR}/tmp/logs/dns_errors.msgs
touch ${CHROOT_DIR}/tmp/logs/dns_critical.msgs

chown bind:bind ${CHROOT_DIR}/tmp/logs/{dns_queries.msgs,dns_debug.msgs,dns_errors.msgs,dns_critical.msgs}
chmod 775 ${CHROOT_DIR}/tmp/logs/{dns_queries.msgs,dns_debug.msgs,dns_errors.msgs,dns_critical.msgs}
chgrp bind ${CHROOT_DIR}/tmp/logs/{dns_queries.msgs,dns_debug.msgs,dns_errors.msgs,dns_critical.msgs}

cat <<-EOF > ${CHROOT_DIR}/etc/bind/named.conf
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
include "/etc/bind/named.conf.logging";

EOF

cat <<-EOF > ${CHROOT_DIR}/etc/bind/named.conf.logging

logging {
    // Syslog logging for general information.
    channel my_syslog {
        syslog daemon;
        severity info;
        print-time yes;
    };

    // All queries sent to our service.
    channel dns_queries {
        file "/tmp/logs/dns_queries.msgs";
        severity info;
        print-time yes;
    };

    // Level 5 debug messages.
    channel dns_debug {
        file "/tmp/logs/dns_debug.msgs";
        severity debug 5;
        print-time yes;
    };

    // Error messages.
    channel dns_errors {
        file "/tmp/logs/dns_errors.msgs";
        severity error;
        print-time yes;
    };

    // Critical messages.
    channel dns_critical {
        file "/tmp/logs/dns_critical.msgs";
        severity error;
        print-time yes;
    };

    // Throwaway
    channel null {
        null;
    };

    category general { 
        dns_critical; 
        dns_debug;
        dns_errors; 
    };

    category queries { 
        dns_queries;
    };
};

EOF
cat ${CHROOT_DIR}/etc/bind/named.conf.logging


cat <<- EOF > ${CHROOT_DIR}/etc/bind/named.conf.options
options {
    directory "/var/cache/bind";

    auth-nxdomain no;

    recursion no;

    forwarders {
        208.67.220.220;
        208.67.222.222;
    };

    allow-transfer {
        localhost;
        172.20.240.0/24;
        172.20.241.0/24;
    };

    dnssec-validation auto;

    listen-on-v6 { none; };

    forward only;

    version none;

    rrset-order {order cyclic;};

    # rate-limit {
    #     responses-per-second 5;
    # };

    max-cache-size 100M;
    max-cache-ttl 3600;
    max-ncache-ttl 3600;
};

EOF

systemctl restart bind9

cat <<-EOF > /etc/motd
UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED

You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts and actions to access or use this system may result in civil
and/or criminal penalties.

All activities performed on this device are logged and monitored.
EOF

cat <<-EOF > /etc/issue
UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED

You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts and actions to access or use this system may result in civil
and/or criminal penalties.

All activities performed on this device are logged and monitored.
EOF

cat <<-EOF > /etc/issue.net
UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED

You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts and actions to access or use this system may result in civil
and/or criminal penalties.

All activities performed on this device are logged and monitored.
EOF

chown root:root /etc/issue /etc/issue.net /etc.motd
chmod 0600 /etc/issue /etc/issue.net /etc.motd

touch /usr/sbin/backup
chmod +x /usr/sbin/backup

cat > /usr/sbin/backup << 'EOF'
#!/bin/bash

if [[ "$EUID" -ne 0 ]]
then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

if [ -z $1 ]; then
    echo "Please enter the location of the backup directory [q to exit] : "
    read backup_dir
    if [ "$backup_dir" == "q" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Exiting"
        exit 1
    fi
    if [ -d "$backup_dir" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Backup found..."
    else
        echo -e "[${YELLOW}WARNING${RESET}] Backup directory '$backup_dir' not in file system. Creating..."
        mkdir -p "$backup_dir"
    fi
else
    backup_dir="$1"
fi

# Define the file that contains the list of files to back up
if [ -z $2 ]; then
    echo "Please enter the location of the file list [q to exit] : "
    read file_list
    if [ "$file_list" == "q" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Exiting"
        exit 0
    fi
    if [ -f "$file_list" ]; then
        echo -e "[${GREEN}OKAY${RESET}] File list found..."
    else
        echo -e "[${RED}FAILURE${RESET}] File list not found. Exiting with 2."
        exit 2
    fi
else
    file_list="$2"
fi

# Read the file list line by line
while IFS= read -r file; do
    # Check if the file exists before copying
    if [ -f "$file" ] || [ -d "$file" ]; then
        file_dir="$(dirname $file)"
        mkdir -p "$backup_dir$file_dir"
        cp -r "$file" "$backup_dir$file"
        if [ $? -ne 0 ]; then
            echo -e "[${RED}FAILURE${RESET}] Unable to backup: $file"
        else
            echo -e "[${GREEN}OKAY${RESET}] Backup made for: $file"
        fi

    else
        echo -e "[${RED}FAILURE${RESET}] File or Directory not found: $file"
    fi
done < "$file_list"

echo -e "[${GREEN}OKAY${RESET}] Backup completed."
exit 0
EOF

#!/bin/bash

touch /usr/sbin/load
chmod +x /usr/sbin/load

cat > /usr/sbin/load << 'EOF'
#!/bin/bash

if [[ "$EUID" -ne 0 ]]
then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

if [ -z "$1" ]; then
    echo "Please enter the location of the backup directory [q to exit] : "
    read backup_dir
    if [ "$backup_dir" == "q" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Exiting"
        exit 0
    fi
    if [ -d "$backup_dir" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Backup found..."
    else
        echo -e "[${RED}WARNING${RESET}] Backup directory '$backup_dir' not in file system... Exiting."
        exit 1
    fi
else
    backup_dir="$1"
fi

# Define the file that contains the list of files to back up
if [ -z "$2" ]; then
    echo "Please enter the location of the file list [q to exit] : "
    read file_list
    if [ "$file_list" == "q" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Exiting"
        exit 0
    fi
    if [ -f "$file_list" ]; then
        echo -e "[${GREEN}OKAY${RESET}] File list found..."
    else
        echo -e "[${RED}FAILURE${RESET}] File list not found. Exiting."
        exit 1
    fi
else
    file_list="$2"
fi

# Create the backup directory if it does not exist
mkdir -p "$backup_dir"

# Read the file list line by line
while IFS= read -r file; do
    # Check if the file exists before copying
    if [ -f "$backup_dir$file" ] || [ -d "$backup_dir$file" ]; then
        cp -r "$backup_dir$file" "$file"
        if [ $? -ne 0 ]; then
            echo -e "[${RED}FAILURE${RESET}] Unable to copy: $backup_dir$file"
        else
            echo -e "[${GREEN}OKAY${RESET}] Backup loaded for: $backup_dir$file"
        fi
    else
        echo -e "[${RED}FAILURE${RESET}] File or Directory not found: $file"
    fi
done < "$file_list"

echo -e "[${GREEN}OKAY${RESET}] Backups loaded."
exit 0
EOF

cat > /.files.txt << 'EOF'
/etc/bind/
/etc/apparmor.d/usr.sbin.named
/etc/bind/bind.keys
/etc/bind/db.0
/etc/bind/db.127
/etc/bind/db.255
/etc/bind/db.empty
/etc/bind/db.local
/etc/bind/named.conf
/etc/bind/named.conf.default-zones
/etc/bind/named.conf.local
/etc/bind/named.conf.options
/etc/bind/zones.rfc1918
/etc/init.d/bind9
/etc/insserv.conf.d/bind9
/etc/network/if-down.d/bind9
/etc/network/if-up.d/bind9
/etc/ppp/ip-down.d/bind9
/etc/ppp/ip-up.d/bind9
/etc/ufw/applications.d/bind9
/lib/systemd/system/bind9-pkcs11.service
/lib/systemd/system/bind9-resolvconf.service
/lib/systemd/system/bind9.service
/usr/bin/arpaname
/usr/bin/bind9-config
/usr/bin/named-rrchecker
/usr/lib/tmpfiles.d/bind9.conf
/usr/sbin/ddns-confgen
/usr/sbin/dnssec-importkey
/usr/sbin/genrandom
/usr/sbin/isc-hmac-fixup
/usr/sbin/named
/usr/sbin/named-journalprint
/usr/sbin/named-nzd2nzf
/usr/sbin/named-pkcs11
/usr/sbin/nsec3hash
/usr/sbin/tsig-keygen
EOF
cp /.files.txt /etc/rockyraccoon/files.txt

backup /baks /.files.txt

touch /usr/sbin/validate
chmod +x /usr/sbin/validate
cat > /usr/sbin/validate << 'EOF'
#!/bin/bash
if [[ "$EUID" -ne 0 ]]
then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

if [ -z "$1" ]; then
    echo "Please enter the location of the records file [q to exit] : "
    read file_name
    if [ "$file_name" == "q" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Exiting"
        exit 0
    fi
    if [ -f "$file_name" ]; then
        echo -e "[${GREEN}OKAY${RESET}] Records list found..."
    else
        echo -e "[${RED}WARNING${RESET}] Records list '$file_name' not in file system... Exiting."
        exit 1
    fi
else
    file_name="$1"
fi

source "$file_name"

echo -e "Checking domain resolving..."

for i in $(seq 0 $((${#DOMAIN_ARR[@]} - 1)));
do
	timeout 5s nslookup ${DOMAIN_ARR[i]} localhost > /dev/null
    if [ $? -eq 124 ]; then
    echo -e "[${GREEN}RED${RESET}] ${DOMAIN_ARR[i]} did not resolve... (Command timed out)"        
        exit 1
    fi
    echo -e "[${GREEN}WORKING${RESET}] ${DOMAIN_ARR[i]} should resolve to ${RESOLVE_ARR[i]}..."
	IPADDR=$(nslookup ${DOMAIN_ARR[i]} localhost | grep 'Address:' | awk '{print $2}' | sed -n '2p')
	if [ "${RESOLVE_ARR[i]}" == "${IPADDR}" ]; then
        echo -e "[${GREEN}OKAY${RESET}] ${DOMAIN_ARR[i]} resolved!"
        # It will check for a '0' to determine success.
	else
        echo -e "[${GREEN}RED${RESET}] ${DOMAIN_ARR[i]} did not resolve..."
        # It will check for a '0' to determine success.
		exit 1;
	fi
	echo "	${IPADDR}"
done

exit 0
EOF


touch /usr/sbin/zones
chmod +x /usr/sbin/zones
cat > /usr/sbin/zones << 'EOF'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Please enter where all the zones at : "
    read zone_dir
else
    zone_dir="$1"
fi

if [ "$zone_dir" == "" ]; then
    zone_dir="/etc/bind/zones"
fi

find "$zone_dir" -type f -name "db*" -o -name "*db" -o -name "*zone" | while read -r zone_file; do
    echo "OKAY processing $zone_file"
    grep -E '^\s*\S+\s+IN\s+A\s+\S+' "$zone_file" | while read -r line; do
        domain=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $NF}')
        echo "$domain resolves to $ip"
    done
        grep -E '^\s*\S+\s+IN\s+AAAA\s+\S+' "$zone_file" | while read -r line; do
        domain=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $NF}')
        echo "$domain resolves to $ip"
    done
    grep -E '^\s*\s+IN\s+NS\s+\S+' "$zone_file" | while read -r line; do
        domain=$(echo "$line" | awk '{print $3}')
        echo "$domain is a name server"
    done
done
EOF

mkdir -p /etc/rockyraccoon/
touch /etc/rockyraccoon/records.txt
cat > /etc/rockyraccoon/records.txt << 'EOF'
DOMAIN_ARR=("blog.ccdclab.net" "storage.ccdclab.net");
RESOLVE_ARR=("172.21.34.236" "172.19.190.85");
EOF

touch /etc/rockyraccoon/files.txt
cp /.files.txt /etc/rockyraccoon/files.txt

touch /var/log/rocky.log

touch /etc/systemd/system/rockyraccoon.service
chmod +x /etc/systemd/system/rockyraccoon.service
cat > /etc/rockyraccoon/rockyraccoon.service << 'EOF'
[Unit]
Description=Gideon's Bible
[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=/usr/sbin/rockyraccoon /etc/rockyraccoon/baks /etc/rockyraccoon/files.txt /etc/rockyraccoon/records.txt
StandardOutput=/var/log/rocky.log
[Install]
WantedBy=multi-user.target
EOF

touch /usr/sbin/rockyraccoon
chmod +x /usr/sbin/rockyraccoon
cat > /usr/sbin/rockyraccoon << 'EOF'
#!/bin/bash

validate $3
if [ $? == '0' ]; then
    echo "[${GREEN}SUCCESS${RESET}] $(date) Rocky Raccoon validated Bind9."
    exit 0
else
    echo "[${$RED}FAILURE${RESET}] $(date) Bind9 has not been validated. Attempting restore."
    load $2 $3
    if [ $? == '0' ]; then
        echo "[${GREEN}SUCCESS${RESET}] $(date) Rocky Raccoon restored Bind9."
    else
        echo "[${RED}FAILURE${RESET}] $(date) Bind9 has not been restored. Oh no."
        exit 1
    fi
    
    validate $3
    if [ $? == '0' ]; then
        echo "[${GREEN}SUCCESS${RESET}] $(date) Rocky Raccoon restoration confirmed."
    else
        echo "[${RED}FAILURE${RESET}] $(date) f***."
    fi    
fi

EOF

yes | sudo apt-get purge apache2*
yes | sudo apt-get purge exim4*
yes | sudo apt-get purge openssh*
yes | sudo apt-get purge ssh*
yes | sudo apt-get purge proftpd-basi*
yes | sudo apt-get purge rpcbind*
yes | sudo apt-get purge exim4*
yes | sudo apt-get purge anacron*
yes | sudo apt-get purge ampd*
yes | sudo apt-get purge atd*
yes | sudo apt-get purge autofs*
yes | sudo apt-get purge cups*
yes | sudo apt-get purge gpm*
yes | sudo apt-get purge irda*
yes | sudo apt-get purge isdn*
yes | sudo apt-get purge kuzu*
yes | sudo apt-get purge lpd*
yes | sudo apt-get purge netfs*
yes | sudo apt-get purge nfs*
yes | sudo apt-get purge nfslock*
yes | sudo apt-get purge pmcia*
yes | sudo apt-get purge portmap*
yes | sudo apt-get purge rawdevices*
yes | sudo apt-get purge snmpd*
yes | sudo apt-get purge snmtptrap*
yes | sudo apt-get purge winbind*
yes | sudo apt-get purge xfs*
yes | sudo apt-get purge ypbind*
yes | sudo apt-get autoremove

yes | apt install iptables

mkdir -p /var/ccdc/
touch /etc/init.d/iptables.sh
chmod +x /etc/init.d/iptables.sh
touch /var/ccdc/iptables.sh
chmod +x /etc/init.d/iptables.sh

cat <<EOF > /var/ccdc/iptables.sh
if [[ \$EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

#!/bin/bash

# This script can be used for rebuilding our table if it is in some way compromised.
# Specific services may have a prompt attached to them in case the engineer wants to experiment.

# Empty all rules
iptables -t filter -F
iptables -t filter -X

# Block everything by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# Authorize already established connections
# TODO: PROMPT YES OR NO AND FIGURE OUT IF THIS IS NECESSARY
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS 
# (Important! This is what our service operates on. DNS Protocol uses either TCP or UDP. DNSSEC operates on the same port)
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS 
# (If needed; We don't have a service operating on the port unless we specifically make a request so this could be disabled otherwise.)
iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (Server time, if needed.)
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

# Splunk 
# For logging.
iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
EOF
cp /var/ccdc/iptables.sh /etc/init.d/iptables.sh 

bash /var/ccdc/iptables.sh

yes | apt install git
git clone https://github.com/CISOfy/lynis
mv lynis /var/ccdc/

chown root:root /etc/init.d/*
chmod -R 700 /etc/init.d/*

yes | apt-get install chkrootkit
yes | apt-get install slapd

git clone https://github.com/ovh/debian-cis.git && cd debian-cis
cp debian/default /etc/default/cis-cat
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
# ./bin/hardening/1.1.1.1_disable_freevxfs.sh --audit
cd ../
mv debian-cis /var/ccdc/



yes | apt install auditd
cat > /etc/audit/audit.rules << 'EOF'
#
#  _  __                      _       __  __ _ _              __  __             _              _____       _           
# | |/ /                     ( )     |  \/  (_) |            |  \/  |           (_)            |  __ \     | |          
# | ' / __ _ _   _ _ __   ___|/ ___  | \  / |_| |_ _ __ ___  | \  / | __ _ _ __  _  __ _  ___  | |__) |   _| | ___  ___ 
# |  < / _` | | | | '_ \ / _ \ / __| | |\/| | | __| '__/ _ \ | |\/| |/ _` | '_ \| |/ _` |/ __| |  _  / | | | |/ _ \/ __|
# | . \ (_| | |_| | | | |  __/ \__ \ | |  | | | |_| | |  __/ | |  | | (_| | | | | | (_| | (__  | | \ \ |_| | |  __/\__ \
# |_|\_\__,_|\__, |_| |_|\___| |___/ |_|  |_|_|\__|_|  \___| |_|  |_|\__,_|_| |_|_|\__,_|\___| |_|  \_\__,_|_|\___||___/
#            __/ |                                                                                                     
#            |___/                                                                                                      
#             
#                                                                                   
# Compiled by Kayne Whitney
#
# This is built around the MITRE ATTACK framework.
# The tactics Execution, Persistence, Privilege Escalation, Defense Evasion, and Command and Control and their techniques are all monitored with this ruleset.

# PLACE INTO
# /etc/audit/audit.rules
#
#
# Created  : 02/20/2025
#
# Based on rules published here:
#   https://attack.mitre.org/tactics/enterprise/

# Remove any existing rules
-D

# Buffer Size
## Feel free to increase this if the machine panic's
-b 8192

# Failure Mode
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 1

# Ignore errors
## e.g. caused by users or files not found in the local environment
-i
# NOTES: when auid is set to >=1000 that means it is monitoring for all non root users.
# If you dont have root users you need to change it to auid=0


########################### START OF EXECUTION RULES ###########################

## =========================
## T1059.x: Command & Scripting Interpreters
## =========================
-a always,exit -F path=/bin/sh           -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_shell
-a always,exit -F path=/bin/bash         -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_shell
-a always,exit -F path=/usr/bin/bash     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_shell
-a always,exit -F path=/bin/dash         -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_shell
-a always,exit -F path=/bin/zsh          -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_shell

-a always,exit -F path=/usr/bin/python   -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_python
-a always,exit -F path=/usr/bin/python3  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_python
-a always,exit -F path=/usr/bin/perl     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_perl
-a always,exit -F path=/usr/bin/ruby     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_ruby
-a always,exit -F path=/usr/bin/node     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_nodejs

# SQL shells
-a always,exit -F path=/usr/bin/mysql    -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_sql
-a always,exit -F path=/usr/bin/psql     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1059_sql


## =========================
## T1569.001: System Services
## =========================
-a always,exit -F path=/usr/sbin/service -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1569_systemservice
-a always,exit -F path=/bin/systemctl    -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1569_systemservice
-a always,exit -F dir=/etc/init.d        -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1569_systemservice


## =========================
## T1072: Software Deployment Tools
## =========================
-a always,exit -F path=/usr/bin/ansible     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1072_deployment
-a always,exit -F path=/usr/bin/puppet      -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1072_deployment
-a always,exit -F path=/usr/bin/chef-client -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1072_deployment
-a always,exit -F path=/usr/bin/salt        -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1072_deployment


## =========================
## T1609: Container Administration
## =========================
-a always,exit -F path=/usr/bin/docker  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1609_containers
-a always,exit -F path=/usr/bin/podman  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1609_containers
-a always,exit -F path=/usr/bin/kubectl -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1609_containers
-a always,exit -F path=/usr/bin/crictl  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0002_t1609_containers



########################### START OF PERSISTENCE RULES ###########################

############## T1037.004 RC Scripts & T1037.003 (Init & Profile) ##############
-w /etc/init.d       -p wa -k ta0003_rc_scripts
-w /etc/rc.d         -p wa -k ta0003_rc_scripts
-w /etc/rc.local     -p wa -k ta0003_rc_scripts

# System-wide profile & bashrc
-w /etc/profile      -p wa -k ta0003_system_profile
-w /etc/bashrc       -p wa -k ta0003_system_profile
-w /etc/bash.bashrc  -p wa -k ta0003_system_profile

# User shell config files (trap-based or other). Root specifically:
-w /root/.bashrc         -p wa -k ta0003_shell_config
-w /root/.bash_profile   -p wa -k ta0003_shell_config

## (Optional) All user home directories - THIS IS GOING TO BE NOISY:
#-w /home/ -p wa -k ta0003_user_shell


######################### T1053.003 Cron / Scheduled Tasks #####################
-w /etc/crontab           -p wa -k ta0003_cron
-w /etc/cron.d            -p wa -k ta0003_cron
-w /etc/cron.daily        -p wa -k ta0003_cron
-w /etc/cron.hourly       -p wa -k ta0003_cron
-w /etc/cron.weekly       -p wa -k ta0003_cron
-w /etc/cron.monthly      -p wa -k ta0003_cron
-w /var/spool/cron        -p wa -k ta0003_cron
-w /var/spool/cron/crontabs -p wa -k ta0003_cron

## If systemd timers exist on your Fedora 14 environment:
-w /etc/systemd/system          -p wa -k ta0003_systemd_timers


#################### T1078 / T1136 / T1098: Account Mods #######################
-w /etc/passwd      -p wa -k ta0003_accounts
-w /etc/shadow      -p wa -k ta0003_accounts
-w /etc/group       -p wa -k ta0003_accounts
-w /etc/gshadow     -p wa -k ta0003_accounts

# Sudoers changes:
-w /etc/sudoers     -p wa -k ta0003_sudoers
-w /etc/sudoers.d   -p wa -k ta0003_sudoers


#################### T1098.004 / T1556.004 SSH Authorized Keys #################
#-w /root/.ssh/authorized_keys  -p wa -k ta0003_ssh_keys
# (Optional) All user .ssh directories:
#-w /home/ -p wa -k ta0003_ssh_keys


############### T1543.002 Systemd Service ###############
-w /etc/systemd/system       -p wa -k ta0003_systemd
-w /usr/lib/systemd/system   -p wa -k ta0003_systemd


########### T1547.006 Kernel Modules & T1556.003 Modify PAM Auth ###############
# Kernel modules & tools
-w /lib/modules    -p wa -k ta0003_kmods
-w /etc/modules    -p wa -k ta0003_kmods
-w /sbin/insmod    -p wa -k ta0003_kmod_tools
-w /sbin/rmmod     -p wa -k ta0003_kmod_tools
-w /sbin/modprobe  -p wa -k ta0003_kmod_tools

# Pluggable Authentication Modules (PAM)
-w /etc/pam.d      -p wa -k ta0003_pam
-w /lib/security   -p wa -k ta0003_pam
-w /lib64/security -p wa -k ta0003_pam


################### LD_PRELOAD and LD config manipulations #####################
-w /etc/ld.so.preload  -p wa -k ta0003_ld_preload
-w /etc/ld.so.conf     -p wa -k ta0003_ld_preload


########################## Gnome/KDE Autostart ######################
-w /etc/xdg/autostart  -p wa -k ta0003_autostart
# (Optional) All user config autostart:
#-w /home/ -p wa -k ta0003_autostart

########################### START OF PRIV ESC RULES ###########################

########################
# 1 Detect SUID/SGID Bit Setting (T1548.001)
########################
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat \
   -F auid>=1000 -F auid!=4294967295 \
   -F a2&0x4000 \
   -k ta0004_t1548_suid
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat \
   -F auid>=1000 -F auid!=4294967295 \
   -F a2&0x4000 \
   -k ta0004_t1548_suid

########################
# 2 Watch known SUID binaries for unauthorized changes
########################
-w /usr/bin/passwd -p wa -k ta0004_suidbin
-w /usr/bin/sudo   -p wa -k ta0004_suidbin
# (Add or remove any typical SUID binaries in your environment)

########################
# 3 Sudo watchers (T1548.003)
########################
-w /etc/sudoers       -p wa -k ta0004_t1548_sudoers
-w /etc/sudoers.d     -p wa -k ta0004_t1548_sudoers

-a always,exit -F path=/usr/bin/sudo -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_t1548_sudoexec

########################
# 4 Capabilities changes (setcap)
########################
-a always,exit -F path=/usr/sbin/setcap -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_t1548_capabilities

# (Optional) Watch xattr syscalls if you want all extended attribute changes
#-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr \
#   -F auid>=1000 -F auid!=4294967295 \
#   -k ta0004_capability_xattr

########################
# 5 'su' usage
########################
-a always,exit -F path=/bin/su -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_su_usage

########################
# 6 Container Escape to Host (T1611)
########################
-a always,exit -F path=/usr/bin/docker  -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_t1611_container
-a always,exit -F path=/usr/bin/podman  -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_t1611_container
-a always,exit -F path=/usr/bin/nsenter -F perm=x \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0004_t1611_container

########################
# 7 Kernel Modules (T1068 overlap)
########################
-a always,exit -F path=/sbin/insmod    -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0004_kmods
-a always,exit -F path=/sbin/rmmod     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0004_kmods
-a always,exit -F path=/sbin/modprobe  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0004_kmods

-w /lib/modules -p wa -k ta0004_kmods

########################### START OF DEFENSE EVASION ###########################


########## 1 Clear/Modify System Logs (T1070.002) ##########
-a always,exit -F dir=/var/log -F perm=wa -F auid>=1000 -F auid!=4294967295 \
   -k ta0005_t1070_clearlogs

########## 2 Clear Command History (T1070.003) ##########
# Broad watch for writes to user .bash_history, .zsh_history, etc. (noisy)
-w /root/.bash_history -p wa -k ta0005_t1070_history
# (Optional) for all home directories in older syntax:
#-w /home/ -p wa -k ta0005_t1070_history

########## 3 File Deletion & Timestomp (T1070.004 / T1070.006) ##########
# Deletions
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0005_t1070_filedelete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0005_t1070_filedelete

# Timestomp
-a always,exit -F arch=b64 -S utime,utimes,futimesat,utimensat \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0005_t1070_timestomp
-a always,exit -F arch=b32 -S utime,utimes,futime,futimesat,utimensat \
   -F auid>=1000 -F auid!=4294967295 \
   -k ta0005_t1070_timestomp

########## 4 Disable or Modify Firewall (T1562.004) ##########
-a always,exit -F path=/usr/sbin/iptables        -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0005_t1562_firewall
-a always,exit -F path=/usr/sbin/iptables-restore -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0005_t1562_firewall
-a always,exit -F path=/usr/sbin/ip6tables       -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0005_t1562_firewall
-a always,exit -F path=/usr/sbin/nft             -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0005_t1562_firewall
-a always,exit -F path=/usr/bin/firewall-cmd     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0005_t1562_firewall

-w /etc/firewalld      -p wa -k ta0005_t1562_firewall
-w /etc/sysconfig/iptables -p wa -k ta0005_t1562_firewall
# Uncomment for IPV6
# -w /etc/sysconfig/ip6tables -p wa -k ta0005_t1562_firewall

########## 5 Disable or Modify Logging (T1562.007) ##########
-w /etc/rsyslog.conf     -p wa -k ta0005_t1562_logging
-w /etc/rsyslog.d        -p wa -k ta0005_t1562_logging
-w /etc/audit/auditd.conf -p wa -k ta0005_t1562_logging
-w /etc/syslog-ng/       -p wa -k ta0005_t1562_logging
-w /etc/systemd/journald.conf -p wa -k ta0005_t1562_logging

########## 6 Masquerading via rename/link in system dirs (T1036) ##########
-a always,exit -F dir=/usr/bin -F auid>=1000 -F auid!=4294967295 \
   -F syscall=rename,renameat,link,linkat,symlink,symlinkat \
   -k ta0005_t1036_masquerading
-a always,exit -F dir=/bin -F auid>=1000 -F auid!=4294967295 \
   -F syscall=rename,renameat,link,linkat,symlink,symlinkat \
   -k ta0005_t1036_masquerading

########## 7 Hidden Files and Directories (T1564.001) ##########
# Monitor file creation in /home or /tmp; watch for leading dots in the SIEM
-a always,exit -F dir=/home -F auid>=1000 -F auid!=4294967295 \
   -S open,openat,creat \
   -k ta0005_t1564_hidden
-a always,exit -F dir=/tmp -F auid>=1000 -F auid!=4294967295 \
   -S open,openat,creat \
   -k ta0005_t1564_hidden



########################### START OF COMMAND AND CONTROL ###########################



-a always,exit -F path=/usr/bin/nc   -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_nettools
-a always,exit -F path=/bin/nc       -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_nettools
-a always,exit -F path=/usr/bin/ncat -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_nettools
-a always,exit -F path=/usr/bin/socat -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_nettools
-a always,exit -F path=/usr/bin/curl  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_download
-a always,exit -F path=/usr/bin/wget  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_download
-a always,exit -F path=/usr/bin/openssl -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_nettools
-a always,exit -F path=/usr/bin/ssh   -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_ssh
-a always,exit -F path=/usr/bin/scp   -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_ssh
-a always,exit -F path=/usr/bin/sftp  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_ssh
-a always,exit -F path=/usr/bin/ftp   -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_ftp

########## 2 Syscall-based Network Monitoring (connect, bind, etc.) ##########
-a always,exit -F arch=b64 -S connect -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_connect
-a always,exit -F arch=b32 -S connect -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_connect

# Optional: inbound connections (very noisy)
#-a always,exit -F arch=b64 -S bind,listen,accept,accept4 -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_bind
#-a always,exit -F arch=b32 -S bind,listen,accept         -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_bind

########## 3 Changes to DNS / Host Config for C2 (T1568) ##########
-w /etc/resolv.conf -p wa -k ta0011_dns_config
-w /etc/hosts       -p wa -k ta0011_dns_config
-w /etc/nsswitch.conf -p wa -k ta0011_dns_config

########## 4 Proxy / Tunneling Tools (T1090) ##########
-a always,exit -F path=/usr/bin/proxychains -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_proxy
-a always,exit -F path=/usr/bin/tor         -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_proxy
-a always,exit -F path=/usr/sbin/openvpn    -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_proxy
-a always,exit -F path=/usr/bin/stunnel     -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_proxy

########## 5 Container Exec for C2 Pivot ##########
-a always,exit -F path=/usr/bin/docker  -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_container
-a always,exit -F path=/usr/bin/kubectl -F perm=x -F auid>=1000 -F auid!=4294967295 -k ta0011_c2_container

EOF

touch /usr/sbin/changes
chmod +x /usr/sbin/changes
cat > /usr/sbin/changes << 'EOF'
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
EOF

yes | apt install clamav clamav-daemon
yes | apt install tiger

reboot
