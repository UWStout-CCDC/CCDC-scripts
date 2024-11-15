#!/bin/bash
#
# init.sh
# 
# 
# 

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color


# if prompt <prompt> n; then; <cmds>; fi
# Defaults to NO
# if prompt <prompt> y; then; <cmds>; fi
# Defaults to YES
prompt() {
    case "$2" in 
        y) def="[Y/n]" ;;
        n) def="[y/N]" ;;
        *) echo "Invalid."; exit ;;
    esac
    read -p "$1 $def" ans
    case $ans in
        y|Y) true ;;
        n|N) false ;;
        *) [[ "$def" != "[y/N]" ]] ;;
    esac
}

echo -e "${GREEN}  _____            _    _    _               _ ____  _           _"
echo -e  " |  __ \          | |  | |  | |             | |  _ \(_)         | |"
echo -e  " | |__) |___   ___| | _| |__| | __ _ _ __ __| | |_) |_ _ __   __| | ___ _ _"
echo -e  " |  _  // _ \ / __| |/ /  __  |/ _  \| __/ _  |  _ <| |  _ \ / _  |/ _ \  __|"
echo -e  " | | \ \ (_) | (__|   <| |  | | (_| | | | (_| | |_) | | | | | (_| |  __/ |"
echo -e  " |_|  \_\___/ \___|_|\_\_|  |_|\__,_|_|  \__,_|____/|_|_| |_|\__,_|\___|_| ${NC}"


printf "${GREEN}Rock Hard Binder initialization has begun...\n\n${NC}"
printf "${RED}PASSWORDS MUST BE CHANGED PRIOR TO RUNNING!!!\n\n${NC}"

# Defaults to no. Only use is during PERSONAL development.
if prompt "Have Passwords been changed for ALL relevent users?" n
then
  exit 1
fi


# Error Method:
error() {
    printf "${RED}${$1}${NC}"
}

# Ensure the script is ran as root.
if [ $(whoami) != "root" ];
then
    error 'Must be run as root, exiting!'
    exit 1
fi

#
# START OF IPTABLES
#
printf "${GREEN}Configuring IPTables...\n\n${NC}"

mkdir -p /rhb/
touch /rhb/iptables.sh
cat <<-EOF > /rhb/iptables.sh
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

bash /rhb/iptables.sh

#
# END OF IPTABLES
#
printf "${GREEN}IPTables Configured!\n\n${NC}"

#
# START OF UNUSED SERVICES
#
printf "${GREEN}Configuring Services...\n\n${NC}"

systemctl stop ssh
systemctl disable ssh

# DISABLE BLUETOOTH. THIS IS VERY IMPORTANT!
systemctl stop bluetooth.target
systemctl disable bluetooth.target

apt-get install dnsutils
apt-get install bind9
#
# END OF UNUSED SERVICES
#
printf "${GREEN}Configured Services!\n\n${NC}"


#
# START OF BIND9
#
printf "${GREEN}Configuring Bind9...\n\n${NC}"

CHROOT_DIR=/var/bind9/chroot

cat <<-EOF > /etc/default/bind9
#
# run resolvconf?
RESOLVCONF=no

# Startup options for the server
OPTIONS="-u bind -t ${CHROOT_DIR}"
EOF

/etc/init.d/bind9 stop


systemctl reenable bind9
systemctl daemon-reload

mkdir -p ${CHROOT_DIR}/{etc,dev,run/named,var/cache/bind,usr/share}

mknod ${CHROOT_DIR}/dev/null c 1 3
mknod ${CHROOT_DIR}/dev/random c 1 8
mknod ${CHROOT_DIR}/dev/urandom c 1 9
chmod 666 ${CHROOT_DIR}/dev/{null,random,urandom}

mv /etc/bind ${CHROOT_DIR}/etc

ln -s ${CHROOT_DIR}/etc/bind /etc/bind

cp /etc/localtime ${CHROOT_DIR}/etc/
cp -a /usr/share/dns /var/bind9/chroot/usr/share/

chown bind:bind ${CHROOT_DIR}/etc/bind/rndc.key
chown bind:bind ${CHROOT_DIR}/run/named
chmod 775 ${CHROOT_DIR}/{var/cache/bind,run/named}
chgrp bind ${CHROOT_DIR}/{var/cache/bind,run/named}

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

rndc querylog

#
# END OF BIND9
#
printf "${GREEN}Bind9 Configured!\n\n${NC}"

#
# START OF MOTD
#
printf "${GREEN}MOTD Configuring...\n\n${NC}"

cat <<-EOF > /etc/motd

░█████╗░██╗░░░██╗████████╗██╗░░██╗░█████╗░██████╗░██╗███████╗███████╗██████╗░
██╔══██╗██║░░░██║╚══██╔══╝██║░░██║██╔══██╗██╔══██╗██║╚════██║██╔════╝██╔══██╗
███████║██║░░░██║░░░██║░░░███████║██║░░██║██████╔╝██║░░███╔═╝█████╗░░██║░░██║
██╔══██║██║░░░██║░░░██║░░░██╔══██║██║░░██║██╔══██╗██║██╔══╝░░██╔══╝░░██║░░██║
██║░░██║╚██████╔╝░░░██║░░░██║░░██║╚█████╔╝██║░░██║██║███████╗███████╗██████╔╝
╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝╚══════╝╚══════╝╚═════╝░

░█████╗░░█████╗░░█████╗░███████╗░██████╗░██████╗  ░█████╗░███╗░░██╗██╗░░░░░██╗░░░██╗░░░
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝  ██╔══██╗████╗░██║██║░░░░░╚██╗░██╔╝░░░
███████║██║░░╚═╝██║░░╚═╝█████╗░░╚█████╗░╚█████╗░  ██║░░██║██╔██╗██║██║░░░░░░╚████╔╝░░░░
██╔══██║██║░░██╗██║░░██╗██╔══╝░░░╚═══██╗░╚═══██╗  ██║░░██║██║╚████║██║░░░░░░░╚██╔╝░░░░░
██║░░██║╚█████╔╝╚█████╔╝███████╗██████╔╝██████╔╝  ╚█████╔╝██║░╚███║███████╗░░░██║░░░██╗
╚═╝░░╚═╝░╚════╝░░╚════╝░╚══════╝╚═════╝░╚═════╝░  ░╚════╝░╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝

██╗░░░██╗██╗░█████╗░██╗░░░░░░█████╗░████████╗░█████╗░██████╗░░██████╗  ░██╗░░░░░░░██╗██╗██╗░░░░░██╗░░░░░
██║░░░██║██║██╔══██╗██║░░░░░██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝  ░██║░░██╗░░██║██║██║░░░░░██║░░░░░
╚██╗░██╔╝██║██║░░██║██║░░░░░███████║░░░██║░░░██║░░██║██████╔╝╚█████╗░  ░╚██╗████╗██╔╝██║██║░░░░░██║░░░░░
░╚████╔╝░██║██║░░██║██║░░░░░██╔══██║░░░██║░░░██║░░██║██╔══██╗░╚═══██╗  ░░████╔═████║░██║██║░░░░░██║░░░░░
░░╚██╔╝░░██║╚█████╔╝███████╗██║░░██║░░░██║░░░╚█████╔╝██║░░██║██████╔╝  ░░╚██╔╝░╚██╔╝░██║███████╗███████╗
░░░╚═╝░░░╚═╝░╚════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═════╝░  ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝╚══════╝

██████╗░███████╗  ███████╗░█████╗░██╗░░░██╗███╗░░██╗██████╗░  ░█████╗░███╗░░██╗██████╗░
██╔══██╗██╔════╝  ██╔════╝██╔══██╗██║░░░██║████╗░██║██╔══██╗  ██╔══██╗████╗░██║██╔══██╗
██████╦╝█████╗░░  █████╗░░██║░░██║██║░░░██║██╔██╗██║██║░░██║  ███████║██╔██╗██║██║░░██║
██╔══██╗██╔══╝░░  ██╔══╝░░██║░░██║██║░░░██║██║╚████║██║░░██║  ██╔══██║██║╚████║██║░░██║
██████╦╝███████╗  ██║░░░░░╚█████╔╝╚██████╔╝██║░╚███║██████╔╝  ██║░░██║██║░╚███║██████╔╝
╚═════╝░╚══════╝  ╚═╝░░░░░░╚════╝░░╚═════╝░╚═╝░░╚══╝╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░

██████╗░░██╗░░░░░░░██╗███╗░░██╗██████╗░░░░
██╔══██╗░██║░░██╗░░██║████╗░██║██╔══██╗░░░
██████╔╝░╚██╗████╗██╔╝██╔██╗██║██║░░██║░░░
██╔═══╝░░░████╔═████║░██║╚████║██║░░██║░░░
██║░░░░░░░╚██╔╝░╚██╔╝░██║░╚███║██████╔╝██╗
╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝░░╚══╝╚═════╝░╚═╝

EOF

cat <<-EOF > /etc/issue

░█████╗░██╗░░░██╗████████╗██╗░░██╗░█████╗░██████╗░██╗███████╗███████╗██████╗░
██╔══██╗██║░░░██║╚══██╔══╝██║░░██║██╔══██╗██╔══██╗██║╚════██║██╔════╝██╔══██╗
███████║██║░░░██║░░░██║░░░███████║██║░░██║██████╔╝██║░░███╔═╝█████╗░░██║░░██║
██╔══██║██║░░░██║░░░██║░░░██╔══██║██║░░██║██╔══██╗██║██╔══╝░░██╔══╝░░██║░░██║
██║░░██║╚██████╔╝░░░██║░░░██║░░██║╚█████╔╝██║░░██║██║███████╗███████╗██████╔╝
╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝╚══════╝╚══════╝╚═════╝░

░█████╗░░█████╗░░█████╗░███████╗░██████╗░██████╗  ░█████╗░███╗░░██╗██╗░░░░░██╗░░░██╗░░░
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝  ██╔══██╗████╗░██║██║░░░░░╚██╗░██╔╝░░░
███████║██║░░╚═╝██║░░╚═╝█████╗░░╚█████╗░╚█████╗░  ██║░░██║██╔██╗██║██║░░░░░░╚████╔╝░░░░
██╔══██║██║░░██╗██║░░██╗██╔══╝░░░╚═══██╗░╚═══██╗  ██║░░██║██║╚████║██║░░░░░░░╚██╔╝░░░░░
██║░░██║╚█████╔╝╚█████╔╝███████╗██████╔╝██████╔╝  ╚█████╔╝██║░╚███║███████╗░░░██║░░░██╗
╚═╝░░╚═╝░╚════╝░░╚════╝░╚══════╝╚═════╝░╚═════╝░  ░╚════╝░╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝

██╗░░░██╗██╗░█████╗░██╗░░░░░░█████╗░████████╗░█████╗░██████╗░░██████╗  ░██╗░░░░░░░██╗██╗██╗░░░░░██╗░░░░░
██║░░░██║██║██╔══██╗██║░░░░░██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝  ░██║░░██╗░░██║██║██║░░░░░██║░░░░░
╚██╗░██╔╝██║██║░░██║██║░░░░░███████║░░░██║░░░██║░░██║██████╔╝╚█████╗░  ░╚██╗████╗██╔╝██║██║░░░░░██║░░░░░
░╚████╔╝░██║██║░░██║██║░░░░░██╔══██║░░░██║░░░██║░░██║██╔══██╗░╚═══██╗  ░░████╔═████║░██║██║░░░░░██║░░░░░
░░╚██╔╝░░██║╚█████╔╝███████╗██║░░██║░░░██║░░░╚█████╔╝██║░░██║██████╔╝  ░░╚██╔╝░╚██╔╝░██║███████╗███████╗
░░░╚═╝░░░╚═╝░╚════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═════╝░  ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝╚══════╝

██████╗░███████╗  ███████╗░█████╗░██╗░░░██╗███╗░░██╗██████╗░  ░█████╗░███╗░░██╗██████╗░
██╔══██╗██╔════╝  ██╔════╝██╔══██╗██║░░░██║████╗░██║██╔══██╗  ██╔══██╗████╗░██║██╔══██╗
██████╦╝█████╗░░  █████╗░░██║░░██║██║░░░██║██╔██╗██║██║░░██║  ███████║██╔██╗██║██║░░██║
██╔══██╗██╔══╝░░  ██╔══╝░░██║░░██║██║░░░██║██║╚████║██║░░██║  ██╔══██║██║╚████║██║░░██║
██████╦╝███████╗  ██║░░░░░╚█████╔╝╚██████╔╝██║░╚███║██████╔╝  ██║░░██║██║░╚███║██████╔╝
╚═════╝░╚══════╝  ╚═╝░░░░░░╚════╝░░╚═════╝░╚═╝░░╚══╝╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░

██████╗░░██╗░░░░░░░██╗███╗░░██╗██████╗░░░░
██╔══██╗░██║░░██╗░░██║████╗░██║██╔══██╗░░░
██████╔╝░╚██╗████╗██╔╝██╔██╗██║██║░░██║░░░
██╔═══╝░░░████╔═████║░██║╚████║██║░░██║░░░
██║░░░░░░░╚██╔╝░╚██╔╝░██║░╚███║██████╔╝██╗
╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝░░╚══╝╚═════╝░╚═╝

EOF

cat <<-EOF > /etc/issue.net

░█████╗░██╗░░░██╗████████╗██╗░░██╗░█████╗░██████╗░██╗███████╗███████╗██████╗░
██╔══██╗██║░░░██║╚══██╔══╝██║░░██║██╔══██╗██╔══██╗██║╚════██║██╔════╝██╔══██╗
███████║██║░░░██║░░░██║░░░███████║██║░░██║██████╔╝██║░░███╔═╝█████╗░░██║░░██║
██╔══██║██║░░░██║░░░██║░░░██╔══██║██║░░██║██╔══██╗██║██╔══╝░░██╔══╝░░██║░░██║
██║░░██║╚██████╔╝░░░██║░░░██║░░██║╚█████╔╝██║░░██║██║███████╗███████╗██████╔╝
╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝╚══════╝╚══════╝╚═════╝░

░█████╗░░█████╗░░█████╗░███████╗░██████╗░██████╗  ░█████╗░███╗░░██╗██╗░░░░░██╗░░░██╗░░░
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝  ██╔══██╗████╗░██║██║░░░░░╚██╗░██╔╝░░░
███████║██║░░╚═╝██║░░╚═╝█████╗░░╚█████╗░╚█████╗░  ██║░░██║██╔██╗██║██║░░░░░░╚████╔╝░░░░
██╔══██║██║░░██╗██║░░██╗██╔══╝░░░╚═══██╗░╚═══██╗  ██║░░██║██║╚████║██║░░░░░░░╚██╔╝░░░░░
██║░░██║╚█████╔╝╚█████╔╝███████╗██████╔╝██████╔╝  ╚█████╔╝██║░╚███║███████╗░░░██║░░░██╗
╚═╝░░╚═╝░╚════╝░░╚════╝░╚══════╝╚═════╝░╚═════╝░  ░╚════╝░╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝

██╗░░░██╗██╗░█████╗░██╗░░░░░░█████╗░████████╗░█████╗░██████╗░░██████╗  ░██╗░░░░░░░██╗██╗██╗░░░░░██╗░░░░░
██║░░░██║██║██╔══██╗██║░░░░░██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝  ░██║░░██╗░░██║██║██║░░░░░██║░░░░░
╚██╗░██╔╝██║██║░░██║██║░░░░░███████║░░░██║░░░██║░░██║██████╔╝╚█████╗░  ░╚██╗████╗██╔╝██║██║░░░░░██║░░░░░
░╚████╔╝░██║██║░░██║██║░░░░░██╔══██║░░░██║░░░██║░░██║██╔══██╗░╚═══██╗  ░░████╔═████║░██║██║░░░░░██║░░░░░
░░╚██╔╝░░██║╚█████╔╝███████╗██║░░██║░░░██║░░░╚█████╔╝██║░░██║██████╔╝  ░░╚██╔╝░╚██╔╝░██║███████╗███████╗
░░░╚═╝░░░╚═╝░╚════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═════╝░  ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝╚══════╝

██████╗░███████╗  ███████╗░█████╗░██╗░░░██╗███╗░░██╗██████╗░  ░█████╗░███╗░░██╗██████╗░
██╔══██╗██╔════╝  ██╔════╝██╔══██╗██║░░░██║████╗░██║██╔══██╗  ██╔══██╗████╗░██║██╔══██╗
██████╦╝█████╗░░  █████╗░░██║░░██║██║░░░██║██╔██╗██║██║░░██║  ███████║██╔██╗██║██║░░██║
██╔══██╗██╔══╝░░  ██╔══╝░░██║░░██║██║░░░██║██║╚████║██║░░██║  ██╔══██║██║╚████║██║░░██║
██████╦╝███████╗  ██║░░░░░╚█████╔╝╚██████╔╝██║░╚███║██████╔╝  ██║░░██║██║░╚███║██████╔╝
╚═════╝░╚══════╝  ╚═╝░░░░░░╚════╝░░╚═════╝░╚═╝░░╚══╝╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░

██████╗░░██╗░░░░░░░██╗███╗░░██╗██████╗░░░░
██╔══██╗░██║░░██╗░░██║████╗░██║██╔══██╗░░░
██████╔╝░╚██╗████╗██╔╝██╔██╗██║██║░░██║░░░
██╔═══╝░░░████╔═████║░██║╚████║██║░░██║░░░
██║░░░░░░░╚██╔╝░╚██╔╝░██║░╚███║██████╔╝██╗
╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝░░╚══╝╚═════╝░╚═╝

EOF
#
#   END OF MOTD
#
printf "${GREEN}MOTD Configured!\n\n${NC}"

#
#   START OF UPDATE
#
printf "${GREEN}Updating and modifying mirror servers...\n\n${NC}"

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
#
#   END OF UPDATE
#
printf "${GREEN}Updated!\n\n${NC}"


#
#   START OF BACKUPS
#
printf "${GREEN}Creating Backups...\n\n${NC}"
tar -cf /backup.tar /etc/bind
printf "${GREEN}Finished Backups!\n\n${NC}"
#
#   END OF BACKUPS
#


#
#   START OF OTHER CRAP
#
printf "${GREEN}Creating monitor script...\n\n${NC}"

cat <<-EOF > /rhb/monitor.sh
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
printf "${GREEN}Finished monitor script! Located in /rhb/.\n\n${NC}"

