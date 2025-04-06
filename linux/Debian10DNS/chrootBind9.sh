apt-get install dnsutils
apt-get install bind9

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

mkdir -p ${CHROOT_DIR}/{etc,dev,run/named,var/cache/bind,usr/share,/var/log/bind9/}

mknod ${CHROOT_DIR}/dev/null c 1 3
mknod ${CHROOT_DIR}/dev/random c 1 8
mknod ${CHROOT_DIR}/dev/urandom c 1 9
chmod 666 ${CHROOT_DIR}/dev/{null,random,urandom}

cp -r /etc/bind ${CHROOT_DIR}/etc

ln -s ${CHROOT_DIR}/etc/bind /etc/bind

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

rndc querylog

#
# END OF BIND9
#
printf "${GREEN}Bind9 Configured!\n\n${NC}"