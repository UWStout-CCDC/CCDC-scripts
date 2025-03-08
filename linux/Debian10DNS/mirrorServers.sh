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