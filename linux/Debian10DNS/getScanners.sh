apt-get install nmap
apt-get install chkroot
apt-get install auditd
git clone https://github.com/CISOfy/lynis /tools


## Auditd configuration
## Configuration hint:
cat << EOF > /etc/audit/audit.rules
## -w watch file system object, -p sets [r|w|x|a]
## -a add rule: exit, upon syscall exit

## Remove any existing rules
-D

## Having a large buffer ensures we avoid dropping logs
-b 8192

## Failure Mode
## Possible values are 0 (silent), 1 (printk, print a failure message),
## and 2 (panic, halt the system).
-f 1

## Audit the audit logs, and execution of auditd reporting tools

-w /var/log/audit/ -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-a always,exit -F dir=/var/log/audit/ -F perm=r -F auid>=1000 -F auid!=unset -k audittools
-a always,exit -F path=/usr/sbin/ausearch -F perm=x -k audittools
-a always,exit -F path=/usr/sbin/aureport -F perm=x -k audittools
-a always,exit -F path=/usr/sbin/aulast -F perm=x -k audittools
-a always,exit -F path=/usr/sbin/aulastlogin -F perm=x -k audittools
-a always,exit -F path=/usr/sbin/auvirt -F perm=x -k audittools

## Log all process execution: disabled here by default due to load
# -a exit,always -S execve -k cmd
## Log all process executions by root
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

## Identify creation of filesystem nodes and file system mounts
-a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b32 -S mount -S umount -S umount2 -k mount
-a exit,always -F arch=b64 -S mount -S umount2 -k mount

## Clock and time zone changes
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-w /etc/localtime -p wa -k localtime

## Updates to cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron

## Updates to Bind
-w  /etc/bind -p rwxa
-w  /var/bind9/chroot/etc/bind -p rwxa

## Credential/user/group/login changes
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd
-w /usr/bin/passwd -p x -k passwd_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

## Changes to network configurations
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network

## system startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init

## library search paths
-w /etc/ld.so.conf -p wa -k libpath

## kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl

## modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe

## pam configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam


## system configuration changes
-w /etc/ssh/sshd_config -k sshd
-a exit,always -F arch=b32 -S sethostname -k hostname
-a exit,always -F arch=b64 -S sethostname -k hostname
-w /etc/issue -p wa -k etcissue
-w /etc/issue.net -p wa -k etcissue


## Capture all failures to access on critical elements
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess

## Monitor for use of process ID change (switching accounts) applications
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc

## Monitor usage of commands to change power state
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power

## Do not allow configuration changes
## -e 0 disables, -e 1 enables, -e 2 locks configuration until reboot
-e 1
EOF
