#!/bin/bash

# This is a standalone script that creates the systemd unit for the firewall

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  #exit 1
fi

CCDC_DIR="/ccdc"
SCRIPT_DIR="$CCDC_DIR/scripts"
IPTABLES_SCRIPT="$SCRIPT_DIR/linux/iptables.sh"

if [[ ! -f "$IPTABLES_SCRIPT" ]]; then
  printf 'iptables script not found. Please install it before continuing\n'
  exit 1
fi

# Create systemd unit for the firewall
mkdir -p /etc/systemd/system/
cat <<-EOF > /etc/systemd/system/ccdc_firewall.service
[Unit]
Description=ZDSFirewall
After=syslog.target network.target

[Service]
Type=oneshot
ExecStart=$IPTABLES_SCRIPT
ExecStop=/sbin/iptables -F
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

if type systemctl
then
  systemctl daemon-reload
  systemctl restart iptables

  # Disable other firewalls
  # (--now also runs a start/stop with the enable/disable)
  systemctl disable --now firewalld
  systemctl disable --now ufw

  # Automatically apply IPTABLES_SCRIPT on boot
  systemctl enable --now ccdc_firewall.service
else
  echo "!! Non systemd systems are not supported !!"
fi