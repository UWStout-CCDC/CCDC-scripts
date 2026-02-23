# nftbuild
A Go-based Binary for rapidly deploying hardened `nftables` firewall configurations on Linux systems. It auto-detects your distro, installs `nftables` if needed, generates a role-appropriate ruleset, and does some other cool stuff.

**Version:** v1.2.0  
**Author:** doshowipospf

---

## Requirements

- Linux (Ubuntu/Debian, Fedora/RHEL/CentOS/Rocky, Arch, openSUSE)
- Root or `sudo` privileges

---

## Usage

```
nftbuild -sys <system> [options]
```

### Required Flag

| Flag | Description |
|---|---|
| `-sys <system>` | Specifies the role/type of the machine being hardened |

### System Options

| Value | Description |
|---|---|
| `webserver` | Opens inbound TCP 80 (HTTP) and 443 (HTTPS) |
| `mail` | Opens inbound SMTP (25/465/587), POP3 (110/995), IMAP (143/993), and outbound LDAP (389/636) |
| `splunk` | Opens inbound Splunk UI (8000) and forwarder ports (8089/9997) |
| `dnsntp` | Opens inbound/outbound DNS (53) and NTP (123) |
| `wrkstn` | Standard workstation ruleset with no extra services |
| `docker` | Opens DNS/NTP and web ports (80/443) |

### Optional Flags

| Flag | Description |
|---|---|
| `-w` | Adds Wazuh Server SIEM rules — inbound 9200/1514/514, outbound 1514/9200/55000 |
| `-z` | Zero Trust mode — use if you are paranoid of persistence (disable by rerunning binary without z flag)|
| `-ssh` | Allows outbound SSH connections |
| `-h` | Displays the help menu |

---

## Examples

Basic workstation setup:
```bash
sudo nftbuild -sys wrkstn
```

Web server with Wazuh forwarding and outbound SSH:
```bash
sudo nftbuild -sys webserver -w -ssh
```

Mail server in Zero Trust mode:
```bash
sudo nftbuild -sys mail -z
```

Splunk server with Wazuh:
```bash
sudo nftbuild -sys splunk -w
```

---

## What It Does

1. **Checks for nftables** — installs it automatically if missing, removing conflicting firewalls (ufw, firewalld, iptables) as appropriate for the distro.
2. **Generates a ruleset** based on the selected system role and flags.
3. **Writes the config** to `/etc/nftables.conf` and a backup to a secure location.
4. **Other stuff that is confidential** ask doshowipospf for questions.
5. **Enables and starts** the `nftables` systemd service.

---

## Default Ruleset Behavior

Regardless of system role, all configurations include:

- **Prerouting:** Drops invalid packets and malformed TCP flags.
- **Input chain (default DROP):**
  - Accepts loopback and established/related traffic.
  - Temporary IP blacklist with a 5-minute timeout.
  - Scan detection: NULL, XMAS, and FIN scans are blacklisted and dropped.
  - Splunk forwarder ports (8089/9997) always allowed inbound.
  - Wazuh agent ports (1515/1514) allowed inbound by default (or 9200/1514/514 with `-w`).
  - Suspicious UDP and rate-limited traffic is dropped and logged.
- **Forward chain (default DROP):** All forwarded traffic is dropped.
- **Output chain (default DROP):**
  - Established/related traffic accepted.
  - NTP (123) always allowed outbound.
  - Splunk forwarder (8089/9997) always allowed outbound.
  - HTTP/HTTPS/DNS outbound allowed unless `-z` (Zero Trust) is set.

All dropped packets are logged with descriptive prefixes (e.g., `NFT DROP [NULL scan]:`).

---

## File Locations

| Path | Purpose |
|---|---|
| `/etc/nftables.conf` | Active nftables configuration (set immutable after write) |
| `/var/log/kern.log` | Kernal log location for firewall rule blocks |
| `/etc/sysconfig/nftables.conf` | Symlink target used on Fedora/RHEL-based systems |

---

## Notes

- To view firewall blocks use `tail -f /var/log/kern.log`
