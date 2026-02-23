# Cyber@Stout - Windows Security Scripts

This repository contains a collection of PowerShell scripts designed by the Cyber@Stout CCDC comptition team. Each script automates essential security tasks and configurations for Windows Server and client environments. These scripts are aimed at improving baseline security and can be used individually or as part of a comprehensive hardening process.

***NOTE: This repository is only for development of scripts, and SHOULD AND WILL NOT BE USED during competition, since it will be updated after the cutoff dates. These scripts may also be out of date and broken. DO NOT submit this repository to CCDC.***

## Getting Started

To run these scripts, simply download the repository or individual scripts using `wget`:

```bash
wget "https://tinyurl.com/4nv9t38p" -OutFile "init.ps1"
```

Before running the script, makes sure you have admin privileges and that you set the excution policy with:

```bash
Set-ExecutionPolicy Unrestricted
```
Make sure to set it back to Restricted after running the scripts. All scripts should run after running init.ps1

---

## Scripts Overview

### 1. init.ps1

**Purpose:** This script does some inital hardening:
  - Changes password
  - Clears persistence in Registry
  - Rotates Kerberos password
  - Downloads and applies GPOs

**Usage:** Download and run:

```bash
.\init.ps1
```

---

### 2. Startup-Script.ps1
**Purpose:** This script performs essential security hardening tasks on Windows systems. It includes functions such as:
  - Synchronizing the system time
  - Changing and renaming the local administrator account
  - Enforcing password policies
  - Disabling guest accounts
  - Configuring Windows Defender, Windows Firewall, and audit policies
  - Disabling unnecessary services and IPv6
  - Downloads and installs Firefox, providing a secure alternative to Internet Explorer
  - Downloads and installs ClamAV, a free and open-source antivirus tool. It schedules daily scans for malware protection and updates ClamAV settings to log scan results.
  - Downloads and installs and configures the Wazuh (OSSEC) Agent in local mode for host-based monitoring without an external server connection. This enables basic system monitoring on Windows servers.

**Usage:** This script will run automatically on startup after init.ps1 runs

---

### 3. system-hardening.ps1
**Purpose:** These scripts perfom hardening on thier respective Windows version

**Usage:** This script will run automatically after Startup-Script.ps1 and the corect version will be selected automatically.

