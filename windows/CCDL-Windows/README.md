# UW-Stout CCDL - Windows Security Scripts

This repository contains a collection of PowerShell scripts designed by the UW-Stout Collegiate Cyber Defense League (CCDL) - Windows Team. Each script automates essential security tasks and configurations for Windows Server environments. These scripts are aimed at improving baseline security and can be used individually or as part of a comprehensive hardening process.

***NOTE: This repository is only for development of scripts, and SHOULD AND WILL NOT BE USED during competition, since it will be updated after the cutoff dates. These scripts may also be out of date and broken.***

## Getting Started

To run these scripts, simply download the repository or individual scripts using `wget`:

```bash
wget "https://tinyurl.com/4duuewes" -OutFile "Startup-Script.ps1"
wget "https://tinyurl.com/msc9cyd8" -Outfile "Installs.ps1"
```
```bash
Invoke-WebRequest "https://raw.githubusercontent.com/Baglesrfine/CCDL-Windows/refs/heads/main/Startup-Script.ps1" -OutFile "Startup-Script.ps1"
```

After downloading, run each script in a PowerShell session with administrator privileges to ensure all configurations are applied correctly.

---

## Scripts Overview

### 1. Startup-Script.ps1
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

**Usage:**

```bash
.\Startup-Script.ps1
```

---

### 2. future-script.ps1
**Purpose:** This is a future script

**Usage:**

```bash
.\future-script.ps1
```

---

### 3. future-script.ps1
**Purpose:** This is a future script

**Usage:**

```bash
.\future-script.ps1
```

---

### 4. future-script.ps1
**Purpose:** This is a future script

**Usage:**

```bash
.\future-script.ps1
```
