# Linux Privilege Escalation

## Overview
Linux privilege escalation techniques for moving from a standard user to root level access.

## Enumeration Checklist
Always start with comprehensive enumeration:
- [ ] System information (`uname -a`, `cat /etc/os-release`)
- [ ] User and group information (`id`, `whoami`, `groups`)
- [ ] Sudo permissions (`sudo -l`)
- [ ] SUID/SGID binaries
- [ ] Capabilities
- [ ] Cron jobs
- [ ] World-writable files and directories
- [ ] Environment variables
- [ ] Network connections
- [ ] Running processes

## Common Techniques

### 1. Kernel Exploits
Exploiting vulnerabilities in the Linux kernel.

### 2. SUID/SGID Binaries
Abusing binaries with SUID or SGID bits set.

### 3. Sudo Misconfigurations
- Sudo without password
- Sudo with dangerous commands
- Sudo with vulnerable binaries

### 4. Capabilities
Abusing Linux capabilities for privilege escalation.

### 5. Cron Jobs
- World-writable cron scripts
- Cron jobs running as root
- PATH manipulation in cron

### 6. PATH Manipulation
Adding malicious directories to PATH.

### 7. NFS Misconfigurations
Abusing NFS shares with no_root_squash.

## Tools
- LinPEAS
- LinEnum
- Linux Smart Enumeration
- GTFOBins

## References
- OSCP Course
- HTB Academy
- HackTricks

## Last Updated
[Date]

