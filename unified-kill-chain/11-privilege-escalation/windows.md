# Windows Privilege Escalation

## Overview
Windows privilege escalation techniques for moving from a standard user to administrator or SYSTEM level access.

## Enumeration Checklist
Always start with comprehensive enumeration:
- [ ] System information
- [ ] User and group information
- [ ] Network configuration
- [ ] Running processes and services
- [ ] Installed software and versions
- [ ] Scheduled tasks
- [ ] File and folder permissions
- [ ] Registry permissions
- [ ] Environment variables

## Common Techniques

### 1. Kernel Exploits
Exploiting vulnerabilities in the Windows kernel.

### 2. Service Misconfigurations
- Unquoted service paths
- Weak service permissions
- Service binary permissions

### 3. DLL Hijacking
Placing malicious DLLs in locations where they'll be loaded by legitimate processes.

### 4. Token Impersonation
Using tokens from other processes/users.

### 5. Scheduled Tasks
Abusing scheduled tasks with weak permissions.

### 6. Registry Vulnerabilities
- Autorun keys
- AlwaysInstallElevated
- Winlogon

## Tools
- WinPEAS
- PowerUp
- PrivescCheck
- AccessChk
- Seatbelt

## References
- OSCP Course
- HTB Academy
- HackTricks

## Last Updated
[Date]

