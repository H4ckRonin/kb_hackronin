# MITRE ATT&CK Techniques - Privilege Escalation

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Privilege Escalation phase (Phase 11).

## MITRE ATT&CK Tactic
**Privilege Escalation (TA0004)**

## Techniques

### [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1548.001 - Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/)
- [T1548.002 - Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
- [T1548.003 - Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
- [T1548.004 - Elevated Execution with Prompt](https://attack.mitre.org/techniques/T1548/004/)

**Documentation**: [T1548 - Abuse Elevation Control Mechanism](techniques/T1548-abuse-elevation-control.md) *(when created)*

---

### [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [T1547.002 - Authentication Package](https://attack.mitre.org/techniques/T1547/002/)
- [T1547.003 - Time Providers](https://attack.mitre.org/techniques/T1547/003/)
- [T1547.004 - Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004/)
- [T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [T1547.006 - Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006/)
- [T1547.007 - Re-opened Applications](https://attack.mitre.org/techniques/T1547/007/)
- [T1547.008 - LSASS Driver](https://attack.mitre.org/techniques/T1547/008/)
- [T1547.009 - Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/)
- [T1547.010 - Port Monitors](https://attack.mitre.org/techniques/T1547/010/)
- [T1547.011 - Plist Modification](https://attack.mitre.org/techniques/T1547/011/)
- [T1547.012 - Login Items](https://attack.mitre.org/techniques/T1547/012/)
- [T1547.013 - Outlook Rules](https://attack.mitre.org/techniques/T1547/013/)
- [T1547.014 - Active Setup](https://attack.mitre.org/techniques/T1547/014/)
- [T1547.015 - Login Hook](https://attack.mitre.org/techniques/T1547/015/)

**Documentation**: [T1547 - Boot or Logon Autostart Execution](techniques/T1547-boot-logon-autostart.md) *(when created)*

---

### [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1055.001 - Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
- [T1055.002 - Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)
- [T1055.003 - Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)
- [T1055.004 - Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)
- [T1055.005 - Thread Local Storage](https://attack.mitre.org/techniques/T1055/005/)
- [T1055.008 - Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/)
- [T1055.009 - Proc Memory](https://attack.mitre.org/techniques/T1055/009/)
- [T1055.011 - Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011/)
- [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [T1055.013 - Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013/)
- [T1055.014 - VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014/)
- [T1055.015 - ListPlanting](https://attack.mitre.org/techniques/T1055/015/)

**Documentation**: [T1055 - Process Injection](techniques/T1055-process-injection.md) *(when created)*

---

### [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1134.001 - Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
- [T1134.002 - Create Process with Token](https://attack.mitre.org/techniques/T1134/002/)
- [T1134.003 - Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003/)
- [T1134.004 - Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)
- [T1134.005 - SID-History Injection](https://attack.mitre.org/techniques/T1134/005/)

**Documentation**: [T1134 - Access Token Manipulation](techniques/T1134-access-token-manipulation.md) *(when created)*

---

### [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.

**Documentation**: [T1068 - Exploitation for Privilege Escalation](techniques/T1068-exploitation-privilege-escalation.md) *(when created)*

---

### [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1078.001 - Default Accounts](https://attack.mitre.org/techniques/T1078/001/)
- [T1078.002 - Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [T1078.003 - Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

**Documentation**: [T1078 - Valid Accounts](techniques/T1078-valid-accounts.md) *(when created)*

---

### [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1543.001 - Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
- [T1543.002 - Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
- [T1543.003 - Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [T1543.004 - Launch Daemon](https://attack.mitre.org/techniques/T1543/004/)

**Documentation**: [T1543 - Create or Modify System Process](techniques/T1543-create-modify-system-process.md) *(when created)*

---

## How to Use This Document

1. **Documenting a Technique:**
   - Copy `templates/mitre-technique-template.md`
   - Fill in the MITRE ATT&CK information
   - Add your practical knowledge
   - Update the status in this file

2. **Status Tracking:**
   - [ ] Not Documented - Technique not yet documented
   - [ ] In Progress - Currently being documented
   - [x] Documented - Complete documentation available

3. **Adding New Techniques:**
   - Check MITRE ATT&CK for official technique IDs
   - Add to the appropriate phase's mitre-techniques.md file
   - Create detailed documentation

## MITRE ATT&CK Resources

- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

