# MITRE ATT&CK Techniques - Lateral Movement

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Lateral Movement phase (Phase 14).

## MITRE ATT&CK Tactic
**Lateral Movement (TA0008)**

## Techniques

### [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1021.001 - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [T1021.003 - Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003/)
- [T1021.004 - SSH](https://attack.mitre.org/techniques/T1021/004/)
- [T1021.005 - VNC](https://attack.mitre.org/techniques/T1021/005/)
- [T1021.006 - Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)

**Documentation**: [T1021 - Remote Services](techniques/T1021-remote-services.md) *(when created)*

---

### [T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)
**Status**: [ ] Not Documented

**Description**: Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems.

**Documentation**: [T1072 - Software Deployment Tools](techniques/T1072-software-deployment-tools.md) *(when created)*

---

### [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1550.001 - Pass the Hash](https://attack.mitre.org/techniques/T1550/001/)
- [T1550.002 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/002/)
- [T1550.003 - Web Session Cookie](https://attack.mitre.org/techniques/T1550/003/)
- [T1550.004 - Application Access Token](https://attack.mitre.org/techniques/T1550/004/)

**Documentation**: [T1550 - Use Alternate Authentication Material](techniques/T1550-alternate-authentication-material.md) *(when created)*

---

### [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
**Status**: [ ] Not Documented

**Description**: Adversaries may transfer tools or other files between systems in a compromised environment.

**Documentation**: [T1570 - Lateral Tool Transfer](techniques/T1570-lateral-tool-transfer.md) *(when created)*

---

### [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
**Status**: [ ] Not Documented

**Description**: Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).

**Documentation**: [T1021.002 - SMB/Windows Admin Shares](techniques/T1021.002-smb-admin-shares.md) *(when created)*

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

- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

