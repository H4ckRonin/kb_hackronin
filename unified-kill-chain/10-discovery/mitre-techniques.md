# MITRE ATT&CK Techniques - Discovery

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Discovery phase (Phase 10).

## MITRE ATT&CK Tactic
**Discovery (TA0007)**

## Techniques

### [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
**Status**: [ ] Not Documented

**Description**: Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.

**Documentation**: [T1083 - File and Directory Discovery](techniques/T1083-file-directory-discovery.md) *(when created)*

---

### [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
**Status**: [ ] Not Documented

**Description**: An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.

**Documentation**: [T1082 - System Information Discovery](techniques/T1082-system-information-discovery.md) *(when created)*

---

### [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
**Status**: [ ] Not Documented

**Description**: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement.

**Documentation**: [T1018 - Remote System Discovery](techniques/T1018-remote-system-discovery.md) *(when created)*

---

### [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
**Status**: [ ] Not Documented

**Description**: Adversaries may scan for open ports and services to map the network and identify potential attack vectors.

**Documentation**: [T1046 - Network Service Scanning](techniques/T1046-network-service-scanning.md) *(when created)*

---

### [T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
**Status**: [ ] Not Documented

**Description**: Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

**Documentation**: [T1135 - Network Share Discovery](techniques/T1135-network-share-discovery.md) *(when created)*

---

### [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
**Status**: [ ] Not Documented

**Description**: Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.

**Documentation**: [T1040 - Network Sniffing](techniques/T1040-network-sniffing.md) *(when created)*

---

### [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1087.001 - Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [T1087.002 - Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [T1087.003 - Email Account](https://attack.mitre.org/techniques/T1087/003/)
- [T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)

**Documentation**: [T1087 - Account Discovery](techniques/T1087-account-discovery.md) *(when created)*

---

### [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
**Status**: [ ] Not Documented

**Description**: Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.

**Documentation**: [T1033 - System Owner/User Discovery](techniques/T1033-system-owner-user-discovery.md) *(when created)*

---

### [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)
**Status**: [ ] Not Documented

**Description**: Adversaries may attempt to get information about running processes on a system.

**Documentation**: [T1057 - Process Discovery](techniques/T1057-process-discovery.md) *(when created)*

---

### [T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1518.001 - Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/)

**Documentation**: [T1518 - Software Discovery](techniques/T1518-software-discovery.md) *(when created)*

---

### [T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1069.001 - Local Groups](https://attack.mitre.org/techniques/T1069/001/)
- [T1069.002 - Domain Groups](https://attack.mitre.org/techniques/T1069/002/)
- [T1069.003 - Cloud Groups](https://attack.mitre.org/techniques/T1069/003/)

**Documentation**: [T1069 - Permission Groups Discovery](techniques/T1069-permission-groups-discovery.md) *(when created)*

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

- [MITRE ATT&CK - Discovery](https://attack.mitre.org/tactics/TA0007/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

