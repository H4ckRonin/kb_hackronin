# MITRE ATT&CK Techniques - Pivoting

## ⚠️ Note: Unified Kill Chain Specific Phase
**Pivoting** is a phase specific to the Unified Kill Chain framework. While it maps to MITRE ATT&CK's **Lateral Movement (TA0008)** tactic, "Pivoting" represents a more specific concept focused on tunneling traffic through controlled systems to access otherwise unreachable systems. This phase emphasizes network pivoting techniques that may not be explicitly categorized in MITRE ATT&CK but are essential in red team operations.

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Pivoting phase (Phase 9).

## MITRE ATT&CK Tactic
**Lateral Movement (TA0008)** - Note: Pivoting is a Unified Kill Chain specific concept that encompasses tunneling and network pivoting techniques

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

### [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
**Status**: [ ] Not Documented

**Description**: Adversaries may transfer tools or other files between systems in a compromised environment.

**Documentation**: [T1570 - Lateral Tool Transfer](techniques/T1570-lateral-tool-transfer.md) *(when created)*

---

### [T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1090.001 - Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
- [T1090.002 - External Proxy](https://attack.mitre.org/techniques/T1090/002/)
- [T1090.003 - Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
- [T1090.004 - Domain Fronting](https://attack.mitre.org/techniques/T1090/004/)

**Documentation**: [T1090 - Proxy](techniques/T1090-proxy.md) *(when created)*

---

### [T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
**Status**: [ ] Not Documented

**Description**: Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.

**Documentation**: [T1572 - Protocol Tunneling](techniques/T1572-protocol-tunneling.md) *(when created)*

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

