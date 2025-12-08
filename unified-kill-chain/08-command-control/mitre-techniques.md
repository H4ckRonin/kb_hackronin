# MITRE ATT&CK Techniques - Command & Control

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Command & Control phase (Phase 8).

## MITRE ATT&CK Tactic
**Command and Control (TA0011)**

## Techniques

### [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1071.002 - File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002/)
- [T1071.003 - Mail Protocols](https://attack.mitre.org/techniques/T1071/003/)
- [T1071.004 - DNS](https://attack.mitre.org/techniques/T1071/004/)

**Documentation**: [T1071 - Application Layer Protocol](techniques/T1071-application-layer-protocol.md) *(when created)*

---

### [T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
**Status**: [ ] Not Documented

**Description**: Adversaries may use a non-application layer protocol for communication between host and C2 server.

**Documentation**: [T1095 - Non-Application Layer Protocol](techniques/T1095-non-application-layer-protocol.md) *(when created)*

---

### [T1573 - Encrypted Channel](https://attack.mitre.org/techniques/T1573/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1573.001 - Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
- [T1573.002 - Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)

**Documentation**: [T1573 - Encrypted Channel](techniques/T1573-encrypted-channel.md) *(when created)*

---

### [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
**Status**: [ ] Not Documented

**Description**: Adversaries may transfer tools or other files from an external system into a compromised environment.

**Documentation**: [T1105 - Ingress Tool Transfer](techniques/T1105-ingress-tool-transfer.md) *(when created)*

---

### [T1104 - Multi-Stage Channels](https://attack.mitre.org/techniques/T1104/)
**Status**: [ ] Not Documented

**Description**: Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions.

**Documentation**: [T1104 - Multi-Stage Channels](techniques/T1104-multi-stage-channels.md) *(when created)*

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

### [T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)
**Status**: [ ] Not Documented

**Description**: Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible.

**Documentation**: [T1008 - Fallback Channels](techniques/T1008-fallback-channels.md) *(when created)*

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

- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

