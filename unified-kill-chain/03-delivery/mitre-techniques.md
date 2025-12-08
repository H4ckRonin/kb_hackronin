# MITRE ATT&CK Techniques - Delivery

## ⚠️ Note: Unified Kill Chain Specific Phase
**Delivery** is a phase specific to the Unified Kill Chain framework. While it maps to MITRE ATT&CK's **Initial Access (TA0001)** tactic, "Delivery" focuses specifically on the transmission of weaponized objects to the target environment. This phase emphasizes the delivery mechanism itself (email, web, USB, etc.) rather than the broader concept of initial access.

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Delivery phase (Phase 3).

## MITRE ATT&CK Tactic
**Initial Access (TA0001)** - Note: Delivery is a Unified Kill Chain specific concept focusing on transmission mechanisms

## Techniques

### [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1566.003 - Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

**Documentation**: [T1566 - Phishing](techniques/T1566-phishing.md) *(when created)*

---

### [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exploit software vulnerabilities in public-facing applications to gain initial access.

**Documentation**: [T1190 - Exploit Public-Facing Application](techniques/T1190-exploit-public-facing-app.md) *(when created)*

---

### [T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
**Status**: [ ] Not Documented

**Description**: Adversaries may breach or otherwise leverage organizations that have access to intended victims.

**Documentation**: [T1199 - Trusted Relationship](techniques/T1199-trusted-relationship.md) *(when created)*

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

### [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
**Status**: [ ] Not Documented

**Description**: Adversaries may leverage external-facing remote services to gain initial access to internal networks.

**Documentation**: [T1133 - External Remote Services](techniques/T1133-external-remote-services.md) *(when created)*

---

### [T1200 - Hardware Additions](https://attack.mitre.org/techniques/T1200/)
**Status**: [ ] Not Documented

**Description**: Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access.

**Documentation**: [T1200 - Hardware Additions](techniques/T1200-hardware-additions.md) *(when created)*

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

- [MITRE ATT&CK - Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

