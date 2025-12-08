# MITRE ATT&CK Techniques - Exfiltration

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Exfiltration phase (Phase 16).

## MITRE ATT&CK Tactic
**Exfiltration (TA0010)**

## Techniques

### [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
**Status**: [ ] Not Documented

**Description**: Adversaries may steal data by exfiltrating it over an existing command and control channel.

**Documentation**: [T1041 - Exfiltration Over C2 Channel](techniques/T1041-exfiltration-c2-channel.md) *(when created)*

---

### [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
- [T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
- [T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/)

**Documentation**: [T1048 - Exfiltration Over Alternative Protocol](techniques/T1048-exfiltration-alternative-protocol.md) *(when created)*

---

### [T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.

**Documentation**: [T1020 - Automated Exfiltration](techniques/T1020-automated-exfiltration.md) *(when created)*

---

### [T1011 - Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1011.001 - Exfiltration Over Bluetooth](https://attack.mitre.org/techniques/T1011/001/)
- [T1011.002 - Exfiltration Over USB](https://attack.mitre.org/techniques/T1011/002/)

**Documentation**: [T1011 - Exfiltration Over Other Network Medium](techniques/T1011-exfiltration-other-network-medium.md) *(when created)*

---

### [T1030 - Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds.

**Documentation**: [T1030 - Data Transfer Size Limits](techniques/T1030-data-transfer-size-limits.md) *(when created)*

---

### [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exfiltrate data to a cloud storage account rather than their primary command and control channel.

**Documentation**: [T1537 - Transfer Data to Cloud Account](techniques/T1537-transfer-data-cloud-account.md) *(when created)*

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

- [MITRE ATT&CK - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

