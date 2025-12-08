# MITRE ATT&CK Techniques - Collection

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Collection phase (Phase 15).

## MITRE ATT&CK Tactic
**Collection (TA0009)**

## Techniques

### [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
**Status**: [ ] Not Documented

**Description**: Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.

**Documentation**: [T1005 - Data from Local System](techniques/T1005-data-local-system.md) *(when created)*

---

### [T1039 - Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039/)
**Status**: [ ] Not Documented

**Description**: Adversaries may search network shares on computers they have compromised to find files of interest.

**Documentation**: [T1039 - Data from Network Shared Drive](techniques/T1039-data-network-shared-drive.md) *(when created)*

---

### [T1001 - Data Obfuscation](https://attack.mitre.org/techniques/T1001/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1001.001 - Junk Data](https://attack.mitre.org/techniques/T1001/001/)
- [T1001.002 - Steganography](https://attack.mitre.org/techniques/T1001/002/)
- [T1001.003 - Protocol Impersonation](https://attack.mitre.org/techniques/T1001/003/)

**Documentation**: [T1001 - Data Obfuscation](techniques/T1001-data-obfuscation.md) *(when created)*

---

### [T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1114.001 - Local Email Collection](https://attack.mitre.org/techniques/T1114/001/)
- [T1114.002 - Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
- [T1114.003 - Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

**Documentation**: [T1114 - Email Collection](techniques/T1114-email-collection.md) *(when created)*

---

### [T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/)
**Status**: [ ] Not Documented

**Description**: Adversaries may collect data stored in the clipboard from users copying information within or between applications.

**Documentation**: [T1115 - Clipboard Data](techniques/T1115-clipboard-data.md) *(when created)*

---

### [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
**Status**: [ ] Not Documented

**Description**: Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.

**Documentation**: [T1113 - Screen Capture](techniques/T1113-screen-capture.md) *(when created)*

---

### [T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1056.001 - Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [T1056.002 - GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/)
- [T1056.003 - Web Portal Capture](https://attack.mitre.org/techniques/T1056/003/)
- [T1056.004 - Credential API Hook](https://attack.mitre.org/techniques/T1056/004/)

**Documentation**: [T1056 - Input Capture](techniques/T1056-input-capture.md) *(when created)*

---

### [T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1074.001 - Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)
- [T1074.002 - Remote Data Staging](https://attack.mitre.org/techniques/T1074/002/)

**Documentation**: [T1074 - Data Staged](techniques/T1074-data-staged.md) *(when created)*

---

### [T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)
**Status**: [ ] Not Documented

**Description**: Adversaries may use automated tools for collecting internal data.

**Documentation**: [T1119 - Automated Collection](techniques/T1119-automated-collection.md) *(when created)*

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

- [MITRE ATT&CK - Collection](https://attack.mitre.org/tactics/TA0009/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

