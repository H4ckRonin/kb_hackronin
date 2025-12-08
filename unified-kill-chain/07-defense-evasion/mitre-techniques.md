# MITRE ATT&CK Techniques - Defense Evasion

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Defense Evasion phase (Phase 7).

## MITRE ATT&CK Tactic
**Defense Evasion (TA0005)**

## Techniques

### [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [T1562.002 - Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)
- [T1562.003 - Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003/)
- [T1562.004 - Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)
- [T1562.006 - Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/)
- [T1562.007 - Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)
- [T1562.008 - Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [T1562.009 - Safe Mode Boot](https://attack.mitre.org/techniques/T1562/009/)

**Documentation**: [T1562 - Impair Defenses](techniques/T1562-impair-defenses.md) *(when created)*

---

### [T1070 - Indicator Removal](https://attack.mitre.org/techniques/T1070/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [T1070.002 - Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002/)
- [T1070.003 - Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [T1070.004 - File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [T1070.005 - Network Share Connection Removal](https://attack.mitre.org/techniques/T1070/005/)
- [T1070.006 - Timestomping](https://attack.mitre.org/techniques/T1070/006/)

**Documentation**: [T1070 - Indicator Removal](techniques/T1070-indicator-removal.md) *(when created)*

---

### [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1027.001 - Binary Padding](https://attack.mitre.org/techniques/T1027/001/)
- [T1027.002 - Software Packing](https://attack.mitre.org/techniques/T1027/002/)
- [T1027.003 - Steganography](https://attack.mitre.org/techniques/T1027/003/)
- [T1027.004 - Compile After Delivery](https://attack.mitre.org/techniques/T1027/004/)
- [T1027.005 - Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005/)

**Documentation**: [T1027 - Obfuscated Files or Information](techniques/T1027-obfuscated-files.md) *(when created)*

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

### [T1620 - Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
**Status**: [ ] Not Documented

**Description**: Adversaries may load code into processes without touching disk to avoid detection.

**Documentation**: [T1620 - Reflective Code Loading](techniques/T1620-reflective-code-loading.md) *(when created)*

---

### [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1036.001 - Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001/)
- [T1036.002 - Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002/)
- [T1036.003 - Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/)
- [T1036.004 - Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004/)
- [T1036.005 - Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)

**Documentation**: [T1036 - Masquerading](techniques/T1036-masquerading.md) *(when created)*

---

### [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)
**Status**: [ ] Not Documented

**Description**: Adversaries may modify the Registry to hide configuration information, remove information as part of cleanup, or as part of other techniques.

**Documentation**: [T1112 - Modify Registry](techniques/T1112-modify-registry.md) *(when created)*

---

### [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
**Status**: [ ] Not Documented

**Description**: Adversaries may use Obfuscated Files or Information to hide artifacts of an attack from detection.

**Documentation**: [T1140 - Deobfuscate/Decode Files or Information](techniques/T1140-deobfuscate-decode.md) *(when created)*

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

- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

