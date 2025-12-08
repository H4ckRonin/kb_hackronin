# MITRE ATT&CK Techniques - Execution

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Execution phase (Phase 12).

## MITRE ATT&CK Tactic
**Execution (TA0002)**

## Techniques

### [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
**Status**: [x] Partially Documented

**Sub-techniques:**
- [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) - [Documented](techniques/T1059.001-powershell.md)
- [T1059.002 - AppleScript](https://attack.mitre.org/techniques/T1059/002/) - [ ] Not Documented
- [T1059.003 - Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) - [ ] Not Documented
- [T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/) - [ ] Not Documented
- [T1059.005 - Visual Basic](https://attack.mitre.org/techniques/T1059/005/) - [ ] Not Documented
- [T1059.006 - Python](https://attack.mitre.org/techniques/T1059/006/) - [ ] Not Documented
- [T1059.007 - JavaScript](https://attack.mitre.org/techniques/T1059/007/) - [ ] Not Documented
- [T1059.008 - Network Device CLI](https://attack.mitre.org/techniques/T1059/008/) - [ ] Not Documented

**Documentation**: [T1059 - Command and Scripting Interpreter](techniques/T1059-command-scripting-interpreter.md) *(when created)*

---

### [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1053.002 - At (Linux)](https://attack.mitre.org/techniques/T1053/002/) - [ ] Not Documented
- [T1053.003 - Cron](https://attack.mitre.org/techniques/T1053/003/) - [ ] Not Documented
- [T1053.005 - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) - [ ] Not Documented
- [T1053.006 - Systemd Timers](https://attack.mitre.org/techniques/T1053/006/) - [ ] Not Documented

**Documentation**: [T1053 - Scheduled Task/Job](techniques/T1053-scheduled-task.md) *(when created)*

---

### [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
**Status**: [ ] Not Documented

**Description**: Adversaries may abuse Windows Management Instrumentation (WMI) to execute arbitrary commands and payloads.

**Documentation**: [T1047 - Windows Management Instrumentation](techniques/T1047-wmi.md) *(when created)*

---

### [T1106 - Native API](https://attack.mitre.org/techniques/T1106/)
**Status**: [ ] Not Documented

**Description**: Adversaries may interact with the native OS application programming interface (API) to execute behaviors.

**Documentation**: [T1106 - Native API](techniques/T1106-native-api.md) *(when created)*

---

### [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
**Status**: [ ] Not Documented

**Description**: Adversaries may exploit software vulnerabilities in client applications to execute code.

**Documentation**: [T1203 - Exploitation for Client Execution](techniques/T1203-exploitation-client.md) *(when created)*

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
   - [x] Partially Documented - Some sub-techniques documented

3. **Adding New Techniques:**
   - Check MITRE ATT&CK for official technique IDs
   - Add to the appropriate phase's mitre-techniques.md file
   - Create detailed documentation

## MITRE ATT&CK Resources

- [MITRE ATT&CK - Execution](https://attack.mitre.org/tactics/TA0002/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

