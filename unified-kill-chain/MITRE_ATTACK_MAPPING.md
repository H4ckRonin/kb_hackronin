# MITRE ATT&CK Mapping

## Overview
This document maps Unified Kill Chain phases to MITRE ATT&CK tactics and techniques. Each phase includes relevant MITRE ATT&CK techniques that can be documented in detail.

## Phase Mapping

### Phase 1: Reconnaissance
**MITRE ATT&CK Tactic:** Reconnaissance (TA0043)

**Key Techniques:**
- T1595 - Active Scanning
- T1592 - Gather Victim Host Information
- T1589 - Gather Victim Identity Information
- T1590 - Gather Victim Network Information
- T1591 - Gather Victim Org Information
- T1598 - Phishing for Information
- T1597 - Search Closed Sources
- T1596 - Search Open Technical Databases
- T1593 - Search Open Websites/Domains
- T1594 - Search Victim-Owned Websites

### Phase 2: Resource Development
**MITRE ATT&CK Tactic:** Resource Development (TA0042)

**Key Techniques:**
- T1583 - Acquire Infrastructure
- T1584 - Compromise Infrastructure
- T1585 - Establish Accounts
- T1586 - Compromise Accounts
- T1587 - Develop Capabilities
- T1588 - Obtain Capabilities

### Phase 3: Delivery
**MITRE ATT&CK Tactic:** Initial Access (TA0001)

**Key Techniques:**
- T1566 - Phishing
- T1190 - Exploit Public-Facing Application
- T1199 - Trusted Relationship
- T1078 - Valid Accounts
- T1133 - External Remote Services
- T1200 - Hardware Additions
- T1566.001 - Spear phishing Attachment
- T1566.002 - Spear phishing Link
- T1566.003 - Spear phishing via Service

### Phase 4: Social Engineering
**MITRE ATT&CK Tactic:** Initial Access (TA0001)

**Key Techniques:**
- T1566 - Phishing
- T1566.001 - Spear phishing Attachment
- T1566.002 - Spear phishing Link
- T1566.003 - Spear phishing via Service
- T1598 - Phishing for Information
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell (for social engineering payloads)

### Phase 5: Exploitation
**MITRE ATT&CK Tactic:** Initial Access (TA0001), Execution (TA0002)

**Key Techniques:**
- T1190 - Exploit Public-Facing Application
- T1210 - Exploit Remote Services
- T1203 - Exploitation for Client Execution
- T1059 - Command and Scripting Interpreter
- T1059.001 - PowerShell
- T1059.003 - Windows Command Shell
- T1059.004 - Unix Shell
- T1059.005 - Visual Basic
- T1059.006 - Python
- T1059.007 - JavaScript
- T1059.008 - Network Device CLI

### Phase 6: Persistence
**MITRE ATT&CK Tactic:** Persistence (TA0003)

**Key Techniques:**
- T1547 - Boot or Logon Autostart Execution
- T1053 - Scheduled Task/Job
- T1134 - Access Token Manipulation
- T1543 - Create or Modify System Process
- T1574 - Hijack Execution Flow
- T1136 - Create Account
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task/Job: Scheduled Task

### Phase 7: Defense Evasion
**MITRE ATT&CK Tactic:** Defense Evasion (TA0005)

**Key Techniques:**
- T1562 - Impair Defenses
- T1070 - Indicator Removal
- T1027 - Obfuscated Files or Information
- T1055 - Process Injection
- T1620 - Reflective Code Loading
- T1036 - Masquerading
- T1562.001 - Disable or Modify Tools
- T1070.004 - Indicator Removal: File Deletion
- T1070.005 - Indicator Removal: Network Share Connection Removal

### Phase 8: Command & Control
**MITRE ATT&CK Tactic:** Command and Control (TA0011)

**Key Techniques:**
- T1071 - Application Layer Protocol
- T1095 - Non-Application Layer Protocol
- T1573 - Encrypted Channel
- T1105 - Ingress Tool Transfer
- T1104 - Multi-Stage Channels
- T1071.001 - Web Protocols
- T1071.002 - File Transfer Protocols
- T1071.003 - Mail Protocols
- T1573.002 - Asymmetric Cryptography

### Phase 9: Pivoting
**MITRE ATT&CK Tactic:** Lateral Movement (TA0008)

**Key Techniques:**
- T1021 - Remote Services
- T1021.001 - Remote Desktop Protocol
- T1021.002 - SMB/Windows Admin Shares
- T1021.003 - Distributed Component Object Model
- T1021.004 - SSH
- T1021.005 - VNC
- T1021.006 - Windows Remote Management
- T1570 - Lateral Tool Transfer

### Phase 10: Discovery
**MITRE ATT&CK Tactic:** Discovery (TA0007)

**Key Techniques:**
- T1083 - File and Directory Discovery
- T1082 - System Information Discovery
- T1018 - Remote System Discovery
- T1046 - Network Service Scanning
- T1135 - Network Share Discovery
- T1040 - Network Sniffing
- T1087 - Account Discovery
- T1033 - System Owner/User Discovery
- T1057 - Process Discovery
- T1518 - Software Discovery

### Phase 11: Privilege Escalation
**MITRE ATT&CK Tactic:** Privilege Escalation (TA0004)

**Key Techniques:**
- T1548 - Abuse Elevation Control Mechanism
- T1547 - Boot or Logon Autostart Execution
- T1055 - Process Injection
- T1134 - Access Token Manipulation
- T1548.001 - Setuid and Setgid
- T1548.002 - Bypass User Account Control
- T1548.003 - Sudo and Sudo Caching
- T1547.001 - Registry Run Keys / Startup Folder

### Phase 12: Execution
**MITRE ATT&CK Tactic:** Execution (TA0002)

**Key Techniques:**
- T1059 - Command and Scripting Interpreter
- T1053 - Scheduled Task/Job
- T1047 - Windows Management Instrumentation
- T1059.001 - PowerShell
- T1059.003 - Windows Command Shell
- T1059.004 - Unix Shell
- T1059.005 - Visual Basic
- T1059.006 - Python
- T1059.007 - JavaScript
- T1053.005 - Scheduled Task

### Phase 13: Credential Access
**MITRE ATT&CK Tactic:** Credential Access (TA0006)

**Key Techniques:**
- T1003 - OS Credential Dumping
- T1110 - Brute Force
- T1555 - Credentials from Password Stores
- T1556 - Modify Authentication Process
- T1056 - Input Capture
- T1003.001 - LSASS Memory
- T1003.002 - Security Account Manager
- T1003.003 - NTDS
- T1003.004 - LSA Secrets
- T1110.001 - Password Guessing
- T1110.002 - Password Cracking
- T1110.003 - Password Spraying
- T1110.004 - Credential Stuffing

### Phase 14: Lateral Movement
**MITRE ATT&CK Tactic:** Lateral Movement (TA0008)

**Key Techniques:**
- T1021 - Remote Services
- T1072 - Software Deployment Tools
- T1021.001 - Remote Desktop Protocol
- T1021.002 - SMB/Windows Admin Shares
- T1021.004 - SSH
- T1550 - Use Alternate Authentication Material
- T1550.001 - Pass the Hash
- T1550.002 - Pass the Ticket
- T1550.003 - Web Session Cookie
- T1570 - Lateral Tool Transfer

### Phase 15: Collection
**MITRE ATT&CK Tactic:** Collection (TA0009)

**Key Techniques:**
- T1005 - Data from Local System
- T1039 - Data from Network Shared Drive
- T1001 - Data Obfuscation
- T1114 - Email Collection
- T1115 - Clipboard Data
- T1113 - Screen Capture
- T1056 - Input Capture
- T1074 - Data Staged
- T1114.001 - Local Email Collection
- T1114.002 - Remote Email Collection

### Phase 16: Exfiltration
**MITRE ATT&CK Tactic:** Exfiltration (TA0010)

**Key Techniques:**
- T1041 - Exfiltration Over C2 Channel
- T1048 - Exfiltration Over Alternative Protocol
- T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
- T1020 - Automated Exfiltration
- T1011 - Exfiltration Over Other Network Medium
- T1030 - Data Transfer Size Limits
- T1537 - Transfer Data to Cloud Account

### Phase 17: Impact
**MITRE ATT&CK Tactic:** Impact (TA0040)

**Key Techniques:**
- T1486 - Data Encrypted for Impact
- T1485 - Data Destruction
- T1491 - Defacement
- T1490 - Inhibit System Recovery
- T1499 - Endpoint Denial of Service
- T1498 - Network Denial of Service
- T1496 - Resource Hijacking
- T1489 - Service Stop
- T1491.001 - Internal Defacement
- T1491.002 - External Defacement

### Phase 18: Objectives
**MITRE ATT&CK Tactic:** Impact (TA0040)

**Note:** Objectives are strategic goals that may involve multiple Impact techniques.

## How to Use This Mapping

1. **When documenting a technique:**
   - Include the MITRE ATT&CK technique ID (e.g., T1059.001)
   - Link to the official MITRE ATT&CK page
   - Reference the technique in your documentation

2. **When adding new techniques:**
   - Check MITRE ATT&CK for the official technique ID
   - Add it to the appropriate phase
   - Create detailed documentation with MITRE reference

3. **Cross-referencing:**
   - Use MITRE IDs for consistency
   - Link between Unified Kill Chain phases and MITRE tactics
   - Maintain alignment with industry standards

## MITRE ATT&CK Resources

- [MITRE ATT&CK Website](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [MITRE ATT&CK GitHub](https://github.com/mitre/cti)

## Last Updated
[Date]

