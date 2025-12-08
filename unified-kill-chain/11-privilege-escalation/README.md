# Phase 11: Privilege Escalation

## Overview
Privilege Escalation involves escalating privileges to gain higher-level access on compromised systems. This phase focuses on moving from standard user access to administrator, root, or domain administrator privileges.

## Objectives
- Escalate from standard user to administrator/root
- Gain domain administrator privileges
- Access privileged accounts
- Bypass access controls
- Achieve full system control

## Common Techniques

### Windows Privilege Escalation
- Kernel exploits
- Service misconfigurations
- Unquoted service paths
- DLL hijacking
- Token impersonation
- Scheduled tasks
- Registry vulnerabilities

### Linux Privilege Escalation
- Kernel exploits
- SUID/SGID binaries
- Sudo misconfigurations
- Capabilities
- Cron jobs
- PATH manipulation
- NFS misconfigurations

### Active Directory Privilege Escalation
- Kerberoasting
- AS-REP roasting
- DCSync
- Unconstrained delegation
- Constrained delegation abuse
- ACL abuse

## Tools
- WinPEAS, LinPEAS
- PowerUp, PrivescCheck
- BloodHound
- Impacket
- Mimikatz, Rubeus

## Defensive Measures
- Patch management
- Least privilege principle
- Service hardening
- Monitoring privilege escalation attempts
- Regular security assessments

## Related Phases
- **Previous**: Discovery (Phase 10), Exploitation (Phase 5)
- **Next**: Execution (Phase 12), Credential Access (Phase 13)

## References
- MITRE ATT&CK: Privilege Escalation

## Last Updated
[Date]

