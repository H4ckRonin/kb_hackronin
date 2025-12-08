# Phase 14: Lateral Movement

## Overview
Lateral Movement involves moving through the network using credentials and other methods to access additional systems. This phase focuses on expanding access across the network infrastructure.

## Objectives
- Move laterally through the network
- Access additional systems
- Expand network presence
- Reach high-value targets
- Maintain access across multiple systems

## Common Techniques

### Remote Services
- RDP (Remote Desktop Protocol)
- SSH (Secure Shell)
- WinRM (Windows Remote Management)
- SMB (Server Message Block)
- VNC

### Pass the Hash
Using NTLM hashes to authenticate without passwords.

### Pass the Ticket
Using Kerberos tickets for authentication.

### Taint Shared Content
- Compromising shared drives
- Poisoning shared resources
- DLL hijacking via shares

### Network Pivoting
- Port forwarding
- SOCKS proxy
- VPN pivoting
- SSH tunneling

## Tools
- Proxychains
- SSH
- RDP
- Impacket tools
- BloodHound
- CrackMapExec

## Defensive Measures
- Network segmentation
- Monitoring lateral movement
- Credential management
- Privileged access management
- Network traffic analysis

## Related Phases
- **Previous**: Credential Access (Phase 13), Pivoting (Phase 9)
- **Next**: Objectives (Phase 15)

## References
- MITRE ATT&CK: Lateral Movement

## Last Updated
[Date]
