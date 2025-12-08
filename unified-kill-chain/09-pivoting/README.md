# Phase 9: Pivoting

## Overview
Pivoting (also known as lateral movement) involves moving through the network from an initial compromised system to access additional systems and resources. This phase is essential for expanding access and reaching high-value targets.

## Objectives
- Move laterally through the network
- Access additional systems
- Expand network presence
- Reach high-value targets
- Maintain access across multiple systems

## Techniques

### Remote Services
- RDP (Remote Desktop Protocol)
- SSH (Secure Shell)
- WinRM (Windows Remote Management)
- SMB (Server Message Block)
- VNC

### Credential-Based Movement
- Pass the Hash
- Pass the Ticket
- Over-Pass the Hash
- Credential reuse

### Network Pivoting
- Port forwarding
- SOCKS proxy
- VPN pivoting
- SSH tunneling

### Taint Shared Content
- Compromising shared drives
- Poisoning shared resources

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
- **Previous**: Command & Control (Phase 8)
- **Next**: Discovery (Phase 10)

## References
- MITRE ATT&CK: Lateral Movement
- Network Segmentation Best Practices

## Last Updated
[Date]

