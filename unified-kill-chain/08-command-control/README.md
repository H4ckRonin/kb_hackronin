# Phase 8: Command & Control

## Overview
Command & Control (C2) involves establishing communication channels between compromised systems and attacker infrastructure. This phase enables remote control and data exfiltration.

## Objectives
- Establish reliable C2 channels
- Maintain communication
- Evade detection
- Support multiple protocols
- Enable remote control

## Techniques

### Application Layer Protocol
- HTTP/HTTPS
- DNS
- SMTP
- Custom protocols

### Data Encoding
- Base64 encoding
- Custom encoding
- Encryption

### Non-Standard Port
- Using non-standard ports
- Port hopping

### Protocol Tunneling
- Tunneling over legitimate protocols
- Encrypted tunnels

### Domain Fronting
- Using CDN services
- Hiding C2 traffic

## Tools
- Cobalt Strike
- Empire
- Covenant
- Sliver
- Metasploit

## Defensive Measures
- Network monitoring
- DNS monitoring
- Traffic analysis
- Behavioral detection
- Threat intelligence

## Related Phases
- **Previous**: Defense Evasion (Phase 7)
- **Next**: Pivoting (Phase 9)

## References
- MITRE ATT&CK: Command and Control

## Last Updated
[Date]

