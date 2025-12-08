# Unified Kill Chain Framework

## Overview

The Unified Kill Chain is a comprehensive framework that combines elements from various attack frameworks to provide a unified model for understanding and categorizing cyber attacks.

## Framework Phases

The Unified Kill Chain consists of 18 phases that represent the complete lifecycle of a cyber attack:

### 1. Reconnaissance
Researching, identifying and selecting targets using active or passive reconnaissance.

### 2. Resource Development
Preparatory activities aimed at setting up the infrastructure required for the attack.

### 3. Delivery
Techniques resulting in the transmission of a weaponized object to the targeted environment.

### 4. Social Engineering
Techniques aimed at the manipulation of people to perform unsafe actions.

### 5. Exploitation
Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution.

### 6. Persistence
Any access, action or change to a system that gives an attacker persistent presence on the system.

### 7. Defense Evasion
Techniques an attacker may specifically use for evading detection or avoiding other defenses.

### 8. Command & Control
Techniques that allow attackers to communicate with controlled systems within a target network.

### 9. Pivoting
Tunneling traffic through a controlled system to other systems that are not directly accessible.

### 10. Discovery
Techniques that allow an attacker to gain knowledge about a system and its network environment.

### 11. Privilege Escalation
The result of techniques that provide an attacker with higher permissions on a system or network.

### 12. Execution
Techniques that result in execution of attacker-controlled code on a local or remote system.

### 13. Credential Access
Techniques resulting in the access of, or control over, system, service or domain credentials.

### 14. Lateral Movement
Techniques that enable an adversary to horizontally access and control other remote systems.

### 15. Collection
Techniques used to identify and gather data from a target network prior to exfiltration.

### 16. Exfiltration
Techniques that result or aid in an attacker removing data from a target network.

### 17. Impact
Techniques aimed at manipulating, interrupting or destroying the target system or data.

### 18. Objectives
Socio-technical objectives of an attack that are intended to achieve a strategic goal.

## How to Use This Framework

### For Learning
- Study techniques within each phase
- Understand how phases connect
- Learn defensive measures for each phase

### For Documentation
- Categorize techniques by kill chain phase
- Map engagements to kill chain phases
- Track which phases you've mastered

### For Engagements
- Plan attacks using the kill chain
- Identify gaps in your methodology
- Document techniques used per phase

## Mapping to Other Frameworks

### MITRE ATT&CK
The Unified Kill Chain phases map to MITRE ATT&CK tactics:
- Reconnaissance → Reconnaissance
- Resource Development → Resource Development
- Delivery → Initial Access
- Social Engineering → Initial Access
- Exploitation → Initial Access, Execution
- Persistence → Persistence
- Defense Evasion → Defense Evasion
- Command & Control → Command and Control
- Pivoting → Lateral Movement
- Discovery → Discovery
- Privilege Escalation → Privilege Escalation
- Execution → Execution
- Credential Access → Credential Access
- Lateral Movement → Lateral Movement
- Collection → Collection
- Exfiltration → Exfiltration
- Impact → Impact
- Objectives → Impact

## Benefits

1. **Comprehensive Coverage**: Covers the entire attack lifecycle
2. **Unified Model**: Combines best elements from multiple frameworks
3. **Practical Application**: Directly applicable to red team and penetration testing
4. **Defense Alignment**: Helps understand where to place defensive controls
5. **Knowledge Organization**: Provides clear structure for organizing techniques

## References

- [Unified Kill Chain Paper](https://www.unifiedkillchain.com/)
- MITRE ATT&CK Framework
- Lockheed Martin Cyber Kill Chain

## Last Updated
[Date]
