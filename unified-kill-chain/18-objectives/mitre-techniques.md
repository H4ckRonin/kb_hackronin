# MITRE ATT&CK Techniques - Objectives

## ⚠️ Note: Unified Kill Chain Specific Phase
**Objectives** is a phase unique to the Unified Kill Chain framework. Unlike MITRE ATT&CK which focuses on technical tactics, Objectives represents the **socio-technical goals** of an attack - the strategic reasons why an attack is conducted (financial gain, espionage, disruption, etc.). This phase maps to MITRE ATT&CK's **Impact (TA0040)** tactic but goes beyond technical impact to include strategic objectives and business outcomes.

## Overview
This document lists MITRE ATT&CK techniques and considerations relevant to the Objectives phase (Phase 18).

## MITRE ATT&CK Tactic
**Impact (TA0040)** - Note: Objectives are strategic goals that may involve multiple Impact techniques

## Strategic Objectives

### Financial Gain
**Related Techniques:**
- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) (Ransomware)
- [T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/) (Cryptocurrency Mining)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/) (Financial Fraud)

**Documentation**: [Financial Gain Objectives](objectives/financial-gain.md) *(when created)*

---

### Data Theft
**Related Techniques:**
- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1039 - Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

**Documentation**: [Data Theft Objectives](objectives/data-theft.md) *(when created)*

---

### Espionage
**Related Techniques:**
- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)

**Documentation**: [Espionage Objectives](objectives/espionage.md) *(when created)*

---

### Disruption
**Related Techniques:**
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

**Documentation**: [Disruption Objectives](objectives/disruption.md) *(when created)*

---

### Destruction
**Related Techniques:**
- [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

**Documentation**: [Destruction Objectives](objectives/destruction.md) *(when created)*

---

### Brand Damage
**Related Techniques:**
- [T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [T1070 - Indicator Removal](https://attack.mitre.org/techniques/T1070/) (to hide attribution)

**Documentation**: [Brand Damage Objectives](objectives/brand-damage.md) *(when created)*

---

## How to Use This Document

1. **Documenting Objectives:**
   - Objectives are strategic goals, not specific techniques
   - Document which techniques were used to achieve objectives
   - Map objectives to business impact
   - Track success metrics

2. **Status Tracking:**
   - [ ] Not Documented - Objective not yet documented
   - [ ] In Progress - Currently being documented
   - [x] Documented - Complete documentation available

3. **Adding New Objectives:**
   - Identify the strategic goal
   - Map to relevant MITRE ATT&CK techniques
   - Document business impact
   - Create detailed documentation

## MITRE ATT&CK Resources

- [MITRE ATT&CK - Impact](https://attack.mitre.org/tactics/TA0040/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

