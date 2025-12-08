# MITRE ATT&CK Techniques - Credential Access

## Overview
This document lists all MITRE ATT&CK techniques relevant to the Credential Access phase (Phase 13).

## MITRE ATT&CK Tactic
**Credential Access (TA0006)**

## Techniques

### [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1003.001 - LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [T1003.002 - Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)
- [T1003.003 - NTDS](https://attack.mitre.org/techniques/T1003/003/)
- [T1003.004 - LSA Secrets](https://attack.mitre.org/techniques/T1003/004/)
- [T1003.005 - Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)
- [T1003.006 - DCSync](https://attack.mitre.org/techniques/T1003/006/)

**Documentation**: [T1003 - OS Credential Dumping](techniques/T1003-os-credential-dumping.md) *(when created)*

---

### [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.002 - Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
- [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)

**Documentation**: [T1110 - Brute Force](techniques/T1110-brute-force.md) *(when created)*

---

### [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1555.001 - Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [T1555.002 - Securityd Memory](https://attack.mitre.org/techniques/T1555/002/)
- [T1555.003 - Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [T1555.004 - Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)

**Documentation**: [T1555 - Credentials from Password Stores](techniques/T1555-credentials-password-stores.md) *(when created)*

---

### [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1556.001 - Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001/)
- [T1556.002 - Password Filter DLL](https://attack.mitre.org/techniques/T1556/002/)
- [T1556.003 - Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003/)
- [T1556.004 - Network Device Authentication](https://attack.mitre.org/techniques/T1556/004/)
- [T1556.005 - Reversible Encryption](https://attack.mitre.org/techniques/T1556/005/)

**Documentation**: [T1556 - Modify Authentication Process](techniques/T1556-modify-authentication-process.md) *(when created)*

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

### [T1111 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1111/)
**Status**: [ ] Not Documented

**Description**: Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms.

**Documentation**: [T1111 - Multi-Factor Authentication Request Generation](techniques/T1111-mfa-request-generation.md) *(when created)*

---

### [T1621 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
**Status**: [ ] Not Documented

**Sub-techniques:**
- [T1621.001 - Password Manager Application](https://attack.mitre.org/techniques/T1621/001/)
- [T1621.002 - Keychain](https://attack.mitre.org/techniques/T1621/002/)

**Documentation**: [T1621 - Multi-Factor Authentication Request Generation](techniques/T1621-mfa-request-generation.md) *(when created)*

---

### [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
**Status**: [ ] Not Documented

**Description**: Adversaries may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user.

**Documentation**: [T1539 - Steal Web Session Cookie](techniques/T1539-steal-web-session-cookie.md) *(when created)*

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

- [MITRE ATT&CK - Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Last Updated
[Date]

