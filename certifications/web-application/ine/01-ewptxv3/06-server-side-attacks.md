# Server-Side Attacks - eWPTXv3

## Overview
Server-side attack techniques including SSRF, deserialization, and file/resource attacks.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/server-side-attacks)

## Learning Objectives
- Identify and exploit SSRF attacks against server-side services
- Perform deserialization attacks to manipulate server-side objects
- Perform LDAP injection attacks against web application directories

## Server-Side Request Forgery (SSRF)

### Understanding SSRF
- Server making requests on behalf of attacker
- Internal network access
- Cloud metadata access
- Port scanning

### Testing
```bash
# Basic SSRF
http://internal-server/
http://127.0.0.1/
http://localhost/

# Cloud metadata
http://169.254.169.254/
http://metadata.google.internal/
```

### Bypass Techniques
- URL encoding
- DNS rebinding
- IPv6
- Alternative schemes (file://, gopher://)

## Deserialization

### Understanding Deserialization
- Object serialization
- Insecure deserialization
- Code execution
- Remote code execution

### Languages
- Java (Java serialization)
- PHP (unserialize)
- Python (pickle)
- .NET (BinaryFormatter)

### Exploitation
- Gadget chains
- POP chains
- RCE via deserialization

## File & Resource Attacks

### File Upload Vulnerability
- Unrestricted file upload
- File type validation bypass
- Path traversal in uploads
- Web shell upload

### Directory Traversal
```bash
# Basic
../../../etc/passwd
..\..\..\windows\system32\config\sam

# Encoded
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### File Inclusion (LFI and RFI)

#### Local File Inclusion (LFI)
- Including local files
- PHP wrappers (php://filter)
- Log poisoning
- Session file inclusion

#### Remote File Inclusion (RFI)
- Including remote files
- Web shell inclusion
- Code execution

## CMS Pentesting

### WordPress, Drupal & Magento
- Version enumeration
- Plugin/theme vulnerabilities
- Configuration issues
- Default credentials

## LDAP Injection

### Understanding LDAP
- Lightweight Directory Access Protocol
- LDAP queries
- Injection points

### Testing
```bash
# Basic
*)(&
*))%00
```

## Tools
- **Burp Suite** - SSRF testing
- **ysoserial** - Deserialization payloads
- **PHPGGC** - PHP deserialization
- **LDAP injection tools**

## Last Updated
December 2023

