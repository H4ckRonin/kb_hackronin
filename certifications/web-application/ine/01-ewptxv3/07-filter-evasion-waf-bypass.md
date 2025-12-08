# Filter Evasion & WAF Bypass - eWPTXv3

## Overview
Techniques for bypassing Web Application Firewalls (WAF) and input validation mechanisms.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/filter-evasion-and-waf-bypass)

## Learning Objectives
- Analyze and test WAF rules to identify weak configurations
- Perform hands-on WAF evasion techniques (encoding, obfuscation, payload fragmentation)
- Bypass input validation mechanisms through obfuscation and encoding

## Obfuscating Attacks Using Encodings

### Encoding Techniques
- URL encoding
- Double URL encoding
- Unicode encoding
- Hex encoding
- Base64 encoding
- HTML entity encoding

### Examples
```bash
# SQL Injection
' OR '1'='1
%27%20OR%20%271%27%3D%271
%2527%20OR%20%25271%2527%3D%25271

# XSS
<script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert(1)&lt;/script&gt;
```

## WAF Bypass Techniques

### Method Override
- X-HTTP-Method-Override header
- X-Original-URL
- X-Rewrite-URL

### Case Variation
- Mixed case
- Case alternation
- Unicode case variations

### Comment Injection
- SQL comments (--, /* */)
- HTML comments
- JavaScript comments

### String Concatenation
- SQL: CONCAT(), ||
- JavaScript: + operator
- PHP: . operator

### Payload Fragmentation
- Splitting payloads
- Multiple parameters
- Chunked encoding

## SSRF Bypass

### Techniques
- URL encoding
- IPv6
- DNS rebinding
- Alternative schemes
- Host header manipulation

## XXE Bypass

### Techniques
- External entity references
- Parameter entities
- Blind XXE
- Out-of-band XXE

## Tools
- **Burp Suite** - Encoding/decoding
- **CyberChef** - Encoding operations
- **WAF bypass tools**
- **Custom scripts**

## Last Updated
December 2023

