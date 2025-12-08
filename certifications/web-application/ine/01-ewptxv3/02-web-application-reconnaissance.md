# Web Application Reconnaissance - eWPTXv3

## Overview
Comprehensive passive and active reconnaissance techniques for web applications.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/web-application-reconnaissance)

## Learning Objectives
- Perform comprehensive passive and active reconnaissance on designated target web applications
- Extract information about target organization's domains, subdomains, and IP addresses
- Utilize fuzzing techniques to discover input validation vulnerabilities
- Utilize Git-specific tools to automate the discovery of secrets and vulnerabilities in code

## Information Gathering

### DNS Recon

#### DNS Zone Transfer
```bash
# Attempt zone transfer
dig axfr @<nameserver> <domain>
host -l <domain> <nameserver>
dnsrecon -d <domain> -t axfr
```

#### Subdomain Enumeration
```bash
# Tools
sublist3r -d <domain>
amass enum -d <domain>
subfinder -d <domain>
crt.sh - Search certificates
```

### WAF Recon
- Identify WAF presence
- WAF fingerprinting
- Bypass techniques
- Common WAFs: Cloudflare, AWS WAF, ModSecurity, etc.

## Passive Crawling & Spidering

### Tools
- Burp Suite Spider
- OWASP ZAP Spider
- WebScarab
- Custom scripts

### Techniques
- Manual browsing
- Automated crawling
- Sitemap analysis
- robots.txt analysis

## Web Server Fingerprinting

### Techniques
- HTTP headers analysis
- Error message analysis
- Banner grabbing
- SSL/TLS fingerprinting

### File & Directory Brute-Force
```bash
# Tools
dirb <url>
gobuster dir -u <url> -w <wordlist>
wfuzz -c -z file,wordlist.txt <url>/FUZZ
dirsearch -u <url> -e <extensions>
```

## Web Proxies

### Burp Suite
- Proxy configuration
- Intercepting requests
- Repeater
- Intruder
- Scanner

### OWASP ZAP
- Automated scanning
- Manual testing
- API testing
- Fuzzing

## Git Reconnaissance

### Tools
- GitHacker
- GitTools
- truffleHog
- git-secrets

### Techniques
- .git directory exposure
- GitHub/GitLab enumeration
- Commit history analysis
- Secret scanning

## Fuzzing

### Input Fuzzing
- Parameter fuzzing
- Header fuzzing
- Cookie fuzzing
- File upload fuzzing

### Tools
- Burp Intruder
- Wfuzz
- ffuf
- Custom scripts

## Tools
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Security testing tool
- **Sublist3r** - Subdomain enumeration
- **Amass** - Subdomain enumeration
- **dirb/gobuster** - Directory brute-forcing
- **GitTools** - Git repository analysis

## Last Updated
December 2023

