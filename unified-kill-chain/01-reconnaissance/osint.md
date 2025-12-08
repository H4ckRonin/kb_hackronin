# OSINT (Open Source Intelligence)

## Overview
OSINT involves gathering information from publicly available sources to build a comprehensive picture of a target.

## Information Gathering Categories

### Domain Information
- WHOIS records
- DNS records
- Subdomain enumeration
- Historical DNS data
- SSL certificates

### Email Information
- Email addresses
- Email format patterns
- Breach databases
- Social media accounts

### Employee Information
- LinkedIn profiles
- Social media accounts
- Conference presentations
- GitHub accounts
- Personal websites

### Technology Stack
- Web technologies (Wappalyzer, BuiltWith)
- Server information
- Framework versions
- Third-party services

### Infrastructure
- IP ranges
- ASN information
- Cloud providers
- CDN usage
- Historical data

## Tools

### Passive Tools
- **theHarvester**: Email, subdomain, host discovery
- **Shodan**: Internet-connected device search
- **Censys**: Internet-wide scanning data
- **Maltego**: Link analysis
- **Recon-ng**: Web reconnaissance framework
- **SpiderFoot**: OSINT automation

### Active Tools
- **Nmap**: Network scanning
- **Masscan**: Fast port scanning
- **RustScan**: Modern port scanner

## Methodology

### 1. Domain Research
```bash
# WHOIS lookup
whois example.com

# DNS enumeration
dig example.com ANY
nslookup example.com

# Subdomain discovery
subfinder -d example.com
amass enum -d example.com
```

### 2. Email Discovery
```bash
# Using theHarvester
theHarvester -d example.com -b all

# Using Hunter.io (web)
# Using Email Format (web)
```

### 3. Technology Identification
```bash
# Wappalyzer (browser extension)
# BuiltWith (web)
# WhatWeb
whatweb http://example.com
```

### 4. Social Media Research
- LinkedIn company page
- Employee profiles
- Company posts and updates
- Technology mentions

### 5. Code Repository Research
```bash
# GitHub search
# GitLab search
# Bitbucket search
```

## Best Practices
- Start broad, then narrow down
- Document everything
- Verify information from multiple sources
- Respect privacy and legal boundaries
- Use multiple tools for validation

## Legal Considerations
- Only use publicly available information
- Respect robots.txt
- Follow terms of service
- Understand local laws
- Get proper authorization

## References
- OSINT Framework
- IntelTechniques
- Bellingcat

## Last Updated
[Date]

