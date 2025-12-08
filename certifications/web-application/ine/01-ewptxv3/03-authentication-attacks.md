# Authentication Attacks - eWPTXv3

## Overview
Testing various authentication methods and identifying vulnerabilities in authentication mechanisms.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/authentication-attacks)

## Learning Objectives
- Test various authentication methods (e.g., Basic, Digest, OAuth)
- Execute practical attacks such as credential stuffing and brute force
- Identify common vulnerabilities in SSO implementations
- Identify and exploit Session Management vulnerabilities
- Identify and exploit weaknesses in OAuth and OpenID Connect protocols

## HTTP Attacks

### HTTP Method Tampering
- Testing HTTP methods
- PUT, DELETE, PATCH exploitation
- Method override techniques
- Bypassing restrictions

### Attacking HTTP Authentication

#### Basic Authentication
```bash
# Brute force
hydra -l <user> -P <wordlist> <target> http-get /protected
medusa -h <target> -u <user> -P <wordlist> -M http
```

#### Digest Authentication
- Challenge-response analysis
- Replay attacks
- Brute force techniques

## Session Attacks

### Session Hijacking
- Cookie theft
- Session fixation
- Session prediction
- Man-in-the-middle attacks

### Session Fixation
1. Obtain a session ID
2. Force victim to use the session ID
3. Access the session after authentication

### Session Hijacking via Cookie Tampering
- Cookie manipulation
- HttpOnly flag bypass
- Secure flag analysis
- SameSite attribute testing

## JWT Attacks

### JWT Structure
- Header
- Payload
- Signature

### Common Attacks
- Algorithm confusion (none algorithm)
- Weak secret key
- Signature verification bypass
- Payload manipulation

### Tools
- jwt_tool
- jwt.io
- Burp JWT extension

## CSRF (Cross-Site Request Forgery)

### Understanding CSRF
- Same-origin policy
- CSRF token mechanisms
- Bypass techniques

### Testing
- Token validation
- Referer header checks
- SameSite cookie attribute
- Custom headers

### Exploitation
- GET-based CSRF
- POST-based CSRF
- JSON CSRF
- File upload CSRF

## OAuth & OpenID Connect

### OAuth Flows
- Authorization Code
- Implicit
- Client Credentials
- Resource Owner Password

### Common Vulnerabilities
- Redirect URI manipulation
- Client secret exposure
- Token leakage
- Scope escalation

### Testing
- Parameter manipulation
- State parameter validation
- Redirect URI validation
- Token analysis

## SSO (Single Sign-On) Vulnerabilities

### Common Issues
- SAML vulnerabilities
- OpenID Connect misconfigurations
- Token handling issues
- Session management

## Credential Stuffing
- Using breached credentials
- Automation tools
- Rate limiting bypass
- Account enumeration

## Brute Force Attacks
```bash
# Tools
hydra
medusa
patator
burp intruder
```

## Tools
- **Burp Suite** - Authentication testing
- **OWASP ZAP** - Session management testing
- **jwt_tool** - JWT manipulation
- **Hydra** - Brute force tool
- **OAuth testing tools**

## Last Updated
December 2023

