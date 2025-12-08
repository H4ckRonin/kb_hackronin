# Injection Vulnerabilities - eWPTXv3

## Overview
Identifying and exploiting various injection vulnerabilities including SQL, NoSQL, and command injection.

**Source**: [dev-angelist GitBook](https://dev-angelist.gitbook.io/ewptxv3-notes/injection-vulnerabilities)

## Learning Objectives
- Identify and exploit SQL injection vulnerabilities (error-based, blind, time-based)
- Utilize SQLMap and other tools to automate SQL injection attacks
- Identify and exploit NoSQL injection vulnerabilities
- Extract sensitive data from compromised databases

## Command Injection

### Testing
```bash
# Basic payloads
; whoami
| whoami
`whoami`
$(whoami)
```

### Bypass Techniques
- Encoding
- Command chaining
- Time delays
- Out-of-band exfiltration

## Cross-Site Scripting (XSS)

### XSS Anatomy
- Reflected XSS
- Stored XSS
- DOM-based XSS

### Reflected XSS
- Input reflection
- Parameter manipulation
- Header injection

### Stored XSS
- Persistent storage
- Database injection
- File upload exploitation

### DOM-Based XSS
- Client-side execution
- Source and sink analysis
- DOM manipulation

### Identifying & Exploiting XSS with XSSer
```bash
xsser -u <url> -p <parameter>
xsser --auto -u <url>
```

## SQL Injection (SQLi)

### DB & SQL Introduction
- Database fundamentals
- SQL syntax
- Common database systems
- SQL queries

### SQL Injection (SQLi)
- Understanding SQLi
- Injection points
- Error messages
- Data extraction

### In-Band SQLi
- Union-based
- Error-based
- Direct data retrieval

### Blind SQLi
- Boolean-based
- Time-based
- Inference techniques

### NoSQL
- MongoDB injection
- CouchDB injection
- Query manipulation
- Operator injection

### SQLMap
```bash
# Basic usage
sqlmap -u <url> -p <parameter>

# Options
sqlmap -u <url> --dbs
sqlmap -u <url> -D <database> --tables
sqlmap -u <url> -D <database> -T <table> --dump
sqlmap -r <request_file>
sqlmap -u <url> --batch --level 5 --risk 3
```

### Mitigation Strategies
- Prepared statements
- Parameterized queries
- Input validation
- Least privilege
- WAF rules

## Tools
- **SQLMap** - Automated SQL injection
- **NoSQLMap** - NoSQL injection tool
- **XSSer** - XSS exploitation
- **Burp Suite** - Manual testing
- **Commix** - Command injection tool

## Last Updated
December 2023

