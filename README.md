# WORLDTREEBOY Vulnerability Scanner

```
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝
```

<p align="center">
  <strong>Static Code Security Scanner</strong><br>
  <sub>Fast vulnerability detection with taint tracking</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

---

## Overview

A cross-platform static analysis tool for detecting security vulnerabilities in source code.

| Scanner | Description |
|---------|-------------|
| `vuln-scanner.py` | Regex-based, fast pattern matching |
| `ast-scanner.py` | AST-based with taint tracking, lower false positives |

**Primary Languages:** Python, JavaScript/TypeScript, Java, PHP, C#

> Other languages have minimal support and detection is not comprehensive.

---

## Quick Start

```bash
# Scan a file or directory
python3 vuln-scanner.py target.py
python3 vuln-scanner.py /path/to/project

# AST-based scan with taint tracking
python3 ast-scanner.py /path/to/project

# Output as JSON
python3 vuln-scanner.py /path/to/project --output json -o report.json
```

---

## Vulnerability Coverage

| Category | Severity | Examples |
|----------|:--------:|----------|
| SQL Injection | CRITICAL | String concat, f-strings, Arel.sql(), raw queries |
| Code Injection | CRITICAL | eval(), exec(), Runtime.exec(), vm module |
| Command Injection | CRITICAL | os.system(), subprocess, shell=True |
| Deserialization | CRITICAL | pickle, yaml.load, unserialize, Marshal |
| SSTI | CRITICAL | Jinja2, Twig, Freemarker, ERB |
| XXE | CRITICAL | XML parser misconfigurations |
| NoSQL Injection | HIGH | MongoDB, Redis, operator injection |
| SSRF | HIGH | Server-side request forgery |
| Path Traversal | HIGH | User-controlled file paths |
| Prototype Pollution | HIGH | __proto__, unsafe merge functions |
| Auth Bypass | HIGH | Hardcoded creds, weak JWT handling |

---

## Scanner Comparison

| Feature | vuln-scanner | ast-scanner |
|---------|:------------:|:-----------:|
| Speed | Fast | Moderate |
| Taint Tracking | No | Yes |
| False Positive Rate | Higher | Lower |
| Binary Analysis | Yes | No |
| Evasion Detection | Basic | Advanced |

**Use `vuln-scanner.py`** for quick scans, CI/CD, binary analysis

**Use `ast-scanner.py`** for deep analysis, taint chains, verification

---

## Sample Output

**Regex Scanner:**
```
[CRITICAL] SQL Injection - String Concatenation
  Line 45: query = "SELECT * FROM users WHERE id = " + user_id

[CRITICAL] Code Injection - Python eval
  Line 89: result = eval(user_input)
```

**AST Scanner:**
```
[CRITICAL] SQL Injection - execute() with tainted query (Confidence: HIGH)
  Line 23: cursor.execute(query)
  -> User-controlled data in SQL query.
  Taint: request.args.get('id') (line 21)
```

---

## Options

```bash
# Category filter
python3 vuln-scanner.py project/ --category sql code ssrf

# Confidence filter (ast-scanner)
python3 ast-scanner.py project/ --min-confidence HIGH

# Binary analysis
python3 vuln-scanner.py project/ --scan-binaries --decompile

# Verbose output
python3 vuln-scanner.py project/ -v
```

**Categories:** `sql`, `nosql`, `code`, `command`, `deser`, `ssti`, `ssrf`, `auth`, `proto`, `xpath`, `xxe`, `path`

---

## Detection Examples

**SQL Injection**
```python
query = "SELECT * FROM users WHERE id = " + user_id      # Detected
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # Detected
```

**Command Injection**
```python
os.system("ping " + host)           # Detected
subprocess.call(cmd, shell=True)    # Detected
```

**Deserialization**
```python
pickle.loads(user_data)    # Detected
yaml.load(data)            # Detected (missing SafeLoader)
```

**Prototype Pollution (JS)**
```javascript
_.merge(target, req.body);              # Detected
obj[userKey] = userValue;               # Detected
```

---

## Evasion Detection

The AST scanner detects obfuscation techniques:

```python
# Base64/ROT13 obfuscation
codecs.decode(s, 'rot_13')              # Detected
base64.b64decode(encoded)               # Detected

# Dynamic imports
__import__(module_name)                 # Detected
getattr(subprocess, method)             # Detected
```

```javascript
// Function constructor
const fn = [].constructor.constructor('return ' + code);  # Detected

// Dynamic require
const mod = require('child_' + 'process');  # Detected
```

---

## Project Structure

```
vuln-scanner/
├── vuln-scanner.py    # Regex-based scanner
├── ast-scanner.py     # AST-based scanner
├── README.md
└── LICENSE
```

---

## Disclaimer

This tool is for **authorized security testing only**.

- Obtain proper authorization before scanning
- Verify findings manually - false positives are possible
- Use as part of a comprehensive security program

---

## License

MIT License

---

<p align="center">
  <strong>worldtreeboy</strong><br>
  <a href="https://github.com/worldtreeboy">github.com/worldtreeboy</a>
</p>
