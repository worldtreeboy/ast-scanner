# 🛡️ WORLDTREEBOY Vulnerability Scanner

```
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝ 
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝  
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║   
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝   
                              Source Code Security Scanner v3.1
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Kali-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A **cross-platform static code analysis tool** for detecting security vulnerabilities in source code. Supports 15+ programming languages with .NET DLL decompilation, JAR/APK analysis, and comprehensive vulnerability pattern detection.

**Now with dual scanning modes:**
- **Regex-based scanning** (`vuln-scanner.py`) - Fast, comprehensive pattern matching
- **AST-based scanning** (`ast-scanner.py`) - Deep code analysis with taint tracking for reduced false positives

---

## ✨ Features

### 🔍 Multi-Language Support
| Language | Extensions |
|----------|------------|
| **JavaScript/TypeScript** | `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs` |
| **Python** | `.py` |
| **PHP** | `.php`, `.phtml` |
| **Java/Kotlin** | `.java`, `.kt`, `.scala` |
| **C#/.NET** | `.cs`, `.vb` |
| **Ruby** | `.rb`, `.erb` |
| **Go** | `.go` |
| **Shell** | `.sh`, `.bash` |

### 🎯 Vulnerability Categories

| Category | Severity | Description |
|----------|----------|-------------|
| **SQL Injection** | 🔴 CRITICAL | String concatenation, template literals, raw queries |
| **NoSQL Injection** | 🔴 CRITICAL | MongoDB, Redis, CouchDB injection patterns |
| **Code Injection** | 🔴 CRITICAL | `eval()`, `exec()`, command injection, RCE |
| **Insecure Deserialization** | 🔴 CRITICAL | pickle, yaml.load, ObjectInputStream, BinaryFormatter |
| **SSTI** | 🔴 CRITICAL | Jinja2, Twig, Freemarker, Thymeleaf, ERB |
| **SSRF** | 🟠 HIGH | Server-side request forgery patterns |
| **XPath Injection** | 🟠 HIGH | Dynamic XPath query construction |
| **Authentication Bypass** | 🟠 HIGH | Hardcoded credentials, weak JWT, insecure comparison |
| **Prototype Pollution** | 🟠 HIGH | `__proto__`, constructor.prototype manipulation |

### 🔬 Binary Analysis (Optional)
- **.NET DLL Decompilation** via ILSpy (Linux) or dnSpy (Windows)
- **JAR/WAR/APK** archive extraction and analysis
- **String extraction** from compiled binaries
- **Credential detection** in binaries (AWS keys, API tokens, connection strings)

### 🧠 AST-Based Scanner (ast-scanner.py)
A secondary scanner providing deeper code analysis through:
- **Taint Tracking** - Traces user input through variable assignments
- **Data Flow Analysis** - Follows data from sources to dangerous sinks
- **Context-Aware Detection** - Understands function calls, imports, and code structure
- **Confidence Scoring** - HIGH/MEDIUM/LOW confidence ratings for each finding
- **Reduced False Positives** - Semantic analysis filters out safe patterns

| Feature | vuln-scanner.py | ast-scanner.py |
|---------|-----------------|----------------|
| Speed | Fast | Moderate |
| Languages | 15+ | Python, JavaScript/TypeScript |
| Analysis Depth | Pattern matching | AST + Taint tracking |
| False Positive Rate | Higher | Lower |
| Use Case | Broad scanning | Deep analysis |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/worldtreeboy/vuln-scanner.git
cd vuln-scanner

# No dependencies required for basic usage!
# Python 3.8+ is all you need
```

### Basic Usage

```bash
# Scan a single file
python3 vuln-scanner.py target.py

# Scan a directory
python3 vuln-scanner.py /path/to/project

# Scan with verbose output
python3 vuln-scanner.py /path/to/project -v

# Output as JSON
python3 vuln-scanner.py /path/to/project --output json -o report.json
```

### Category-Specific Scans

```bash
# Scan only for SQL injection
python3 vuln-scanner.py /path/to/project --category sql

# Scan for multiple categories
python3 vuln-scanner.py /path/to/project --category sql code auth ssrf

# Scan all categories (default)
python3 vuln-scanner.py /path/to/project --category all
```

### AST-Based Scanner Usage

```bash
# Basic scan with AST analysis
python3 ast-scanner.py /path/to/project

# Verbose output showing taint tracking
python3 ast-scanner.py /path/to/project -v

# Scan specific categories with confidence filtering
python3 ast-scanner.py /path/to/project --category sql code ssrf --min-confidence HIGH

# Output as JSON
python3 ast-scanner.py /path/to/project --output json -o ast-report.json

# Combined workflow: Use both scanners
python3 vuln-scanner.py /path/to/project -o regex-report.json --output json
python3 ast-scanner.py /path/to/project -o ast-report.json --output json
```

### Binary Analysis

```bash
# Enable binary scanning (DLL, EXE, JAR, APK)
python3 vuln-scanner.py /path/to/project --scan-binaries

# Enable .NET decompilation (requires ilspycmd)
python3 vuln-scanner.py /path/to/app.dll --scan-binaries --decompile
```

---

## 📋 Command Line Options

### vuln-scanner.py (Regex-based)

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | | Output format: `text` (default) or `json` |
| `--output-file` | `-o` | Save report to file |
| `--verbose` | `-v` | Show detailed scanning progress |
| `--category` | `-c` | Categories to scan (sql, nosql, code, auth, ssti, ssrf, etc.) |
| `--scan-binaries` | `-b` | Enable DLL/EXE/JAR binary analysis |
| `--decompile` | `-d` | Decompile .NET binaries using ILSpy |
| `--exclude-dir` | | Additional directories to exclude |
| `--exclude-file` | | Additional files to exclude |
| `--exclude-ext` | | File extensions to exclude |
| `--include-ext` | | Only scan these extensions |
| `--no-default-excludes` | | Don't use default exclusion lists |

### ast-scanner.py (AST-based)

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | | Output format: `text` (default) or `json` |
| `--output-file` | `-o` | Save report to file |
| `--verbose` | `-v` | Show detailed scanning progress with taint tracking |
| `--category` | `-c` | Categories: sql, nosql, code, command, deser, ssti, ssrf, auth, proto, xpath, xxe, path |
| `--min-confidence` | | Minimum confidence level: HIGH, MEDIUM, LOW (default) |

---

## 📊 Sample Output

```
================================================================================
VULNERABILITY SCAN REPORT
================================================================================
Platform: LINUX
Files scanned: 142 | Binaries: 3
Total findings: 28

  CRITICAL  : 8
  HIGH      : 12
  MEDIUM    : 6
  LOW       : 2

================================================================================

FILE: app/controllers/user_controller.py
--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - String Concatenation
  Line 45: query = "SELECT * FROM users WHERE id = " + user_id

[CRITICAL] Code Injection - Python eval
  Line 89: result = eval(user_input)

FILE: api/handlers/auth.js
--------------------------------------------------------------------------------
[HIGH] Auth Bypass - Hardcoded Credentials
  Line 12: const API_KEY = "sk_live_abc123xyz789"
```

### AST Scanner Sample Output

```
================================================================================
AST-BASED VULNERABILITY SCAN REPORT
================================================================================
Scan Date: 2026-01-23 14:30:00
Files Scanned: 45
Parse Errors: 0
Total Findings: 12

Summary by Severity:
  CRITICAL  : 3
  HIGH      : 5
  MEDIUM    : 4

Summary by Confidence:
  HIGH      : 6
  MEDIUM    : 4
  LOW       : 2

================================================================================

FILE: app/services/database.py
--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - execute() with tainted query (Confidence: HIGH)
  Line 23: cursor.execute(query)
  -> User-controlled data used in SQL query without parameterization.
  Taint: request: request.args.get('id') (line 21)

[HIGH] SSRF - requests.get() with user-controlled URL (Confidence: HIGH)
  Line 45: response = requests.get(target_url)
  -> User-controlled URL can lead to Server-Side Request Forgery.
  Taint: request: request.form['url'] (line 43)

FILE: app/utils/template.py
--------------------------------------------------------------------------------
[CRITICAL] SSTI - render_template_string() with user input (Confidence: HIGH)
  Line 18: return render_template_string(user_template)
  -> Flask render_template_string() with user input enables SSTI.
  Taint: request: request.args.get('template') (line 15)
```

---

## 🔧 .NET Decompilation Setup

### Linux/Kali

```bash
# Install .NET SDK
wget https://dot.net/v1/dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 8.0

# Install ILSpy CLI
dotnet tool install -g ilspycmd

# Add to PATH
export PATH="$PATH:$HOME/.dotnet/tools"
```

### Windows

1. Download [dnSpy](https://github.com/dnSpy/dnSpy/releases) or install ilspycmd
2. Add to system PATH
3. Run scanner with `--decompile` flag

---

## 🛠️ Default Exclusions

The scanner automatically excludes common non-source directories and files to reduce noise:

**Directories:** `node_modules`, `.git`, `__pycache__`, `venv`, `vendor`, `dist`, `build`, `test`, `tests`, `docs`

**Files:** `package-lock.json`, `yarn.lock`, `*.min.js`, `jquery*.js`, `bootstrap*.js`, `react*.js`

Use `--no-default-excludes` to scan everything.

---

## 🎯 Detection Examples

### SQL Injection

```python
# String concatenation
query = "SELECT * FROM users WHERE id = " + user_id  # ✅ Detected

# F-strings
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # ✅ Detected

# Format strings  
query = "SELECT * FROM users WHERE id = %s" % user_id  # ✅ Detected
```

### Code Injection

```python
# Direct eval
eval(user_input)  # ✅ Detected

# Command injection
os.system("ping " + host)  # ✅ Detected
subprocess.call(cmd, shell=True)  # ✅ Detected
```

### Deserialization

```python
# Python pickle
pickle.loads(user_data)  # ✅ Detected

# YAML unsafe load
yaml.load(data)  # ✅ Detected (missing SafeLoader)

# PHP unserialize
unserialize($_GET['data'])  # ✅ Detected
```

---

## 📁 Project Structure

```
vuln-scanner/
├── vuln-scanner.py      # Regex-based scanner (fast, comprehensive)
├── ast-scanner.py       # AST-based scanner (deep analysis, lower FP)
├── README.md
└── LICENSE
```

### When to Use Each Scanner

| Scenario | Recommended Scanner |
|----------|---------------------|
| Initial broad scan of large codebase | vuln-scanner.py |
| Deep analysis of critical files | ast-scanner.py |
| CI/CD pipeline quick check | vuln-scanner.py |
| Reviewing specific vulnerability reports | ast-scanner.py (with --min-confidence HIGH) |
| Scanning non-Python/JS languages | vuln-scanner.py |
| Taint tracking analysis | ast-scanner.py |

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add new vulnerability patterns** - Submit PRs with new regex patterns
2. **Improve false positive handling** - Help reduce noise
3. **Add language support** - Extend to new languages
4. **Report bugs** - Open issues for any problems found

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. 

- Always obtain proper authorization before scanning code
- False positives are possible - verify findings manually
- This is a static analysis tool - it cannot detect all vulnerabilities
- Use as part of a comprehensive security program, not as the only measure

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👤 Author

**worldtreeboy**

- GitHub: [@worldtreeboy](https://github.com/worldtreeboy)

---

## 🌟 Star History

If this tool helps you, please consider giving it a ⭐!

---

<p align="center">
  <b>Happy Hunting! 🎯</b>
</p>
