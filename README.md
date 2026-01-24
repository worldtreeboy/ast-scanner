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
  <strong>Advanced Static Code Security Analysis</strong><br>
  <sub>Taint tracking | AST analysis | Multi-language support</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-0078D4?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="License">
</p>

---

## Overview

A cross-platform static analysis toolkit for detecting security vulnerabilities in source code. Features two complementary scanning engines optimized for different use cases.

<table>
<tr>
<td width="50%">

### AST Scanner
**Deep analysis with taint tracking**

- Traces user input through code paths
- Context-aware detection
- Confidence scoring (HIGH/MEDIUM/LOW)
- Constant folding & obfuscation detection
- Virtual sink & factory pattern tracking
- JNI native method detection (Java)
- Python AST + multi-language regex

</td>
<td width="50%">

### Regex Scanner
**Fast pattern-based detection**

- High-speed scanning
- Binary & DLL analysis
- .NET decompilation (ILSpy)
- Broad pattern coverage

</td>
</tr>
</table>

---

## AST Scanner - Deep Analysis Engine

The AST scanner (`ast-scanner.py`) provides advanced vulnerability detection through **taint tracking** - following user-controlled data from sources to dangerous sinks.

### How Taint Tracking Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   TAINT SOURCE  │────▶│   PROPAGATION   │────▶│  DANGEROUS SINK │
│                 │     │                 │     │                 │
│ • request.args  │     │ • Assignment    │     │ • cursor.execute│
│ • request.form  │     │ • Concatenation │     │ • os.system()   │
│ • input()       │     │ • String format │     │ • eval()        │
│ • os.environ    │     │ • Function args │     │ • pickle.loads  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Taint Sources Tracked

| Framework | Sources |
|-----------|---------|
| **Flask** | `request.args`, `request.form`, `request.json`, `request.data`, `request.cookies` |
| **Django** | `request.GET`, `request.POST`, `request.body`, `request.META`, `request.FILES` |
| **FastAPI** | `Query()`, `Body()`, `Form()`, `File()`, `Header()`, `Cookie()`, `Path()` |
| **General** | `input()`, `sys.argv`, `os.environ`, `os.getenv()` |

### Dangerous Sinks Detected

```python
# SQL Injection Sinks
cursor.execute(query)          # Direct execution
connection.execute(sql)        # Connection methods
session.execute(raw_sql)       # ORM raw queries

# Command Injection Sinks
os.system(cmd)                 # Shell execution
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd)

# Code Injection Sinks
eval(user_input)               # Dynamic evaluation
exec(code_string)              # Code execution
compile(source, ...)           # Dynamic compilation

# Deserialization Sinks
pickle.loads(data)             # Pickle
yaml.load(data)                # YAML (unsafe)
marshal.loads(data)            # Marshal
```

### Confidence Levels

| Level | Description | Example |
|:-----:|-------------|---------|
| **HIGH** | Direct taint flow to sink | `cursor.execute(request.args.get('q'))` |
| **MEDIUM** | Indirect flow through variables | Variable assigned from request, used in query |
| **LOW** | Potential vulnerability pattern | Suspicious pattern without clear taint |

---

## Quick Start

### Basic Scanning

```bash
# AST-based scan with taint tracking (recommended for code review)
python3 ast-scanner.py /path/to/project

# Regex-based scan (fast, includes binary support)
python3 vuln-scanner.py /path/to/project

# Scan single file
python3 ast-scanner.py vulnerable_app.py
```

### Filter by Category

```bash
# Focus on injection vulnerabilities
python3 ast-scanner.py project/ --category sql code command

# Check for deserialization issues
python3 ast-scanner.py project/ --category deser
```

### Filter by Confidence

```bash
# Only high-confidence findings (fewer false positives)
python3 ast-scanner.py project/ --min-confidence HIGH

# Include medium confidence
python3 ast-scanner.py project/ --min-confidence MEDIUM
```

### Output Formats

```bash
# JSON output for integration
python3 ast-scanner.py project/ --output json -o report.json

# Verbose mode for debugging
python3 ast-scanner.py project/ -v
```

---

## Vulnerability Categories

| Category | Severity | AST Scanner | Regex Scanner |
|----------|:--------:|:-----------:|:-------------:|
| SQL Injection | CRITICAL | Full taint tracking | Pattern matching |
| Command Injection | CRITICAL | Shell detection + taint | Pattern matching |
| Code Injection | CRITICAL | eval/exec taint flow | Pattern matching |
| Deserialization | CRITICAL | pickle/yaml/marshal | Pattern matching |
| SSTI | CRITICAL | Template injection | Pattern matching |
| XXE | CRITICAL | XML parser analysis | Pattern matching |
| NoSQL Injection | HIGH | MongoDB/Redis taint | Pattern matching |
| SSRF | HIGH | HTTP client taint | Pattern matching |
| Path Traversal | HIGH | File operation taint | Pattern matching |
| Prototype Pollution | HIGH | JS-specific analysis | Pattern matching |
| XPath Injection | HIGH | XPath taint flow | Pattern matching |
| Auth Bypass | HIGH | Credential patterns | Pattern matching |

---

## Language Support

<table>
<tr>
<th>Language</th>
<th>Extensions</th>
<th>AST Analysis</th>
<th>Taint Tracking</th>
</tr>
<tr>
<td><strong>Python</strong></td>
<td><code>.py</code></td>
<td>Full AST parsing</td>
<td>Complete</td>
</tr>
<tr>
<td><strong>JavaScript/TypeScript</strong></td>
<td><code>.js</code>, <code>.ts</code>, <code>.jsx</code>, <code>.tsx</code></td>
<td>Regex-enhanced</td>
<td>Variable tracking</td>
</tr>
<tr>
<td><strong>Java/Kotlin/Scala</strong></td>
<td><code>.java</code>, <code>.kt</code>, <code>.scala</code></td>
<td>Regex-enhanced</td>
<td>Variable tracking</td>
</tr>
<tr>
<td><strong>PHP</strong></td>
<td><code>.php</code>, <code>.phtml</code></td>
<td>Regex-enhanced</td>
<td>Variable tracking</td>
</tr>
<tr>
<td><strong>C#</strong></td>
<td><code>.cs</code></td>
<td>Regex-enhanced</td>
<td>Full taint + ProcessStartInfo block analysis</td>
</tr>
<tr>
<td><strong>Go</strong></td>
<td><code>.go</code></td>
<td>Regex-enhanced</td>
<td>Variable tracking</td>
</tr>
<tr>
<td><strong>Ruby</strong></td>
<td><code>.rb</code>, <code>.erb</code></td>
<td>Regex-enhanced</td>
<td>Variable tracking</td>
</tr>
</table>

---

## Sample Output

### AST Scanner (Taint Tracking)

```
================================================================================
                     AST-Based Vulnerability Scanner v2.0
                    Taint Tracking & Data Flow Analysis
================================================================================

Scanning: /home/user/webapp
Engine: Python AST with taint propagation

--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - execute() with tainted query
  File: app/routes.py
  Line 47, Column 4
  Code: cursor.execute(query)
  Confidence: HIGH

  Taint Chain:
    └─▶ user_id = request.args.get('id')  [line 43]
    └─▶ query = "SELECT * FROM users WHERE id = " + user_id  [line 45]
    └─▶ cursor.execute(query)  [line 47]

  Description: User-controlled data flows directly into SQL query execution.
--------------------------------------------------------------------------------

[CRITICAL] Command Injection - subprocess with shell=True
  File: app/utils.py
  Line 89, Column 8
  Code: subprocess.call(cmd, shell=True)
  Confidence: HIGH

  Taint Chain:
    └─▶ filename = request.form['file']  [line 85]
    └─▶ cmd = "convert " + filename  [line 87]
    └─▶ subprocess.call(cmd, shell=True)  [line 89]

  Description: User-controlled input passed to shell command execution.
--------------------------------------------------------------------------------

================================================================================
                              SCAN SUMMARY
================================================================================
Files scanned:     156
Findings:          12
  CRITICAL:        4
  HIGH:            5
  MEDIUM:          3

By Category:
  SQL Injection:        3
  Command Injection:    2
  Code Injection:       2
  Deserialization:      2
  SSRF:                 3
================================================================================
```

### Regex Scanner

```
================================================================================
              Cross-Platform Vulnerability Scanner v3.1
================================================================================

[CRITICAL] SQL Injection - String Concatenation
  app/models.py:45
  query = "SELECT * FROM users WHERE id = " + user_id

[CRITICAL] Code Injection - Python eval
  app/utils.py:89
  result = eval(user_input)

[HIGH] Insecure Deserialization - pickle.loads
  app/cache.py:34
  data = pickle.loads(cached_data)

================================================================================
Summary: 3 findings in 45 files scanned
================================================================================
```

---

## Evasion Detection

The AST scanner detects common obfuscation techniques through advanced analysis:

### Constant Folding & Obfuscation Resolution

```python
# Detected: Hex-encoded function names are resolved at analysis time
func_name = bytes.fromhex('73797374656d').decode()  # Resolves to 'system'
sink = getattr(os, func_name)
sink(user_input)

# Detected: Base64-encoded payloads tracked through decode chains
encoded = base64.b64decode(user_data).decode('utf-8')
os.system(encoded)
```

### Virtual Sink & Factory Pattern Detection

```python
# Detected: Factory functions that return dangerous sinks
def bridge_factory(module_name, func_hex):
    mod = __import__(module_name)
    func_name = bytes.fromhex(func_hex).decode()
    return getattr(mod, func_name)  # Returns os.system

# Detected: Virtual sink called with tainted data
sink_ptr = bridge_factory('os', '73797374656d')
sink_ptr(user_input)  # Flagged as command injection

# Detected: Closure-based execution patterns
def handler(data):
    sink_ptr(data)  # Taint flows through closures
```

### Dynamic Execution Patterns

```python
# Detected: Dynamic import obfuscation
module = __import__(user_controlled_name)

# Detected: getattr-based evasion
func = getattr(os, method_name)
func(user_input)

# Detected: Encoded payload execution
decoded = base64.b64decode(encoded_payload)
exec(decoded)
```

### Shell Injection Patterns

```python
# Detected: Shell with environment taint
cmd = os.environ.get('USER_CMD')
os.system(cmd)

# Detected: Subprocess with shell flag
subprocess.Popen(user_input, shell=True)

# Detected: Command array injection
subprocess.call(['/bin/sh', '-c', user_cmd])
```

### JavaScript Evasion

```javascript
// Detected: Function constructor
const fn = [].constructor.constructor('return ' + code);

// Detected: Dynamic require
const mod = require('child_' + 'process');

// Detected: Indirect eval
const indirect = (0, eval);
indirect(user_input);
```

### Java JNI Native Method Detection

```java
// Detected: Taint escaping to native code via JNI
public class NativeWrapper {
    // Native method declaration - sink escapes to C/C++
    public native void executeInternal(String cmd);

    static {
        System.loadLibrary("native_lib");
    }

    public void processRequest(String userInput) {
        // Flagged: Tainted data flows to native method
        executeInternal(userInput);
    }
}
```

### C# OS Command Injection Detection

The scanner detects common "helper wrapper" patterns where developers create utility methods for system tools without proper input escaping:

```csharp
// Detected: ProcessStartInfo object initializer with tainted arguments
public class NetworkTools {
    public void PingHost(string address) {
        // VULNERABLE: User input concatenated into shell arguments
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "cmd.exe",
            Arguments = "/c ping " + address,  // Attack: "8.8.8.8 && rm -rf /"
            UseShellExecute = false
        };
        Process.Start(psi);
    }
}

// Detected: Interpolated strings in Arguments
public void NslookupHost(string domain) {
    var psi = new ProcessStartInfo {
        FileName = "cmd.exe",
        Arguments = $"/c nslookup {domain}",  // Flagged
        UseShellExecute = false
    };
    Process.Start(psi);
}

// Detected: ASP.NET request input flowing to Process.Start
public void HandleRequest(HttpRequest request) {
    string host = request.QueryString["host"];  // Taint source
    ProcessStartInfo psi = new ProcessStartInfo {
        FileName = "cmd.exe",
        Arguments = "/c ping " + host,  // Flagged as CRITICAL
        UseShellExecute = false
    };
    Process.Start(psi);
}
```

**Detected Patterns:**
- `ProcessStartInfo` object initializer blocks with shell commands
- `Arguments` property with string concatenation (`+`), interpolation (`$""`), or `String.Format`
- 30+ system tools: `ping`, `ipconfig`, `git`, `nslookup`, `tracert`, `curl`, `wget`, `ssh`, `nmap`, etc.
- Shell wrappers: `cmd.exe`, `powershell.exe`, `/bin/sh`, `/bin/bash`
- Direct `Process.Start()` calls with tainted arguments
- Reflection-based process invocation (evasion detection)

---

## CLI Reference

### AST Scanner

```
usage: ast-scanner.py [-h] [-v] [-c CATEGORY] [--output {text,json}]
                      [-o OUTPUT_FILE] [--min-confidence {HIGH,MEDIUM,LOW}]
                      target

Options:
  target                    File or directory to scan
  -v, --verbose             Enable detailed output
  -c, --category CATEGORY   Filter by category (sql, code, command, etc.)
  --output {text,json}      Output format
  -o, --output-file FILE    Save report to file
  --min-confidence LEVEL    Minimum confidence (HIGH, MEDIUM, LOW)
```

### Regex Scanner

```
usage: vuln-scanner.py [-h] [-v] [-c CATEGORY] [--output {text,json}]
                       [-o OUTPUT_FILE] [--scan-binaries] [--decompile]
                       target

Options:
  target                    File or directory to scan
  -v, --verbose             Enable detailed output
  -c, --category CATEGORY   Filter by category
  --output {text,json}      Output format
  -o, --output-file FILE    Save report to file
  --scan-binaries, -b       Enable binary/DLL analysis
  --decompile, -d           Decompile .NET with ILSpy/dnSpy
```

### Categories

| Flag | Description |
|------|-------------|
| `sql` | SQL Injection |
| `nosql` | NoSQL Injection |
| `code` | Code Injection (eval, exec) |
| `command` | Command Injection (system, subprocess) |
| `deser` | Insecure Deserialization |
| `ssti` | Server-Side Template Injection |
| `ssrf` | Server-Side Request Forgery |
| `auth` | Authentication Bypass |
| `proto` | Prototype Pollution |
| `xpath` | XPath Injection |
| `xxe` | XML External Entity |
| `path` | Path Traversal |
| `all` | All categories (default) |

---

## Scanner Comparison

| Feature | AST Scanner | Regex Scanner |
|---------|:-----------:|:-------------:|
| **Speed** | Moderate | Fast |
| **Accuracy** | Higher | Lower |
| **Taint Tracking** | Yes | No |
| **Confidence Scores** | Yes | No |
| **Binary/DLL Analysis** | No | Yes |
| **.NET Decompile** | No | Yes |
| **Python Analysis** | Full AST | Regex |
| **Best For** | Code review | CI/CD, quick scans |

**Recommendation:**
- Use `ast-scanner.py` for thorough security audits and code review
- Use `vuln-scanner.py` for quick scans, CI pipelines, and binary analysis

---

## Project Structure

```
vuln-scanner/
├── ast-scanner.py      # AST-based scanner with taint tracking
├── vuln-scanner.py     # Regex-based pattern scanner
├── README.md           # Documentation
└── LICENSE             # MIT License
```

---

## Integration Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run AST Scanner
        run: |
          python3 ast-scanner.py . --min-confidence HIGH --output json -o results.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: results.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

python3 ast-scanner.py . --min-confidence HIGH --category sql code command
if [ $? -ne 0 ]; then
    echo "Security vulnerabilities found. Commit blocked."
    exit 1
fi
```

---

## Disclaimer

This tool is for **authorized security testing only**.

- Obtain proper authorization before scanning third-party code
- Verify findings manually - automated tools can produce false positives
- Use as part of a comprehensive security program, not as a sole measure
- The authors are not responsible for misuse of this tool

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>worldtreeboy</strong><br>
  <a href="https://github.com/worldtreeboy">github.com/worldtreeboy</a>
</p>

<p align="center">
  <sub>Built for security researchers, by security researchers.</sub>
</p>
