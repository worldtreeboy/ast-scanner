<h1 align="center">
  <br>
  <pre>
 █████╗ ███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║███████╗   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
  </pre>
</h1>

<h3 align="center">🔥 Advanced Multi-Language SAST with 2nd-Order Injection Detection 🔥</h3>

<p align="center">
  <a href="#-2nd-order-detection">2nd-Order Detection</a> •
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-detection-patterns">Detection Patterns</a> •
  <a href="#-language-support">Languages</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/languages-8+-22c55e?style=for-the-badge" alt="8+ Languages">
  <img src="https://img.shields.io/badge/2nd--Order-Detection-ff6b6b?style=for-the-badge" alt="2nd-Order">
  <img src="https://img.shields.io/badge/version-2.1-blueviolet?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="C#">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white" alt="Ruby">
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
</p>

---

## 🎯 What Makes AST-Scanner Different?

Most SAST tools detect **1st-order injection** - where user input flows directly to a sink. **AST-Scanner** goes deeper, detecting **2nd-order injection** where payloads are:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  PHASE 1: STORE │     │  PHASE 2: FETCH │     │  PHASE 3: USE   │     │  PHASE 4: BOOM  │
│                 │     │                 │     │                 │     │                 │
│ Attacker stores │────▶│ App loads data  │────▶│ Data used in    │────▶│ Payload         │
│ payload in DB   │     │ from database   │     │ query/command   │     │ executes        │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

**The payload sleeps in the database, waiting to strike.**

---

## 🚀 2nd-Order Detection

### The "FINAL BOSS" Patterns Other Scanners Miss

<table>
<tr>
<td width="50%">

#### 🗄️ SQL/HQL Injection
```java
// Entity value → HQL query
User user = repo.findById(id).get();
String filter = user.getSavedFilter();

// 💀 DETECTED: 2nd-Order HQL Injection
String hql = "FROM Product WHERE " + filter;
em.createQuery(hql).getResultList();
```

</td>
<td width="50%">

#### 🌲 XPath Injection
```java
// Entity value → XPath query
User user = repo.findById(id).get();
String dept = user.getDepartment();

// 💀 DETECTED: 2nd-Order XPath Injection
String expr = "//dept[@name='" + dept + "']";
xpath.evaluate(expr, doc);
```

</td>
</tr>
<tr>
<td width="50%">

#### 🍃 MongoDB NoSQL Injection
```javascript
// DB value → $where operator
const user = await User.findById(id);
const filter = user.savedFilter;

// 💀 DETECTED: 2nd-Order NoSQL Injection
Items.find({ $where: filter });
```

</td>
<td width="50%">

#### 🐼 Pandas Code Injection
```python
# DB value → df.query() (executes code!)
row = cursor.fetchone()
expr = row['filter_expression']

# 💀 DETECTED: 2nd-Order Code Injection
df.query(expr)  # Pandas evaluates as code
```

</td>
</tr>
<tr>
<td width="50%">

#### 🔓 PHP Double-Unserialize
```php
// Serialized payload → unserialize → SQL
$row = $pdo->fetch();
$prefs = unserialize($row['prefs']);

// 💀 DETECTED: Double-Unserialize SQLi
$sql = "SELECT * FROM t WHERE id=" . $prefs->id;
```

</td>
<td width="50%">

#### ⚡ C# Entity Framework
```csharp
// Entity value → FromSqlRaw
var user = db.Users.Find(id);
var filter = user.CustomFilter;

// 💀 DETECTED: 2nd-Order SQLi
db.Products.FromSqlRaw(
    $"SELECT * FROM Products WHERE {filter}");
```

</td>
</tr>
</table>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔬 Core Engine
- **Taint Tracking** - Traces data flow source → sink
- **Entity-Source Detection** - Tracks ORM/Repository patterns
- **Cross-Function Analysis** - Follows data through methods
- **Evasion Detection** - Catches obfuscation tricks
- **Confidence Scoring** - HIGH/MEDIUM/LOW ratings

</td>
<td width="50%">

### 🎯 Detection Categories
- SQL/NoSQL/HQL Injection
- Command Injection
- Code Injection (eval/exec)
- XPath/XQuery Injection
- XXE & XSLT Attacks
- SSRF & SSTI
- Insecure Deserialization
- Path Traversal

</td>
</tr>
</table>

### 📊 Detection Quality Matrix

| Category | 1st-Order | 2nd-Order | Evasion Detection |
|----------|:---------:|:---------:|:-----------------:|
| SQL Injection | ✅ Excellent | ✅ Excellent | ✅ strrev, base64 |
| NoSQL Injection | ✅ Excellent | ✅ $where, $function | ✅ JSON poisoning |
| Command Injection | ✅ Excellent | ✅ DB-sourced | ✅ getattr, LINQ |
| Code Injection | ✅ Excellent | ✅ pandas, ScriptEngine | ✅ Proxy traps |
| XPath Injection | ✅ Excellent | ✅ Entity-sourced | ✅ StringBuilder |
| Deserialization | ✅ Excellent | ✅ Double-unserialize | ✅ ViewState |
| XXE/XSLT | ✅ Excellent | - | ✅ XmlResolver |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/worldtreeboy/ast-scanner.git
cd ast-scanner

# Scan a project (no dependencies required!)
python3 ast-scanner.py /path/to/project

# Scan single file
python3 ast-scanner.py vulnerable_app.java

# JSON output for CI/CD
python3 ast-scanner.py project/ --output json -o report.json

# High-confidence only
python3 ast-scanner.py project/ --min-confidence HIGH
```

---

## 🔍 Detection Patterns

### 2nd-Order Source Tracking

The scanner tracks data from these **entity sources**:

| Language | Tracked Patterns |
|----------|-----------------|
| **Java** | `repo.findById()`, `em.find()`, `entityManager.createQuery().getSingleResult()`, getter chains |
| **C#** | `db.Users.Find()`, `context.Set<T>().FirstOrDefault()`, EF Core navigation properties |
| **JavaScript** | `Model.findOne()`, `Model.findById()`, Mongoose/Sequelize results |
| **Python** | `session.query().first()`, `cursor.fetchone()`, `pd.read_sql()` |
| **PHP** | `fetch_assoc()`, `fetch_object()`, `PDO::fetch()`, `json_decode()`, `unserialize()` |
| **Ruby** | `Model.find()`, `Model.find_by()`, ActiveRecord results |

### Dangerous Sinks Detected

| Sink Type | Examples |
|-----------|----------|
| **SQL** | `executeQuery()`, `createNativeQuery()`, `FromSqlRaw()`, `cursor.execute()` |
| **HQL/JPQL** | `createQuery()`, Criteria API `root.get()`, `cb.asc()`/`cb.desc()` |
| **NoSQL** | `$where`, `$accumulator`, `$function`, `mapReduce` |
| **XPath** | `xpath.evaluate()`, `SelectNodes()`, `DOMXPath->query()` |
| **Command** | `Process.Start()`, `Runtime.exec()`, `os.system()`, `exec()` |
| **Code** | `eval()`, `ScriptEngine.eval()`, `df.query()`, `df.eval()` |

---

## 🛡️ Evasion Detection

AST-Scanner catches sophisticated evasion techniques:

<details>
<summary><b>🐍 Python: getattr Shadow Attack</b></summary>

```python
# DETECTED: Dynamic attribute access on dangerous module
func_name = user_data.get("action")  # "system"
method = getattr(os, func_name)       # os.system
method(user_data.get("arg"))          # RCE!
```
</details>

<details>
<summary><b>🐘 PHP: strrev() Evasion</b></summary>

```php
// DETECTED: strrev hides "system"
$func = strrev("metsys");  // "system"
$func($_GET['cmd']);       // Command injection
```
</details>

<details>
<summary><b>🔷 C#: LINQ Taint Tunnel</b></summary>

```csharp
// DETECTED: LINQ transforms taint to shell
var cmds = inputs.Select(x => $"/c {x}").ToList();
Process.Start("cmd.exe", cmds.First());
```
</details>

<details>
<summary><b>🟨 JavaScript: Proxy Trap</b></summary>

```javascript
// DETECTED: Proxy get trap with eval
const proxy = new Proxy({}, {
    get: (t, p) => eval(sessionStorage.getItem(p))
});
proxy.payload;  // Any property triggers eval
```
</details>

---

## 📋 Sample Output

```
================================================================================
                            AST-SCANNER REPORT
================================================================================
Scan Date: 2026-01-25
Files Scanned: 156
Total Findings: 12

Summary by Severity:
  CRITICAL  : 7
  HIGH      : 4
  MEDIUM    : 1
================================================================================

FILE: services/ReportService.java
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order SQLi - HQL string with entity value (FINAL BOSS)
  Line 45: String hql = "FROM Report WHERE " + user.getFilter();
  -> Entity value from Repository.find.getFilter() used in HQL construction.
     Enables DB function hijacking (dbms_pipe.receive_message, pg_sleep).

[CRITICAL] 2nd-Order XPath Injection - evaluate() with entity value
  Line 89: xpath.evaluate("//dept[@name='" + dept + "']", doc);
  -> Entity value from Repository.find.getDepartment() in XPath.evaluate().
     Payload can break out of XML tree logic or enumerate nodes.

FILE: controllers/DataController.py
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order Code Injection - pandas df.query() with DB-sourced value
  Line 34: result = df.query(filter_expr)
  -> DB value from SQLAlchemy query result passed to df.query().
     Pandas query() evaluates strings as expressions with @var syntax.

FILE: models/UserPrefs.php
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order SQLi - Unserialized object in SQL (Double-Unserialize)
  Line 67: $sql = "SELECT * FROM items WHERE cat = " . $prefs->category;
  -> Unserialized object from unserialize(PDO::fetch) used in SQL.
     Payload chain: DB -> unserialize -> property -> SQL sink.
================================================================================
```

---

## 🌐 Language Support

| Language | Extensions | Frameworks | 2nd-Order Detection |
|----------|------------|------------|:-------------------:|
| **Java** | `.java` | Spring, JPA/Hibernate, Criteria API | ✅ |
| **C#** | `.cs` | ASP.NET, Entity Framework, EF Core | ✅ |
| **JavaScript** | `.js`, `.jsx` | Express, Mongoose, Sequelize | ✅ |
| **TypeScript** | `.ts`, `.tsx` | Node.js, TypeORM | ✅ |
| **Python** | `.py` | Flask, Django, SQLAlchemy, Pandas | ✅ |
| **PHP** | `.php` | Laravel, PDO, mysqli | ✅ |
| **Go** | `.go` | GORM, database/sql | ✅ |
| **Ruby** | `.rb` | Rails, ActiveRecord | ✅ |

---

## 🔧 CLI Reference

```bash
usage: ast-scanner.py [-h] [-v] [-c CATEGORY] [--output {text,json}]
                      [-o FILE] [--min-confidence {HIGH,MEDIUM,LOW}]
                      [--scan-all] target

positional arguments:
  target                    File or directory to scan

options:
  -h, --help                Show help message
  -v, --verbose             Detailed output
  -c, --category CATEGORY   Filter: sql, nosql, xpath, code, command, deser, xxe, ssrf, ssti, xss, path
  --output {text,json}      Output format
  -o, --output-file FILE    Save to file
  --min-confidence LEVEL    HIGH, MEDIUM, or LOW
  --scan-all                Include vendor/minified files
```

---

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    python3 ast-scanner.py . --min-confidence HIGH --output json -o results.json
    if grep -q '"severity": "CRITICAL"' results.json; then
      echo "::error::Critical vulnerabilities found!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
python3 ast-scanner.py . --min-confidence HIGH --category sql command code xpath
[ $? -ne 0 ] && echo "Security issues found!" && exit 1
```

---

## 📁 Project Structure

```
ast-scanner/
├── ast-scanner.py          # Main scanner engine
├── README.md
├── LICENSE
└── test-files/
    ├── xpath-2nd-order.java       # XPath injection tests
    ├── hql-function-injection.java # HQL FINAL BOSS tests
    ├── pandas-2nd-order.py        # Pandas df.query() tests
    ├── php-double-unserialize.php # Double-unserialize tests
    ├── criteria-api-injection.java # Criteria API tests
    └── ...
```

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning. Verify findings manually. The authors are not responsible for misuse.

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Created by worldtreeboy</b><br>
  <sub>Hunting 2nd-order vulnerabilities that others miss.</sub>
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy">
    <img src="https://img.shields.io/badge/GitHub-worldtreeboy-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
</p>
