# 🔍 Vulnerability Scanner

A cross-platform static analysis tool for detecting security vulnerabilities in web applications and binaries. Supports multiple languages including C#, Python, JavaScript, PHP, Java, Ruby, and Go.

> **Built with [Claude](https://claude.ai)** - Anthropic's AI assistant

## Features

- **Multi-Language**: Supports C#, Python, JavaScript/TypeScript, PHP, Java, Ruby, Go, Kotlin, Scala
- **Cross-Platform**: Works on Windows and Kali Linux
- **Binary Analysis**: Scan DLL/EXE/SO files using string extraction
- **.NET Decompilation**: Optional ILSpy/dnSpy integration for deeper analysis
- **Archive Support**: Scan JAR, WAR, APK, ZIP, NuGet packages
- **Multiple Output Formats**: Text, JSON

## Vulnerabilities Detected

### Insecure Deserialization

| Language | Dangerous Functions |
|----------|---------------------|
| **C#** | `BinaryFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, `LosFormatter`, `SoapFormatter`, `JavaScriptSerializer`, `XmlSerializer`, `XamlReader`, `JsonConvert.DeserializeObject` (with TypeNameHandling), `fastJSON`, `YamlDotNet`, `DataContractSerializer` |
| **Python** | `pickle.loads()`, `yaml.load()`, `shelve.open()`, `dill.loads()` |
| **PHP** | `unserialize()`, `phar://` |
| **Java** | `ObjectInputStream.readObject()`, `XMLDecoder`, `XStream`, `SnakeYAML` |
| **Ruby** | `Marshal.load()`, `YAML.load()` |
| **Node.js** | `node-serialize`, `serialize-javascript` |

### SQL Injection
| Language | Patterns Detected |
|----------|-------------------|
| **All** | String concatenation, template literals, format strings |
| **C#** | `SqlCommand`, `FromSqlRaw`, `ExecuteSqlRaw`, Dapper raw queries |
| **Python** | f-strings in queries, `.format()`, `%` formatting |
| **PHP** | `mysql_query()`, `mysqli_query()` with variables |
| **Java** | `executeQuery()` with concatenation |
| **Node.js** | `sequelize.query()`, `knex.raw()`, `prisma.$queryRaw` |

### Code Injection (eval)
| Language | Dangerous Functions |
|----------|---------------------|
| **JavaScript** | `eval()`, `new Function()`, `setTimeout/setInterval` with strings |
| **Python** | `eval()`, `exec()`, `compile()` |
| **PHP** | `eval()`, `assert()`, `create_function()`, `preg_replace` with /e |
| **C#** | `CSharpCodeProvider`, dynamic compilation |

### Other Vulnerabilities
- **NoSQL Injection** - MongoDB `$where`, operator injection, Redis
- **XPath Injection** - Dynamic XPath queries in all languages
- **Prototype Pollution** - `__proto__`, `constructor.prototype`, unsafe merge/extend (lodash, jQuery, hoek, deepmerge)
- **SSTI** - Jinja2, Django, Twig, Smarty, Pug, EJS, Handlebars, Razor, Freemarker, Thymeleaf, ERB
- **SSRF** - `requests`, `urllib`, `file_get_contents`, `curl`, `HttpClient`, `axios`, `fetch`
- **Authentication Bypass** - Hardcoded credentials, JWT none algorithm, weak comparisons

## Installation

```bash
# Clone the repository
git clone https://github.com/worldtreeboy/vuln-scanner.git
cd vuln-scanner

# No dependencies required - uses Python standard library only
python vuln_scanner.py --help
```

### Optional: ILSpy for DLL Decompilation (Kali/Linux)

```bash
# Install .NET SDK
sudo apt install dotnet-sdk-8.0

# Install ILSpy CLI
dotnet tool install -g ilspycmd
export PATH="$PATH:$HOME/.dotnet/tools"
```

## Usage

### Basic Scan
```bash
# Scan a directory
python vuln_scanner.py /path/to/project

# Scan a single file
python vuln_scanner.py app.cs
```

### Binary/DLL Analysis
```bash
# Scan DLL/EXE files
python vuln_scanner.py MyApp.dll --scan-binaries

# Scan with decompilation (requires ilspycmd)
python vuln_scanner.py MyApp.dll --scan-binaries --decompile

# Scan entire bin folder
python vuln_scanner.py ./bin --scan-binaries
```

### Filter by Category
```bash
# Scan only for deserialization and SQL injection
python vuln_scanner.py /path/to/project -c deserialization sql

# Available categories:
# sql, postgresql, nosql, xpath, deserialization, auth, ssti, ssrf, code, eval, prototype, all
```

### Output Options
```bash
# JSON output
python vuln_scanner.py /path/to/project --output json -o report.json

# Verbose mode
python vuln_scanner.py /path/to/project -v
```

### Exclusions
```bash
# Exclude directories
python vuln_scanner.py /path/to/project --exclude-dir tests migrations

# Exclude files
python vuln_scanner.py /path/to/project --exclude-file config.py

# Exclude extensions
python vuln_scanner.py /path/to/project --exclude-ext .min.js .map
```

## Example Output

```
================================================================================
VULNERABILITY SCAN REPORT
================================================================================
Platform: WINDOWS
Files scanned: 1 | Binaries: 1
Total findings: 4

  HIGH      : 4
================================================================================

FILE: TeeTrove.dll
--------------------------------------------------------------------------------
[HIGH] Binary: Deserialization Indicators
  Line 237: set_TypeNameHandling

[HIGH] Binary: Deserialization Indicators
  Line 363: BinaryFormatter

[HIGH] Binary: Deserialization Indicators
  Line 369: XmlSerializer

[HIGH] Binary: Deserialization Indicators
  Line 430: DeserializeObject
```

## Supported Languages

| Language | Extensions |
|----------|------------|
| C# | `.cs` |
| JavaScript/TypeScript | `.js`, `.ts`, `.jsx`, `.tsx` |
| Python | `.py` |
| PHP | `.php` |
| Java/Kotlin | `.java`, `.kt`, `.scala` |
| Ruby | `.rb` |
| Go | `.go` |

## Use Cases

- **Penetration Testing**: Quickly identify deserialization vulnerabilities in .NET apps
- **Code Review**: Static analysis during security assessments
- **CTF/HTB**: Fast reconnaissance on challenge binaries
- **CI/CD Integration**: Automated security scanning in pipelines

## Limitations

- Static analysis only (no runtime detection)
- Pattern-based matching may produce false positives
- Binary analysis relies on string extraction (obfuscated code may evade detection)
- Decompilation requires external tools (ILSpy/dnSpy)

## Contributing

Pull requests welcome! Please open an issue first to discuss proposed changes.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with assistance from [Claude](https://claude.ai) by Anthropic
- Inspired by tools like Semgrep, ysoserial.net, and dnSpy

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always obtain proper permission before scanning systems you don't own.
