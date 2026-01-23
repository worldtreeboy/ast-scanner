#!/usr/bin/env python3
"""
AST-Based Vulnerability Scanner v1.0
=====================================
A secondary scanner using Abstract Syntax Tree analysis to reduce false positives
from regex-based scanning. Provides deeper code analysis through:
- Taint tracking (tracing user input through variables)
- Data flow analysis
- Function call context analysis
- Import and module analysis

Supports: Python, JavaScript/TypeScript (basic), and provides hooks for other languages.

Categories covered:
- SQL Injection
- NoSQL Injection
- Code Injection (eval, exec, command injection)
- Insecure Deserialization
- Server-Side Template Injection (SSTI)
- Server-Side Request Forgery (SSRF)
- Authentication Bypass
- Prototype Pollution
- XPath Injection
- XXE (XML External Entity)
"""

import os
import sys
import ast
import json
import argparse
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from enum import Enum
from datetime import datetime
from collections import defaultdict
import textwrap


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(Enum):
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    CODE_INJECTION = "Code Injection"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Insecure Deserialization"
    SSTI = "Server-Side Template Injection"
    SSRF = "Server-Side Request Forgery"
    AUTH_BYPASS = "Authentication Bypass"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    XPATH_INJECTION = "XPath Injection"
    XXE = "XML External Entity"
    PATH_TRAVERSAL = "Path Traversal"


@dataclass
class TaintSource:
    """Represents a source of tainted (user-controlled) data."""
    name: str
    line: int
    col: int
    source_type: str  # 'request', 'input', 'argv', 'env', 'file', etc.


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    file_path: str
    line_number: int
    col_offset: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity
    confidence: str  # 'HIGH', 'MEDIUM', 'LOW'
    taint_chain: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "column": self.col_offset,
            "code": self.line_content.strip(),
            "vulnerability": self.vulnerability_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "taint_chain": self.taint_chain,
            "description": self.description,
        }


# ============================================================================
# TAINT SOURCES - Variables/patterns that introduce user-controlled data
# ============================================================================

PYTHON_TAINT_SOURCES = {
    # Flask
    'request.args', 'request.form', 'request.json', 'request.data',
    'request.values', 'request.files', 'request.cookies', 'request.headers',
    'request.get_json', 'request.get_data',
    # Django
    'request.GET', 'request.POST', 'request.body', 'request.COOKIES',
    'request.META', 'request.FILES', 'request.data',
    # FastAPI
    'Query', 'Body', 'Form', 'File', 'Header', 'Cookie', 'Path',
    # General
    'input', 'sys.argv', 'os.environ', 'raw_input',
}

PYTHON_TAINT_FUNCTIONS = {
    'input': 'user_input',
    'raw_input': 'user_input',
}

# Dangerous sinks by category
PYTHON_SINKS = {
    VulnCategory.SQL_INJECTION: {
        'execute': ['cursor.execute', 'connection.execute', 'db.execute',
                    'session.execute', 'engine.execute', 'raw', 'executemany',
                    'executescript'],
        'raw_query': ['RawSQL', 'raw', 'extra', 'cursor.executemany'],
    },
    VulnCategory.CODE_INJECTION: {
        'eval': ['eval', 'exec', 'compile', 'execfile'],
        'import': ['__import__', 'importlib.import_module'],
        'getattr': ['getattr', 'setattr', 'delattr'],
    },
    VulnCategory.COMMAND_INJECTION: {
        'os': ['os.system', 'os.popen', 'os.popen2', 'os.popen3', 'os.popen4',
               'os.spawn', 'os.spawnl', 'os.spawnle', 'os.spawnlp', 'os.spawnlpe',
               'os.spawnv', 'os.spawnve', 'os.spawnvp', 'os.spawnvpe',
               'os.exec', 'os.execl', 'os.execle', 'os.execlp', 'os.execlpe',
               'os.execv', 'os.execve', 'os.execvp', 'os.execvpe'],
        'subprocess': ['subprocess.call', 'subprocess.run', 'subprocess.Popen',
                       'subprocess.check_output', 'subprocess.check_call',
                       'subprocess.getoutput', 'subprocess.getstatusoutput'],
        'commands': ['commands.getoutput', 'commands.getstatusoutput'],
    },
    VulnCategory.DESERIALIZATION: {
        'pickle': ['pickle.loads', 'pickle.load', 'cPickle.loads', 'cPickle.load',
                   '_pickle.loads', '_pickle.load'],
        'yaml': ['yaml.load', 'yaml.unsafe_load', 'yaml.full_load',
                 'yaml.load_all', 'yaml.unsafe_load_all'],
        'marshal': ['marshal.loads', 'marshal.load'],
        'shelve': ['shelve.open'],
    },
    VulnCategory.SSTI: {
        'jinja2': ['Template', 'Environment.from_string', 'from_string'],
        'mako': ['Template', 'mako.template.Template'],
        'django': ['Template'],
    },
    VulnCategory.SSRF: {
        'requests': ['requests.get', 'requests.post', 'requests.put',
                     'requests.delete', 'requests.patch', 'requests.head',
                     'requests.options', 'requests.request'],
        'urllib': ['urllib.request.urlopen', 'urllib.request.Request',
                   'urllib.urlopen', 'urllib2.urlopen'],
        'httpx': ['httpx.get', 'httpx.post', 'httpx.put', 'httpx.delete',
                  'httpx.patch', 'httpx.AsyncClient'],
        'aiohttp': ['aiohttp.ClientSession', 'session.get', 'session.post'],
    },
    VulnCategory.XPATH_INJECTION: {
        'xpath': ['xpath', 'find', 'findall', 'findtext', 'iterfind'],
        'lxml': ['lxml.etree.XPath', 'etree.xpath'],
    },
    VulnCategory.XXE: {
        'xml': ['xml.etree.ElementTree.parse', 'xml.etree.ElementTree.fromstring',
                'xml.dom.minidom.parse', 'xml.dom.minidom.parseString',
                'xml.sax.parse', 'xml.sax.parseString',
                'lxml.etree.parse', 'lxml.etree.fromstring'],
    },
    VulnCategory.PATH_TRAVERSAL: {
        'file': ['open', 'file', 'io.open'],
        'path': ['os.path.join', 'pathlib.Path'],
        'shutil': ['shutil.copy', 'shutil.copy2', 'shutil.copytree',
                   'shutil.move', 'shutil.rmtree'],
    },
}


class PythonTaintTracker(ast.NodeVisitor):
    """
    AST visitor that tracks taint propagation through Python code.
    Implements basic dataflow analysis to trace user input to dangerous sinks.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Taint tracking
        self.tainted_vars: Dict[str, TaintSource] = {}
        self.taint_propagation: Dict[str, List[str]] = defaultdict(list)

        # Import tracking
        self.imports: Dict[str, str] = {}  # alias -> full module name
        self.from_imports: Dict[str, str] = {}  # name -> module

        # Function definitions for interprocedural analysis
        self.function_params: Dict[str, List[str]] = {}
        self.function_returns_tainted: Set[str] = set()

        # Context tracking
        self.current_function: Optional[str] = None
        self.in_try_block = False
        self.shell_param_seen = False

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def get_full_attr_name(self, node: ast.AST) -> Optional[str]:
        """Get the full dotted name from an attribute node."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        return None

    def is_tainted(self, node: ast.AST) -> Tuple[bool, Optional[TaintSource]]:
        """Check if an AST node represents tainted data."""
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return True, self.tainted_vars[node.id]
            # Check if it's a known taint source function result
            if node.id in PYTHON_TAINT_FUNCTIONS:
                return True, TaintSource(node.id, node.lineno, node.col_offset, 'function')

        elif isinstance(node, ast.Attribute):
            full_name = self.get_full_attr_name(node)
            if full_name:
                # Check direct taint sources
                for source in PYTHON_TAINT_SOURCES:
                    if full_name == source or full_name.endswith('.' + source):
                        return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')
                # Check if base is tainted
                if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                    return True, self.tainted_vars[node.value.id]

        elif isinstance(node, ast.Call):
            # Check if calling a taint source function
            if isinstance(node.func, ast.Name):
                if node.func.id in PYTHON_TAINT_FUNCTIONS:
                    return True, TaintSource(node.func.id, node.lineno, node.col_offset, 'function')
                if node.func.id == 'input':
                    return True, TaintSource('input()', node.lineno, node.col_offset, 'user_input')

            # Check for request.args.get(), request.form.get(), etc.
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                full_name = self.get_full_attr_name(node.func.value)
                if full_name:
                    for source in PYTHON_TAINT_SOURCES:
                        if source in full_name:
                            return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')

        elif isinstance(node, ast.Subscript):
            # Check request['key'] style access
            if isinstance(node.value, ast.Attribute):
                full_name = self.get_full_attr_name(node.value)
                if full_name:
                    for source in PYTHON_TAINT_SOURCES:
                        if source in full_name:
                            return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')
            # Check if base is tainted
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                return True, self.tainted_vars[node.value.id]

        elif isinstance(node, ast.BinOp):
            # String concatenation or formatting can propagate taint
            left_tainted, left_source = self.is_tainted(node.left)
            right_tainted, right_source = self.is_tainted(node.right)
            if left_tainted:
                return True, left_source
            if right_tainted:
                return True, right_source

        elif isinstance(node, ast.JoinedStr):
            # f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    tainted, source = self.is_tainted(value.value)
                    if tainted:
                        return True, source

        elif isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            for elt in node.elts:
                tainted, source = self.is_tainted(elt)
                if tainted:
                    return True, source

        return False, None

    def add_finding(self, node: ast.AST, vuln_name: str, category: VulnCategory,
                    severity: Severity, confidence: str, taint_source: Optional[TaintSource] = None,
                    description: str = ""):
        """Add a vulnerability finding."""
        line_content = self.get_line_content(node.lineno)
        taint_chain = []
        if taint_source:
            taint_chain = [f"{taint_source.source_type}: {taint_source.name} (line {taint_source.line})"]

        finding = Finding(
            file_path=self.file_path,
            line_number=node.lineno,
            col_offset=getattr(node, 'col_offset', 0),
            line_content=line_content,
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            taint_chain=taint_chain,
            description=description,
        )
        self.findings.append(finding)

    def visit_Import(self, node: ast.Import):
        """Track imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports."""
        module = node.module or ''
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.from_imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments for taint propagation."""
        # Check if right side is tainted
        tainted, source = self.is_tainted(node.value)

        if tainted and source:
            # Propagate taint to all assigned targets
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = source
                    self.taint_propagation[target.id].append(source.name)
                elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                    # Handle tuple unpacking
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_vars[elt.id] = source

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name

        # Track parameters
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        self.function_params[node.name] = params

        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track async function definitions."""
        self.visit_FunctionDef(node)  # Same handling

    def visit_Call(self, node: ast.Call):
        """Analyze function calls for dangerous sinks."""
        func_name = None
        full_func_name = None

        # Get function name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Resolve imports
            if func_name in self.from_imports:
                full_func_name = self.from_imports[func_name]
            else:
                full_func_name = func_name
        elif isinstance(node.func, ast.Attribute):
            full_func_name = self.get_full_attr_name(node.func)
            if full_func_name:
                func_name = full_func_name.split('.')[-1]

        if full_func_name:
            self._check_dangerous_call(node, func_name, full_func_name)

        self.generic_visit(node)

    def _check_dangerous_call(self, node: ast.Call, func_name: str, full_func_name: str):
        """Check if a function call is a dangerous sink with tainted input."""

        # ===== CODE INJECTION =====
        if func_name in ('eval', 'exec', 'compile'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, f"Code Injection - {func_name}() with user input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", source,
                        f"User-controlled data passed to {func_name}() can lead to arbitrary code execution."
                    )
                else:
                    # Still flag eval/exec usage as it's risky
                    self.add_finding(
                        node, f"Code Injection - {func_name}() usage",
                        VulnCategory.CODE_INJECTION, Severity.MEDIUM, "LOW",
                        description=f"Usage of {func_name}() detected. Verify input is not user-controlled."
                    )

        # ===== COMMAND INJECTION =====
        if func_name == 'system' or full_func_name == 'os.system':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Command Injection - os.system() with user input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data passed to os.system() can lead to command injection."
                    )

        if func_name in ('popen', 'popen2', 'popen3', 'popen4'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, f"Command Injection - os.{func_name}() with user input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        f"User-controlled data passed to os.{func_name}() can lead to command injection."
                    )

        # subprocess with shell=True
        if 'subprocess' in full_func_name or func_name in ('call', 'run', 'Popen', 'check_output', 'check_call'):
            shell_true = False
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        shell_true = True
                    elif isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                        shell_true = True

            if shell_true and node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Command Injection - subprocess with shell=True and user input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "subprocess called with shell=True and user-controlled data."
                    )
                else:
                    self.add_finding(
                        node, "Command Injection - subprocess with shell=True",
                        VulnCategory.COMMAND_INJECTION, Severity.MEDIUM, "MEDIUM",
                        description="subprocess called with shell=True. Verify input is sanitized."
                    )

        # ===== SQL INJECTION =====
        if func_name in ('execute', 'executemany', 'executescript'):
            if node.args:
                first_arg = node.args[0]
                tainted, source = self.is_tainted(first_arg)

                # Check for string concatenation/formatting in query
                is_dynamic = self._is_dynamic_string(first_arg)

                if tainted:
                    self.add_finding(
                        node, "SQL Injection - execute() with tainted query",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data used in SQL query without parameterization."
                    )
                elif is_dynamic:
                    # Check if using parameterized query (has second argument)
                    if len(node.args) < 2 or self._is_tainted_in_args(node.args[1:]):
                        self.add_finding(
                            node, "SQL Injection - Dynamic query construction",
                            VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                            description="SQL query appears to use string formatting. Use parameterized queries."
                        )

        # Raw SQL methods
        if func_name in ('raw', 'RawSQL', 'extra'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SQL Injection - Raw SQL with user input",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data used in raw SQL query."
                    )

        # ===== DESERIALIZATION =====
        if 'pickle' in full_func_name and func_name in ('load', 'loads'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Insecure Deserialization - pickle with user input",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                        "Deserializing user-controlled data with pickle can lead to RCE."
                    )
                else:
                    self.add_finding(
                        node, "Insecure Deserialization - pickle usage",
                        VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                        description="pickle.load/loads detected. Ensure data source is trusted."
                    )

        if 'yaml' in full_func_name and func_name in ('load', 'unsafe_load', 'full_load'):
            # Check for SafeLoader
            uses_safe_loader = False
            for keyword in node.keywords:
                if keyword.arg == 'Loader':
                    if isinstance(keyword.value, ast.Attribute):
                        if 'Safe' in self.get_full_attr_name(keyword.value) or '':
                            uses_safe_loader = True
                    elif isinstance(keyword.value, ast.Name):
                        if 'Safe' in keyword.value.id:
                            uses_safe_loader = True

            if not uses_safe_loader:
                if node.args:
                    tainted, source = self.is_tainted(node.args[0])
                    if tainted:
                        self.add_finding(
                            node, "Insecure Deserialization - yaml.load without SafeLoader",
                            VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                            "yaml.load with user data without SafeLoader can lead to RCE."
                        )
                    else:
                        self.add_finding(
                            node, "Insecure Deserialization - yaml.load without SafeLoader",
                            VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                            description="yaml.load without SafeLoader. Use yaml.safe_load() instead."
                        )

        if 'marshal' in full_func_name and func_name in ('load', 'loads'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Insecure Deserialization - marshal with user input",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                        "marshal.load/loads with user data is dangerous."
                    )

        # ===== SSRF =====
        ssrf_funcs = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request', 'urlopen']
        if func_name in ssrf_funcs:
            if 'requests' in full_func_name or 'urllib' in full_func_name or 'httpx' in full_func_name:
                if node.args:
                    tainted, source = self.is_tainted(node.args[0])
                    if tainted:
                        self.add_finding(
                            node, f"SSRF - {full_func_name}() with user-controlled URL",
                            VulnCategory.SSRF, Severity.HIGH, "HIGH", source,
                            "User-controlled URL can lead to Server-Side Request Forgery."
                        )
                    # Check for variable URL (non-literal)
                    elif isinstance(node.args[0], ast.Name):
                        var_name = node.args[0].id.lower()
                        if any(hint in var_name for hint in ['url', 'uri', 'target', 'endpoint', 'link', 'href']):
                            self.add_finding(
                                node, f"SSRF - {full_func_name}() with variable URL",
                                VulnCategory.SSRF, Severity.MEDIUM, "MEDIUM",
                                description=f"URL from variable '{node.args[0].id}'. Verify URL is validated."
                            )

        # ===== SSTI =====
        if func_name == 'Template' or 'Template' in full_func_name:
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - Template() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "User-controlled template string can lead to Server-Side Template Injection."
                    )

        if func_name == 'from_string' or 'from_string' in full_func_name:
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - Environment.from_string() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "User-controlled template string in Jinja2 from_string()."
                    )

        if func_name == 'render_template_string':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - render_template_string() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "Flask render_template_string() with user input enables SSTI."
                    )

        # ===== XPATH INJECTION =====
        if func_name in ('xpath', 'find', 'findall', 'findtext', 'iterfind'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "XPath Injection - xpath() with user input",
                        VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH", source,
                        "User-controlled XPath expression can lead to XPath Injection."
                    )
                elif self._is_dynamic_string(node.args[0]):
                    self.add_finding(
                        node, "XPath Injection - Dynamic XPath expression",
                        VulnCategory.XPATH_INJECTION, Severity.MEDIUM, "MEDIUM",
                        description="XPath expression appears to be dynamically constructed."
                    )

        # ===== XXE =====
        xml_parse_funcs = ['parse', 'fromstring', 'parseString', 'iterparse']
        if func_name in xml_parse_funcs:
            if 'xml' in full_func_name or 'etree' in full_func_name or 'minidom' in full_func_name:
                # Check if defusedxml is used (safe)
                if 'defused' not in full_func_name.lower():
                    self.add_finding(
                        node, "XXE - XML parsing without defusedxml",
                        VulnCategory.XXE, Severity.MEDIUM, "MEDIUM",
                        description="XML parsing without defusedxml. Consider using defusedxml to prevent XXE."
                    )

        # ===== PATH TRAVERSAL =====
        if func_name == 'open' or func_name == 'file':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Path Traversal - open() with user input",
                        VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", source,
                        "User-controlled file path can lead to path traversal attacks."
                    )

        if func_name == 'join' and 'os.path' in full_func_name:
            for arg in node.args:
                tainted, source = self.is_tainted(arg)
                if tainted:
                    self.add_finding(
                        node, "Path Traversal - os.path.join() with user input",
                        VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", source,
                        "User-controlled path component in os.path.join()."
                    )
                    break

        # ===== AUTHENTICATION BYPASS =====
        # JWT decode without verification
        if func_name == 'decode' and 'jwt' in full_func_name:
            verify_false = False
            for keyword in node.keywords:
                if keyword.arg == 'verify' or keyword.arg == 'options':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        verify_false = True
                    elif isinstance(keyword.value, ast.Dict):
                        for k, v in zip(keyword.value.keys, keyword.value.values):
                            if isinstance(k, ast.Constant) and 'verify' in str(k.value).lower():
                                if isinstance(v, ast.Constant) and v.value is False:
                                    verify_false = True
            if verify_false:
                self.add_finding(
                    node, "Auth Bypass - JWT decode without verification",
                    VulnCategory.AUTH_BYPASS, Severity.CRITICAL, "HIGH",
                    description="JWT decoded without signature verification (verify=False)."
                )

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if a node represents a dynamically constructed string."""
        if isinstance(node, ast.BinOp):
            # String concatenation
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        elif isinstance(node, ast.JoinedStr):
            # f-string
            return True
        elif isinstance(node, ast.Call):
            # String formatting methods
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ('format', 'join', '%'):
                    return True
        return False

    def _is_tainted_in_args(self, args: list) -> bool:
        """Check if any argument is tainted."""
        for arg in args:
            if isinstance(arg, (ast.List, ast.Tuple)):
                for elt in arg.elts:
                    tainted, _ = self.is_tainted(elt)
                    if tainted:
                        return True
            else:
                tainted, _ = self.is_tainted(arg)
                if tainted:
                    return True
        return False

    def visit_Compare(self, node: ast.Compare):
        """Check for weak password comparisons."""
        # Detect patterns like: password == user_input
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left_name = self._get_name(node.left)

            if left_name and any(kw in left_name.lower() for kw in ['password', 'passwd', 'pwd', 'secret', 'token']):
                if node.comparators:
                    tainted, source = self.is_tainted(node.comparators[0])
                    # This is actually expected - comparing password to user input
                    # But we should flag == instead of constant-time comparison
                    self.add_finding(
                        node, "Auth Bypass - Timing-unsafe password comparison",
                        VulnCategory.AUTH_BYPASS, Severity.LOW, "LOW",
                        description="Use hmac.compare_digest() for constant-time comparison."
                    )

        self.generic_visit(node)

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Get a simple name from a node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None


class JavaScriptAnalyzer:
    """
    Basic JavaScript/TypeScript analyzer using regex-enhanced pattern matching.
    For production use, consider integrating with esprima or typescript parser.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Track variable assignments for basic taint tracking
        self.tainted_vars: Set[str] = set()
        self._identify_taint_sources()

    def _identify_taint_sources(self):
        """Identify variables that hold user input."""
        taint_patterns = [
            r'(\w+)\s*=\s*req\.(body|query|params|cookies|headers)',
            r'(\w+)\s*=\s*request\.(body|query|params)',
            r'const\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            r'let\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            r'(\w+)\s*=\s*process\.argv',
            r'(\w+)\s*=\s*document\.(location|URL|referrer|cookie)',
        ]

        for pattern in taint_patterns:
            for match in re.finditer(pattern, self.source_code):
                var_name = match.group(1)
                if '{' in var_name:
                    # Destructuring
                    vars_list = [v.strip().split(':')[0].strip() for v in var_name.split(',')]
                    self.tainted_vars.update(vars_list)
                else:
                    self.tainted_vars.add(var_name)

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self):
        """Run the analysis."""
        self._check_eval_injection()
        self._check_command_injection()
        self._check_sql_injection()
        self._check_prototype_pollution()
        self._check_ssrf()
        self._check_deserialization()
        self._check_ssti()
        self._check_nosql_injection()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, description: str = ""):
        """Add a finding."""
        finding = Finding(
            file_path=self.file_path,
            line_number=line_num,
            col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
        )
        self.findings.append(finding)

    def _check_eval_injection(self):
        """Check for eval/Function constructor injection."""
        patterns = [
            (r'\beval\s*\(\s*(?![\'"]\s*\))', "Code Injection - eval()"),
            (r'\bnew\s+Function\s*\(', "Code Injection - Function constructor"),
            (r'setTimeout\s*\(\s*[`"\'][^`"\']*\$\{', "Code Injection - setTimeout with template"),
            (r'setInterval\s*\(\s*[`"\'][^`"\']*\$\{', "Code Injection - setInterval with template"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    # Check if tainted variable is used
                    for var in self.tainted_vars:
                        if var in line:
                            self._add_finding(i, f"{vuln_name} with user input",
                                              VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                              "User-controlled data in code execution context.")
                            break
                    else:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.CODE_INJECTION, Severity.MEDIUM, "MEDIUM",
                                          "Potential code injection. Verify input source.")

    def _check_command_injection(self):
        """Check for command injection."""
        patterns = [
            r'child_process\.exec\s*\(',
            r'child_process\.execSync\s*\(',
            r'child_process\.spawn\s*\(',
            r'\.exec\s*\(\s*[`"\']',
            r'\.execSync\s*\(\s*[`"\']',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check for tainted input
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_template = '${' in line or "' +" in line or '" +' in line

                    if has_taint:
                        self._add_finding(i, "Command Injection - exec with user input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                          "User-controlled data in shell command.")
                    elif has_template:
                        self._add_finding(i, "Command Injection - Dynamic command",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                          "Shell command with dynamic string construction.")

    def _check_sql_injection(self):
        """Check for SQL injection patterns."""
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)'

        for i, line in enumerate(self.source_lines, 1):
            # Check for string concatenation with SQL
            if re.search(rf'["\'][^"\']*{sql_keywords}[^"\']*["\']\s*\+', line, re.IGNORECASE):
                self._add_finding(i, "SQL Injection - String concatenation",
                                  VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                  "SQL query uses string concatenation.")

            # Check for template literals with SQL
            if re.search(rf'`[^`]*{sql_keywords}[^`]*\$\{{', line, re.IGNORECASE):
                self._add_finding(i, "SQL Injection - Template literal",
                                  VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                  "SQL query uses template literal interpolation.")

            # Check for query method with tainted variable
            if re.search(r'\.query\s*\(\s*(?!["\'])', line):
                for var in self.tainted_vars:
                    if var in line:
                        self._add_finding(i, "SQL Injection - query() with variable",
                                          VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                          "Query method called with variable. Use parameterized queries.")
                        break

    def _check_prototype_pollution(self):
        """Check for prototype pollution patterns."""
        patterns = [
            (r'\[[\s]*["\']__proto__["\'][\s]*\]', "Prototype Pollution - __proto__ access"),
            (r'\.__proto__\s*[=\[]', "Prototype Pollution - __proto__ assignment"),
            (r'\[[\s]*["\']constructor["\'][\s]*\]\s*\[[\s]*["\']prototype["\']', "Prototype Pollution - constructor.prototype"),
            (r'Object\.assign\s*\([^)]*req\.body', "Prototype Pollution - Object.assign with request body"),
            (r'\.\.\.req\.body', "Prototype Pollution - Spread operator with request body"),
            (r'_\.merge\s*\(', "Prototype Pollution - lodash merge (check version)"),
            (r'_\.defaultsDeep\s*\(', "Prototype Pollution - lodash defaultsDeep (check version)"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, "MEDIUM",
                                      "Potential prototype pollution vulnerability.")

    def _check_ssrf(self):
        """Check for SSRF patterns."""
        fetch_patterns = [
            r'fetch\s*\(\s*(?!["\']https?://)',
            r'axios\.(get|post|put|delete)\s*\(\s*(?!["\'])',
            r'https?\.get\s*\(\s*(?!["\'])',
            r'got\s*\(\s*(?!["\'])',
            r'request\s*\(\s*(?!["\'])',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in fetch_patterns:
                if re.search(pattern, line):
                    # Check for user input
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_req_input = 'req.' in line or 'request.' in line

                    if has_taint or has_req_input:
                        self._add_finding(i, "SSRF - HTTP request with user-controlled URL",
                                          VulnCategory.SSRF, Severity.HIGH, "HIGH",
                                          "User-controlled URL in HTTP request.")
                    elif '${' in line or '" +' in line:
                        self._add_finding(i, "SSRF - HTTP request with dynamic URL",
                                          VulnCategory.SSRF, Severity.MEDIUM, "MEDIUM",
                                          "HTTP request with dynamic URL construction.")

    def _check_deserialization(self):
        """Check for deserialization vulnerabilities."""
        patterns = [
            (r'serialize\.unserialize\s*\(', "Insecure Deserialization - node-serialize"),
            (r'require\s*\(\s*["\']node-serialize["\']', "Insecure Deserialization - node-serialize import"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                      "node-serialize is vulnerable to RCE.")

    def _check_ssti(self):
        """Check for SSTI patterns."""
        patterns = [
            (r'ejs\.render\s*\(\s*req\.', "SSTI - EJS render with request data"),
            (r'pug\.render\s*\(\s*req\.', "SSTI - Pug render with request data"),
            (r'handlebars\.compile\s*\(\s*req\.', "SSTI - Handlebars with request data"),
            (r'nunjucks\.renderString\s*\(\s*req\.', "SSTI - Nunjucks with request data"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                                      "Template engine rendering user-controlled string.")

    def _check_nosql_injection(self):
        """Check for NoSQL injection patterns."""
        patterns = [
            (r'\.find\s*\(\s*\{[^}]*:\s*req\.', "NoSQL Injection - MongoDB find with request"),
            (r'\.findOne\s*\(\s*\{[^}]*:\s*req\.', "NoSQL Injection - MongoDB findOne with request"),
            (r'\$where\s*:', "NoSQL Injection - $where operator"),
            (r'\$regex\s*:\s*req\.', "NoSQL Injection - $regex with request data"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                      "Potential NoSQL injection vulnerability.")


class ASTScanner:
    """Main scanner class that orchestrates AST-based analysis."""

    SUPPORTED_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
    }

    DEFAULT_EXCLUDES = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'vendor', 'dist', 'build', '.tox', '.pytest_cache', 'site-packages',
        '.eggs', '*.egg-info', 'htmlcov', '.mypy_cache',
    }

    def __init__(self, verbose: bool = False, categories: Optional[List[str]] = None):
        self.verbose = verbose
        self.categories = categories
        self.all_findings: List[Finding] = []
        self.files_scanned = 0
        self.parse_errors = 0

    def log(self, message: str):
        """Print verbose logging."""
        if self.verbose:
            print(f"[*] {message}")

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        # Check extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False

        # Check exclusions
        parts = file_path.parts
        for exclude in self.DEFAULT_EXCLUDES:
            if any(exclude.replace('*', '') in part for part in parts):
                return False

        return True

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file."""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
        except (IOError, OSError) as e:
            self.log(f"Error reading {file_path}: {e}")
            return findings

        ext = file_path.suffix.lower()
        lang = self.SUPPORTED_EXTENSIONS.get(ext)

        self.log(f"Scanning {file_path} ({lang})")

        try:
            if lang == 'python':
                findings = self._scan_python(source_code, str(file_path))
            elif lang in ('javascript', 'typescript'):
                findings = self._scan_javascript(source_code, str(file_path))
        except Exception as e:
            self.log(f"Error scanning {file_path}: {e}")
            self.parse_errors += 1

        self.files_scanned += 1
        return findings

    def _scan_python(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Python source code."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            self.log(f"Syntax error in {file_path}: {e}")
            self.parse_errors += 1
            return []

        tracker = PythonTaintTracker(source_code, file_path)
        tracker.visit(tree)

        return self._filter_findings(tracker.findings)

    def _scan_javascript(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan JavaScript/TypeScript source code."""
        analyzer = JavaScriptAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by category if specified."""
        if not self.categories:
            return findings

        category_map = {
            'sql': VulnCategory.SQL_INJECTION,
            'nosql': VulnCategory.NOSQL_INJECTION,
            'code': VulnCategory.CODE_INJECTION,
            'command': VulnCategory.COMMAND_INJECTION,
            'deser': VulnCategory.DESERIALIZATION,
            'deserialization': VulnCategory.DESERIALIZATION,
            'ssti': VulnCategory.SSTI,
            'ssrf': VulnCategory.SSRF,
            'auth': VulnCategory.AUTH_BYPASS,
            'proto': VulnCategory.PROTOTYPE_POLLUTION,
            'xpath': VulnCategory.XPATH_INJECTION,
            'xxe': VulnCategory.XXE,
            'path': VulnCategory.PATH_TRAVERSAL,
        }

        allowed = set()
        for cat in self.categories:
            cat_lower = cat.lower()
            if cat_lower in category_map:
                allowed.add(category_map[cat_lower])
            elif cat_lower == 'all':
                return findings

        return [f for f in findings if f.category in allowed]

    def scan_directory(self, directory: Path) -> List[Finding]:
        """Recursively scan a directory."""
        findings = []

        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]

            for file in files:
                file_path = Path(root) / file
                if self.should_scan_file(file_path):
                    file_findings = self.scan_file(file_path)
                    findings.extend(file_findings)

        return findings

    def scan(self, target: str) -> List[Finding]:
        """Scan a file or directory."""
        target_path = Path(target)

        if not target_path.exists():
            print(f"Error: {target} does not exist")
            return []

        if target_path.is_file():
            findings = self.scan_file(target_path)
        else:
            findings = self.scan_directory(target_path)

        self.all_findings = findings
        return findings

    def print_report(self, output_format: str = 'text', output_file: Optional[str] = None):
        """Print the scan report."""
        if output_format == 'json':
            report = {
                'scan_date': datetime.now().isoformat(),
                'files_scanned': self.files_scanned,
                'parse_errors': self.parse_errors,
                'total_findings': len(self.all_findings),
                'findings': [f.to_dict() for f in self.all_findings],
                'summary': self._get_summary(),
            }
            output = json.dumps(report, indent=2)
        else:
            output = self._format_text_report()

        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"Report saved to {output_file}")
        else:
            print(output)

    def _get_summary(self) -> dict:
        """Get findings summary."""
        summary = {
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'by_confidence': defaultdict(int),
        }

        for f in self.all_findings:
            summary['by_severity'][f.severity.value] += 1
            summary['by_category'][f.category.value] += 1
            summary['by_confidence'][f.confidence] += 1

        return dict(summary)

    def _format_text_report(self) -> str:
        """Format findings as text report."""
        lines = []

        lines.append("=" * 80)
        lines.append("AST-BASED VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Files Scanned: {self.files_scanned}")
        lines.append(f"Parse Errors: {self.parse_errors}")
        lines.append(f"Total Findings: {len(self.all_findings)}")
        lines.append("")

        # Summary by severity
        summary = self._get_summary()
        lines.append("Summary by Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary['by_severity'].get(sev, 0)
            if count > 0:
                lines.append(f"  {sev:10}: {count}")
        lines.append("")

        # Summary by confidence
        lines.append("Summary by Confidence:")
        for conf in ['HIGH', 'MEDIUM', 'LOW']:
            count = summary['by_confidence'].get(conf, 0)
            if count > 0:
                lines.append(f"  {conf:10}: {count}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("")

        # Group findings by file
        findings_by_file = defaultdict(list)
        for f in self.all_findings:
            findings_by_file[f.file_path].append(f)

        for file_path, file_findings in sorted(findings_by_file.items()):
            lines.append(f"FILE: {file_path}")
            lines.append("-" * 80)

            for f in sorted(file_findings, key=lambda x: x.line_number):
                sev_color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[93m',      # Yellow
                    'MEDIUM': '\033[94m',    # Blue
                    'LOW': '\033[92m',       # Green
                    'INFO': '\033[90m',      # Gray
                }
                reset = '\033[0m'

                lines.append(f"[{f.severity.value}] {f.vulnerability_name} (Confidence: {f.confidence})")
                lines.append(f"  Line {f.line_number}: {f.line_content.strip()[:100]}")
                if f.description:
                    lines.append(f"  -> {f.description}")
                if f.taint_chain:
                    lines.append(f"  Taint: {' -> '.join(f.taint_chain)}")
                lines.append("")

            lines.append("")

        if not self.all_findings:
            lines.append("No vulnerabilities found.")
            lines.append("")

        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='AST-Based Vulnerability Scanner - Reduces false positives through code analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              python3 ast-scanner.py /path/to/project
              python3 ast-scanner.py app.py --verbose
              python3 ast-scanner.py /path/to/project --category sql code ssrf
              python3 ast-scanner.py /path/to/project --output json -o report.json

            Categories:
              sql       - SQL Injection
              nosql     - NoSQL Injection
              code      - Code Injection (eval, exec)
              command   - Command Injection (os.system, subprocess)
              deser     - Insecure Deserialization
              ssti      - Server-Side Template Injection
              ssrf      - Server-Side Request Forgery
              auth      - Authentication Bypass
              proto     - Prototype Pollution
              xpath     - XPath Injection
              xxe       - XML External Entity
              path      - Path Traversal
              all       - All categories (default)
        ''')
    )

    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-c', '--category', nargs='+', default=['all'],
                        help='Categories to scan (default: all)')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('-o', '--output-file', help='Save report to file')
    parser.add_argument('--min-confidence', choices=['HIGH', 'MEDIUM', 'LOW'], default='LOW',
                        help='Minimum confidence level to report (default: LOW)')

    args = parser.parse_args()

    # Print banner
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║            AST-Based Vulnerability Scanner v1.0               ║
    ║         Deeper code analysis, fewer false positives           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    scanner = ASTScanner(verbose=args.verbose, categories=args.category)
    findings = scanner.scan(args.target)

    # Filter by confidence
    conf_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    min_conf = conf_levels[args.min_confidence]
    findings = [f for f in findings if conf_levels.get(f.confidence, 0) >= min_conf]
    scanner.all_findings = findings

    scanner.print_report(output_format=args.output, output_file=args.output_file)

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == '__main__':
    main()
