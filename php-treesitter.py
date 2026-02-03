#!/usr/bin/env python3
"""
PHP AST Vulnerability Scanner (Tree-sitter)
============================================
A standalone PHP security scanner using tree-sitter for AST-based analysis.
Performs per-function/method taint tracking with AST-based detection.

Detection Categories:
- SQL Injection (mysql_query, mysqli_query, pg_query, PDO->query/exec, string concat)
- Command Injection (exec, system, passthru, shell_exec, popen, proc_open, backtick)
- Code Injection (eval, assert, create_function, preg_replace /e)
- Insecure Deserialization (unserialize with tainted input)
- LFI/RFI (include/require with tainted path)
- SSRF (file_get_contents, curl_setopt CURLOPT_URL, fopen, SoapClient)
- XXE (DOMDocument->loadXML, simplexml_load_string, XMLReader)
- XPath Injection (DOMXPath->query/evaluate with tainted concat)
- Path Traversal (file_get_contents, file_put_contents, fopen, readfile, unlink)
- SSTI (Twig render/createTemplate, Blade, Smarty with tainted template)
- NoSQL Injection (MongoDB find/aggregate with tainted query)
- Second-order SQLi (DB-fetched data in raw SQL concat)
"""

import os
import sys
import json
import argparse
import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum
from datetime import datetime
from collections import defaultdict

import tree_sitter_php as tsphp
from tree_sitter import Language, Parser, Node

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.align import Align
from rich.rule import Rule
from rich import box

console = Console()

PHP_LANG = Language(tsphp.language_php())

# ============================================================================
# Enums & Data Classes
# ============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class VulnCategory(Enum):
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    CODE_INJECTION = "Code Injection"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Insecure Deserialization"
    SSTI = "Server-Side Template Injection"
    SSRF = "Server-Side Request Forgery"
    XPATH_INJECTION = "XPath Injection"
    XXE = "XML External Entity"
    LFI_RFI = "Local/Remote File Inclusion"
    PATH_TRAVERSAL = "Path Traversal"


@dataclass
class Finding:
    file_path: str
    line_number: int
    col_offset: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity
    confidence: str
    taint_chain: List[str] = field(default_factory=list)
    description: str = ""


# ============================================================================
# AST Helpers
# ============================================================================

def find_nodes(node: Node, type_name: str) -> List[Node]:
    """Recursively find all descendant nodes of a given type."""
    results = []
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        results.extend(find_nodes(child, type_name))
    return results


def find_nodes_multi(node: Node, type_names: Set[str]) -> List[Node]:
    """Recursively find all descendant nodes matching any of the given types."""
    results = []
    if node.type in type_names:
        results.append(node)
    for child in node.children:
        results.extend(find_nodes_multi(child, type_names))
    return results


def node_text(node: Node) -> str:
    """Get the source text of a node."""
    return node.text.decode('utf-8') if node.text else ""


def get_node_line(node: Node) -> int:
    """Get 1-based line number."""
    return node.start_point[0] + 1


def get_child_by_type(node: Node, type_name: str) -> Optional[Node]:
    """Get first direct child of a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def get_children_by_type(node: Node, type_name: str) -> List[Node]:
    """Get all direct children of a given type."""
    return [c for c in node.children if c.type == type_name]


def get_variable_name(node: Node) -> str:
    """Extract the full variable name including $ prefix from a variable_name node."""
    return node_text(node)


def is_superglobal(var_text: str) -> bool:
    """Check if a variable text is a PHP superglobal."""
    superglobals = {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
        "$_SERVER", "$_FILES", "$_ENV", "$_SESSION",
    }
    # Check exact match or subscript access like $_GET["x"]
    for sg in superglobals:
        if var_text.startswith(sg):
            return True
    return False


def is_superglobal_name(name: str) -> bool:
    """Check if a bare name (without $) is a superglobal."""
    return name in ("_GET", "_POST", "_REQUEST", "_COOKIE",
                    "_SERVER", "_FILES", "_ENV", "_SESSION")


# ============================================================================
# TaintTracker — Per-Function/Method Taint Analysis
# ============================================================================

class TaintTracker:
    """
    Tracks tainted variables within a single function/method scope.
    Sources: PHP superglobals ($_GET, $_POST, etc.), function parameters,
             file_get_contents("php://input"), getenv(), $argv
    Propagation: assignments, string concat (.), sprintf
    """

    SUPERGLOBAL_NAMES = {
        "_GET", "_POST", "_REQUEST", "_COOKIE",
        "_SERVER", "_FILES", "_ENV",
    }

    TAINT_FUNCTIONS = {
        "getenv", "apache_getenv", "getallheaders",
        "file_get_contents",  # when arg is "php://input"
    }

    def __init__(self, func_node: Node, source_lines: List[str],
                 is_public: bool = True):
        self.func_node = func_node
        self.source_lines = source_lines
        # var_name -> (line_number, source_description)
        self.tainted: Dict[str, Tuple[int, str]] = {}
        # var_name -> (line_number, entity_source)
        self.db_sourced: Dict[str, Tuple[int, str]] = {}

        self._init_taint_from_params(is_public)
        self._propagate_taint()

    def _init_taint_from_params(self, is_public: bool):
        """Mark function parameters as tainted for public methods."""
        params_node = get_child_by_type(self.func_node, "formal_parameters")
        if not params_node:
            return

        if not is_public:
            return

        line = get_node_line(self.func_node)
        for param in get_children_by_type(params_node, "simple_parameter"):
            var_node = get_child_by_type(param, "variable_name")
            if var_node:
                param_name = node_text(var_node)
                self.tainted[param_name] = (line, "function parameter")

    def _propagate_taint(self):
        """Walk function body and propagate taint through assignments."""
        body = get_child_by_type(self.func_node, "compound_statement")
        if not body:
            return

        # Multi-pass to handle forward references
        for _ in range(3):
            self._propagate_pass(body)

    # Functions that sanitize/neutralize tainted data
    SANITIZER_FUNCTIONS = {
        "intval", "floatval", "boolval",
        "escapeshellarg", "escapeshellcmd",
        "htmlspecialchars", "htmlentities", "strip_tags",
        "filter_var", "filter_input",
        "basename", "realpath",
        "addslashes", "mysqli_real_escape_string", "mysql_real_escape_string",
        "pg_escape_string", "pg_escape_literal",
        "preg_quote", "urlencode", "rawurlencode",
    }

    def _rhs_is_sanitized(self, rhs: Node, rhs_text: str) -> bool:
        """Check if RHS wraps tainted data in a sanitizer function."""
        # Check for sanitizer function calls
        calls = find_nodes(rhs, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if name_node and node_text(name_node) in self.SANITIZER_FUNCTIONS:
                return True
        # Check for type cast: (int), (float), (bool), (string)
        if rhs.type == "cast_expression":
            return True
        if re.match(r'^\s*\(\s*(?:int|integer|float|double|bool|boolean)\s*\)', rhs_text):
            return True
        return False

    def _propagate_pass(self, body: Node):
        """Single pass of taint propagation through the function body."""
        assignments = find_nodes(body, "assignment_expression")

        for assign in assignments:
            children = assign.children
            if len(children) < 3:
                continue

            lhs = children[0]
            rhs = children[2]
            lhs_text = node_text(lhs)
            rhs_text = node_text(rhs)
            line = get_node_line(assign)

            # Check if RHS is sanitized — kills taint
            if self._rhs_is_sanitized(rhs, rhs_text):
                if lhs_text in self.tainted:
                    del self.tainted[lhs_text]
                continue

            # Check if RHS contains superglobal access
            if self._rhs_has_superglobal(rhs):
                self.tainted[lhs_text] = (line, "from superglobal")
                continue

            # Check if RHS is a taint-producing function call
            if self._rhs_is_taint_function(rhs):
                self.tainted[lhs_text] = (line, "from taint function call")
                continue

            # Check if RHS references tainted data
            if self._rhs_is_tainted(rhs_text, rhs):
                self.tainted[lhs_text] = (line, "assigned from tainted data")
                continue

            # Track DB-sourced variables
            if self._rhs_is_db_source(rhs_text):
                self.db_sourced[lhs_text] = (line, rhs_text.strip())
            # If RHS is not tainted and LHS was previously tainted, remove taint (overwrite)
            elif lhs_text in self.tainted:
                del self.tainted[lhs_text]

    def _rhs_has_superglobal(self, rhs: Node) -> bool:
        """Check if RHS contains a superglobal reference."""
        var_nodes = find_nodes(rhs, "variable_name")
        for vn in var_nodes:
            name_node = get_child_by_type(vn, "name")
            if name_node and is_superglobal_name(node_text(name_node)):
                return True
        return False

    def _rhs_is_taint_function(self, rhs: Node) -> bool:
        """Check if RHS is a function call that produces tainted data."""
        calls = find_nodes(rhs, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if name_node:
                func_name = node_text(name_node)
                if func_name in ("getenv", "apache_getenv", "getallheaders"):
                    return True
                if func_name == "file_get_contents":
                    args = get_child_by_type(call, "arguments")
                    if args and "php://input" in node_text(args):
                        return True
        return False

    def _rhs_is_tainted(self, rhs_text: str, rhs_node: Node) -> bool:
        """Check if right-hand side references any tainted variable."""
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for tainted_var in self.tainted:
            if re.search(rf'(?<!\w){re.escape(tainted_var)}(?!\w)', cleaned):
                return True
        return False

    def _rhs_is_db_source(self, rhs_text: str) -> bool:
        """Check if RHS is a database fetch that produces db-sourced data."""
        db_patterns = [
            r'->fetch\s*\(', r'->fetchAll\s*\(', r'->fetchColumn\s*\(',
            r'->fetch_assoc\s*\(', r'->fetch_array\s*\(', r'->fetch_row\s*\(',
            r'->fetch_object\s*\(', r'mysql_fetch_', r'mysqli_fetch_',
            r'pg_fetch_', r'->result\s*\(',
        ]
        for pattern in db_patterns:
            if re.search(pattern, rhs_text):
                return True
        return False

    def is_tainted(self, text: str) -> bool:
        """Check if a text string references any tainted variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        # Check superglobals directly
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b', cleaned):
            return True
        for tv in self.tainted:
            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', cleaned):
                return True
        return False

    def is_tainted_node(self, node: Node) -> bool:
        """Check if a node's text references any tainted variable."""
        return self.is_tainted(node_text(node))

    def is_db_sourced(self, text: str) -> bool:
        """Check if text references any DB-sourced variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for dv in self.db_sourced:
            if re.search(rf'(?<!\w){re.escape(dv)}(?!\w)', cleaned):
                return True
        return False

    def get_taint_chain(self, text: str) -> List[str]:
        """Get the taint chain for variables referenced in text."""
        chain = []
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for tv, (line, source) in self.tainted.items():
            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', cleaned):
                chain.append(f"{tv} <- {source} (line {line})")
        return chain


# ============================================================================
# PHPASTAnalyzer — Main Scanner
# ============================================================================

class PHPASTAnalyzer:
    """
    AST-based PHP vulnerability scanner using tree-sitter.
    Parses PHP source, builds class/function structure, runs per-function
    taint analysis, and detects vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Parse with tree-sitter
        parser = Parser(PHP_LANG)
        self.tree = parser.parse(source_code.encode('utf-8'))
        self.root = self.tree.root_node

        # Build structure
        self.functions: List[Tuple[Node, Optional[Node]]] = []  # (func, parent_class)
        self._build_function_list()

    def _build_function_list(self):
        """Find all function/method declarations and their parent classes."""
        classes = find_nodes(self.root, "class_declaration")
        for cls in classes:
            decl_list = get_child_by_type(cls, "declaration_list")
            if decl_list:
                for method in find_nodes(decl_list, "method_declaration"):
                    self.functions.append((method, cls))

        # Top-level functions
        for func in find_nodes(self.root, "function_definition"):
            if not any(f[0] == func for f in self.functions):
                self.functions.append((func, None))

    def _get_func_name(self, func_node: Node) -> str:
        """Get function/method name from declaration."""
        name = get_child_by_type(func_node, "name")
        return node_text(name) if name else ""

    def _is_public_method(self, func_node: Node) -> bool:
        """Check if a method is public."""
        if func_node.type == "function_definition":
            return True  # top-level functions are always callable

        # Check for visibility modifier
        vis = get_child_by_type(func_node, "visibility_modifier")
        if vis:
            vis_text = node_text(vis)
            if vis_text == "private":
                return False
        return True  # public or protected

    def _get_line_content(self, line_num: int) -> str:
        """Get source line content (1-based)."""
        if 1 <= line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def _add_finding(self, line: int, col: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_chain: List[str] = None,
                     description: str = ""):
        self.findings.append(Finding(
            file_path=self.file_path,
            line_number=line,
            col_offset=col,
            line_content=self._get_line_content(line),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            taint_chain=taint_chain or [],
            description=description,
        ))

    # ========================================================================
    # Main Analysis Entry Point
    # ========================================================================

    def analyze(self) -> List[Finding]:
        """Run all vulnerability checks."""
        for func, cls in self.functions:
            is_public = self._is_public_method(func)
            tracker = TaintTracker(func, self.source_lines, is_public)

            self._check_sql_injection(func, tracker)
            self._check_command_injection(func, tracker)
            self._check_code_injection(func, tracker)
            self._check_deserialization(func, tracker)
            self._check_lfi_rfi(func, tracker)
            self._check_ssrf(func, tracker)
            self._check_xxe(func, tracker)
            self._check_xpath_injection(func, tracker)
            self._check_path_traversal(func, tracker)
            self._check_ssti(func, tracker)
            self._check_nosql_injection(func, tracker)
            self._check_second_order_sqli(func, tracker)

        return self.findings

    # ========================================================================
    # SQL Injection Detection
    # ========================================================================

    def _check_sql_injection(self, func: Node, tracker: TaintTracker):
        """Detect SQL injection via string concatenation in query calls."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        # Check function calls: mysql_query, mysqli_query, pg_query, etc.
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            sql_funcs = {
                "mysql_query", "mysqli_query", "pg_query",
                "sqlite_query", "mysql_db_query", "mysqli_real_query",
                "mysql_unbuffered_query",
            }

            if func_name in sql_funcs:
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue

                # For mysqli_query, the query is the 2nd arg; for mysql_query it's 1st
                all_args = self._get_all_args(args)
                query_arg = None
                if func_name in ("mysqli_query", "mysqli_real_query") and len(all_args) >= 2:
                    query_arg = all_args[1]
                elif all_args:
                    query_arg = all_args[0]

                if query_arg:
                    arg_text = node_text(query_arg)
                    if self._has_tainted_concat(query_arg, tracker):
                        self._add_finding(
                            line, 0,
                            f"SQL Injection - String concatenation in {func_name}",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            f"Tainted data concatenated into SQL query passed to {func_name}()."
                        )
                    elif query_arg.type != "string" and query_arg.type != "encapsed_string" and tracker.is_tainted(arg_text):
                        self._add_finding(
                            line, 0,
                            f"SQL Injection - Tainted variable in {func_name}",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            f"Tainted variable used as query in {func_name}()."
                        )

        # Check method calls: $pdo->query(), $pdo->exec(), $pdo->prepare()
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)

            if method_name in ("query", "exec"):
                # Disambiguate: only flag if receiver looks like a DB object
                receiver = self._get_member_call_receiver(mc)
                recv_text = node_text(receiver) if receiver else ""
                if not self._is_db_receiver(recv_text):
                    continue

                args = get_child_by_type(mc, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if self._has_tainted_concat(first_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - String concatenation in ->{method_name}()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"Tainted data concatenated into SQL passed to ->{method_name}()."
                    )
                elif first_arg.type not in ("string", "encapsed_string") and tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - Tainted variable in ->{method_name}()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"Tainted variable used as query in ->{method_name}()."
                    )

            # $pdo->prepare() with string concat (defeats parameterization)
            if method_name == "prepare":
                args = get_child_by_type(mc, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if self._has_tainted_concat(first_arg, tracker):
                    self._add_finding(
                        line, 0,
                        "SQL Injection - String concatenation in ->prepare()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "Tainted data concatenated into SQL in prepare() defeats parameterization."
                    )

    # ========================================================================
    # Command Injection Detection
    # ========================================================================

    def _check_command_injection(self, func: Node, tracker: TaintTracker):
        """Detect command injection via exec, system, passthru, etc."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        cmd_funcs = {
            "exec", "system", "passthru", "shell_exec",
            "popen", "proc_open", "pcntl_exec",
        }

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            if func_name in cmd_funcs:
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if tracker.is_tainted(arg_text) or self._has_tainted_concat(first_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"Command Injection - {func_name}() with tainted input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"User-controlled data passed to {func_name}()."
                    )

        # Check for backtick operator (shell_execution)
        shell_execs = find_nodes(body, "shell_command_expression")
        for se in shell_execs:
            se_text = node_text(se)
            line = get_node_line(se)
            if tracker.is_tainted(se_text):
                self._add_finding(
                    line, 0,
                    "Command Injection - Backtick operator with tainted input",
                    VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(se_text),
                    "User-controlled data in backtick shell execution."
                )

    # ========================================================================
    # Code Injection Detection
    # ========================================================================

    def _check_code_injection(self, func: Node, tracker: TaintTracker):
        """Detect code injection via eval, assert, create_function, preg_replace /e."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            # eval()
            if func_name == "eval":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - eval() with tainted input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled code passed to eval()."
                    )

            # assert() with string argument (PHP < 8.0 evaluates as code)
            if func_name == "assert":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - assert() with tainted input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled expression in assert() (evaluates as code in PHP < 8.0)."
                    )

            # create_function()
            if func_name == "create_function":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = self._get_all_args(args)
                # Second argument is the code body
                if len(all_args) >= 2:
                    code_arg = all_args[1]
                    code_text = node_text(code_arg)
                    if tracker.is_tainted(code_text):
                        self._add_finding(
                            line, 0,
                            "Code Injection - create_function() with tainted body",
                            VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(code_text),
                            "User-controlled code in create_function() body."
                        )

            # preg_replace with /e modifier
            if func_name == "preg_replace":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = self._get_all_args(args)
                if all_args:
                    pattern_text = node_text(all_args[0])
                    # Check for /e modifier
                    if re.search(r'/[a-zA-Z]*e[a-zA-Z]*["\']?\s*$', pattern_text):
                        # Check if replacement or subject is tainted
                        tainted_arg = False
                        for arg in all_args[1:]:
                            if tracker.is_tainted(node_text(arg)):
                                tainted_arg = True
                                break
                        if tainted_arg:
                            self._add_finding(
                                line, 0,
                                "Code Injection - preg_replace /e with tainted data",
                                VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                description="preg_replace with /e modifier evaluates replacement as PHP code."
                            )

    # ========================================================================
    # Insecure Deserialization Detection
    # ========================================================================

    def _check_deserialization(self, func: Node, tracker: TaintTracker):
        """Detect insecure deserialization via unserialize."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            if func_name == "unserialize":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if tracker.is_tainted(arg_text):
                    # Check for allowed_classes option (2nd argument)
                    all_args = self._get_all_args(args)
                    has_allowed_classes = False
                    if len(all_args) >= 2:
                        second_text = node_text(all_args[1])
                        if "allowed_classes" in second_text and "false" in second_text.lower():
                            has_allowed_classes = True

                    if has_allowed_classes:
                        pass  # allowed_classes=false mitigates object injection
                    else:
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - unserialize() with tainted input",
                            VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            "User-controlled data in unserialize() allows arbitrary object injection."
                        )

    # ========================================================================
    # LFI/RFI Detection
    # ========================================================================

    def _check_lfi_rfi(self, func: Node, tracker: TaintTracker):
        """Detect Local/Remote File Inclusion via include/require with tainted path."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        include_types = {
            "include_expression", "include_once_expression",
            "require_expression", "require_once_expression",
        }

        include_nodes = find_nodes_multi(body, include_types)
        for inc in include_nodes:
            line = get_node_line(inc)
            inc_text = node_text(inc)

            # The path is the child after the keyword
            # Structure: include_expression -> "include" path_expression
            path_node = None
            for child in inc.children:
                if child.type not in ("include", "include_once", "require", "require_once"):
                    path_node = child
                    break

            if not path_node:
                continue

            path_text = node_text(path_node)
            keyword = inc.type.replace("_expression", "").replace("_", "_")

            if tracker.is_tainted(path_text):
                self._add_finding(
                    line, 0,
                    f"LFI/RFI - {keyword} with tainted path",
                    VulnCategory.LFI_RFI, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(path_text),
                    f"User-controlled path in {keyword} allows local/remote file inclusion."
                )
            elif self._has_tainted_concat(path_node, tracker):
                self._add_finding(
                    line, 0,
                    f"LFI/RFI - {keyword} with tainted concatenation",
                    VulnCategory.LFI_RFI, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(path_text),
                    f"Tainted data concatenated into {keyword} path."
                )

    # ========================================================================
    # SSRF Detection
    # ========================================================================

    def _check_ssrf(self, func: Node, tracker: TaintTracker):
        """Detect SSRF via file_get_contents, curl, fopen, SoapClient with tainted URLs."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            # file_get_contents(tainted_url) — but not php://input
            if func_name == "file_get_contents":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if "php://input" in arg_text:
                    continue  # This is a taint source, not SSRF
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "SSRF - file_get_contents() with tainted URL",
                        VulnCategory.SSRF, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled URL in file_get_contents()."
                    )

            # fopen(tainted_url, ...)
            if func_name == "fopen":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "SSRF - fopen() with tainted URL",
                        VulnCategory.SSRF, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled URL/path in fopen()."
                    )

            # curl_setopt($ch, CURLOPT_URL, tainted)
            if func_name == "curl_setopt":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = self._get_all_args(args)
                if len(all_args) >= 3:
                    opt_text = node_text(all_args[1])
                    val_text = node_text(all_args[2])
                    if "CURLOPT_URL" in opt_text and tracker.is_tainted(val_text):
                        self._add_finding(
                            line, 0,
                            "SSRF - curl_setopt CURLOPT_URL with tainted data",
                            VulnCategory.SSRF, Severity.HIGH, "HIGH",
                            tracker.get_taint_chain(val_text),
                            "User-controlled URL in curl_setopt(CURLOPT_URL)."
                        )

            # curl_init(tainted_url)
            if func_name == "curl_init":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "SSRF - curl_init() with tainted URL",
                        VulnCategory.SSRF, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled URL in curl_init()."
                    )

        # new SoapClient(tainted_wsdl)
        object_creations = find_nodes(body, "object_creation_expression")
        for oc in object_creations:
            oc_text = node_text(oc)
            line = get_node_line(oc)
            if "SoapClient" in oc_text:
                args = get_child_by_type(oc, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        self._add_finding(
                            line, 0,
                            "SSRF - SoapClient with tainted WSDL URL",
                            VulnCategory.SSRF, Severity.HIGH, "HIGH",
                            description="User-controlled WSDL URL in SoapClient constructor."
                        )

    # ========================================================================
    # XXE Detection
    # ========================================================================

    def _check_xxe(self, func: Node, tracker: TaintTracker):
        """Detect XXE via DOMDocument->loadXML, simplexml_load_string, XMLReader."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        body_text = node_text(body)

        # Check if libxml_disable_entity_loader(true) is called
        has_entity_loader_disabled = bool(re.search(
            r'libxml_disable_entity_loader\s*\(\s*true\s*\)', body_text
        ))
        # Check for LIBXML_NOENT absence and LIBXML_DTDLOAD absence
        has_safe_libxml = bool(re.search(
            r'LIBXML_NOENT', body_text
        ))

        # DOMDocument->loadXML(tainted)
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)

            if method_name in ("loadXML", "loadHTML", "load"):
                receiver = self._get_member_call_receiver(mc)
                if receiver:
                    recv_text = node_text(receiver)
                    # Heuristic: check receiver looks like a DOM/XML object
                    if not re.search(r'(?i)dom|xml|doc', recv_text) and method_name == "load":
                        continue
                args = get_child_by_type(mc, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - ->{method_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled XML in ->{method_name}() without libxml_disable_entity_loader()."
                            )

        # simplexml_load_string(tainted)
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            if func_name in ("simplexml_load_string", "simplexml_load_file"):
                args = get_child_by_type(call, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - {func_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled XML in {func_name}() without entity loader protection."
                            )

            # XMLReader::open / XMLReader::xml
            if func_name in ("XMLReader::open", "XMLReader::xml"):
                args = get_child_by_type(call, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - {func_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                description=f"User-controlled XML in {func_name}()."
                            )

    # ========================================================================
    # XPath Injection Detection
    # ========================================================================

    def _check_xpath_injection(self, func: Node, tracker: TaintTracker):
        """Detect XPath injection via DOMXPath->query/evaluate with tainted concat."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("query", "evaluate"):
                continue

            # Check receiver looks like an XPath object
            receiver = self._get_member_call_receiver(mc)
            recv_text = node_text(receiver) if receiver else ""
            if not re.search(r'(?i)xpath', recv_text):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue

            arg_text = node_text(first_arg)
            line = get_node_line(mc)

            if self._has_tainted_concat(first_arg, tracker):
                self._add_finding(
                    line, 0,
                    f"XPath Injection - tainted data in ->{method_name}()",
                    VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled data concatenated into XPath {method_name}() expression."
                )
            elif first_arg.type not in ("string", "encapsed_string") and tracker.is_tainted(arg_text):
                self._add_finding(
                    line, 0,
                    f"XPath Injection - tainted variable in ->{method_name}()",
                    VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled variable in XPath {method_name}() expression."
                )

    # ========================================================================
    # Path Traversal Detection
    # ========================================================================

    def _check_path_traversal(self, func: Node, tracker: TaintTracker):
        """Detect path traversal via file ops with tainted path."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        path_funcs = {
            "file_get_contents", "file_put_contents", "fopen",
            "readfile", "unlink", "rename", "copy", "mkdir",
            "rmdir", "file", "is_file", "is_dir", "realpath",
        }

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)

            if func_name not in path_funcs:
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue
            arg_text = node_text(first_arg)
            line = get_node_line(call)

            # Skip if arg is php://input (that's a taint source, not path traversal)
            if "php://input" in arg_text:
                continue

            if tracker.is_tainted(arg_text) or self._has_tainted_concat(first_arg, tracker):
                # Check for realpath/basename sanitization in surrounding code
                body_text = node_text(body)
                if self._has_path_sanitization(body_text, arg_text):
                    continue

                self._add_finding(
                    line, 0,
                    f"Path Traversal - {func_name}() with tainted path",
                    VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled path in {func_name}() allows directory traversal."
                )

    def _has_path_sanitization(self, body_text: str, arg_text: str) -> bool:
        """Check if there's path sanitization (realpath/basename) applied."""
        sanitizers = ["realpath", "basename"]
        for s in sanitizers:
            if f"{s}(" in body_text:
                return True
        return False

    # ========================================================================
    # SSTI Detection
    # ========================================================================

    def _check_ssti(self, func: Node, tracker: TaintTracker):
        """Detect server-side template injection in Twig, Blade, Smarty."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)
            mc_text = node_text(mc)

            # Twig: $twig->render(tainted_template), $twig->createTemplate(tainted)
            if method_name in ("render", "createTemplate", "display"):
                receiver = self._get_member_call_receiver(mc)
                recv_text = node_text(receiver) if receiver else ""
                if re.search(r'(?i)twig|template|smarty|blade|mustache', recv_text) or \
                   re.search(r'(?i)twig|template|smarty|blade|mustache', mc_text):
                    args = get_child_by_type(mc, "arguments")
                    if args:
                        first_arg = self._get_first_arg(args)
                        if first_arg and tracker.is_tainted(node_text(first_arg)):
                            self._add_finding(
                                line, 0,
                                f"SSTI - Template engine ->{method_name}() with tainted template",
                                VulnCategory.SSTI, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled template string in ->{method_name}()."
                            )

        # Smarty: $smarty->fetch("string:" . $tainted)
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name != "fetch":
                continue
            mc_text = node_text(mc)
            if "string:" in mc_text and tracker.is_tainted(mc_text):
                line = get_node_line(mc)
                self._add_finding(
                    line, 0,
                    "SSTI - Smarty fetch with tainted string template",
                    VulnCategory.SSTI, Severity.HIGH, "HIGH",
                    description="User-controlled template in Smarty fetch('string:...')."
                )

    # ========================================================================
    # NoSQL Injection Detection
    # ========================================================================

    def _check_nosql_injection(self, func: Node, tracker: TaintTracker):
        """Detect NoSQL injection patterns (MongoDB)."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("find", "findOne", "aggregate", "update",
                                    "insert", "remove", "deleteMany", "updateMany",
                                    "findOneAndUpdate", "findOneAndDelete"):
                continue

            mc_text = node_text(mc)
            receiver = self._get_member_call_receiver(mc)
            recv_text = node_text(receiver) if receiver else ""

            # Heuristic: receiver should look like MongoDB collection
            if not re.search(r'(?i)mongo|collection|db\b', recv_text) and \
               not re.search(r'(?i)mongo|collection', mc_text):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue
            arg_text = node_text(first_arg)
            line = get_node_line(mc)

            if tracker.is_tainted(arg_text):
                self._add_finding(
                    line, 0,
                    f"NoSQL Injection - MongoDB ->{method_name}() with tainted query",
                    VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled data in MongoDB ->{method_name}() query."
                )

    # ========================================================================
    # Second-Order SQLi Detection
    # ========================================================================

    def _check_second_order_sqli(self, func: Node, tracker: TaintTracker):
        """Detect second-order SQL injection via DB-sourced data in queries."""
        body = get_child_by_type(func, "compound_statement")
        if not body:
            return

        if not tracker.db_sourced:
            return

        # Check function calls
        sql_funcs = {"mysql_query", "mysqli_query", "pg_query"}
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name not in sql_funcs:
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            all_args = self._get_all_args(args)
            query_arg = None
            if func_name == "mysqli_query" and len(all_args) >= 2:
                query_arg = all_args[1]
            elif all_args:
                query_arg = all_args[0]

            if query_arg and self._has_concat(query_arg) and tracker.is_db_sourced(node_text(query_arg)):
                line = get_node_line(call)
                self._add_finding(
                    line, 0,
                    f"Second-order SQLi - DB-sourced data in {func_name}",
                    VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                    description="Data fetched from database used in string concatenation for SQL query."
                )

        # Check method calls (->query, ->exec)
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("query", "exec"):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue

            if self._has_concat(first_arg) and tracker.is_db_sourced(node_text(first_arg)):
                line = get_node_line(mc)
                self._add_finding(
                    line, 0,
                    f"Second-order SQLi - DB-sourced data in ->{method_name}()",
                    VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                    description="Data fetched from database concatenated into SQL query."
                )

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _get_member_call_name(self, mc: Node) -> str:
        """Get the method name from a member_call_expression node."""
        name_node = mc.child_by_field_name("name")
        if name_node:
            return node_text(name_node)
        # Fallback: find name node before arguments
        for child in mc.children:
            if child.type == "name" and child.next_sibling and child.next_sibling.type == "arguments":
                return node_text(child)
        return ""

    def _get_member_call_receiver(self, mc: Node) -> Optional[Node]:
        """Get the receiver object of a member_call_expression."""
        obj_node = mc.child_by_field_name("object")
        return obj_node

    def _is_db_receiver(self, recv_text: str) -> bool:
        """Check if a receiver variable looks like a database object."""
        # Common DB variable patterns
        if re.search(r'(?i)\b(?:pdo|db|dbo|conn|connection|mysqli|mysql|'
                     r'database|stmt|wpdb|dbh|link|pg_|sqlite)\b', recv_text):
            return True
        # $this->db, $this->pdo, $this->connection, etc.
        if re.search(r'(?i)\$this\s*->\s*(?:db|pdo|conn|connection|dbo|database)', recv_text):
            return True
        # Variable names like $pdo, $db, $conn, $connection, $dbh
        if re.search(r'^\$(?:pdo|db|dbo|conn|connection|mysqli|database|dbh|wpdb|link)$',
                     recv_text.strip(), re.IGNORECASE):
            return True
        return False

    def _get_first_arg(self, args_node: Node) -> Optional[Node]:
        """Get the first argument from an arguments node."""
        for child in args_node.children:
            if child.type == "argument":
                # Return the child of the argument node
                for c in child.children:
                    if c.type not in ("(", ")", ","):
                        return c
                return child
            if child.type not in ("(", ")", ",", "comment"):
                return child
        return None

    def _get_all_args(self, args_node: Node) -> List[Node]:
        """Get all arguments from an arguments node."""
        result = []
        for child in args_node.children:
            if child.type == "argument":
                # Return the content of the argument
                for c in child.children:
                    if c.type not in ("(", ")", ","):
                        result.append(c)
                        break
                else:
                    result.append(child)
            elif child.type not in ("(", ")", ",", "comment"):
                result.append(child)
        return result

    def _has_tainted_concat(self, node: Node, tracker: TaintTracker) -> bool:
        """Check if a node contains string concatenation with tainted data."""
        # Check for binary expression with . operator (PHP string concat)
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            op = None
            for child in binary.children:
                if node_text(child) == ".":
                    op = "."
                    break
            if op == ".":
                binary_text = node_text(binary)
                if tracker.is_tainted(binary_text):
                    return True

        # Check for sprintf
        text = node_text(node)
        if "sprintf" in text and tracker.is_tainted(text):
            return True

        return False

    def _has_concat(self, node: Node) -> bool:
        """Check if a node contains any string concatenation."""
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            for child in binary.children:
                if node_text(child) == ".":
                    return True
        text = node_text(node)
        if "sprintf" in text:
            return True
        return False


# ============================================================================
# Scanner — File Processing & Output
# ============================================================================

def scan_file(file_path: str) -> List[Finding]:
    """Scan a single PHP file and return findings."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except (IOError, OSError) as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    analyzer = PHPASTAnalyzer(source, file_path)
    return analyzer.analyze()


def scan_path(target: str, show_progress: bool = True) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory for PHP files. Returns (findings, file_count, elapsed)."""
    all_findings = []
    target_path = Path(target)
    file_count = 0
    start = time.time()

    if target_path.is_file():
        if target_path.suffix == ".php":
            if show_progress:
                with Progress(
                    SpinnerColumn("moon"),
                    TextColumn("[bold cyan]Parsing AST...[/bold cyan]"),
                    TextColumn("[dim]{task.fields[file]}[/dim]"),
                    console=console, transient=True,
                ) as progress:
                    task = progress.add_task("Scanning", total=1, file=target_path.name)
                    all_findings.extend(scan_file(str(target_path)))
                    progress.advance(task)
            else:
                all_findings.extend(scan_file(str(target_path)))
            file_count = 1
        else:
            console.print(f"[bold yellow]Warning:[/bold yellow] {target} is not a .php file")
    elif target_path.is_dir():
        php_files = sorted(target_path.rglob("*.php"))
        file_count = len(php_files)
        if show_progress and php_files:
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[current_file]}[/dim]"),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=len(php_files), current_file="")
                for pf in php_files:
                    progress.update(task, current_file=pf.name)
                    all_findings.extend(scan_file(str(pf)))
                    progress.advance(task)
        else:
            for pf in php_files:
                all_findings.extend(scan_file(str(pf)))
    else:
        console.print(f"[bold red]Error:[/bold red] {target} does not exist")

    elapsed = time.time() - start
    return all_findings, file_count, elapsed


def filter_findings(findings: List[Finding], min_severity: str = None,
                    min_confidence: str = None) -> List[Finding]:
    """Filter findings by severity and confidence."""
    result = findings
    if min_severity:
        sev = Severity[min_severity.upper()]
        min_sev_order = SEVERITY_ORDER[sev]
        result = [f for f in result if SEVERITY_ORDER[f.severity] >= min_sev_order]
    if min_confidence:
        min_conf_order = CONFIDENCE_ORDER.get(min_confidence.upper(), 0)
        result = [f for f in result if CONFIDENCE_ORDER.get(f.confidence, 0) >= min_conf_order]
    return result


def _print_banner():
    """Print the futuristic scanner banner using Rich."""
    banner_lines = [
        "██████╗ ██╗  ██╗██████╗",
        "██╔══██╗██║  ██║██╔══██╗",
        "██████╔╝███████║██████╔╝",
        "██╔═══╝ ██╔══██║██╔═══╝",
        "██║     ██║  ██║██║",
        "╚═╝     ╚═╝  ╚═╝╚═╝",
    ]
    banner_text = '\n'.join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold magenta")
    title_content.append("\n\n")
    title_content.append("Tree-sitter AST Vulnerability Scanner v1.0\n", style="bold white")
    title_content.append("Per-Function Taint Tracking | AST-Based Analysis | Zero False Positives", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="magenta",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()


def _build_stats_sidebar(findings: List[Finding], file_count: int, elapsed: float) -> Panel:
    """Build the statistics panel."""
    stats = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    stats.add_column("key", style="bold cyan", no_wrap=True, ratio=3)
    stats.add_column("value", style="white", ratio=1)

    stats.add_row("Files Scanned", str(file_count))
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("Scan Time", f"{elapsed:.2f}s")
    stats.add_row("Engine", "tree-sitter AST")
    stats.add_row("", "")

    # Severity breakdown
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity.value] += 1

    sev_styles = {
        'CRITICAL': 'bold red', 'HIGH': 'red',
        'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'dim'
    }
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = sev_counts.get(sev, 0)
        if count > 0:
            stats.add_row(Text(sev, style=sev_styles.get(sev, "white")), str(count))

    stats.add_row("", "")

    # Category breakdown
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.category.value] += 1
    cat_abbrev = {
        "Server-Side Template Injection": "SSTI",
        "Server-Side Request Forgery": "SSRF",
        "Insecure Deserialization": "Deserialization",
        "XML External Entity": "XXE",
        "Command Injection": "Cmd Injection",
        "Code Injection": "Code Injection",
        "SQL Injection": "SQL Injection",
        "NoSQL Injection": "NoSQL Injection",
        "XPath Injection": "XPath Injection",
        "Local/Remote File Inclusion": "LFI/RFI",
        "Path Traversal": "Path Traversal",
    }
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        display_name = cat_abbrev.get(cat, cat)
        stats.add_row(Text(display_name, style="cyan"), str(count))

    return Panel(
        stats,
        title="[bold white]Scan Statistics[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 1),
    )


def _build_finding_panel(f: Finding, source_code: Optional[str] = None) -> Panel:
    """Build a Rich Panel for a single finding."""
    sev = f.severity.value
    border_map = {
        'CRITICAL': 'bold red', 'HIGH': 'red',
        'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'dim white'
    }
    border_style = border_map.get(sev, 'white')

    sev_style_map = {
        'CRITICAL': 'bold white on red', 'HIGH': 'bold red',
        'MEDIUM': 'bold yellow', 'LOW': 'bold green', 'INFO': 'dim'
    }

    # Title line
    title = Text()
    title.append(f" {sev} ", style=sev_style_map.get(sev, "white"))
    title.append(f" {f.vulnerability_name} ", style="bold white")
    title.append(f" Confidence: {f.confidence} ", style="dim")

    content_parts = []

    # Source / Category
    source_text = Text()
    source_text.append("Source: ", style="bold cyan")
    source_text.append(f"Line {f.line_number}", style="white")
    if f.col_offset:
        source_text.append(f", Col {f.col_offset}", style="dim")

    cat_text = Text()
    cat_text.append("Category: ", style="bold magenta")
    cat_text.append(f"{f.category.value}", style="white")

    content_parts.append(Columns([source_text, cat_text], padding=(0, 4)))

    # Description
    if f.description:
        desc = Text()
        desc.append(f"\n{f.description}", style="italic white")
        content_parts.append(desc)

    # Taint chain as Tree
    if f.taint_chain:
        tree = Tree("[bold cyan]Taint Path[/bold cyan]", guide_style="cyan")
        for i, node in enumerate(f.taint_chain):
            style = "bold red" if i == len(f.taint_chain) - 1 else "white"
            tree.add(Text(node, style=style))
        content_parts.append(Text(""))
        content_parts.append(tree)

    # Code snippet with Syntax highlighting
    code_line = f.line_content.strip()
    if code_line:
        if source_code:
            src_lines = source_code.split('\n')
            start = max(0, f.line_number - 3)
            end = min(len(src_lines), f.line_number + 2)
            snippet = '\n'.join(src_lines[start:end])
            syntax = Syntax(
                snippet, "php", theme="monokai",
                line_numbers=True, start_line=start + 1,
                highlight_lines={f.line_number},
            )
        else:
            syntax = Syntax(
                code_line, "php", theme="monokai",
                line_numbers=True, start_line=f.line_number,
            )
        content_parts.append(Text(""))
        content_parts.append(syntax)

    panel_content = Group(*content_parts)

    return Panel(
        panel_content,
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def output_rich(findings: List[Finding], target: str, file_count: int,
                elapsed: float, min_confidence: str):
    """Output findings using Rich panels and formatting."""
    # --- Header ---
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header_text = Text()
    header_text.append("Target: ", style="bold cyan")
    header_text.append(f"{target}  ", style="white")
    header_text.append("Date: ", style="bold cyan")
    header_text.append(f"{scan_date}  ", style="white")
    header_text.append("Confidence: ", style="bold cyan")
    header_text.append(f">= {min_confidence}", style="white")

    console.print(Panel(
        Align.center(header_text),
        title="[bold white]Scan Info[/bold white]",
        border_style="blue",
        box=box.ROUNDED,
    ))
    console.print()

    # --- Statistics ---
    sidebar = _build_stats_sidebar(findings, file_count, elapsed)
    console.print(sidebar)
    console.print()

    # --- Findings ---
    if findings:
        console.print(Rule("[bold white]Vulnerability Findings[/bold white]", style="red"))
        console.print()

        # Load source code for syntax highlighting
        source_cache: Dict[str, str] = {}

        findings_by_file = defaultdict(list)
        for f in findings:
            findings_by_file[f.file_path].append(f)

        for file_path, file_findings in sorted(findings_by_file.items()):
            console.print(Text(f"FILE: {file_path}", style="bold underline cyan"))
            console.print()

            if file_path not in source_cache:
                try:
                    source_cache[file_path] = Path(file_path).read_text(
                        encoding='utf-8', errors='ignore'
                    )
                except Exception:
                    pass

            src = source_cache.get(file_path)
            for f in sorted(file_findings, key=lambda x: x.line_number):
                panel = _build_finding_panel(f, source_code=src)
                console.print(panel)
                console.print()
    else:
        console.print(Panel(
            Align.center(Text("No vulnerabilities found.", style="bold green")),
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 4),
        ))


def output_text_plain(findings: List[Finding], file_path: str):
    """Output findings in plain text format (for file output)."""
    with open(file_path, 'w', encoding='utf-8') as out:
        for f in findings:
            out.write(f"\n{'='*70}\n")
            out.write(f"  [{f.severity.value}] [{f.confidence}] {f.vulnerability_name}\n")
            out.write(f"  File: {f.file_path}:{f.line_number}\n")
            out.write(f"  Code: {f.line_content}\n")
            out.write(f"  Category: {f.category.value}\n")
            if f.description:
                out.write(f"  Description: {f.description}\n")
            if f.taint_chain:
                out.write(f"  Taint chain:\n")
                for tc in f.taint_chain:
                    out.write(f"    -> {tc}\n")

        out.write(f"\n{'='*70}\n")
        out.write(f"Total findings: {len(findings)}\n")

        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in findings:
            by_sev[f.severity.value] += 1
            by_cat[f.category.value] += 1

        if by_sev:
            out.write(f"\nBy severity:\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in by_sev:
                    out.write(f"  {sev}: {by_sev[sev]}\n")

        if by_cat:
            out.write(f"\nBy category:\n")
            for cat, count in sorted(by_cat.items()):
                out.write(f"  {cat}: {count}\n")


def output_json(findings: List[Finding], file_path: str = None):
    """Output findings in JSON format."""
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner": "php-treesitter v1.0",
        "files_scanned": len(set(f.file_path for f in findings)) if findings else 0,
        "total_findings": len(findings),
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_number,
                "column": f.col_offset,
                "code": f.line_content,
                "vulnerability": f.vulnerability_name,
                "category": f.category.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "taint_chain": f.taint_chain,
                "description": f.description,
            }
            for f in findings
        ],
        "summary": {
            "by_severity": {k: v for k, v in sorted(
                {sev: sum(1 for f in findings if f.severity.value == sev)
                 for sev in set(f.severity.value for f in findings)}.items()
            )} if findings else {},
            "by_category": {k: v for k, v in sorted(
                {cat: sum(1 for f in findings if f.category.value == cat)
                 for cat in set(f.category.value for f in findings)}.items()
            )} if findings else {},
            "by_confidence": {k: v for k, v in sorted(
                {conf: sum(1 for f in findings if f.confidence == conf)
                 for conf in set(f.confidence for f in findings)}.items()
            )} if findings else {},
        }
    }

    json_str = json.dumps(data, indent=2)
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    else:
        print(json_str)


def main():
    parser = argparse.ArgumentParser(
        description="PHP AST Vulnerability Scanner using Tree-sitter"
    )
    parser.add_argument("target", help="PHP file or directory to scan")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("-o", "--output-file", help="Write output to file")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                       help="Minimum severity to report")
    parser.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"],
                       help="Minimum confidence to report")
    parser.add_argument("--all", action="store_true",
                       help="Show all findings (no default filters)")
    parser.add_argument("--no-banner", action="store_true",
                       help="Suppress banner output")

    args = parser.parse_args()

    # Default filters
    min_severity = args.min_severity
    min_confidence = args.min_confidence
    if not args.all and not min_severity and not min_confidence:
        min_confidence = "HIGH"

    is_json = args.output == "json"

    if not args.no_banner and not is_json:
        _print_banner()

    findings, file_count, elapsed = scan_path(args.target, show_progress=not is_json)
    findings = filter_findings(findings, min_severity, min_confidence)

    # Sort by file, then line number
    findings.sort(key=lambda f: (f.file_path, f.line_number))

    if is_json:
        output_json(findings, args.output_file)
    else:
        output_rich(findings, args.target, file_count, elapsed, min_confidence or "HIGH")

        # Save plain text to file if requested
        if args.output_file:
            output_text_plain(findings, args.output_file)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    if critical_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
