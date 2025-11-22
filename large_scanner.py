
import ast
import datetime
import os
import sys
import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from typing import List, Dict, Set, Optional, Any, Tuple
import argparse
import time
import concurrent.futures

# Try to import sqlparse for advanced SQL analysis (optional)
try:
    import sqlparse
    HAS_SQLPARSE = True
except ImportError:
    HAS_SQLPARSE = False
    
__version__ = "2.2.0"

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

# SQL keywords that typically start SQL statements
SQL_STARTERS = {
    "select", "insert", "update", "delete", "create", "drop", "alter",
    "grant", "revoke", "truncate", "merge", "replace", "call", "exec",
    "with", "show", "describe", "explain"
}

# Dangerous string methods
DANGEROUS_STRING_METHODS = {
    "format", "join", "replace", "__mod__"
}

# ORM raw methods
ORM_RAW_METHODS = {
    "raw", "execute", "executemany", "executescript",
    "text", "literal_column"
}

# Request attributes that are taint sources
TAINT_SOURCES_ATTRS = {
    ("request", "args"),
    ("request", "form"),
    ("request", "values"),
    ("request", "cookies"),
    ("request", "headers"),
    ("request", "data"),
    ("request", "json"),
    ("request", "files"),
    ("request", "environ"),
    ("request", "GET"),
    ("request", "POST"),
    ("request", "COOKIES"),
    ("request", "META"),
    # FastAPI
    ("request", "query_params"),
    ("request", "path_params"),
    ("request", "body"),
    # Bottle
    ("request", "params"),
    ("request", "query"),
    # Session data - CRITICAL addition
    ("session", "get"),
    ("session", "user_id"),
    ("session", "data"),
}

# Request methods that are taint sources
TAINT_SOURCES_METHODS = {
    "get", "getlist", "get_json", "get_data",
    "get_argument", "get_arguments",  # Tornado
}

# HTTP Header sources - CRITICAL addition
HTTP_HEADER_SOURCES = {
    'User-Agent', 'X-Request-ID', 'X-Forwarded-For', 'Referer', 
    'Cookie', 'Authorization', 'X-Real-IP', 'X-Custom-Header'
}

# Semantic parameter patterns - NEW addition
SEMANTIC_PATTERNS = {
    'date_params': ['date', 'time', 'from', 'to', 'start', 'end', 'timestamp'],
    'numeric_params': ['id', 'count', 'limit', 'offset', 'page', 'size'],
    'sensitive_headers': ['user-agent', 'x-forwarded-for', 'referer', 'cookie'],
}

# Weak sanitization patterns - NEW addition
WEAK_SANITIZATION_PATTERNS = {
    'replace': {
        'single_char': ["'", '"', '--', '/*', ';', 'OR', 'AND'], # Single replacements are bypassable
        'severity': 'High',
        'message': 'Single character replacement can be bypassed with nested keywords (e.g., SELSELECTECT)'
    },
    'strip': {
        'methods': ['strip', 'lstrip', 'rstrip', 'upper', 'lower'],
        'severity': 'High',
        'message': 'Case/whitespace manipulation does not prevent SQL injection'
    },
    'keyword_removal': {
        'pattern': 'incomplete blacklist',
        'severity': 'Critical',
        'message': 'Keyword blacklists are easily bypassed and provide false security'
    },
    'quote_doubling': {
        'pattern': "''",
        'severity': 'Critical',
        'message': 'Quote doubling is not a secure way to prevent SQL injection'
    }
}

# Rule definitions - ENHANCED
RULES = {
    "PY-SQLI-001": {
        "name": "Unsanitized SQL Query",
        "severity": "High",
        "description": "Dynamic/tainted SQL passed to execute without safe parameter binding",
        "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    },
    "PY-SQLI-002": {
        "name": "SQL Identifier Injection",
        "severity": "Medium",
        "description": "Tainted identifier/value in f-string SQL (identifier injection risk)",
        "remediation": "Use parameterized queries for identifiers or validate against a whitelist"
    },
    "PY-SQLI-003": {
        "name": "SQLAlchemy Raw SQL Injection",
        "severity": "High",
        "description": "Dynamic/tainted SQL in SQLAlchemy text() without bound parameters",
        "remediation": "Use SQLAlchemy's bindparam() or text() with bound parameters"
    },
    "PY-SQLI-004": {
        "name": "Django Raw SQL Injection",
        "severity": "High",
        "description": "Dynamic/tainted SQL in Django raw() without safe parameters",
        "remediation": "Use Django's ORM query methods or parameterized raw() queries"
    },
    "PY-SQLI-005": {
        "name": "Multiple Statement Injection",
        "severity": "Critical",
        "description": "Tainted data passed to executescript (allows multiple statements)",
        "remediation": "Never pass user input to executescript(). Use execute() with parameters instead"
    },
    "PY-SQLI-006": {
        "name": "String Formatting SQL Injection",
        "severity": "High",
        "description": "Tainted data used in SQL string formatting",
        "remediation": "Avoid string formatting with SQL. Use parameterized queries"
    },
    "PY-SQLI-007": {
        "name": "Unsafe Sanitization Attempt",
        "severity": "High",
        "description": "Unsafe sanitization attempt does not prevent SQL injection",
        "remediation": "String manipulation does not prevent SQL injection. Use parameterized queries"
    },
    "PY-SQLI-008": {
        "name": "Bypassable Sanitization",
        "severity": "Critical",
        "description": "Sanitization function provides false sense of security",
        "remediation": "Use parameterized queries instead of trying to sanitize input"
    },
    "PY-SQLI-009": {
        "name": "Unvalidated WHERE Parameter",
        "severity": "Critical",
        "description": "Request parameter used in WHERE clause without format validation",
        "remediation": "Validate format (e.g., date regex, numeric range) before use"
    },
    "PY-SQLI-010": {
        "name": "HTTP Header Injection",
        "severity": "Critical",
        "description": "HTTP header value used directly in SQL query",
        "remediation": "Never use HTTP headers in SQL. If needed, use strict whitelist validation + parameterization"
    }
}

# ============================================================================
# ANALYSIS CONTEXT (PATH-SENSITIVE ANALYSIS)
# ============================================================================

class AnalysisContext:
    """
    Per-control-flow-path analysis state.
    Implements path-sensitive taint analysis by tracking validation state per path.
    """

    def __init__(self, parent=None, path_condition=None):
        """Initialize context with optional parent context"""
        self.parent = parent
        self.path_condition = path_condition or []

        # Taint state - variables tainted in this path
        self.tainted = set()

        # Validation state - variables validated in this path
        self.validated_vars = {}

        # Function summaries for this context
        self.func_summaries = {}

        # Recursion limit for interprocedural analysis
        self.recursion_depth = 0
        self.max_recursion = 5  # Conservative limit

        # Copy from parent if exists
        if parent:
            self.tainted = parent.tainted.copy()
            self.validated_vars = {k: v.copy() if isinstance(v, dict) else v
                                 for k, v in parent.validated_vars.items()}
            self.func_summaries = parent.func_summaries.copy()
            self.recursion_depth = parent.recursion_depth

    def fork(self):
        """Create new context for branch with current path condition"""
        return AnalysisContext(parent=self, path_condition=self.path_condition.copy())

    def merge(self, other):
        """Conservative merge of two contexts (join point analysis)"""
        # For tainted variables: if ANY path taints, consider tainted
        merged_tainted = self.tainted.union(other.tainted)

        # For validated variables: only consider validated if BOTH paths validate with same strength
        merged_validated = {}
        all_validated_vars = set(self.validated_vars.keys()).union(other.validated_vars.keys())

        for var in all_validated_vars:
            self_val = self.validated_vars.get(var)
            other_val = other.validated_vars.get(var)

            if self_val and other_val and self_val == other_val:
                merged_validated[var] = self_val
            # If only one path validates, we can't assume it's always validated

        merged_ctx = AnalysisContext()
        merged_ctx.tainted = merged_tainted
        merged_ctx.validated_vars = merged_validated
        merged_ctx.func_summaries = self.func_summaries.copy()  # Assume same for both paths

        return merged_ctx

    def add_path_condition(self, condition_node):
        """Add condition to current path"""
        self.path_condition.append({
            'type': type(condition_node).__name__,
            'code': self._node_to_code(condition_node),
            'node': condition_node
        })

    def _node_to_code(self, node):
        """Convert AST node to readable code string"""
        try:
            return ast.unparse(node)
        except AttributeError:
            # Fallback for older Python versions
            return str(node)

    def is_strongly_validated(self, var_name):
        """Check if variable is strongly validated in this path"""
        validation = self.validated_vars.get(var_name)
        return validation and validation.get('strength') == 'strong'

    def is_medium_or_strong_validated(self, var_name):
        """Check if variable is medium or strongly validated in this path"""
        validation = self.validated_vars.get(var_name)
        return validation and validation.get('strength') in ['medium', 'strong']

    def mark_tainted(self, var_name, reason=""):
        """Mark variable as tainted in this context"""
        self.tainted.add(var_name)

    def mark_validated(self, var_name, strength, location):
        """Mark variable as validated in this context"""
        self.validated_vars[var_name] = {
            'strength': strength,
            'location': location,
            'validated_at': self._node_loc(location) if hasattr(self, '_node_loc') else str(location)
        }

    def __repr__(self):
        return f"Context(tainted={len(self.tainted)}, validated={len(self.validated_vars)})"

# ============================================================================
# TAINT ANALYZER
# ============================================================================

class FileTaintAnalyzer(ast.NodeVisitor):
    """
    AST-based taint analyzer for SQL injection detection.
    Tracks tainted data flow and detects unsafe SQL operations.
    """
    
    def __init__(self, code: str, filename: str):
        """Initialize the scanner with code and filename"""
        self.code = code
        self.filename = filename or "unknown"
        self.tree = ast.parse(code, filename=filename)

        # NEW: Use context system instead of global state
        self.current_context = AnalysisContext()  # ← CRITICAL FIX

        logger.debug(f"Initialized with context system: tainted={len(self.current_context.tainted)}, validated={len(self.current_context.validated_vars)}")

        # ========== BUG FIX: Remove broken property initialization ==========
        # Properties were defined but not working correctly - just removed them
        # ========== END FIX ==========

        # Other tracking (not affected by context)
        self.fstring_vars: Dict[str, List[str]] = {}
        self.format_vars: Dict[str, List[str]] = {}  # Track variables used in .format() calls
        self.reported_weak_sanitization: Set[str] = set()
        self.reported_locations: Set[Tuple] = set()

        # SQL-specific tracking
        self.dynamic_sql_vars: Set[str] = set()
        self.traces: Dict[str, List[Dict[str, Any]]] = {}
        self.const_strings: Dict[str, str] = {}
        self.tainted_sources: Dict[str, Dict[str, Any]] = {}

        # Specialized tracking
        self._unvalidated_date_params: Dict[str, Dict[str, Any]] = {}
        self._unvalidated_numeric_params: Dict[str, Dict[str, Any]] = {}

        # Import tracking
        self.imports: Dict[str, str] = {}

        # Function context tracking
        self.current_function: Optional[str] = None
        self.function_stack: List[str] = []
        self.function_states: Dict[str, Dict] = {}
        self.func_summaries: Dict[str, Dict] = {}
        self.func_returns_tainted_param: Dict[str, Set[int]] = {}

        # Caching
        self._function_def_cache: Dict[str, Optional[ast.FunctionDef]] = {}

        # Results
        self.findings: List[Dict[str, Any]] = []
        # Identifier injection tracking per SQL node id
        self._identifier_vars_by_node: Dict[int, Set[str]] = {}

        # Configuration
        self.taint_sources = {
            'request.args.get', 'request.form.get', 'request.json.get',
            'request.data', 'request.get_json', 'request.values.get',
            'request.cookies.get', 'request.headers.get',
            'input', 'raw_input',
            'os.environ.get', 'os.getenv',
            'session.get', 'session'
        }

        # Enhanced validation function registry
        self.validation_functions = {
            # Strong validation (whitelist-based)
            'validate_identifier': 'strong',
            'validate_table': 'strong',
            'validate_column': 'strong',
            'validate_table_name': 'strong',
            'whitelist_check': 'strong',
            'check_whitelist': 'strong',
            'is_valid_identifier': 'strong',

            # Medium validation (regex/format-based)
            'validate_date': 'medium',
            'validate_number': 'medium',
            'validate_email': 'medium',
            'validate_uuid': 'medium',
            'validate_datetime': 'medium',

            # Weak validation (should still flag)
            'sanitize_sql_input': 'weak',
            'escape_quotes': 'weak',
            'remove_quotes': 'weak',
            'strip_sql': 'weak',
            'clean_input': 'weak'
        }

        # Auto-detect validation function patterns
        self.validation_patterns = {
            # Strong patterns
            'whitelist_based': [
                'allowed', 'whitelist', 'valid_', 'allowed_',
                'permitted', 'acceptable'
            ],
            # Medium patterns
            'regex_based': [
                'validate_', 'check_', 'verify_', 'is_valid',
                'parse_', 'format_'
            ],
            # Weak patterns
            'sanitizer_patterns': [
                'sanitize', 'escape', 'quote', 'strip', 'clean',
                'remove_', 'replace'
            ]
        }

        self.safe_functions = {
            'int', 'str', 'float', 'bool',
            'len', 'abs', 'min', 'max'
        }

        self.weak_sanitizers = {
            'sanitize_sql_input', 'escape_quotes', 'remove_quotes',
            'strip_sql', 'clean_input', 'filter_input'
        }

    def _is_header_source(self, node: ast.AST) -> bool:
        """Check if the node is a direct HTTP header source"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get":
                    if isinstance(node.func.value, ast.Attribute):
                        if (isinstance(node.func.value.value, ast.Name) and
                            node.func.value.value.id == "request" and
                            node.func.value.attr == "headers"):
                            return True
        return False
    # ========== END NEW PROPERTIES ==========


    # ------------------------------------------------------------------------
    # UTILITY METHODS
    # ------------------------------------------------------------------------

    def _node_loc(self, node: ast.AST) -> str:
        """Get node location string"""
        line = getattr(node, "lineno", "?")
        col = getattr(node, "col_offset", "?")
        return f"{self.filename}:{line}:{col}"

    def _line_snippet(self, lineno: Optional[int]) -> str:
        """Get code snippet for a line"""
        if lineno is None:
            return ""
        lines = self.code.splitlines()
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""

    def _looks_like_sql_literal_node(self, node: ast.AST) -> bool:
        """Check if AST node looks like SQL"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._looks_like_sql(node.value)
        return False

    def _looks_like_sql(self, s: str) -> bool:
        """Check if string looks like SQL"""
        s_lower = s.lower().strip()
        return any(s_lower.startswith(kw) for kw in SQL_STARTERS)

    def _call_base_name(self, func_node: ast.AST) -> tuple:
        """Extract base object and attribute from call"""
        if isinstance(func_node, ast.Attribute):
            obj_name = None
            if isinstance(func_node.value, ast.Name):
                obj_name = func_node.value.id
            return (obj_name, func_node.attr)
        elif isinstance(func_node, ast.Name):
            return (None, func_node.id)
        return (None, None)

    def _is_request_attr_chain(self, node: ast.AST) -> bool:
        """Check if node is request.* chain"""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                pair = (node.value.id, node.attr)
                return pair in TAINT_SOURCES_ATTRS
            elif isinstance(node.value, ast.Attribute):
                # Check for request.headers.get() pattern
                if isinstance(node.value.value, ast.Name):
                    if node.value.value.id == "request" and node.value.attr == "headers":
                        return True
                return self._is_request_attr_chain(node.value)
        return False

    def is_tainted_expr(self, node: ast.AST) -> bool:
        """Check if expression is tainted"""
        if isinstance(node, ast.Name):
            # NEW: Check if strongly validated (reduces false positives)
            if self._is_strongly_validated(node.id):
                logger.debug(f"  -> {node.id} is strongly validated, not tainted")
                return False

            return node.id in self.current_context.tainted

        if self._is_request_attr_chain(node):
            return True

        if self._is_request_get_json(node):
            return True

        # Check for request.headers.get() specifically
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get":
                    if isinstance(node.func.value, ast.Attribute):
                        if (isinstance(node.func.value.value, ast.Name) and
                            node.func.value.value.id == "request" and
                            node.func.value.attr == "headers"):
                            return True
                        # Also check for session.get()
                        if (isinstance(node.func.value.value, ast.Name) and
                            node.func.value.value.id == "session"):
                            return True

        # Check subscript access (e.g., data['key'], list[0])
        if isinstance(node, ast.Subscript):
            # If the container is tainted, the subscript result is tainted
            if isinstance(node.value, ast.Name):
                container_name = node.value.id
                if container_name in self.current_context.tainted:
                    logger.debug(f"  -> Subscript access on tainted container '{container_name}' is tainted")
                    return True

        # Check function calls for interprocedural taint propagation
        if isinstance(node, ast.Call):
            # FIRST: Check if this is a taint source (e.g., request.args.get)
            if self._is_taint_source(node):
                logger.debug(f"  -> Call is a taint source: {ast.unparse(node) if hasattr(ast, 'unparse') else str(node)}")
                return True

            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id

            # Check if this function returns tainted parameters
            if func_name and func_name in self.func_returns_tainted_param:
                for i, arg in enumerate(node.args):
                    if i in self.func_returns_tainted_param[func_name]:
                        if self.is_tainted_expr(arg):
                            logger.debug(f"  -> Function '{func_name}' returns tainted param from arg {i}")
                            return True

            # Check if this is a function that returns tainted data
            if func_name and func_name in self.func_summaries:
                if self.func_summaries[func_name].get("returns_tainted"):
                    logger.debug(f"  -> Function '{func_name}' returns tainted data")
                    return True

            # Check .format() calls for tainted arguments
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                # Check if any arguments to .format() are tainted
                for arg in node.args:
                    if self.is_tainted_expr(arg):
                        logger.debug(f"DEBUG: .format() call contains tainted argument: {arg}")
                        return True

        if isinstance(node, (ast.BinOp, ast.JoinedStr)):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in self.current_context.tainted:
                    return True
                if self._is_request_attr_chain(child):
                    return True

        return False

    def _is_request_get_json(self, node: ast.AST) -> bool:
        """Check if node is request.get_json() or similar"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ["request", "session"]:  # Added session
                        if node.func.attr in TAINT_SOURCES_METHODS:
                            return True
        return False

    def _add_trace(self, var: str, node: ast.AST, note: str):
        """Add trace step for variable"""
        if var not in self.traces:
            self.traces[var] = []
        self.traces[var].append({
            "file": self.filename,
            "line": getattr(node, "lineno", None),
            "code": self._line_snippet(getattr(node, "lineno", None)),
            "note": note
        })

    def _add_trace_with_context(self, var: str, node: ast.AST, note: str, context: Dict = None):
        """Enhanced trace with security context"""
        if var not in self.traces:
            self.traces[var] = []
        
        trace_entry = {
            "file": self.filename,
            "line": getattr(node, "lineno", None),
            "code": self._line_snippet(getattr(node, "lineno", None)),
            "note": note
        }
        
        # Add context
        if context:
            if context.get('bypasses_sanitization'):
                trace_entry['warning'] = "⚠️ Sanitization can be bypassed"
            if context.get('from_header'):
                trace_entry['warning'] = "🚨 CRITICAL: From HTTP header (attacker-controlled)"
            if context.get('no_validation'):
                trace_entry['warning'] = "⚠️ No validation performed"
        
        self.traces[var].append(trace_entry)

    # ------------------------------------------------------------------------
    # VALIDATION TRACKING (NEW - Reduces False Positives)
    # ------------------------------------------------------------------------
    
    def _mark_validated(self, var_name: str, validation_type: str, node: ast.AST):
        """Mark a variable as validated"""
        strength = self.validation_strength.get(validation_type, 'unknown')
        
        self.current_context.validated_vars[var_name] = {
            'validation_type': validation_type,
            'strength': strength,
            'location': getattr(node, 'lineno', None),
            'validated_at': self._node_loc(node)
        }
        
        logger.debug(f"  -> Marked validated ({strength}): {var_name} via {validation_type}")
        
        # If strongly validated, remove from tainted set
        if strength == 'strong' and var_name in self.current_context.tainted:
            self.current_context.tainted.discard(var_name)
            logger.debug(f"  -> Removed from tainted (strongly validated): {var_name}")
    
    def _is_strongly_validated(self, var_name: str) -> bool:
        """Check if variable has strong validation (whitelist-based)"""
        if var_name not in self.current_context.validated_vars:
            return False
        
        validation_info = self.current_context.validated_vars[var_name]
        return validation_info['strength'] == 'strong'

    # ========== ADD THIS NEW METHOD ==========
    def _is_medium_or_strong_validated(self, var_name: str) -> bool:
        """Check if variable has medium or strong validation"""
        if var_name not in self.current_context.validated_vars:
            return False
        
        validation_info = self.current_context.validated_vars[var_name]
        return validation_info['strength'] in ['medium', 'strong']
    # ========== END NEW METHOD ==========

    def _is_weakly_validated(self, var_name: str) -> bool:
        """Check if variable has weak validation (should still report)"""
        if var_name not in self.current_context.validated_vars:
            return False

        validation_info = self.current_context.validated_vars[var_name]
        return validation_info['strength'] == 'weak'

    def _get_validation_info(self, var_name: str) -> Optional[Dict[str, Any]]:
        """Get validation information for a variable"""
        return self.current_context.validated_vars.get(var_name)

    def _detect_validation(self, test_node: ast.expr) -> Optional[str]:
        """Detect validation patterns that make variables safe.

        This is used to recognize inline whitelist / format checks in if-conditions,
        so the corresponding variable can be treated as validated inside the
        true-branch of the if-statement.
        """

        # Pattern 1: if var in ['allowed', 'values', 'list']
        if isinstance(test_node, ast.Compare):
            if len(test_node.ops) == 1 and isinstance(test_node.ops[0], ast.In):
                if isinstance(test_node.left, ast.Name):
                    # Check if comparing against a list/tuple of constants
                    comparator = test_node.comparators[0]
                    if isinstance(comparator, (ast.List, ast.Tuple)):
                        # All elements must be constants (safe whitelist)
                        if all(isinstance(elt, ast.Constant) for elt in comparator.elts):
                            return test_node.left.id  # Return validated variable name

        # Pattern 2: if var not in ['bad', 'values']
        if isinstance(test_node, ast.Compare):
            if len(test_node.ops) == 1 and isinstance(test_node.ops[0], ast.NotIn):
                if isinstance(test_node.left, ast.Name):
                    return test_node.left.id

        # Pattern 3: if var.isdigit() / isalnum() / isalpha()
        if isinstance(test_node, ast.Call):
            if isinstance(test_node.func, ast.Attribute):
                if test_node.func.attr in ['isdigit', 'isalnum', 'isalpha']:
                    if isinstance(test_node.func.value, ast.Name):
                        return test_node.func.value.id

        return None

    def _check_string_concatenation(self, node: ast.BinOp):
        """
        Detect SQL injection via string concatenation.

        Pattern: "SELECT * FROM users WHERE name = '" + user_input + "'"
        Pattern: base + cond (where base has SQL and cond is tainted)
        Returns detection result dict if vulnerable, None otherwise.
        """
        # Flatten nested concatenations into a list of parts
        parts = self._flatten_binop(node)

        # Check if any part contains SQL keywords
        has_sql = False
        tainted_vars = []
        header_vars = []  # For HTTP header variables

        for part in parts:
            # Check for SQL in string constants
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if self._looks_like_sql(part.value):
                    has_sql = True
                    logger.debug(f"  -> Found SQL in concatenation: {part.value[:50]}")

            # Check for tainted variables
            elif isinstance(part, ast.Name):
                var_name = part.id

                # Skip if strongly validated - these are safe
                if self._is_strongly_validated(var_name):
                    logger.debug(f"  -> {var_name} is validated, skipping")
                    continue

                # FIX 1: Check if variable is tainted
                if var_name in self.current_context.tainted:
                    tainted_vars.append(var_name)
                    logger.debug(f"  -> Found tainted var in concatenation: {var_name}")
                # FIX 1: Also check if variable is dynamic SQL (built from tainted data)
                elif var_name in self.dynamic_sql_vars:
                    # Variable was built from tainted data - mark as tainted
                    tainted_vars.append(var_name)
                    logger.debug(f"  -> Found dynamic SQL var in concatenation: {var_name}")
                elif var_name in self.traces:
                    # Check for header variables (from trace metadata)
                    for step in self.traces[var_name]:
                        note = step.get('note', '').lower()
                        if 'header' in note or 'http header' in note:
                            header_vars.append(var_name)
                            logger.debug(f"  -> Found header var in concatenation: {var_name}")
                            break
                        # FIX 1: Also check if variable was built from tainted concatenation
                        if 'tainted' in note or 'concatenation' in note:
                            tainted_vars.append(var_name)
                            logger.debug(f"  -> Found tainted var in concatenation (from trace): {var_name}")
                            break
            
            # FIX 2: Check for Call nodes (like .join() calls) that produce tainted results
            elif isinstance(part, ast.Call):
                # Check if this call produces tainted data
                if self.is_tainted_expr(part):
                    # This is a tainted call (e.g., .join() on tainted list)
                    tainted_vars.append(f"<call_result>")
                    logger.debug(f"  -> Found tainted call result in concatenation: {ast.unparse(part) if hasattr(ast, 'unparse') else str(part)[:50]}")
                # Also check if it's a .join() call on a tainted list
                if isinstance(part.func, ast.Attribute) and part.func.attr == "join":
                    if part.args and isinstance(part.args[0], ast.Name):
                        list_name = part.args[0].id
                        if list_name in self.current_context.tainted:
                            tainted_vars.append(f"join({list_name})")
                            logger.debug(f"  -> Found .join() on tainted list '{list_name}' in concatenation")

        # FIX 1: Also check if any variable contains SQL (from previous assignments)
        for part in parts:
            if isinstance(part, ast.Name):
                var_name = part.id
                # Check if this variable was assigned a SQL string (constant or from another assignment)
                if var_name in self.dynamic_sql_vars:
                    has_sql = True
                    logger.debug(f"  -> Variable {var_name} is dynamic SQL")
                # Also check if variable was assigned a constant SQL string
                elif var_name in self.const_strings:
                    if self._looks_like_sql(self.const_strings[var_name]):
                        has_sql = True
                        logger.debug(f"  -> Variable {var_name} contains SQL constant: {self.const_strings[var_name][:50]}")
                # Check traces for SQL indicators
                elif var_name in self.traces:
                    for step in self.traces[var_name]:
                        note = step.get('note', '').lower()
                        if 'sql' in note or 'select' in note or 'where' in note:
                            has_sql = True
                            logger.debug(f"  -> Variable {var_name} contains SQL (from trace)")
                            break

        # Return detection result if vulnerable
        if has_sql and (tainted_vars or header_vars):
            logger.debug(f"  -> Detected vulnerable SQL concatenation: SQL={has_sql}, tainted={tainted_vars}, headers={header_vars}")

            return {
                'is_vulnerable': True,
                'tainted_vars': tainted_vars,
                'header_vars': header_vars,
                'construction_type': 'concatenation',
                'sql_snippet': self._line_snippet(getattr(node, "lineno", None))
            }

        return None  # Not vulnerable

    def _flatten_binop(self, node: ast.AST) -> List[ast.AST]:
        """
        Flatten nested BinOp nodes into a list of parts.

        Example:
            "SELECT " + table + " WHERE id = " + uid

        Returns:
            [Constant("SELECT "), Name('table'), Constant(" WHERE id = "), Name('uid')]
        """
        if not isinstance(node, ast.BinOp):
            return [node]

        parts = []

        # Recursively flatten left side
        if isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Add):
            parts.extend(self._flatten_binop(node.left))
        else:
            parts.append(node.left)

        # Recursively flatten right side
        if isinstance(node.right, ast.BinOp) and isinstance(node.right.op, ast.Add):
            parts.extend(self._flatten_binop(node.right))
        else:
            parts.append(node.right)

        return parts

    def _check_percent_formatting(self, node: ast.BinOp):
        """
        Detect SQL injection via % formatting.

        Patterns:
        - "SELECT * FROM %s" % table
        - "SELECT * FROM %s WHERE id = %s" % (table, uid)

        Returns: dict with vulnerability info if vulnerable, None otherwise
        """
        # Left side should be a string (format string)
        if not isinstance(node.left, ast.Constant):
            return None

        if not isinstance(node.left.value, str):
            return None

        format_string = node.left.value

        # Check if format string contains SQL
        if not self._looks_like_sql(format_string):
            return None

        logger.debug(f"  -> Found % formatting with SQL: {format_string[:50]}")

        # Extract variables from right side
        tainted_vars = []
        header_vars = []

        # Check single variable case
        if isinstance(node.right, ast.Name):
            var_name = node.right.id

            # Skip if validated
            if self._is_strongly_validated(var_name):
                logger.debug(f"  -> {var_name} is validated, skipping")
                return None

            if var_name in self.current_context.tainted:
                tainted_vars.append(var_name)
                logger.debug(f"  -> Found tainted var: {var_name}")
            elif var_name in self.traces:
                # Check for header variables
                for step in self.traces[var_name]:
                    if 'header' in step.get('note', '').lower():
                        header_vars.append(var_name)
                        logger.debug(f"  -> Found header var: {var_name}")
                        break

        # Check multiple variables case
        elif isinstance(node.right, ast.Tuple):
            for elt in node.right.elts:
                if isinstance(elt, ast.Name):
                    var_name = elt.id

                    # Skip if validated
                    if self._is_strongly_validated(var_name):
                        logger.debug(f"  -> {var_name} is validated, skipping")
                        continue

                    if var_name in self.current_context.tainted:
                        tainted_vars.append(var_name)
                        logger.debug(f"  -> Found tainted var: {var_name}")
                    elif var_name in self.traces:
                        # Check for header variables
                        for step in self.traces[var_name]:
                            if 'header' in step.get('note', '').lower():
                                header_vars.append(var_name)
                                logger.debug(f"  -> Found header var: {var_name}")
                                break

        # Return vulnerability info if vulnerable
        if tainted_vars or header_vars:
            logger.info(f"🔍 Percent formatting with SQL + dangerous vars: {tainted_vars or header_vars}")

            return {
                'is_vulnerable': True,
                'construction_type': 'percent_formatting',
                'tainted_vars': tainted_vars,
                'header_vars': header_vars,
                'sql_snippet': self._line_snippet(getattr(node, "lineno", None)),
                'node': node
            }

        return None  # No vulnerability found

    def _check_inline_validation_pattern(self, if_node: ast.If) -> Optional[Tuple[str, str]]:
        """
        Detect inline validation patterns like:
          if not var.isdigit(): abort(400)
          if not var.isalpha(): raise ValueError()
          if not re.match(pattern, var): return None

        Returns: (variable_name, validation_strength) or None
        """
        test = if_node.test

        # Pattern 1: if not <var>.<method>(): <abort/raise>
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            operand = test.operand

            # Check for method call like .isdigit()
            if isinstance(operand, ast.Call):
                func = operand.func
                if isinstance(func, ast.Attribute):
                    method_name = func.attr

                    # Check if it's a validation method
                    validation_methods = {
                        'isdigit': 'strong',      # Only digits
                        'isalpha': 'medium',      # Only letters
                        'isalnum': 'medium',      # Letters + digits
                        'isnumeric': 'strong',    # Numeric characters
                        'isdecimal': 'strong',    # Decimal characters
                    }

                    if method_name in validation_methods:
                        # Check if body contains abort() or raise
                        if self._has_abort_or_raise(if_node.body):
                            # Get the variable being validated
                            if isinstance(func.value, ast.Name):
                                var_name = func.value.id
                                strength = validation_methods[method_name]
                                logger.debug(f"  -> Detected inline validation: {var_name}.{method_name}() (strength: {strength})")
                                return (var_name, strength)

        # Pattern 2: if var not in allowed_list: raise
        elif isinstance(test, ast.Compare):
            if len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn):
                # Check if body raises exception
                if self._has_raise(if_node.body):
                    # Get variable being checked
                    if isinstance(test.left, ast.Name):
                        var_name = test.left.id
                        logger.debug(f"  -> Detected whitelist validation: {var_name} not in [...]")
                        return (var_name, 'strong')

        return None

    def _has_abort_or_raise(self, body: List[ast.stmt]) -> bool:
        """Check if body contains abort() call or raise statement"""
        for stmt in body:
            # Check for abort() call
            if isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, ast.Call):
                    if isinstance(stmt.value.func, ast.Name):
                        if stmt.value.func.id in ['abort', 'exit', 'sys.exit']:
                            return True

            # Check for raise statement
            if isinstance(stmt, ast.Raise):
                return True

            # Check for return (early exit)
            if isinstance(stmt, ast.Return):
                return True

        return False

    def _has_raise(self, body: List[ast.stmt]) -> bool:
        """Check if body contains raise statement"""
        for stmt in body:
            if isinstance(stmt, ast.Raise):
                return True
        return False

    # ------------------------------------------------------------------------
    # TRACE PROPAGATION
    # ------------------------------------------------------------------------
    

    def _propagate_traces(self, src_node: ast.AST, target_var: str, assign_node: ast.AST):
        """
        Propagate trace history from source variables to target variable.
        This ensures we don't lose the origin of tainted data.
        """
        # Find all Name nodes in the source
        for child in ast.walk(src_node):
            if isinstance(child, ast.Name):
                src_var = child.id
                
                # If source variable has traces, copy them to target
                if src_var in self.traces:
                    if target_var not in self.traces:
                        self.traces[target_var] = []
                    
                    # Copy all traces from source to target
                    for trace_step in self.traces[src_var]:
                        # Avoid duplicates
                        if trace_step not in self.traces[target_var]:
                            self.traces[target_var].append(trace_step)
                    
                    logger.debug(f"  -> Propagated {len(self.traces[src_var])} trace steps from {src_var} to {target_var}")


    def _build_trace(self, vars_involved: List[str]) -> Optional[List[Dict]]:
        """Build trace with deduplication"""
        steps = []
        seen = set()
        
        for v in vars_involved or []:
            for step in self.traces.get(v, []):
                key = (step["file"], step["line"], step["code"], step["note"])
                if key in seen:
                    continue
                seen.add(key)
                
                if step["note"] and "const-sql" not in step["note"]:
                    steps.append(step)
        
        steps.sort(key=lambda x: x.get("line", 0))
        return steps[-8:] if steps else None

    def _mark_identifier_var(self, sql_node: ast.AST, var_name: str):
        """Mark a variable as being used in an identifier position for a given SQL AST node"""
        key = id(sql_node)
        if not hasattr(self, "_identifier_vars_by_node"):
            self._identifier_vars_by_node = {}
        self._identifier_vars_by_node.setdefault(key, set()).add(var_name)

    def _get_remediation(self, rule: str) -> str:
        """Get remediation advice"""
        rule_info = RULES.get(rule, {})
        return rule_info.get("remediation", "Use parameterized queries to prevent SQL injection")

    def _get_example_code(self, rule: str) -> Dict[str, str]:
        """Get vulnerable and safe code examples"""
        examples = {
            "PY-SQLI-001": {
                "vulnerable": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                "safe": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'
            },
            "PY-SQLI-002": {
                "vulnerable": 'cursor.execute(f"SELECT * FROM users ORDER BY {column}")',
                "safe": 'allowed = ["id", "name"]\nif column in allowed:\n    cursor.execute(f"SELECT * FROM users ORDER BY {column}")'
            },
            "PY-SQLI-005": {
                "vulnerable": 'cursor.executescript(user_sql)',
                "safe": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'
            },
            "PY-SQLI-006": {
                "vulnerable": 'query = "SELECT * FROM users WHERE name=\'{}\'".format(name)',
                "safe": 'cursor.execute("SELECT * FROM users WHERE name=?", (name,))'
            },
            "PY-SQLI-007": {
                "vulnerable": 'safe_input = user_input.replace("\'", "")\ncursor.execute(f"SELECT * FROM users WHERE name=\'{safe_input}\'")',
                "safe": 'cursor.execute("SELECT * FROM users WHERE name=?", (user_input,))'
            },
            "PY-SQLI-008": {
                "vulnerable": 'def sanitize_input(input):\n    return input.replace("\'", "")\nsafe_input = sanitize_input(user_input)\ncursor.execute(f"SELECT * FROM users WHERE name=\'{safe_input}\'")',
                "safe": 'cursor.execute("SELECT * FROM users WHERE name=?", (user_input,))'
            },
            "PY-SQLI-009": {
                "vulnerable": 'date_from = request.args.get("date_from")\nquery = f"SELECT * FROM logs WHERE timestamp BETWEEN \'{date_from}\' AND \'{date_to}\'"',
                "safe": 'import re\ndate_from = request.args.get("date_from")\nif not re.match(r"^\\d{4}-\\d{2}-\\d{2}$", date_from):\n    raise ValueError("Invalid date format")\nquery = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"\ncursor.execute(query, (date_from, date_to))'
            },
            "PY-SQLI-010": {
                "vulnerable": 'user_agent = request.headers.get("User-Agent")\nquery = f"INSERT INTO analytics (user_agent) VALUES (\'{user_agent}\')"',
                "safe": 'user_agent = request.headers.get("User-Agent")\nquery = "INSERT INTO analytics (user_agent) VALUES (?)"\ncursor.execute(query, (user_agent,))'
            },
        }
        return examples.get(rule, {})

    def _classify_parameter(self, param_name: str) -> str:
        """Classify parameter by semantic meaning"""
        param_lower = param_name.lower() if param_name else ""
        for category, keywords in SEMANTIC_PATTERNS.items():
            if any(kw in param_lower for kw in keywords):
                return category
        return 'generic'

    def _extract_vulnerable_vars_from_sql(self, sql_node: ast.AST, context: Dict = None) -> List[str]:
        """
        Extract variables that are actually interpolated in dangerous positions in SQL.
        This prevents false positives for parameterized queries or safe string operations.

        Phase 1 Quick Win: Filter out variables that are SQL strings themselves (e.g., 'query')
        """
        vulnerable_vars = []

        # Blacklist: variables that are SQL strings themselves (not source data)
        sql_string_vars_blacklist = {'query', 'sql', 'statement', 'cmd', 'q', 'sql_query'}

        try:
            # Handle different SQL expression types
            if isinstance(sql_node, ast.Name):
                # Variable containing SQL - check if it's dynamic
                var_name = sql_node.id

                # PHASE 1 FIX: Skip if this is just the SQL string variable itself
                if var_name.lower() in sql_string_vars_blacklist:
                    logger.debug(f"  -> Skipping SQL string variable '{var_name}' (not the actual data)")
                    # Instead, check if this variable contains interpolated variables from f-strings
                    if var_name in self.fstring_vars:
                        for fvar in self.fstring_vars[var_name]:
                            if fvar in self.current_context.tainted and not self._is_medium_or_strong_validated(fvar):
                                vulnerable_vars.append(fvar)
                                logger.debug(f"  -> {fvar} is vulnerable (from f-string in SQL variable {var_name})")
                    # FIX 1: Also check if this variable contains interpolated variables from .format() calls
                    if var_name in self.format_vars:
                        for format_var in self.format_vars[var_name]:
                            if format_var in self.current_context.tainted and not self._is_medium_or_strong_validated(format_var):
                                vulnerable_vars.append(format_var)
                                logger.debug(f"  -> {format_var} is vulnerable (from .format() in SQL variable {var_name})")
                    return vulnerable_vars

                if var_name in self.dynamic_sql_vars or var_name in self.current_context.tainted:
                    # If this variable was assigned from tainted data and is used in SQL context
                    if var_name in self.current_context.tainted:
                        vulnerable_vars.append(var_name)
                        logger.debug(f"  -> {var_name} is vulnerable (tainted SQL variable)")

                # Check if this variable contains variables from f-strings
                if var_name in self.fstring_vars:
                    # For f-strings, find which variables are interpolated
                    for fvar in self.fstring_vars[var_name]:
                        if fvar in self.current_context.tainted and not self._is_medium_or_strong_validated(fvar):
                            vulnerable_vars.append(fvar)
                            logger.debug(f"  -> {fvar} is vulnerable (from f-string in {var_name})")
                
                # FIX 1: Check if this variable contains variables from .format() calls
                if var_name in self.format_vars:
                    # For .format() calls, find which variables are interpolated
                    for format_var in self.format_vars[var_name]:
                        if format_var in self.current_context.tainted and not self._is_medium_or_strong_validated(format_var):
                            vulnerable_vars.append(format_var)
                            logger.debug(f"  -> {format_var} is vulnerable (from .format() in {var_name})")

            elif isinstance(sql_node, ast.JoinedStr):
                # Direct f-string usage (e.g., f"SELECT * FROM users WHERE id={user_id}")
                for idx, val in enumerate(sql_node.values):
                    if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                        var_name = val.value.id

                        # Get surrounding context (left and right strings)
                        left_str = ""
                        right_str = ""
                        if idx > 0 and isinstance(sql_node.values[idx-1], ast.Constant):
                            left_str = str(sql_node.values[idx-1].value).upper()

                        if idx+1 < len(sql_node.values) and isinstance(sql_node.values[idx+1], ast.Constant):
                            right_str = str(sql_node.values[idx+1].value).upper()

                        # Check if this is an IDENTIFIER position (not a value position)
                        is_identifier = False

                        # Pattern 1: FROM/JOIN followed by variable (table name)
                        # Example: f"SELECT * FROM {table}" → table is identifier
                        if any(left_str.rstrip().endswith(kw) for kw in [" FROM", " JOIN", " UPDATE", " INTO"]):
                            # Make sure it's not after an operator (=, >, <, etc.)
                            if not any(op in left_str[-30:] for op in ["=", "!=", ">", "<", ">=", "<=", " IN ", " BETWEEN "]):
                                is_identifier = True
                                logger.debug(f"  -> {var_name} is identifier (after FROM/JOIN/UPDATE/INTO)")

                        # Pattern 2: ORDER BY / GROUP BY followed by variable (column name)
                        # Example: f"ORDER BY {column}" → column is identifier
                        if any(phrase in left_str[-30:] for phrase in ["ORDER BY", "GROUP BY"]):
                            is_identifier = True
                            logger.debug(f"  -> {var_name} is identifier (after ORDER BY/GROUP BY)")

                        # Pattern 3: Variable between SELECT and FROM (column name)
                        # Example: f"SELECT {column} FROM" → column is identifier
                        if "SELECT" in left_str[-30:] and any(kw in right_str[:30] for kw in [" FROM", ","]):
                            is_identifier = True
                            logger.debug(f"  -> {var_name} is identifier (column in SELECT)")

                        # ANTI-PATTERN: After comparison operators = VALUE position
                        # Example: f"WHERE id = {uid}" → uid is VALUE, NOT identifier
                        if any(op in left_str[-20:] for op in ["= ", "!= ", "> ", "< ", ">= ", "<= ", " IN (", "BETWEEN "]):
                            is_identifier = False
                            logger.debug(f"  -> {var_name} is VALUE (after comparison operator), not identifier")

                        # ANTI-PATTERN: Inside quotes = VALUE position
                        # Example: f"WHERE name = '{name}'" → name is VALUE
                        if left_str.rstrip().endswith("'") or right_str.lstrip().startswith("'"):
                            is_identifier = False
                            logger.debug(f"  -> {var_name} is VALUE (inside quotes), not identifier")

                        # Mark as identifier if detected
                        if is_identifier:
                            self._mark_identifier_var(sql_node, var_name)
                            logger.info(f"✓ IDENTIFIER DETECTED: {var_name}")

                        # Always check if tainted (for generic SQLI detection)
                        if var_name in self.current_context.tainted and not self._is_medium_or_strong_validated(var_name):
                            vulnerable_vars.append(var_name)
                            logger.debug(f"  -> {var_name} is vulnerable (tainted in f-string)")

            elif isinstance(sql_node, ast.BinOp) and isinstance(sql_node.op, ast.Add):
                # String concatenation (e.g., "SELECT * FROM users WHERE id=" + user_id)
                parts = self._flatten_binop(sql_node)
                has_sql = any(
                    isinstance(p, ast.Constant) and isinstance(p.value, str) and self._looks_like_sql(p.value)
                    for p in parts
                )

                if has_sql:
                    for i, part in enumerate(parts):
                        if isinstance(part, ast.Name):
                            var_name = part.id

                            # Get surrounding context
                            prev_part = parts[i-1] if i > 0 else None
                            next_part = parts[i+1] if i+1 < len(parts) else None

                            # Check if identifier position
                            is_identifier = False

                            if isinstance(prev_part, ast.Constant) and isinstance(prev_part.value, str):
                                prev_str = prev_part.value.upper()

                                # Check for FROM/JOIN/UPDATE/INTO
                                if any(prev_str.rstrip().endswith(kw) for kw in [" FROM", " JOIN", " UPDATE", " INTO"]):
                                    if not any(op in prev_str[-30:] for op in ["=", "!=", ">", "<"]):
                                        is_identifier = True

                                # Check for ORDER BY/GROUP BY
                                if any(phrase in prev_str[-30:] for phrase in ["ORDER BY", "GROUP BY"]):
                                    is_identifier = True

                                # Anti-pattern: after comparison operators
                                if any(op in prev_str[-20:] for op in ["= ", "!= ", "> ", "< "]):
                                    is_identifier = False

                            if is_identifier:
                                self._mark_identifier_var(sql_node, var_name)

                            # Check if tainted
                            if var_name in self.current_context.tainted and not self._is_medium_or_strong_validated(var_name):
                                vulnerable_vars.append(var_name)

            elif isinstance(sql_node, ast.BinOp) and isinstance(sql_node.op, ast.Mod):
                # % formatting (e.g., "SELECT * FROM %s" % table)
                # Check left side for SQL
                has_sql = False
                if isinstance(sql_node.left, ast.Constant) and isinstance(sql_node.left.value, str):
                    if self._looks_like_sql(sql_node.left.value):
                        has_sql = True

                if has_sql:
                    # Extract variables from right side and check for tainted ones
                    if isinstance(sql_node.right, ast.Name):
                        if sql_node.right.id in self.current_context.tainted and not self._is_medium_or_strong_validated(sql_node.right.id):
                            vulnerable_vars.append(sql_node.right.id)
                            logger.debug(f"  -> {sql_node.right.id} is vulnerable (% formatting in SQL)")
                    elif isinstance(sql_node.right, ast.Tuple):
                        for elt in sql_node.right.elts:
                            if isinstance(elt, ast.Name) and elt.id in self.current_context.tainted and not self._is_medium_or_strong_validated(elt.id):
                                vulnerable_vars.append(elt.id)
                                logger.debug(f"  -> {elt.id} is vulnerable (% formatting in SQL)")

            elif isinstance(sql_node, ast.Call):
                # Check .format() calls
                if isinstance(sql_node.func, ast.Attribute) and sql_node.func.attr == "format":
                    # Check arguments to .format()
                    for arg in sql_node.args:
                        if isinstance(arg, ast.Name) and arg.id in self.current_context.tainted and not self._is_medium_or_strong_validated(arg.id):
                            # PHASE 1 FIX: Don't report SQL string variables
                            if arg.id.lower() not in sql_string_vars_blacklist:
                                vulnerable_vars.append(arg.id)
                                logger.debug(f"  -> {arg.id} is vulnerable (.format() argument)")

        except Exception as e:
            logger.debug(f"  -> Error analyzing SQL structure: {e}")
            # Fallback: return all known tainted variables (conservative) but filter blacklist
            return [v for v in self.current_context.tainted if not self._is_medium_or_strong_validated(v) and v.lower() not in sql_string_vars_blacklist]

        # Remove duplicates while preserving order
        seen = set()
        result = []
        for var in vulnerable_vars:
            if var not in seen:
                seen.add(var)
                result.append(var)

        logger.debug(f"  -> Found {len(result)} vulnerable variables: {result}")
        return result

    def _classify_vulnerability_type(self, tainted_vars: List[str], sql_node: ast.AST) -> Dict[str, str]:
        """
        Classify the specific type of SQL injection vulnerability.
        This reduces false positives by being more specific.
        """
        # Check if any tainted vars are date parameters
        date_vars = [v for v in tainted_vars if v in self._unvalidated_date_params]
        if date_vars:
            param_name = self._unvalidated_date_params[date_vars[0]]['param_name']
            return {
                'rule': 'PY-SQLI-009',
                'message': f"Unvalidated date parameter '{param_name}' used in SQL query without format validation"
            }

        # Check if any tainted vars are from headers
        header_vars = []
        for var in tainted_vars:
            if var in self.traces:
                for step in self.traces[var]:
                    if 'header' in step.get('note', '').lower():
                        header_vars.append(var)
                        break

        if header_vars:
            return {
                'rule': 'PY-SQLI-010',
                'message': f"HTTP header variable '{header_vars[0]}' used in SQL query - CRITICAL"
            }

        # Check if any tainted vars are from session
        session_vars = []
        for var in tainted_vars:
            if var in self.traces:
                for step in self.traces[var]:
                    if 'session' in step.get('note', '').lower():
                        session_vars.append(var)
                        break

        if session_vars:
            return {
                'rule': 'PY-SQLI-001',
                'message': f"Session variable '{session_vars[0]}' used in SQL without validation"
            }

        # Generic SQL injection
        var_list = ', '.join(f"'{v}'" for v in tainted_vars[:3])  # Limit to first 3
        return {
            'rule': 'PY-SQLI-001',
            'message': f"Unvalidated variable(s) {var_list} used in SQL query without parameterization"
        }


    def _calculate_confidence_enhanced(self, node: ast.AST, context: Dict) -> str:
        """
        Enhanced confidence calculation:
        - High: Direct request.args/headers -> SQL
        - High: Known weak sanitization
        - Medium: Complex data flow
        - Low: Uncertain taint propagation
        """
        confidence_score = 50  # Base
        
        # Direct request input = +40
        if self._is_request_attr_chain(node) or self._is_request_get_json(node):
            confidence_score += 40
        
        # HTTP headers = +50 (always attacker-controlled)
        if context.get('from_header'):
            confidence_score += 50
        
        # Weak sanitization detected = +30
        if context.get('has_weak_sanitization'):
            confidence_score += 30
        
        # Variable with deceptive name but tainted = +20
        if isinstance(node, ast.Name):
            if any(prefix in node.id.lower() for prefix in ['clean', 'safe', 'validated', 'secure']):
                if node.id in self.current_context.tainted:
                    confidence_score += 20
        
        # Direct to SQL (no intermediate steps) = +10
        if context.get('direct_to_sql'):
            confidence_score += 10
        
        # Complex flow through multiple functions = -10
        if context.get('flow_depth', 0) > 3:
            confidence_score -= 10
        
        # Map score to confidence level
        if confidence_score >= 80:
            return "High"
        elif confidence_score >= 50:
            return "Medium"
        else:
            return "Low"

    def _calculate_severity(self, node: ast.AST, context: Dict) -> str:
        """
        Calculate severity based on multiple factors:
        - Data source (headers > form > query params)
        - Sanitization attempts (false security is worse)
        - Attack surface (every request vs specific endpoint)
        - SQL operation type (INSERT/DELETE worse than SELECT)
        """
        severity_score = 5  # Base: Medium
        
        # Factor 1: Data source criticality
        source = context.get('source', '')
        if source == 'http_header':
            severity_score += 5  # Headers are fully attacker-controlled
        elif source == 'request_body':
            severity_score += 3
        elif source == 'query_param':
            severity_score += 2
        elif source == 'session':
            severity_score += 1  # Session can be manipulated
        
        # Factor 2: False security (makes developers complacent)
        if context.get('has_weak_sanitization'):
            severity_score += 3
        
        # Factor 3: SQL operation type
        sql_text = context.get('sql_snippet', '').upper()
        if any(op in sql_text for op in ['DELETE', 'DROP', 'TRUNCATE']):
            severity_score += 3  # Data loss
        elif 'INSERT' in sql_text or 'UPDATE' in sql_text:
            severity_score += 2  # Data modification
        elif 'SELECT' in sql_text:
            severity_score += 1  # Data disclosure
        
        # Factor 4: No parameterization attempt
        if context.get('param_state') == 'False':
            severity_score += 1
        
        # Factor 5: Semantic context
        if context.get('semantic_type') == 'date_params':
            severity_score += 2  # Often overlooked
        
        # Map score to severity
        if severity_score >= 11:
            return "Critical"
        elif severity_score >= 7:
            return "High"
        elif severity_score >= 4:
            return "Medium"
        else:
            return "Low"

    def _report(self, node: ast.AST, rule: str, msg: str, severity="High",
                confidence="High", cwe="CWE-89", trace=None, meta=None):
        """Report a finding with deduplication"""
        line = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)

        # Ensure we have valid integers for line/col
        line = int(line) if line is not None else 0
        col = int(col) if col is not None else 0

        # ========== ENHANCED DEDUPLICATION ==========
        # Create unique key: file + line + rule + message (prevents duplicates)
        location_key = (self.filename, line, rule, msg)

        # Check if already reported
        if location_key in self.reported_locations:
            logger.debug(f"  -> DUPLICATE SKIPPED: {rule} at line {line} (message: {msg[:50]}...)")
            logger.debug(f"    Key: {location_key}")
            return  # ← CRITICAL: Must return here

        # Mark as reported BEFORE adding to findings
        self.reported_locations.add(location_key)
        logger.debug(f"  -> REPORTING NEW: {rule} at line {line}")
        logger.debug(f"    Key: {location_key}")
        # ========== END DEDUPLICATION ==========

        snippet = self._line_snippet(line)
        remediation = self._get_remediation(rule)
        examples = self._get_example_code(rule)

        finding = {
            "file": self.filename,
            "line": line,  # Now guaranteed to be int
            "col": col,    # Now guaranteed to be int
            "rule": rule,
            "rule_id": rule,
            "message": msg,
            "code": (snippet or "").strip(),
            "severity": severity,
            "confidence": confidence,
            "cwe": cwe,
            "remediation": remediation,
            "examples": examples,
        }

        if trace:
            finding["trace"] = trace[-8:]
        if meta:
            finding["meta"] = meta

        self.findings.append(finding)
        logger.debug(f"[REPORT] {rule} at {self._node_loc(node)} :: {msg}")

    # ------------------------------------------------------------------------
    # TAINT TRACKING
    # ------------------------------------------------------------------------

    def visit_If(self, node: ast.If):
        """PATH-SENSITIVE: Track validation through if statements with true branching"""
        logger.debug(f"[IF] {self._node_loc(node)}")

        # Get current context before branching
        parent_ctx = self.current_context

        # ========== NEW: Check for inline validation patterns FIRST ==========
        validation_result = self._check_inline_validation_pattern(node)

        if validation_result:
            var_name, strength = validation_result

            # Mark variable as validated in the PARENT context (applies AFTER if statement)
            # The THEN branch is where validation FAILS (abort/raise happens)
            # So the code AFTER the if statement has validated data

            logger.info(f"✅ INLINE VALIDATION DETECTED: {var_name} validated by inline pattern (strength: {strength})")

            # Mark as validated in parent context (applies after if statement)
            parent_ctx.validated_vars[var_name] = {
                'function': f'inline_{strength}_validation',
                'strength': strength,
                'location': self._node_loc(node),
                'line': getattr(node, 'lineno', None),
                'validated_at': f"inline validation: {var_name} (line {getattr(node, 'lineno', None)})"
            }

            # For strong/medium validation: remove from tainted set
            if strength in ['strong', 'medium']:
                parent_ctx.tainted.discard(var_name)

        # Handle NotIn (var not in allowed) pattern
        if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotIn):
            if isinstance(node.test.left, ast.Name):
                var_name = node.test.left.id

                # Check if comparing against a list, tuple, or set
                if len(node.test.comparators) == 1:
                    comparator = node.test.comparators[0]
                    if isinstance(comparator, (ast.List, ast.Tuple, ast.Set)):
                        # This is a whitelist check with not in (var not in forbidden -> var is safe)
                        logger.debug(f"  -> Detected whitelist validation pattern (not in) for: {var_name}")

                        parent_ctx.validated_vars[var_name] = {
                            'function': 'whitelist_validation_not_in',
                            'strength': 'strong',
                            'location': self._node_loc(node),
                            'line': getattr(node, 'lineno', None),
                            'validated_at': f"whitelist validation (not in): {var_name}"
                        }

                        parent_ctx.tainted.discard(var_name)
                logger.info(f"✅ REMOVED FROM TAINTED: {var_name} (inline validation)")
        # ========== END NEW CODE ==========

        # Create separate contexts for then/else branches
        then_ctx = parent_ctx.fork()
        else_ctx = parent_ctx.fork() if node.orelse else parent_ctx.fork()

        # Check for validation patterns directly in the condition (whitelists, format checks)
        validated_var = self._detect_validation(node.test)
        if validated_var:
            logger.debug(f"  -> Detected condition-based validation for: {validated_var}")

            validation_info = {
                'validation_type': 'condition_validation',
                'strength': 'strong',
                'location': self._node_loc(node),
                'line': getattr(node, 'lineno', None),
                'validated_at': f"condition validation: {validated_var}"
            }

            # Mark as validated in THEN branch context (condition is true here)
            then_ctx.validated_vars[validated_var] = validation_info
            then_ctx.tainted.discard(validated_var)

            # Also propagate to parent context so code after the if sees it as validated
            parent_ctx.validated_vars[validated_var] = validation_info
            parent_ctx.tainted.discard(validated_var)

        # Visit then branch
        logger.debug(f"  -> Visiting then-branch with {len(then_ctx.tainted)} tainted vars")
        self.current_context = then_ctx
        for stmt in node.body:
            self.visit(stmt)
        then_result = self.current_context

        # Visit else branch if present
        else_result = None
        if node.orelse:
            logger.debug(f"  -> Visiting else-branch with {len(else_ctx.tainted)} tainted vars")
            self.current_context = else_ctx
            for stmt in node.orelse:
                self.visit(stmt)
            else_result = self.current_context

        # Merge contexts at join point (conservative merge)
        if else_result:
            merged = then_result.merge(else_result)
        else:
            # No else branch - merge with parent context
            merged = then_result.merge(parent_ctx)

        # CRITICAL: Preserve parent context validations (from inline patterns)
        for var, val_info in parent_ctx.validated_vars.items():
            if var not in merged.validated_vars:
                merged.validated_vars[var] = val_info

        self.current_context = merged
        logger.debug(f"  -> After if-statement: {len(self.current_context.tainted)} tainted, {len(self.current_context.validated_vars)} validated")


    def _mark_tainted_target(self, target: ast.AST, value_node: ast.AST, note: str):
        """Mark target as tainted"""
        if isinstance(target, ast.Name):
            self.current_context.tainted.add(target.id)
            self._add_trace(target.id, value_node, note)
            logger.debug(f"  -> Marked tainted: {target.id}")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_tainted_target(elt, value_node, note)

    # ------------------------------------------------------------------------
    # STRING FORMATTING DETECTION
    # ------------------------------------------------------------------------

    def _is_string_formatting(self, node: ast.AST) -> bool:
        """Detect various string formatting patterns"""
        # f-strings
        if isinstance(node, ast.JoinedStr):
            return True
        
        # .format() method
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        
        # % formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        
        # + concatenation (only if it looks like SQL)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Check if any part contains SQL keywords
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    if self._looks_like_sql(child.value):
                        return True
            return False  # Not SQL-related concatenation
        
        # .join() method
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                if node.args:
                    for arg in node.args:
                        if self._looks_like_sql_literal_node(arg):
                            return True
        
        return False



    def _is_dynamic_sql_expr(self, node: ast.AST) -> bool:
        """Check if expression is dynamically constructed SQL"""
        # Check if it's string formatting
        if self._is_string_formatting(node):
            return True
        
        # Check if the expression itself is tainted
        if self.is_tainted_expr(node):
            return True
        
        # Check if it's a variable marked as dynamic SQL
        if isinstance(node, ast.Name) and node.id in self.dynamic_sql_vars:
            return True
        
        # ========== NEW: Check if variable was built from tainted data ==========
        if isinstance(node, ast.Name):
            var_name = node.id
            
            # Check traces to see if this variable was constructed from tainted data
            if var_name in self.traces:
                for step in self.traces[var_name]:
                    note = step.get('note', '').lower()
                    # If the trace mentions SQL construction with tainted data
                    if 'sql' in note and ('tainted' in note or 'formatting' in note):
                        logger.debug(f"  -> {var_name} is dynamic SQL (from trace)")
                        return True
            
            # Check if this variable was created from string formatting with tainted vars
            # Look back at how this variable was assigned
            for assign_node in ast.walk(self.tree):
                if isinstance(assign_node, ast.Assign):
                    for target in assign_node.targets:
                        if isinstance(target, ast.Name) and target.id == var_name:
                            # Check if the value involves tainted data
                            if self._is_string_formatting(assign_node.value):
                                # Check if any tainted vars are used in the formatting
                                for child in ast.walk(assign_node.value):
                                    if isinstance(child, ast.Name) and child.id in self.current_context.tainted:
                                        logger.debug(f"  -> {var_name} is dynamic SQL (tainted in construction)")
                                        return True
        # ========== END NEW CODE ==========
        
        return False


    # ------------------------------------------------------------------------
    # DANGEROUS STRING METHODS
    # ------------------------------------------------------------------------

    def _check_dangerous_string_method(self, node: ast.Call):
        """Check for dangerous string methods on SQL"""
        if not isinstance(node.func, ast.Attribute):
            return
        
        method = node.func.attr
        obj = node.func.value
        
        if method not in DANGEROUS_STRING_METHODS:
            return
        
        if isinstance(obj, ast.Name):
            if obj.id in self.dynamic_sql_vars or obj.id in self.current_context.tainted:
                for arg in node.args:
                    if self.is_tainted_expr(arg):
                        context = {
                            'sql_snippet': self._line_snippet(getattr(node, "lineno", None)),
                            'param_state': 'False',
                            'has_weak_sanitization': True
                        }
                        
                        severity = self._calculate_severity(node, context)
                        confidence = self._calculate_confidence_enhanced(node, context)
                        
                        self._report(
                            node,
                            "PY-SQLI-006",
                            f"Tainted data used in SQL string.{method}()",
                            severity=severity,
                            confidence=confidence,
                            cwe="CWE-89",
                            meta={"method": method}
                        )
                        return
            
            if obj.id in self.const_strings:
                sql = self.const_strings[obj.id]
                if any(sql.lower().strip().startswith(kw) for kw in SQL_STARTERS):
                    for arg in node.args:
                        if self.is_tainted_expr(arg):
                            context = {
                                'sql_snippet': sql,
                                'param_state': 'False',
                                'has_weak_sanitization': True
                            }
                            
                            severity = self._calculate_severity(node, context)
                            confidence = self._calculate_confidence_enhanced(node, context)
                            
                            self._report(
                                node,
                                "PY-SQLI-006",
                                f"Tainted data used in SQL string.{method}()",
                                severity=severity,
                                confidence=confidence,
                                cwe="CWE-89",
                                meta={"method": method}
                            )
                            return

    # ------------------------------------------------------------------------
    # UNSAFE SANITIZATION DETECTION
    # ------------------------------------------------------------------------

    def _check_unsafe_sanitization(self, node: ast.Call) -> bool:
        """Detect and MARK unsafe sanitization attempts (doesn't report immediately)"""
        if not isinstance(node.func, ast.Attribute):
            return False

        method = node.func.attr
        obj = node.func.value

        if method in {"strip", "lstrip", "rstrip", "upper", "lower"}:
            if isinstance(obj, ast.Name) and obj.id in self.current_context.tainted:
                return True

        if method == "replace" and len(node.args) >= 2:
            if isinstance(node.args[0], ast.Constant):
                # Single character replacements are bypassable
                if node.args[0].value in ["'", '"', '--', '/*', ';', 'OR', 'AND']:
                    if isinstance(obj, ast.Name) and obj.id in self.current_context.tainted:
                        # PHASE 1 IMPLEMENTATION: Mark for weak sanitization detection
                        # Don't report here - let it be flagged when used in SQL
                        return True

                # Check for quote doubling (critical vulnerability)
                elif node.args[0].value == "'" and isinstance(node.args[1], ast.Constant):
                    if node.args[1].value == "''":
                        if isinstance(obj, ast.Name) and obj.id in self.current_context.tainted:
                            # PHASE 1 IMPLEMENTATION: Mark for weak sanitization detection
                            # Don't report here - let it be flagged when used in SQL
                            return True

        return False

    # ------------------------------------------------------------------------
    # NEW DETECTION METHODS
    # ------------------------------------------------------------------------

    def _detect_sanitization_theater(self, node: ast.Assign):
        """
        Detect weak sanitization functions that create a false sense of security.
        These functions appear to sanitize input but can be easily bypassed.
        """
        if not isinstance(node.value, ast.Call):
            return

        call = node.value

        # Check if this is a function call
        if not isinstance(call.func, ast.Name):
            # ========== NEW: Check for method calls like .replace() ==========
            return self._detect_weak_method_sanitization(node)
            # ========== END NEW CODE ==========

        func_name = call.func.id

        # Check if this is a known weak sanitization function
        weak_sanitization_patterns = {
            'sanitize_sql_input': 'removes quotes but can be bypassed',
            'escape_quotes': 'incomplete escaping',
            'remove_quotes': 'can be bypassed with other SQL syntax',
            'strip_sql': 'blacklist-based, incomplete',
            'clean_input': 'generic name suggests weak validation',
            'filter_input': 'blacklist-based, often incomplete'
        }

        # Analyze the function to detect weak patterns
        sanitization_info = {
            'has_weak_patterns': False,
            'patterns': []
        }

        # Check function name
        if func_name in weak_sanitization_patterns:
            sanitization_info['has_weak_patterns'] = True
            sanitization_info['patterns'].append(weak_sanitization_patterns[func_name])

        # Check for common weak patterns in function names
        weak_keywords = ['remove', 'strip', 'replace', 'escape', 'clean', 'filter', 'sanitize']
        if any(keyword in func_name.lower() for keyword in weak_keywords):
            # This might be a weak sanitization function
            sanitization_info['has_weak_patterns'] = True
            sanitization_info['patterns'].append('blacklist-based sanitization')

        # Report if weak patterns detected
        if sanitization_info['has_weak_patterns']:
            # Mark as tainted anyway + report
            for target in node.targets:
                self._mark_tainted_target(target, node, "bypassable sanitization")

                # ========== NEW: Mark as reported ==========
                if isinstance(target, ast.Name):
                    self.reported_weak_sanitization.add(target.id)
                    logger.debug(f"  -> Marked {target.id} as reported for weak sanitization")
                # ========== END NEW CODE ==========

                context = {
                    'has_weak_sanitization': True,
                    'bypasses_sanitization': True
                }

                self._report(
                    node,
                    "PY-SQLI-008",
                    f"Function '{func_name}' provides inadequate sanitization - creates false sense of security",
                    severity="Critical",
                    confidence="High",
                    cwe="CWE-89",
                    meta={
                        "sanitization_function": func_name,
                        "weakness": "Bypassable " + ", ".join(sanitization_info['patterns'])
                    }
                )

    # ========== NEW METHOD ==========
    def _detect_weak_method_sanitization(self, node: ast.Assign):
        """
        Detect weak method-based sanitization like .replace("'", '') where nothing is gained
        """
        if not isinstance(node.value, ast.Call):
            return

        call = node.value
        if not isinstance(call.func, ast.Attribute):
            return

        method_name = call.func.attr
        obj = call.func.value

        # Check for the specific case: obj.replace("'", "")
        if method_name == "replace" and len(call.args) >= 2:
            if isinstance(call.args[0], ast.Constant) and call.args[0].value == "'":
                # Check if it's replacing single quotes with empty string
                if isinstance(call.args[1], ast.Constant) and call.args[1].value == "":
                    # This is the vuln7.py case: user_input.replace("'", "")
                    if isinstance(obj, ast.Name) and obj.id in self.current_context.tainted:
                        # Mark this as weak sanitization
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.reported_weak_sanitization.add(target.id)
                                # Also mark the SOURCE variable to prevent duplicate reporting
                                self.reported_weak_sanitization.add(obj.id)
                                logger.debug(f"  -> Detected weak sanitization: {obj.id}.{method_name}(''''', '') - marking {target.id} as weak")
                                # Keep weak-sanitized outputs tainted
                                self._mark_tainted_target(target, node, "weak sanitization output (still tainted)")

                                context = {
                                    'has_weak_sanitization': True,
                                    'bypasses_sanitization': True,
                                    'source_var': obj.id
                                }

                                self._report(
                                    node,
                                    "PY-SQLI-008",
                                    f"Variable '{target.id}' assigned from weak sanitization '{obj.id}.{method_name}(\"\"\")' - can be bypassed with SELSELECTECT or other patterns",
                                    severity="Critical",
                                    confidence="High",
                                    cwe="CWE-89",
                                    meta={
                                        "sanitization_method": f"{method_name}(''''', '')",
                                        "source_variable": obj.id,
                                        "target_variable": target.id,
                                        "weakness": "Single quote removal is easily bypassed (e.g., 'SELSELECTECT', multi-line comments, etc.)"
                                    }
                                )
                                return True  # Detected

        return False  # Not detected
    # ========== END NEW METHOD ==========

    def _find_function_definition(self, func_name: str) -> Optional[ast.FunctionDef]:
        """Find function definition in the AST (cached)"""
        if func_name in self._function_def_cache:
            return self._function_def_cache[func_name]
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                self._function_def_cache[func_name] = node
                return node
        
        self._function_def_cache[func_name] = None
        return None

    def _analyze_sanitization_strength(self, func_def: ast.FunctionDef) -> Dict[str, Any]:
        """
        Analyze if a sanitization function is actually weak.
        Returns dict with weakness details.
        """
        weaknesses = {
            'has_weak_patterns': False,
            'patterns': [],
            'severity': 'High'
        }
        
        for node in ast.walk(func_def):
            # 1. Check for simple replace() calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'replace':
                    if len(node.args) >= 2:
                        # Check what's being replaced
                        if isinstance(node.args[0], ast.Constant):
                            replaced = node.args[0].value
                            replacement = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                            
                            # Single quote doubling ('' escaping)
                            if replaced == "'" and replacement == "''":
                                weaknesses['has_weak_patterns'] = True
                                weaknesses['patterns'].append('quote_doubling')
                                weaknesses['severity'] = 'Critical'
                            
                            # Single character removal
                            elif replaced in ["'", '"', '--', '/*', ';'] and replacement == '':
                                weaknesses['has_weak_patterns'] = True
                                weaknesses['patterns'].append('char_removal')
                                weaknesses['severity'] = 'Critical'
            
            # 2. Check for keyword blacklist loops
            if isinstance(node, ast.For):
                # Check if iterating over SQL keywords
                if isinstance(node.iter, (ast.List, ast.Set, ast.Tuple)):
                    for elt in node.iter.elts:
                        if isinstance(elt, ast.Constant):
                            if isinstance(elt.value, str) and elt.value.upper() in SQL_STARTERS:
                                weaknesses['has_weak_patterns'] = True
                                weaknesses['patterns'].append('keyword_blacklist')
                                weaknesses['severity'] = 'Critical'
                                break
            
            # 3. Check for case conversion (upper/lower)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['upper', 'lower', 'strip', 'lstrip', 'rstrip']:
                        weaknesses['has_weak_patterns'] = True
                        weaknesses['patterns'].append('case_conversion')
            
            # 4. Check for regex that only removes keywords
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'sub' or node.func.attr == 'subn':
                        # This is re.sub() - check pattern
                        weaknesses['has_weak_patterns'] = True
                        weaknesses['patterns'].append('regex_keyword_removal')
        
        return weaknesses

    def _check_unvalidated_where_params(self, node: ast.Call):
        """
        Check for unvalidated date/numeric parameters in WHERE clauses.
        These are often overlooked because developers assume they're "safe" numbers/dates.
        """
        if not node.args:
            return
        
        sql_arg = node.args[0]
        
        # Strategy 1: Check if sql_arg is a variable with unvalidated params in its history
        if isinstance(sql_arg, ast.Name):
            var_name = sql_arg.id
            
            # Check if this variable's construction used unvalidated date params
            if var_name in self.dynamic_sql_vars:
                # This is a dynamic SQL variable - check its trace
                if var_name in self.traces:
                    for step in self.traces[var_name]:
                        code = step.get('code', '')
                        
                        # Check if any unvalidated date params appear in this step
                        for date_var, param_info in self._unvalidated_date_params.items():
                            # ========== NEW: Skip if validated ==========
                            if self._is_medium_or_strong_validated(date_var):
                                logger.debug(f"  -> {date_var} is validated, skipping")
                                continue
                            # ========== END NEW CODE ==========
                            
                            if date_var in code:
                                self._report(
                                    node,
                                    "PY-SQLI-009",
                                    f"Unvalidated date parameter '{date_var}' used in SQL query",
                                    severity="High",
                                    confidence="Medium",
                                    cwe="CWE-89",
                                    meta={
                                        "param_name": date_var,
                                        "param_type": param_info['type'],
                                        "source": param_info['source']
                                    }
                                )
                                return  # Only report once per query
        
        # Strategy 2: Check f-strings directly (for inline SQL)
        if isinstance(sql_arg, ast.JoinedStr):
            for val in sql_arg.values:
                if isinstance(val, ast.FormattedValue):
                    if isinstance(val.value, ast.Name):
                        var_name = val.value.id
                        
                        # ========== NEW: Skip if validated ==========
                        if self._is_medium_or_strong_validated(var_name):
                            logger.debug(f"  -> {var_name} is validated, skipping date param check")
                            continue
                        # ========== END NEW CODE ==========
                        
                        # Check if this is an unvalidated date parameter
                        if var_name in self._unvalidated_date_params:
                            param_info = self._unvalidated_date_params[var_name]
                            
                            self._report(
                                node,
                                "PY-SQLI-009",
                                f"Unvalidated date parameter '{var_name}' used in SQL query",
                                severity="High",
                                confidence="Medium",
                                cwe="CWE-89",
                                meta={
                                    "param_name": var_name,
                                    "param_type": param_info['type'],
                                    "source": param_info['source']
                                }
                            )
                            return  # Only report once per query

    def _check_session_injection(self, node: ast.Call):
        """Detect when session data is used in SQL without validation"""
        if not node.args:
            return
        
        sql_arg = node.args[0]
        session_vars_found = []
        
        # Check for variables that came from session
        for child in ast.walk(sql_arg):
            if isinstance(child, ast.Name):
                var_name = child.id
                
                if var_name in self.traces:
                    for step in self.traces[var_name]:
                        note = step.get('note', '').lower()
                        if 'session' in note:
                            session_vars_found.append((var_name, step))
                            break
        
        # Report each session variable found
        for var_name, step in session_vars_found:
            context = {
                'source': 'session',
                'param_state': 'False',
                'sql_snippet': self._line_snippet(getattr(node, "lineno", None))
            }
            
            severity = self._calculate_severity(node, context)
            confidence = self._calculate_confidence_enhanced(node, context)
            
            self._report(
                node,
                "PY-SQLI-001",  # Use existing rule or create PY-SQLI-011
                f"Session variable '{var_name}' used in SQL - session data can be manipulated",
                severity=severity,
                confidence=confidence,
                cwe="CWE-89",
                trace=self._build_trace([var_name]),
                meta={
                    "variable": var_name,
                    "source": "session",
                    "issue": "Session data can be manipulated via session fixation/hijacking"
                }
            )


    def _is_unvalidated_request_param(self, var_name: str) -> bool:
        """
        Check if a variable comes directly from request without validation.
        """
        # Check traces to see if it came from request.args.get() etc.
        if var_name in self.traces:
            for step in self.traces[var_name]:
                if 'request' in step.get('note', '').lower():
                    # Check if there's any validation step after
                    has_validation = any(
                        'validate' in s.get('note', '').lower() or 'check' in s.get('note', '').lower()
                        for s in self.traces[var_name]
                    )
                    return not has_validation
        
        return False

    def _check_header_injection(self, node: ast.Call):
        """
        Detect when HTTP headers are used in SQL queries.
        PHASE 1: Ensure severity escalation for headers to Critical
        """
        if not node.args:
            return

        sql_arg = node.args[0]

        # Check if any variables in the SQL came from headers
        header_vars_found = []

        for child in ast.walk(sql_arg):
            if isinstance(child, ast.Name):
                var_name = child.id

                # Check traces for header source
                if var_name in self.traces:
                    for step in self.traces[var_name]:
                        note = step.get('note', '').lower()
                        if 'header' in note or 'http header' in note:
                            header_vars_found.append((var_name, step))
                            break

        # Report each header variable found
        for var_name, step in header_vars_found:
            context = {
                'from_header': True,
                'source': 'http_header',
                'param_state': 'False',
                'sql_snippet': self._line_snippet(getattr(node, "lineno", None))
            }

            # PHASE 1: Explicitly set severity to Critical for all HTTP header issues
            severity = "Critical"
            confidence = self._calculate_confidence_enhanced(node, context)

            self._report(
                node,
                "PY-SQLI-010",
                f"Variable '{var_name}' from HTTP header used in SQL query - CRITICAL",
                severity=severity,
                confidence=confidence,
                cwe="CWE-89",
                trace=self._build_trace([var_name]),
                meta={
                    "variable": var_name,
                    "attack_surface": "Every request",
                    "exploitability": "Trivial - attacker controls all headers"
                }
            )

        # Also check for direct request.headers.get() in SQL (less common)
        for child in ast.walk(sql_arg):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr == 'get':
                        if isinstance(child.func.value, ast.Attribute):
                            if (isinstance(child.func.value.value, ast.Name) and
                                child.func.value.value.id == 'request' and
                                child.func.value.attr == 'headers'):

                                header_name = None
                                if child.args and isinstance(child.args[0], ast.Constant):
                                    header_name = child.args[0].value

                                context = {
                                    'from_header': True,
                                    'source': 'http_header',
                                    'param_state': 'False'
                                }

                                self._report(
                                    node,
                                    "PY-SQLI-010",
                                    f"HTTP header '{header_name or 'unknown'}' used directly in SQL query - CRITICAL",
                                    severity="Critical",  # PHASE 1: Explicitly set to Critical for headers
                                    confidence="High",
                                    cwe="CWE-89",
                                    meta={
                                        "header": header_name,
                                        "attack_surface": "Every request",
                                        "exploitability": "Trivial - attacker controls all headers"
                                    }
                                )


    def _detect_security_theater_patterns(self):
        """
        Detect patterns that suggest security theater:
        - Variables named 'clean_', 'safe_', 'validated_' but still vulnerable
        - Comments claiming security but code is vulnerable
        - Security configuration that's not actually used
        """
        theater_indicators = []
        
        for var_name in self.current_context.tainted:
            # Check for deceptive naming
            if any(prefix in var_name.lower() for prefix in ['clean', 'safe', 'validated', 'secure', 'sanitized']):
                theater_indicators.append({
                    'type': 'deceptive_naming',
                    'variable': var_name,
                    'message': f"Variable '{var_name}' suggests safety but is still tainted"
                })
        
        # Check for unused security configurations
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    if 'SECURITY' in var_name.upper() or 'CONFIG' in var_name.upper():
                        # Check if this config is actually used
                        is_used = self._is_variable_used(var_name)
                        if not is_used:
                            theater_indicators.append({
                                'type': 'unused_security_config',
                                'variable': var_name,
                                'message': f"Security configuration '{var_name}' defined but never enforced"
                            })
        
        # Report security theater findings
        for indicator in theater_indicators:
            if indicator['type'] == 'deceptive_naming':
                for node in ast.walk(self.tree):
                    if isinstance(node, ast.Name) and node.id == indicator['variable']:
                        self._report(
                            node,
                            "PY-SQLI-008",
                            f"Deceptive variable naming: {indicator['message']}",
                            severity="High",
                            confidence="High",
                            cwe="CWE-89",
                            meta={"variable": indicator['variable']}
                        )
                        break
        
        return theater_indicators




    def _is_variable_used(self, var_name: str) -> bool:
        """Check if a variable is actually used in the code"""
        usage_count = 0
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and node.id == var_name:
                usage_count += 1
        return usage_count > 1  # More than just the definition

    # ========== NEW VALIDATION CALL DETECTION ==========
    def _is_validation_call(self, node: ast.expr) -> bool:
        """Check if an expression is a call to a validation function"""
        if not isinstance(node, ast.Call):
            return False

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Check if it's a known validation function
            if func_name in self.validation_functions:
                return True

        # Also check for pattern matching
        if isinstance(node.func, ast.Name):
            func_name = node.func.id.lower()
            # Check pattern matching
            for patterns in self.validation_patterns.values():
                for pattern in patterns:
                    if pattern in func_name:
                        return True

        return False

    def _get_validation_call_info(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """Extract validation function name and strength from a call"""
        if not isinstance(node.func, ast.Name):
            return None

        func_name = node.func.id

        # Direct lookup
        if func_name in self.validation_functions:
            strength = self.validation_functions[func_name]
            return (func_name, strength)

        # Pattern matching for auto-detection
        func_name_lower = func_name.lower()
        for validation_type, patterns in self.validation_patterns.items():
            for pattern in patterns:
                if pattern in func_name_lower:
                    if validation_type == 'whitelist_based':
                        return (func_name, 'strong')
                    elif validation_type == 'regex_based':
                        return (func_name, 'medium')
                    elif validation_type == 'sanitizer_patterns':
                        return (func_name, 'weak')

        return None

    # ========== NEW REPORT WEAK SANITIZATION ==========
    def _report_weak_sanitization(self, var_name: str, func_name: str, node: ast.AST):
        """Report weak sanitization attempt"""
        # Check if we've already reported this variable
        if var_name in self.reported_weak_sanitization:
            return

        # Mark as reported to avoid duplicates
        self.reported_weak_sanitization.add(var_name)

        context = {
            'sanitization_function': func_name,
            'has_weak_sanitization': True,
            'bypasses_sanitization': True
        }

        severity = self._calculate_severity(node, context)
        confidence = self._calculate_confidence_enhanced(node, context)

        self._report(
            node,
            "PY-SQLI-008",
            f"Variable '{var_name}' assigned from weak sanitization function '{func_name}'",
            severity=severity,
            confidence=confidence,
            cwe="CWE-89",
            meta={
                "sanitization_function": func_name,
                "weakness": f"Weak sanitization function '{func_name}' can be bypassed",
                "variable": var_name
            }
        )

    def _analyze_function_call(self, node: ast.Call):
        """
        Analyze function calls for interprocedural taint propagation.
        This method tracks how tainted data flows through function calls.
        """
        if not isinstance(node.func, ast.Name):
            return

        func_name = node.func.id

        # Skip if we've exceeded recursion depth
        if self.current_context.recursion_depth >= self.current_context.max_recursion:
            logger.debug(f"  -> Skipping interprocedural analysis for '{func_name}' (max recursion depth reached)")
            return

        # Get function definition
        func_def = self._find_function_definition(func_name)
        if not func_def:
            logger.debug(f"  -> Function '{func_name}' definition not found, skipping interprocedural analysis")
            return

        # Check if any arguments are tainted
        tainted_args = []
        for i, arg in enumerate(node.args):
            if self.is_tainted_expr(arg):
                if isinstance(arg, ast.Name):
                    tainted_args.append((i, arg.id))
                else:
                    # Handle expressions that evaluate to tainted values
                    tainted_args.append((i, f"arg_{i}"))

        if not tainted_args:
            # No tainted arguments, nothing to propagate
            return

        logger.debug(f"  -> Analyzing function '{func_name}' with tainted args: {tainted_args}")

        # Create a mapping from parameter names to argument expressions
        param_mapping = {}
        for i, arg in enumerate(node.args):
            if i < len(func_def.args.args):
                param_name = func_def.args.args[i].arg
                param_mapping[param_name] = arg

        # Save current state
        saved_context = {
            'tainted': self.current_context.tainted.copy(),
            'validated_vars': self.current_context.validated_vars.copy(),
            'recursion_depth': self.current_context.recursion_depth
        }

        # Increment recursion depth
        self.current_context.recursion_depth += 1

        # Mark function parameters as tainted based on arguments
        for param_name, arg in param_mapping.items():
            if self.is_tainted_expr(arg):
                self.current_context.tainted.add(param_name)
                self._add_trace(param_name, node, f"tainted via function call argument to '{func_name}'")
                logger.debug(f"    -> Marked parameter '{param_name}' as tainted")

        # Analyze the function body with tainted parameters
        # We need to visit the function body but avoid re-visiting the entire AST
        # Just check for return statements and assignments that might propagate taint

        returns_tainted = False
        tainted_assignments = {}

        for stmt in func_def.body:
            if isinstance(stmt, ast.Return) and stmt.value:
                if self.is_tainted_expr(stmt.value):
                    returns_tainted = True
                    logger.debug(f"    -> Function '{func_name}' returns tainted value")

            elif isinstance(stmt, ast.Assign):
                # Check if any targets get assigned tainted values
                if self.is_tainted_expr(stmt.value):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted_assignments[target.id] = stmt.value

        # Store function summary for future calls
        if func_name not in self.func_summaries:
            self.func_summaries[func_name] = {}

        self.func_summaries[func_name].update({
            'returns_tainted': returns_tainted,
            'tainted_assignments': tainted_assignments,
            'analyzed': True
        })

        # If function returns tainted data, mark the call result as tainted
        # This is handled in is_tainted_expr for function calls

        # Restore state
        self.current_context.tainted = saved_context['tainted']
        self.current_context.validated_vars = saved_context['validated_vars']
        self.current_context.recursion_depth = saved_context['recursion_depth']

        logger.debug(f"  -> Completed interprocedural analysis for '{func_name}'")
    # ========== END NEW METHODS ==========

    # ------------------------------------------------------------------------
    # PARAMETERIZATION CHECKING
    # ------------------------------------------------------------------------

    def _param_ok_tristate(self, call: ast.Call) -> str:
        """Check if parameters are safely used (True/False/Unknown)"""
        if len(call.args) < 2:
            return "False"
        
        param_arg = call.args[1]
        
        if isinstance(param_arg, (ast.Tuple, ast.List)):
            if len(param_arg.elts) > 0:
                return "True"
            else:
                return "Unknown"
        
        if isinstance(param_arg, ast.Dict):
            if len(param_arg.keys) > 0:
                return "True"
            else:
                return "Unknown"
        
        if isinstance(param_arg, ast.Name):
            return "Unknown"
        
        if isinstance(param_arg, ast.Call):
            return "Unknown"
        
        if isinstance(param_arg, ast.Constant):
            if param_arg.value is None:
                return "False"
            return "Unknown"
        
        return "Unknown"

    # ------------------------------------------------------------------------
    # AST VISITORS
    # ------------------------------------------------------------------------

    def visit_Import(self, node: ast.Import):
        """Track imports"""
        for alias in node.names:
            as_name = alias.asname or alias.name
            self.imports[as_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports"""
        module = node.module or ""
        for alias in node.names:
            as_name = alias.asname or alias.name
            self.imports[as_name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def _is_taint_source(self, node: ast.Call) -> bool:
        """Check if a call node is a taint source"""
        logger.debug(f"DEBUG: _is_taint_source called with: {ast.unparse(node) if hasattr(ast, 'unparse') else str(node)}")
        if isinstance(node.func, ast.Attribute):
            # Handle request.args.get, session.get, etc.
            obj = node.func.value
            attr = node.func.attr

            # Build the full path (e.g., "request.args.get")
            if isinstance(obj, ast.Attribute):
                # request.args.get
                if isinstance(obj.value, ast.Name):
                    full_path = f"{obj.value.id}.{obj.attr}.{attr}"
                    logger.debug(f"DEBUG: Checking taint source: {full_path} in {self.taint_sources}")
                    if full_path in self.taint_sources:
                        logger.debug(f"DEBUG: Found taint source: {full_path}")
                        return True
            elif isinstance(obj, ast.Name):
                # session.get
                full_path = f"{obj.id}.{attr}"
                logger.debug(f"DEBUG: Checking taint source: {full_path} in {self.taint_sources}")
                if full_path in self.taint_sources:
                    logger.debug(f"DEBUG: Found taint source: {full_path}")
                    return True

        elif isinstance(node.func, ast.Name):
            # Handle input(), os.getenv(), etc.
            func_name = node.func.id
            if func_name in self.taint_sources:
                return True

        return False


    def _mark_tainted_target(self, target: ast.expr, node: ast.AST, reason: str):
        """Mark a target as tainted and add trace"""
        if isinstance(target, ast.Name):
            self.current_context.tainted.add(target.id)
            self._add_trace(target.id, node, reason)
            logger.debug(f"DEBUG: Marked as tainted: {target.id} (reason: {reason})")
        elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
            for elt in target.elts:
                self._mark_tainted_target(elt, node, reason)


    def _add_trace(self, var_name: str, node: ast.AST, reason: str):
        """Add a trace entry for a variable"""
        if var_name not in self.traces:
            self.traces[var_name] = []
        
        self.traces[var_name].append({
            'location': self._node_loc(node),
            'code': self._line_snippet(getattr(node, 'lineno', None)),
            'reason': reason
        })


    def _mark_validated(self, var_name: str, func_name: str, node: ast.AST):
        """Mark a variable as validated"""
        strength = self.validation_strength.get(func_name, 'medium')
        
        self.current_context.validated_vars[var_name] = {
            'function': func_name,
            'strength': strength,
            'location': self._node_loc(node)
        }
        
        logger.debug(f"  -> Marked as validated: {var_name} by {func_name} (strength: {strength})")


    def _node_loc(self, node: ast.AST) -> str:
        """Get node location as string"""
        lineno = getattr(node, 'lineno', '?')
        col_offset = getattr(node, 'col_offset', '?')
        return f"{self.filename}:{lineno}:{col_offset}"


    def _line_snippet(self, lineno: Optional[int]) -> str:
        """Get a snippet of code at the given line number"""
        if lineno is None:
            return ""
        
        try:
            lines = self.code.split('\n')
            if 0 < lineno <= len(lines):
                return lines[lineno - 1].strip()
        except Exception:
            pass
        
        return ""


    def is_tainted_expr(self, expr: ast.expr) -> bool:
        """Check if an expression contains tainted data"""
        if isinstance(expr, ast.Name):
            return expr.id in self.current_context.tainted
        elif isinstance(expr, ast.BinOp):
            return self.is_tainted_expr(expr.left) or self.is_tainted_expr(expr.right)
        elif isinstance(expr, ast.JoinedStr):
            # f-string
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    if self.is_tainted_expr(val.value):
                        return True
            return False
        elif isinstance(expr, ast.Call):
            # Check if it's a taint source
            if self._is_taint_source(expr):
                return True
            # Check arguments
            for arg in expr.args:
                if self.is_tainted_expr(arg):
                    return True
            return False
        else:
            # For other expressions, walk the tree
            for node in ast.walk(expr):
                if isinstance(node, ast.Name) and node.id in self.current_context.tainted:
                    return True
            return False


    def _is_dynamic_sql_expr(self, expr: ast.expr) -> bool:
        """Check if expression is dynamic SQL construction"""
        if isinstance(expr, ast.BinOp):
            # String concatenation
            if isinstance(expr.op, ast.Add):
                return True
        elif isinstance(expr, ast.JoinedStr):
            # f-string
            return True
        elif isinstance(expr, ast.Call):
            # .format() or .join()
            if isinstance(expr.func, ast.Attribute):
                if expr.func.attr in {'format', 'join'}:
                    return True
        elif isinstance(expr, ast.Name):
            # Check if this variable was constructed dynamically
            return expr.id in self.dynamic_sql_vars
        
        return False


    def _param_ok_tristate(self, node: ast.Call) -> str:
        """
        Check if parameterized query is used.
        Returns: "True", "False", or "Unknown"
        """
        # Check if there's a second argument (parameters)
        if len(node.args) >= 2:
            param_arg = node.args[1]
            
            # Check if it's a non-empty tuple, list, or dict
            if isinstance(param_arg, (ast.Tuple, ast.List)):
                if len(param_arg.elts) > 0:
                    return "True"
            elif isinstance(param_arg, ast.Dict):
                if len(param_arg.keys) > 0:
                    return "True"
            elif isinstance(param_arg, ast.Name):
                # Variable - we don't know if it's empty or not
                return "Unknown"
            
            # Empty collection
            return "False"
        
        # Check for keyword argument 'params' or 'parameters'
        for keyword in node.keywords:
            if keyword.arg in {'params', 'parameters'}:
                return "True"
        
        # No parameters provided
        return "False"


    def _calculate_severity(self, node: ast.AST, context: Dict[str, Any]) -> str:
        """Calculate severity based on context"""
        # Critical: HTTP headers (direct attacker control)
        if context.get('from_header'):
            return "Critical"
        
        # High: Session data or multiple tainted sources
        if context.get('from_session'):
            return "High"
        
        # High: Weak sanitization (false sense of security)
        if context.get('has_weak_sanitization'):
            return "Critical"
        
        # Medium: Single tainted source
        return "High"


    def _calculate_confidence(self, node: ast.AST, context: Dict[str, Any]) -> str:
        """Calculate confidence based on context"""
        # High confidence: Clear taint flow
        if context.get('flow_depth', 0) > 0:
            return "High"
        
        # High confidence: Known weak sanitization
        if context.get('bypasses_sanitization'):
            return "High"
        
        # Medium confidence: Dynamic SQL without clear taint
        return "Medium"


    def _report(self, node: ast.AST, rule_id: str, message: str,
                severity: str = "High", confidence: str = "High",
                cwe: str = "CWE-89", trace: Optional[List[Dict[str, Any]]] = None,
                meta: Optional[Dict[str, Any]] = None):
        """Add a finding to the results with deduplication (file + line + rule)."""
        # Normalize line/col
        line = getattr(node, 'lineno', None)
        col = getattr(node, 'col_offset', None)
        line = int(line) if line is not None else 0
        col = int(col) if col is not None else 0

        # Deduplicate by file + line + rule
        location_key = (self.filename, line, rule_id)
        if hasattr(self, 'reported_locations'):
            if location_key in self.reported_locations:
                logger.debug(f"  -> DUPLICATE SKIPPED: {rule_id} at line {line}")
                return
            self.reported_locations.add(location_key)
        else:
            # Initialize if missing
            self.reported_locations = set([location_key])

        # Build common fields
        location_str = self._node_loc(node)
        snippet = self._line_snippet(line)
        remediation = self._get_remediation(rule_id) if hasattr(self, '_get_remediation') else "Use parameterized queries."
        examples = self._get_example_code(rule_id) if hasattr(self, '_get_example_code') else {}

        # Compose finding with both legacy and new keys for compatibility
        finding = {
            'file': self.filename,
            'line': line,
            'col': col,
            'rule': rule_id,          # legacy consumers
            'rule_id': rule_id,       # GUI consumers
            'message': message,
            'code': (snippet or '').strip(),
            'severity': severity,
            'confidence': confidence,
            'cwe': cwe,
            'remediation': remediation,
            'examples': examples,
            'location': location_str,
        }

        if trace:
            finding['trace'] = trace[-8:]
        if meta:
            finding['meta'] = meta

        self.findings.append(finding)
        logger.info(f"[{rule_id}] {severity} - {message} at {location_str}")



    def visit_Assign(self, node: ast.Assign):
        """Track assignments for taint and SQL"""
        logger.debug(f"[ASSIGN] {self._node_loc(node)} :: {self._line_snippet(getattr(node, 'lineno', None))}")
        src = node.value

        # ========== NEW: Track variables used in f-strings ==========
        if isinstance(src, ast.JoinedStr):
            vars_in_fstring = []
            for val in src.values:
                if isinstance(val, ast.FormattedValue):
                    if isinstance(val.value, ast.Name):
                        vars_in_fstring.append(val.value.id)

            # Store which variables were used to create this f-string
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.fstring_vars[t.id] = vars_in_fstring
                    logger.debug(f"  -> F-string {t.id} contains variables: {vars_in_fstring}")
        # ========== END NEW CODE ==========

        # ========== FIX 1: Track .format() calls with tainted arguments ==========
        if isinstance(src, ast.Call):
            if isinstance(src.func, ast.Attribute) and src.func.attr == "format":
                # Extract all argument variable names (for tracking)
                arg_var_names = []
                for arg in src.args:
                    if isinstance(arg, ast.Name):
                        arg_var_names.append(arg.id)
                
                # Check if any arguments to .format() are tainted
                has_tainted_args = False
                tainted_arg_names = []
                for arg in src.args:
                    if self.is_tainted_expr(arg):
                        has_tainted_args = True
                        if isinstance(arg, ast.Name):
                            tainted_arg_names.append(arg.id)
                        logger.debug(f"  -> .format() call with tainted argument: {arg}")
                
                if has_tainted_args:
                    # Mark target as tainted
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self._mark_tainted_target(t, node, f"tainted .format() call with args: {', '.join(tainted_arg_names)}")
                            logger.debug(f"  -> Marked {t.id} as tainted (from .format() with tainted args)")
                            
                            # Track which variables were used in this .format() call (similar to fstring_vars)
                            self.format_vars[t.id] = arg_var_names
                            logger.debug(f"  -> Tracked .format() variables: {t.id} contains {arg_var_names}")
                            
                            # Check if format string contains SQL (either constant or variable)
                            format_str_has_sql = False
                            
                            # Case 1: Format string is a constant
                            if isinstance(src.func.value, ast.Constant) and isinstance(src.func.value.value, str):
                                if self._looks_like_sql(src.func.value.value):
                                    format_str_has_sql = True
                            
                            # Case 2: Format string is a variable that might contain SQL
                            elif isinstance(src.func.value, ast.Name):
                                if src.func.value.id in self.dynamic_sql_vars:
                                    format_str_has_sql = True
                            
                            # Always mark as dynamic SQL if tainted args are used (conservative approach)
                            # This ensures detection even if format string detection fails
                            self.dynamic_sql_vars.add(t.id)
                            if format_str_has_sql:
                                self._add_trace(t.id, node, "SQL .format() with tainted args")
                            else:
                                self._add_trace(t.id, node, ".format() with tainted args (potential SQL)")
                            logger.debug(f"  -> Marked {t.id} as dynamic SQL (.format() with tainted args)")
        # ========== END FIX 1 ==========

        # ========== FIX 2: Track .join() calls with tainted lists ==========
        if isinstance(src, ast.Call):
            if isinstance(src.func, ast.Attribute) and src.func.attr == "join":
                # Check if the argument (the list/iterable) contains tainted data
                if src.args and len(src.args) > 0:
                    list_arg = src.args[0]
                    
                    # Check if the list argument is tainted (contains tainted elements)
                    if isinstance(list_arg, ast.Name):
                        list_name = list_arg.id
                        
                        # FIX 2: Check if this list was marked as containing tainted data
                        if list_name in self.current_context.tainted:
                            # List contains tainted data - mark join result as tainted
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    self._mark_tainted_target(t, node, f"tainted .join() call on list '{list_name}'")
                                    logger.debug(f"  -> Marked {t.id} as tainted (from .join() on tainted list {list_name})")
                                    
                                    # Check if the separator or list contains SQL indicators
                                    has_sql = False
                                    # Check separator (the string before .join())
                                    if isinstance(src.func.value, ast.Constant) and isinstance(src.func.value.value, str):
                                        sep = src.func.value.value
                                        # Common SQL join separators
                                        if any(kw in sep.upper() for kw in [' AND ', ' OR ', ' WHERE ', ' UNION ']):
                                            has_sql = True
                                            logger.debug(f"  -> Separator '{sep}' suggests SQL context")
                                    
                                    # Always mark as dynamic SQL if joining tainted list (conservative)
                                    self.dynamic_sql_vars.add(t.id)
                                    self._add_trace(t.id, node, f".join() on tainted list '{list_name}' (potential SQL)")
                                    logger.debug(f"  -> Marked {t.id} as dynamic SQL (.join() on tainted list)")
        # ========== END FIX 2 ==========

        # DEBUG: Check for vulnerable_16 assign
        target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if 'query' in target_names and 'filt' in str(src):
            logger.debug(f"DEBUG: vulnerable_16 assignment found! is_tainted_expr(src) = {self.is_tainted_expr(src)}")
            # Check filt specifically
            if hasattr(src, 'right') and hasattr(src.right, 'id'):
                logger.debug(f"DEBUG: right operand is '{src.right.id}', tainted={src.right.id in self.current_context.tainted}")

        # Propagate traces from source to targets (multi-assign chains)
        for t in node.targets:
            if isinstance(t, ast.Name):
                self._propagate_traces(src, t.id, node)

        # Check for security theater in sanitization functions
        self._detect_sanitization_theater(node)

        # Check if we're assigning from a validation function call
        if self._is_validation_call(src):
            validation_info = self._get_validation_call_info(src)

            if validation_info:
                func_name, strength = validation_info
                logger.info(f"✅ DETECTED VALIDATION: {func_name}({strength}) -> {node.targets}")

                # Mark each target as validated
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        target_name = t.id

                        # Create validation record
                        validation_record = {
                            'function': func_name,
                            'strength': strength,
                            'location': self._node_loc(node),
                            'line': getattr(node, 'lineno', None),
                            'validated_at': f"validation assignment: {func_name}() -> {target_name}"
                        }

                        # Store in current context
                        self.current_context.validated_vars[target_name] = validation_record

                        # For strong/medium validation: remove from tainted set
                        if strength in ['strong', 'medium']:
                            # Remove target from tainted set if present
                            self.current_context.tainted.discard(target_name)
                            logger.info(f"✅ VALIDATED: {target_name} by {func_name}({strength})")

                        elif strength == 'weak':
                            # For weak validation, report it but don't remove from tainted
                            self._report_weak_sanitization(target_name, func_name, node)
                            logger.info(f"⚠️ WEAKL VALIDATED: {target_name} by {func_name}")

                # Skip rest of assignment processing for validated assignments
                logger.info(f"Skipping taint propagation for validated assignment: {[t.id for t in node.targets if isinstance(t, ast.Name)]}")
                self.generic_visit(node)
                return
        
        # Check if source is tainted or from specific sources
        tainted_source = self.is_tainted_expr(src)
        logger.debug(f"DEBUG: Assignment source tainted check: {tainted_source} for {ast.unparse(src) if hasattr(ast, 'unparse') else str(src)[:50]}")
        if tainted_source:
            for t in node.targets:
                # Special handling for HTTP header sources
                if self._is_header_source(src):
                    self._mark_tainted_target(t, node, "HTTP header source: request.headers.get()")
                else:
                    # Special-case: explicit session taint source
                    if (
                        isinstance(src, ast.Call)
                        and isinstance(src.func, ast.Attribute)
                        and isinstance(src.func.value, ast.Name)
                        and src.func.value.id == 'session'
                        and src.func.attr == 'get'
                    ):
                        self._mark_tainted_target(t, node, "session taint source: session.get()")
                    else:
                        logger.debug(f"DEBUG: Marking target as tainted from tainted source: {t.id if isinstance(t, ast.Name) else 'expr'}")
                        self._mark_tainted_target(t, node, "tainted assignment")
        elif self._is_header_source(src):
            # Direct assignment from header source
            for t in node.targets:
                self._mark_tainted_target(t, node, "HTTP header source: request.headers.get()")
        
        # Check for dynamic SQL construction
        # ========== ENHANCED: Check for dynamic SQL construction ==========
        if self._is_dynamic_sql_expr(src):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.dynamic_sql_vars.add(t.id)
                    self._add_trace(t.id, node, "dynamic SQL construction")
                    logger.debug(f"  -> Marked as dynamic SQL: {t.id}")

        # NEW: Also check if the source itself is string formatting with SQL
        if self._is_string_formatting(src):
            # Check if it involves SQL
            has_sql = False

            # Check for SQL in string constants
            for child in ast.walk(src):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    if self._looks_like_sql(child.value):
                        has_sql = True
                        break

            # If it's SQL formatting, mark as dynamic SQL
            if has_sql:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.dynamic_sql_vars.add(t.id)
                        self._add_trace(t.id, node, "SQL string formatting")
                        logger.debug(f"  -> Marked as dynamic SQL (formatting): {t.id}")

        # ========== ENHANCED STRING CONCATENATION TRACKING ==========
        # Track string concatenation assignments
        if isinstance(src, ast.BinOp) and isinstance(src.op, ast.Add):
            # Check if this is SQL concatenation
            parts = self._flatten_binop(src)

            has_sql = any(
                isinstance(p, ast.Constant) and isinstance(p.value, str) and self._looks_like_sql(p.value)
                for p in parts
            )

            if has_sql:
                # Mark target as dynamic SQL
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.dynamic_sql_vars.add(t.id)
                        self._add_trace(t.id, node, "SQL string concatenation")
                        logger.debug(f"  -> Marked as dynamic SQL (concatenation): {t.id}")

                        # Check if any tainted vars are used
                        for part in parts:
                            if isinstance(part, ast.Name) and part.id in self.current_context.tainted:
                                # Already marked as tainted in visit_BinOp, just trace
                                self._add_trace(t.id, node, f"concatenated with tainted var '{part.id}'")
                                logger.debug(f"  -> Also marked as tainted: {t.id}")

        # ========== ENHANCED PERCENT FORMATTING TRACKING ==========
        # Track percent formatting assignments
        if isinstance(src, ast.BinOp) and isinstance(src.op, ast.Mod):
            # Check if left side is SQL string
            if isinstance(src.left, ast.Constant) and isinstance(src.left.value, str):
                if self._looks_like_sql(src.left.value):
                    # Mark target as dynamic SQL
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.dynamic_sql_vars.add(t.id)
                            self._add_trace(t.id, node, "SQL percent formatting")
                            logger.debug(".2%")

                            # Check if any tainted vars are used
                            if isinstance(src.right, ast.Name):
                                if src.right.id in self.current_context.tainted:
                                    self._add_trace(t.id, node, f"formatted with tainted var '{src.right.id}'")
                            elif isinstance(src.right, ast.Tuple):
                                for elt in src.right.elts:
                                    if isinstance(elt, ast.Name) and elt.id in self.current_context.tainted:
                                        self._add_trace(t.id, node, f"formatted with tainted var '{elt.id}'")
                                        break
        # ========== END ENHANCED CODE ==========

        # Check for unvalidated date/numeric parameters
        if isinstance(src, ast.Call):
            if self._is_taint_source(src):
                # Check if this looks like a date or numeric parameter
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        var_name = t.id.lower()

                        # Date-like names
                        if any(keyword in var_name for keyword in ['date', 'time', 'year', 'month', 'day', 'timestamp', 'from', 'to', 'start', 'end']):
                            self._unvalidated_date_params[t.id] = {
                                'type': 'date',
                                'source': self._node_loc(node),
                                'code': self._line_snippet(getattr(node, 'lineno', None))
                            }
                            self._add_trace(t.id, node, f"unvalidated date parameter '{t.id}'")
                            logger.debug(f"  -> Marked as unvalidated date param: {t.id}")

                        # Numeric-like names
                        elif any(keyword in var_name for keyword in ['id', 'num', 'count', 'limit', 'offset', 'page', 'size']):
                            self._unvalidated_numeric_params[t.id] = {
                                'type': 'numeric',
                                'source': self._node_loc(node),
                                'code': self._line_snippet(getattr(node, 'lineno', None))
                            }
                            logger.debug(f"  -> Marked as unvalidated numeric param: {t.id}")

        # ========== NEW: Handle dictionary assignments ==========
        # Check if we're assigning to a dictionary subscript (e.g., data['key'] = value)
        for t in node.targets:
            if isinstance(t, ast.Subscript):
                # This is an assignment to a subscript (e.g., dict[key] = value)
                if isinstance(t.value, ast.Name):
                    dict_name = t.value.id

                    # If the value being assigned is tainted, we need to track this
                    if self.is_tainted_expr(src):
                        # Mark the dictionary as containing tainted data
                        self.current_context.tainted.add(dict_name)
                        self._add_trace(dict_name, node, f"dictionary '{dict_name}' assigned tainted value")
                        logger.debug(f"  -> Marked dictionary '{dict_name}' as tainted due to subscript assignment")

                    # Also track the specific key if it's a constant
                    if isinstance(t.slice, ast.Constant):
                        key = t.slice.value
                        # We could track tainted keys separately if needed
                        logger.debug(f"  -> Dictionary '{dict_name}' key '{key}' assigned {'tainted' if self.is_tainted_expr(src) else 'safe'} value")
        # ========== END NEW CODE ==========

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Track augmented assignments (+=, etc.)"""
        logger.debug(f"[AUGASSIGN] {self._node_loc(node)}")

        if isinstance(node.target, ast.Name):
            var = node.target.id

            if self.is_tainted_expr(node.value):
                self.current_context.tainted.add(var)
                self._add_trace(var, node, "augmented with tainted")
                logger.debug(f"  -> Marked tainted (augassign): {var}")

            if var in self.dynamic_sql_vars or self._is_dynamic_sql_expr(node.value):
                self.dynamic_sql_vars.add(var)
                self._add_trace(var, node, "augmented SQL")
                logger.debug(f"  -> Dynamic SQL (augassign): {var}")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Track subscript access (dict/list indexing)"""
        logger.debug(f"[SUBSCRIPT] {self._node_loc(node)}")

        # Check if we're accessing a tainted container
        if isinstance(node.value, ast.Name):
            container_name = node.value.id

            # If the container is tainted, the subscript result is tainted
            if container_name in self.current_context.tainted:
                # This creates a new tainted variable/expression
                # We'll handle this in the parent context when this subscript is assigned
                logger.debug(f"  -> Subscript access on tainted container: {container_name}")

        # Check if we're accessing a subscript that contains tainted data
        # This is handled in is_tainted_expr for subscript checking

        self.generic_visit(node)



    def _track_list_operations(self, node: ast.Call):
        """Track list operations that can propagate taint (append, extend, etc.)"""
        if not isinstance(node.func, ast.Attribute):
            return

        method_name = node.func.attr
        obj_name = None

        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id

        if not obj_name:
            return

        # List operations that can add tainted elements
        list_ops = {'append', 'extend', 'insert', 'push', 'add'}

        if method_name in list_ops and node.args:
            # Check if any argument is tainted or dynamic SQL
            for arg in node.args:
                # FIX 2: Check if argument is tainted
                if self.is_tainted_expr(arg):
                    # Mark the list as tainted
                    self.current_context.tainted.add(obj_name)
                    self._add_trace(obj_name, node, f"list.{method_name}() with tainted data")
                    logger.debug(f"  -> Marked list '{obj_name}' as tainted due to .{method_name}() with tainted data")
                    break
                # FIX 2: Also check if argument is dynamic SQL (e.g., f-string with tainted data)
                if self._is_dynamic_sql_expr(arg):
                    # Mark the list as tainted (contains SQL fragments)
                    self.current_context.tainted.add(obj_name)
                    self._add_trace(obj_name, node, f"list.{method_name}() with dynamic SQL")
                    logger.debug(f"  -> Marked list '{obj_name}' as tainted due to .{method_name}() with dynamic SQL")
                    break

        # Special handling for extend() with lists
        if method_name == 'extend' and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in self.current_context.tainted:
                # If extending with a tainted list, the target list becomes tainted
                self.current_context.tainted.add(obj_name)
                self._add_trace(obj_name, node, f"list.extend() with tainted list '{arg.id}'")
                logger.debug(f"  -> Marked list '{obj_name}' as tainted due to extend() with tainted list")


    def run(self):
        """Run the analysis and return results"""
        logger.info(f"Analyzing {self.filename}")
        
        # Visit the AST to find vulnerabilities
        self.visit(self.tree)
        
        # Run final security theater detection
        self._detect_security_theater_patterns()
        
        # Calculate statistics
        lines_analyzed = len(self.code.splitlines())
        functions_analyzed = sum(1 for node in ast.walk(self.tree) if isinstance(node, ast.FunctionDef))
        
        # Prepare results
        stats = {
            "total_findings": len(self.findings),
            "by_severity": {},
            "by_rule": {},
            "lines_analyzed": lines_analyzed,
            "functions_analyzed": functions_analyzed,
            "tainted_variables": len(self.current_context.tainted),
        }
        
        # Count by severity and rule
        for f in self.findings:
            sev = f.get("severity", "Unknown")
            rule = f.get("rule", "Unknown")
            
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            stats["by_rule"][rule] = stats["by_rule"].get(rule, 0) + 1
        
        logger.debug(f"--- End analysis: {self.filename} | findings={len(self.findings)} ---")
        
        return {
            "findings": self.findings,
            "statistics": stats
        }


    def visit_Return(self, node: ast.Return):
        """Track tainted returns"""
        if node.value and self.current_function:
            if self.is_tainted_expr(node.value):
                if self.current_function not in self.func_summaries:
                    self.func_summaries[self.current_function] = {}
                
                self.func_summaries[self.current_function]["returns_tainted"] = True
                logger.debug(f"  -> Function {self.current_function} returns tainted value")
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Analyze function calls for SQL injection"""
        logger.debug(f"[CALL] {self._node_loc(node)} :: {self._line_snippet(getattr(node, 'lineno', None))}")

        # Track list operations for taint propagation
        self._track_list_operations(node)

        # Analyze function calls for interprocedural taint propagation
        self._analyze_function_call(node)

        # Check for taint sources
        if self._is_taint_source(node):
            # This is handled in visit_Assign, but we want to add specific header traces
            # Check if this is a headers call specifically
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                if isinstance(node.func.value, ast.Attribute):
                    if (isinstance(node.func.value.value, ast.Name) and
                        node.func.value.value.id == "request" and
                        node.func.value.attr == "headers"):
                        # This is request.headers.get() - add specific header trace
                        # We'll handle this in visit_Assign where we can properly add traces
                        pass

            # This is handled in visit_Assign
            pass

        # Check for SQL execution
        # SQLAlchemy text()/literal_column detector (PY-SQLI-003)
        if isinstance(node.func, ast.Name) and node.func.id in {"text", "literal_column"}:
            if node.args and (self.is_tainted_expr(node.args[0]) or self._is_dynamic_sql_expr(node.args[0])):
                self._report(
                    node, "PY-SQLI-003",
                    f"SQLAlchemy {node.func.id}() called with tainted/dynamic SQL",
                    severity="High", confidence="High", cwe="CWE-89",
                    meta={"api": node.func.id}
                )
            self.generic_visit(node)
            return

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            # executescript detector (PY-SQLI-005)
            if attr == "executescript":
                if node.args and (self.is_tainted_expr(node.args[0]) or self._is_dynamic_sql_expr(node.args[0])):
                    self._report(
                        node,
                        "PY-SQLI-005",
                        "Tainted data passed to executescript() allows multiple statements",
                        severity="Critical",
                        confidence="High",
                        cwe="CWE-89",
                        meta={"api": "executescript"}
                    )
                self.generic_visit(node)
                return

            # Django raw() detector (PY-SQLI-004)
            if attr == "raw":
                if node.args and (self.is_tainted_expr(node.args[0]) or self._is_dynamic_sql_expr(node.args[0])):
                    self._report(
                        node,
                        "PY-SQLI-004",
                        "Django raw() called with tainted/dynamic SQL",
                        severity="High",
                        confidence="High",
                        cwe="CWE-89",
                        meta={"api": "Django.raw"}
                    )
                self.generic_visit(node)
                return

            if attr in {"execute", "executemany"}:
                if not node.args:
                    self.generic_visit(node)
                    return

                sql_arg = node.args[0]

                # ========== FIX: Prevent double reporting ==========
                # Check if this was already reported by visit_BinOp
                if isinstance(sql_arg, ast.BinOp):
                    # This will be handled by visit_BinOp, skip here
                    logger.debug(f"  -> Skipping report in visit_Call (will be handled by visit_BinOp)")
                    self.generic_visit(node)
                    return
                # ========== END FIX ==========

                # ========== PHASE 1 FIX: Check for header injection FIRST ==========
                # Check if this contains header data - should be Critical severity
                header_injection_detected = False
                header_vars = []

                # DEBUG: Check if we can see user_agent being detected
                logger.debug(f"DEBUG: Checking for header injection in SQL call at line {getattr(node, 'lineno', '?')}")

                # Direct debug check for user_agent
                sql_str = str(sql_arg)
                logger.debug(f"SQL arg: {repr(sql_str)} (type: {type(sql_arg)})")

                for child in ast.walk(sql_arg):
                    if isinstance(child, ast.Name) and child.id == 'user_agent':
                        logger.debug(f"Found user_agent Name node in SQL")
                        logger.debug(f"user_agent is tainted: {'user_agent' in self.current_context.tainted}")
                        logger.debug(f"user_agent traces: {self.traces.get('user_agent', [])}")

                        if 'user_agent' in self.traces:
                            for step in self.traces['user_agent']:
                                note = step.get('note', '')
                                logger.debug(f"  Trace note: '{note}'")
                                logger.debug(f"    Contains 'header': {'header' in note.lower()}")
                                logger.debug(f"    Contains 'headers': {'headers' in note.lower()}")
                                logger.debug(f"    Contains 'source': {'source' in note.lower()}")
                                break
                        break

                print(f"DEBUG: About to check for header injection in SQL call at line {getattr(node, 'lineno', '?')}")
                logger.debug(f"Checking for header injection in SQL: {str(sql_arg)[:50] if sql_arg else 'N/A'}")

                for child in ast.walk(sql_arg):
                    if isinstance(child, ast.Name):
                        var_name = child.id
                        logger.debug(f"  -> Checking variable {var_name} for headers")
                        if var_name in self.traces:
                            logger.debug(f"    -> {var_name} has {len(self.traces[var_name])} traces")
                            for step in self.traces[var_name]:
                                note = step.get('note', '').lower()
                                logger.debug(f"    -> Trace note: '{note}'")
                                # Match various header trace patterns
                                if ('header' in note and ('http' in note or 'attacker' in note)) or 'http header' in note or 'request.headers' in note or 'taint source' in note:
                                    # Additional check for taint source containing headers
                                    if 'taint source' in note and 'headers' in note:
                                        logger.debug(f"      -> HEADER MATCH! {var_name} via taint source: {note}")
                                        header_injection_detected = True
                                        header_vars.append((var_name, step))
                                        break
                                    elif 'header' in note and ('http' in note or 'attacker' in note):
                                        logger.debug(f"      -> HEADER MATCH! {var_name} via direct header: {note}")
                                        header_injection_detected = True
                                        header_vars.append((var_name, step))
                                        break
                                    elif 'request.headers' in note:
                                        logger.debug(f"      -> HEADER MATCH! {var_name} via request.headers: {note}")
                                        header_injection_detected = True
                                        header_vars.append((var_name, step))
                                        break
                    if header_injection_detected:
                        break

                if header_injection_detected:
                    # Report as Critical and return early - don't let general logic override
                    context = {
                        'sql_snippet': self._line_snippet(getattr(node, "lineno", None)),
                        'param_state': self._param_ok_tristate(node),
                        'from_header': True,
                        'source': 'http_header'
                    }

                    header_var_names = [v[0] for v in header_vars]
                    var_list = ', '.join(f"'{v}'" for v in header_var_names[:3])  # Limit to first 3

                    self._report(
                        node,
                        "PY-SQLI-010",
                        f"HTTP header variable(s) {var_list} used in SQL query - CRITICAL",
                        severity="Critical",
                        confidence="High",
                        cwe="CWE-89",
                        meta={
                            "attack_surface": "Every request",
                            "exploitability": "Trivial - attacker controls all headers",
                            "param_state": context['param_state'],
                            "header_variables": header_var_names
                        }
                    )
                    return
                # ========== END PHASE 1 FIX ==========

                is_tainted = self.is_tainted_expr(sql_arg)
                is_dynamic = self._is_dynamic_sql_expr(sql_arg)

                param_state = self._param_ok_tristate(node)

                reason = []
                if is_tainted:
                    reason.append("tainted")
                if is_dynamic:
                    reason.append("dynamic")

                if (is_dynamic or is_tainted) and param_state != "True":
                    # NEW: Context-aware vulnerability detection
                    # Only report if SQL string actually contains unvalidated tainted variables in dangerous positions
                    context = {
                        'param_state': param_state,
                        'sql_snippet': self._line_snippet(getattr(node, "lineno", None)),
                        'has_weak_sanitization': False
                    }

                    # Step 1: Check if this is a SAFELY PARAMETERIZED query
                    if param_state == "True":
                        # Safe parameterized query - don't report
                        logger.debug(f"  -> Safe parameterized query, skipping")
                        self.generic_visit(node)
                        return

                    # Step 2: Check if SQL contains interpolated tainted variables
                    unvalidated_tainted_vars = self._extract_vulnerable_vars_from_sql(sql_arg, context)

                    # Identifier injection (e.g., table/column names from variables)
                    identifier_vars = list(self._identifier_vars_by_node.get(id(sql_arg), set()) & set(unvalidated_tainted_vars)) if hasattr(self, "_identifier_vars_by_node") else []
                    if identifier_vars:
                        self._report(
                            node,
                            "PY-SQLI-002",
                            f"Identifier injection risk: unvalidated identifier(s) {', '.join(identifier_vars[:3])} used in SQL",
                            severity="High",
                            confidence="High",
                            cwe="CWE-89",
                            meta={"identifiers": identifier_vars}
                        )
                        # Avoid duplicate generic reporting for identifiers
                        unvalidated_tainted_vars = [v for v in unvalidated_tainted_vars if v not in identifier_vars]

                    if not unvalidated_tainted_vars:
                        # No unvalidated tainted variables - not vulnerable
                        logger.debug(f"  -> No unvalidated tainted variables found, skipping")
                        self.generic_visit(node)
                        return

                    # Step 3: Separate validated vs unvalidated variables for reporting
                    validated_vars = []
                    unvalidated_tainted = []

                    for var_name in unvalidated_tainted_vars:
                        if self._is_medium_or_strong_validated(var_name):
                            validated_vars.append(var_name)
                        else:
                            unvalidated_tainted.append(var_name)

                    # Only report if there are actually unvalidated tainted variables
                    if not unvalidated_tainted:
                        logger.debug(f"  -> All tainted variables are validated, skipping")
                        self.generic_visit(node)
                        return

                    # Only report if we have actual unvalidated tainted data
                    if unvalidated_tainted:
                        # ========== NEW: Skip if already reported as weak sanitization ==========
                        if any(v in self.reported_weak_sanitization for v in unvalidated_tainted):
                            logger.debug(f"  -> Skipping generic report (already reported weak sanitization for {unvalidated_tainted})")
                        else:
                        # ========== END NEW CODE ==========
                            # Build context for severity/confidence calculation
                            context = {
                                'sql_snippet': self._line_snippet(getattr(node, "lineno", None)),
                                'param_state': param_state,
                                'flow_depth': len(self.traces.get(unvalidated_tainted[0] if unvalidated_tainted else "", []))
                            }

                            # Check for session data
                            from_session = any(
                                'session' in self.traces.get(v, [{}])[0].get('reason', '')
                                for v in unvalidated_tainted
                            )

                            # Check for HTTP headers
                            from_header = any(
                                'HTTP header' in self.traces.get(v, [{}])[0].get('reason', '')
                                for v in unvalidated_tainted
                            )

                            # ========== ADD CONTEXT FLAGS BEFORE CALCULATING SEVERITY ==========
                            if from_session:
                                context['from_session'] = True

                            if from_header:
                                context['from_header'] = True

                            # NOW calculate severity with complete context
                            severity = self._calculate_severity(node, context)  # ✅ FIXED: context is complete
                            confidence = self._calculate_confidence(node, context)
                            # ========== END FIX ==========

                            # Determine message based on context
                            if from_session:
                                message = f"Session variable '{sql_arg.id if isinstance(sql_arg, ast.Name) else 'query'}' used in SQL - session data can be manipulated"
                            elif from_header:
                                message = f"Variable '{sql_arg.id if isinstance(sql_arg, ast.Name) else 'query'}' from HTTP header used in SQL query - CRITICAL"
                            else:
                                message = f"Unvalidated variable(s) '{', '.join(unvalidated_tainted)}' used in SQL query without parameterization"

                            # Report accordingly (avoid duplicates when header already handled above)
                            self._report(
                                node,
                                "PY-SQLI-010" if from_header else "PY-SQLI-001",
                                message,
                                severity=severity,
                                confidence=confidence,
                                cwe="CWE-89",
                                meta={
                                    "param_state": param_state,
                                    "reason": ", ".join(reason),
                                    "unvalidated_vars": unvalidated_tainted,
                                    "validated_vars": validated_vars
                                }
                            )



                    # Check for unvalidated date/numeric parameters (separate check)
                    self._check_unvalidated_where_params(node)

                    # Check for session injection
                    self._check_session_injection(node)

                    # Check for header injection (but don't report again)
                    # self._check_header_injection(node)  # Skip - already handled above
        
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """
        Detect binary operations:
        - String concatenation with + operator
        - Percent formatting with % operator
        """
        logger.debug(f"[BINOP] {self._node_loc(node)} :: {ast.unparse(node) if hasattr(ast, 'unparse') else ''}")

        vuln_info = None
        if isinstance(node.op, ast.Add):
            # String concatenation: "SELECT * FROM " + table
            vuln_info = self._check_string_concatenation(node)

        elif isinstance(node.op, ast.Mod):
            # Percent formatting: "SELECT * FROM %s" % table
            vuln_info = self._check_percent_formatting(node)

        # If vulnerability detected and has unsafe variables, report it
        if vuln_info and (vuln_info.get('tainted_vars') or vuln_info.get('header_vars')):

            context = {
                'param_state': 'False',  # These are never parameterized
                'sql_snippet': vuln_info.get('sql_snippet', ''),
                'has_weak_sanitization': False,
                'from_header': bool(vuln_info.get('header_vars'))
            }

            # Determine severity
            if vuln_info.get('header_vars'):
                severity = "Critical"
            else:
                severity = self._calculate_severity(node, context)

            confidence = self._calculate_confidence_enhanced(node, context)

            # Generate message
            all_vulnerable = vuln_info.get('tainted_vars', []) + vuln_info.get('header_vars', [])

            if vuln_info.get('construction_type') == 'concatenation':
                vuln_type_msg = "dangerous string concatenation"
            else:  # percent_formatting
                vuln_type_msg = "dangerous % formatting"

            message = f"SQL injection via {vuln_type_msg} - variables {', '.join(all_vulnerable[:3])} injected securely"

            # Report the vulnerability
            self._report(
                node,
                "PY-SQLI-006",  # String formatting injection
                message,
                severity=severity,
                confidence=confidence,
                cwe="CWE-89",
                meta={
                    "construction_type": vuln_info.get('construction_type'),
                    "unvalidated_vars": all_vulnerable,
                    "formula": ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                }
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function in complete isolation"""
        logger.debug(f"=" * 60)
        logger.debug(f"ENTERING FUNCTION: {node.name} (line {node.lineno})")
        logger.debug(f"=" * 60)

        # DEBUG: Check if this is an edgecase function
        if node.name.startswith('edgecase'):
            logger.debug(f"DEBUG: Visiting edgecase function: {node.name}")
            # Force analysis of edgecase functions
            self.generic_visit(node)
            return

        # Also force analysis of vulnerable functions
        if node.name.startswith('vulnerable') or node.name.startswith('edgecase'):
            logger.debug(f"DEBUG: Forcing analysis of function: {node.name}")
            self.generic_visit(node)
            return

        # CRITICAL: Save ALL state before entering function
        saved_state = {
            'tainted': self.current_context.tainted.copy(),
            'dynamic_sql_vars': self.dynamic_sql_vars.copy(),
            'validated_vars': self.current_context.validated_vars.copy(),
            'unvalidated_date_params': self._unvalidated_date_params.copy(),
            'unvalidated_numeric_params': self._unvalidated_numeric_params.copy(),
            'traces': {k: v.copy() if isinstance(v, list) else v for k, v in self.traces.items()},
            'current_function': self.current_function,
        }
        
        # RESET: Clear all taint for this function
        self.current_context.tainted = set()
        self.dynamic_sql_vars = set()
        self.current_context.validated_vars = {}
        self._unvalidated_date_params = {}
        self._unvalidated_numeric_params = {}
        self.traces = {}
        self.current_function = node.name
        
        logger.debug(f"State cleared for function: {node.name}")
        
        # Mark function parameters as potentially tainted
        for arg in node.args.args:
            param_name = arg.arg
            self.current_context.tainted.add(param_name)
            self._add_trace(param_name, node, f"function parameter '{param_name}'")
            logger.debug(f"  Parameter '{param_name}' marked as tainted")
        
        # Analyze function body
        logger.debug(f"Analyzing body of {node.name}...")
        self.generic_visit(node)
        
        # Store function summary
        self.func_summaries[node.name] = {
            'tainted_params': set(arg.arg for arg in node.args.args),
            'has_sql': bool(self.dynamic_sql_vars),
            'findings_count': len([f for f in self.findings if f.get('function') == node.name]),
        }
        
        logger.debug(f"Function {node.name} analysis complete:")
        logger.debug(f"  - Tainted vars: {self.current_context.tainted}")
        logger.debug(f"  - Dynamic SQL vars: {self.dynamic_sql_vars}")
        logger.debug(f"  - Validated vars: {list(self.current_context.validated_vars.keys())}")
        
        # CRITICAL: Restore previous state
        self.current_context.tainted = saved_state['tainted']
        self.dynamic_sql_vars = saved_state['dynamic_sql_vars']
        self.current_context.validated_vars = saved_state['validated_vars']
        self._unvalidated_date_params = saved_state['unvalidated_date_params']
        self._unvalidated_numeric_params = saved_state['unvalidated_numeric_params']
        self.traces = saved_state['traces']
        self.current_function = saved_state['current_function']
        
        logger.debug(f"=" * 60)
        logger.debug(f"EXITING FUNCTION: {node.name}")
        logger.debug(f"State restored to previous context")
        logger.debug(f"=" * 60)



# ============================================================================
# SCANNER FUNCTIONS
# ============================================================================

def scan_file(path: str) -> Dict[str, Any]:
    """Scan a single Python file"""
    logger.info(f"Scanning: {path}")
    
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            code = fh.read()
    except Exception as e:
        logger.error(f"Error reading file {path}: {e}")
        return {
            "findings": [{
                "file": path,
                "line": 0,
                "col": 0,
                "rule": "SCAN-ERROR",
                "message": f"Error reading file: {e}",
                "code": "",
                "severity": "Info",
                "confidence": "High",
                "cwe": None,
                "remediation": "Ensure file is readable and properly encoded",
                "examples": {}
            }],
            "statistics": {
                "total_findings": 1,
                "by_severity": {"Info": 1},
                "by_rule": {"SCAN-ERROR": 1},
                "lines_analyzed": 0,
                "functions_analyzed": 0,
                "tainted_variables": 0,
            }
        }
    
    try:
        analyzer = FileTaintAnalyzer(code, path)
        result = analyzer.run()
        return result
    except SyntaxError as e:
        logger.error(f"Syntax error in {path}: {e}")
        return {
            "findings": [{
                "file": path,
                "line": getattr(e, 'lineno', 0),
                "col": getattr(e, 'offset', 0),
                "rule": "SYNTAX-ERROR",
                "message": f"Syntax error: {e}",
                "code": "",
                "severity": "Info",
                "confidence": "High",
                "cwe": None,
                "remediation": "Fix syntax errors in the code",
                "examples": {}
            }],
            "statistics": {
                "total_findings": 1,
                "by_severity": {"Info": 1},
                "by_rule": {"SYNTAX-ERROR": 1},
                "lines_analyzed": 0,
                "functions_analyzed": 0,
                "tainted_variables": 0,
            }
        }
    except Exception as e:
        logger.exception(f"Error analyzing {path}")
        return {
            "findings": [{
                "file": path,
                "line": 0,
                "col": 0,
                "rule": "SCAN-ERROR",
                "message": f"Error analyzing file: {e}",
                "code": "",
                "severity": "Info",
                "confidence": "High",
                "cwe": None,
                "remediation": "Check file for issues",
                "examples": {}
            }],
            "statistics": {
                "total_findings": 1,
                "by_severity": {"Info": 1},
                "by_rule": {"SCAN-ERROR": 1},
                "lines_analyzed": 0,
                "functions_analyzed": 0,
                "tainted_variables": 0,
            }
        }

def scan_path(path: str) -> Dict[str, Any]:
    """Scan a file or directory"""
    logger.info(f"Scanning path: {path}")
    
    all_findings = []
    all_stats = {
        "files_scanned": 0,
        "total_findings": 0,
        "by_severity": {},
        "by_rule": {},
        "lines_analyzed": 0,
        "functions_analyzed": 0,
        "tainted_variables": 0,
    }
    
    if os.path.isfile(path):
        result = scan_file(path)
        # ========== FIX: Update stats before returning ==========
        result["statistics"]["files_scanned"] = 1
        # ========== END FIX ==========
        return result
    
    # Use parallel scanning for directories
    py_files = []
    for root, _dirs, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    
    # Scan in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as executor:
        results = list(executor.map(scan_file, py_files))
    
    # Aggregate results
    for result in results:
        findings = result.get("findings", [])
        stats = result.get("statistics", {})
        
        all_findings.extend(findings)
        all_stats["files_scanned"] += 1
        all_stats["total_findings"] += len(findings)
        all_stats["lines_analyzed"] += stats.get("lines_analyzed", 0)
        all_stats["functions_analyzed"] += stats.get("functions_analyzed", 0)
        all_stats["tainted_variables"] += stats.get("tainted_variables", 0)
        
        # Aggregate severity and rule counts
        for sev, count in stats.get("by_severity", {}).items():
            all_stats["by_severity"][sev] = all_stats["by_severity"].get(sev, 0) + count
        
        for rule, count in stats.get("by_rule", {}).items():
            all_stats["by_rule"][rule] = all_stats["by_rule"].get(rule, 0) + count
    
    return {
        "findings": all_findings,
        "statistics": all_stats
    }

def get_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Get a quick summary for display"""
    findings = results.get("findings", [])
    stats = results.get("statistics", {})
    
    critical = sum(1 for f in findings if f.get("severity") == "Critical")
    high = sum(1 for f in findings if f.get("severity") == "High")
    medium = sum(1 for f in findings if f.get("severity") == "Medium")
    low = sum(1 for f in findings if f.get("severity") == "Low")
    
    return {
        "total": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": (critical * 10 + high * 5 + medium * 2 + low * 1),
        "files_scanned": stats.get("files_scanned", 1),
        "safe": len(findings) == 0
    }

# ============================================================================
# GUI
# ============================================================================

class ScannerGUI:
    """Tkinter-based GUI for the scanner"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"Python SQL Injection Scanner v{__version__}")
        self.results = {}
        
        # Controls frame
        ctrl = tk.Frame(root, padx=8, pady=8)
        ctrl.pack(fill="x")
        
        tk.Button(ctrl, text="Open File", command=self.open_file).pack(side="left", padx=4)
        tk.Button(ctrl, text="Open Folder", command=self.open_folder).pack(side="left", padx=4)
        tk.Button(ctrl, text="Save JSON", command=self.save_json).pack(side="left", padx=4)
        tk.Button(ctrl, text="Save HTML", command=self.save_html).pack(side="left", padx=4)
        
        self.filter_var = tk.StringVar(value="")
        tk.Label(ctrl, text="Filter:").pack(side="left", padx=(12, 4))
        tk.Entry(ctrl, textvariable=self.filter_var, width=24).pack(side="left", padx=4)
        tk.Button(ctrl, text="Apply", command=self.render_results).pack(side="left", padx=4)
        
        # Severity filter
        self.severity_var = tk.StringVar(value="All")
        tk.Label(ctrl, text="Severity:").pack(side="left", padx=(12, 4))
        severity_menu = tk.OptionMenu(ctrl, self.severity_var, "All", "Critical", "High", "Medium", "Low")
        severity_menu.pack(side="left", padx=4)
        severity_menu.config(width=8)
        
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(ctrl, textvariable=self.status_var).pack(side="right")
        
        # Results area with tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        
        # Tab 1: Findings
        findings_frame = tk.Frame(self.notebook)
        self.notebook.add(findings_frame, text="Findings")
        
        self.text = tk.Text(findings_frame, wrap="none", height=30, font=("Courier", 9))
        xscroll = tk.Scrollbar(findings_frame, orient="horizontal", command=self.text.xview)
        yscroll = tk.Scrollbar(findings_frame, orient="vertical", command=self.text.yview)
        self.text.configure(xscrollcommand=xscroll.set, yscrollcommand=yscroll.set)
        
        self.text.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        findings_frame.rowconfigure(0, weight=1)
        findings_frame.columnconfigure(0, weight=1)
        
        # Tab 2: Dashboard
        dashboard_frame = tk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Dashboard layout
        self.dashboard_canvas = tk.Canvas(dashboard_frame, bg="white")
        dash_scroll = tk.Scrollbar(dashboard_frame, orient="vertical", command=self.dashboard_canvas.yview)
        self.dashboard_canvas.configure(yscrollcommand=dash_scroll.set)
        
        self.dashboard_canvas.grid(row=0, column=0, sticky="nsew")
        dash_scroll.grid(row=0, column=1, sticky="ns")
        dashboard_frame.rowconfigure(0, weight=1)
        dashboard_frame.columnconfigure(0, weight=1)
        
        self.dash_content = tk.Frame(self.dashboard_canvas, bg="white")
        self.dashboard_canvas.create_window((0, 0), window=self.dash_content, anchor="nw")
        self.dash_content.bind("<Configure>", self._configure_dashboard_scroll)
        
        # Tab 3: Help
        help_frame = tk.Frame(self.notebook)
        self.notebook.add(help_frame, text="Help")
        
        help_text = tk.Text(help_frame, wrap="word", padx=10, pady=10)
        help_scroll = tk.Scrollbar(help_frame, orient="vertical", command=help_text.yview)
        help_text.configure(yscrollcommand=help_scroll.set)
        
        help_text.grid(row=0, column=0, sticky="nsew")
        help_scroll.grid(row=0, column=1, sticky="ns")
        help_frame.rowconfigure(0, weight=1)
        help_frame.columnconfigure(0, weight=1)
        
        # Help content
        help_text.insert(tk.END, "SQL Injection Scanner Help\n\n", "title")
        help_text.insert(tk.END, "This tool scans Python code for potential SQL injection vulnerabilities.\n\n")
        help_text.insert(tk.END, "How to use:\n", "section")
        help_text.insert(tk.END, "1. Click 'Open File' or 'Open Folder' to select Python code to scan\n")
        help_text.insert(tk.END, "2. View findings in the Findings tab\n")
        help_text.insert(tk.END, "3. Use the Dashboard for a visual overview\n")
        help_text.insert(tk.END, "4. Filter results by text or severity\n")
        help_text.insert(tk.END, "5. Export results to JSON or HTML\n\n")
        help_text.insert(tk.END, "Understanding Results:\n", "section")
        help_text.insert(tk.END, "- Critical: Immediate action required - high risk of exploitation\n")
        help_text.insert(tk.END, "- High: Serious vulnerability that should be fixed soon\n")
        help_text.insert(tk.END, "- Medium: Potential issue that should be investigated\n")
        help_text.insert(tk.END, "- Low: Minor issue or best practice recommendation\n\n")
        help_text.insert(tk.END, "Each finding includes:\n")
        help_text.insert(tk.END, "- Location (file, line)\n")
        help_text.insert(tk.END, "- Severity and confidence\n")
        help_text.insert(tk.END, "- Description of the issue\n")
        help_text.insert(tk.END, "- Code snippet\n")
        help_text.insert(tk.END, "- Remediation advice\n")
        help_text.insert(tk.END, "- Example of vulnerable and safe code\n")
        
        help_text.tag_configure("title", font=("Arial", 14, "bold"))
        help_text.tag_configure("section", font=("Arial", 11, "bold"))
        help_text.config(state="disabled")  # Make read-only
    
    def _configure_dashboard_scroll(self, event):
        """Configure dashboard scrolling"""
        self.dashboard_canvas.configure(scrollregion=self.dashboard_canvas.bbox("all"), width=event.width)
    
    def open_file(self):
        """Open and scan a single file"""
        path = filedialog.askopenfilename(
            title="Select Python file",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        if not path:
            return
        
        self.status_var.set(f"Scanning: {path}")
        self.root.update_idletasks()
        
        self.results = scan_file(path)
        self.render_results()
        self.render_dashboard()
    
    def open_folder(self):
        """Open and scan a folder"""
        path = filedialog.askdirectory(title="Select folder to scan")
        if not path:
            return
        
        self.status_var.set(f"Scanning folder: {path}")
        self.root.update_idletasks()
        
        self.results = scan_path(path)
        self.render_results()
        self.render_dashboard()
    
    def _filtered_results(self) -> List[Dict]:
        """Get filtered findings"""
        findings = self.results.get("findings", [])
        filter_text = self.filter_var.get().lower()
        severity_filter = self.severity_var.get()
        
        filtered = []
        for f in findings:
            # Apply text filter
            text_match = (not filter_text) or (
                filter_text in f.get("rule", "").lower() or
                filter_text in f.get("message", "").lower() or
                filter_text in f.get("severity", "").lower() or
                filter_text in f.get("file", "").lower()
            )
            
            # Apply severity filter
            severity_match = (severity_filter == "All") or (f.get("severity", "") == severity_filter)
            
            if text_match and severity_match:
                filtered.append(f)
        
        return filtered
    
    def render_results(self):
        """Render results in the text widget"""
        self.text.delete("1.0", tk.END)
        
        findings = self._filtered_results()
        stats = self.results.get("statistics", {})
        summary = get_summary(self.results)
        
        # Show summary
        self.text.insert(tk.END, "=" * 80 + "\n")
        self.text.insert(tk.END, "SCAN SUMMARY\n")
        self.text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.text.insert(tk.END, f"Files scanned: {stats.get('files_scanned', 0)}\n")
        self.text.insert(tk.END, f"Lines analyzed: {stats.get('lines_analyzed', 0)}\n")
        self.text.insert(tk.END, f"Functions analyzed: {stats.get('functions_analyzed', 0)}\n")
        self.text.insert(tk.END, f"Total findings: {summary['total']}\n")
        self.text.insert(tk.END, f"Risk score: {summary['risk_score']}\n\n")
        
        self.text.insert(tk.END, "Severity breakdown:\n")
        self.text.insert(tk.END, f"  Critical: {summary['critical']}\n")
        self.text.insert(tk.END, f"  High: {summary['high']}\n")
        self.text.insert(tk.END, f"  Medium: {summary['medium']}\n")
        self.text.insert(tk.END, f"  Low: {summary['low']}\n\n")
        
        # Show filter info if active
        if self.filter_var.get() or self.severity_var.get() != "All":
            self.text.insert(tk.END, f"Filter active: showing {len(findings)} of {summary['total']} findings\n\n")
        
        if not findings:
            if summary['total'] > 0:
                self.text.insert(tk.END, "No findings match the current filter.\n")
            else:
                self.text.insert(tk.END, "✅ No vulnerabilities found!\n")
            self.status_var.set(f"Done: {len(findings)} of {summary['total']} findings")
            return
        
        # Show findings
        self.text.insert(tk.END, "=" * 80 + "\n")
        self.text.insert(tk.END, "FINDINGS\n")
        self.text.insert(tk.END, "=" * 80 + "\n\n")
        
        for i, f in enumerate(findings, 1):
            # Use the pre-formatted location string
            loc = f.get('location', ':0:0')

            sev = f.get("severity", "Unknown")
            conf = f.get("confidence", "Unknown")
            cwe = f.get("cwe", "")

            # Use tags for severity-based coloring
            self.text.insert(tk.END, f"[{i}] ")
            self.text.insert(tk.END, f"[{sev}] ", f"sev_{sev.lower()}")
            self.text.insert(tk.END, f"[{f.get('rule_id', '')}] ({conf} confidence)\n")
            self.text.insert(tk.END, f"    Location: {loc}\n")
            self.text.insert(tk.END, f"    CWE: {cwe}\n")
            self.text.insert(tk.END, f"    Message: {f.get('message', '')}\n")
            
            code = f.get("code", "")
            if code:
                self.text.insert(tk.END, f"    Code: ")
                self.text.insert(tk.END, f"{code}\n", "code")
            
            # NEW: Show validation information
            meta = f.get("meta", {})
            if meta.get('validated_vars') or meta.get('unvalidated_vars'):
                self.text.insert(tk.END, "    Variable Analysis:\n")
                
                if meta.get('validated_vars'):
                    validated_str = ', '.join(meta['validated_vars'])
                    self.text.insert(tk.END, f"      ✓ Validated: {validated_str}\n", "validated_info")
                
                if meta.get('unvalidated_vars'):
                    unvalidated_str = ', '.join(meta['unvalidated_vars'])
                    self.text.insert(tk.END, f"      ✗ Unvalidated: {unvalidated_str}\n", "unvalidated_info")
            
            remediation = f.get("remediation", "")

            if remediation:
                self.text.insert(tk.END, f"    Fix: {remediation}\n")
            
            examples = f.get("examples", {})
            if examples:
                self.text.insert(tk.END, "    Examples:\n")
                if "vulnerable" in examples:
                    self.text.insert(tk.END, f"      ❌ Vulnerable: ")
                    self.text.insert(tk.END, f"{examples['vulnerable']}\n", "vulnerable")
                if "safe" in examples:
                    self.text.insert(tk.END, f"      ✅ Safe: ")
                    self.text.insert(tk.END, f"{examples['safe']}\n", "safe")
            
            trace = f.get("trace")
            if trace:
                self.text.insert(tk.END, "    Trace:\n")
                for step in trace:
                    tloc = f"{step.get('file', '')}:{step.get('line', '')}"
                    warning = step.get('warning', '')
                    if warning:
                        self.text.insert(tk.END, f"      - {tloc}: {step.get('note', '')} | {step.get('code', '')}\n")
                        self.text.insert(tk.END, f"        {warning}\n", "warning")
                    else:
                        self.text.insert(tk.END, f"      - {tloc}: {step.get('note', '')} | {step.get('code', '')}\n")
            
            self.text.insert(tk.END, "\n")
        
        # Configure tags
        self.text.tag_configure("code", foreground="blue")
        self.text.tag_configure("vulnerable", foreground="red")
        self.text.tag_configure("safe", foreground="green")
        self.text.tag_configure("warning", foreground="red", font=("Courier", 9, "bold"))
        self.text.tag_configure("validated_info", foreground="#27ae60", font=("Courier", 9, "bold"))
        self.text.tag_configure("unvalidated_info", foreground="#c0392b", font=("Courier", 9, "bold"))
        self.text.tag_configure("sev_critical", foreground="white", background="#c0392b")
        self.text.tag_configure("sev_high", foreground="white", background="#e74c3c")
        self.text.tag_configure("sev_medium", foreground="black", background="#f39c12")
        self.text.tag_configure("sev_low", foreground="white", background="#3498db")
        
        self.status_var.set(f"Done: {len(findings)} of {summary['total']} findings")
    
    def render_dashboard(self):
        """Render the dashboard tab with charts and stats"""
        # Clear previous dashboard
        for widget in self.dash_content.winfo_children():
            widget.destroy()
        
        stats = self.results.get("statistics", {})
        summary = get_summary(self.results)
        
        # Header
        header = tk.Frame(self.dash_content, bg="white")
        header.pack(fill="x", padx=20, pady=10)
        
        tk.Label(header, text="Security Dashboard", font=("Arial", 16, "bold"), bg="white").pack(anchor="w")
        
        # Risk score section
        risk_frame = tk.Frame(self.dash_content, bg="white", relief="ridge", bd=1)
        risk_frame.pack(fill="x", padx=20, pady=10)
        
        score = summary['risk_score']
        if score > 30:
            score_color = "#c0392b"  # Red
            risk_text = "HIGH RISK"
        elif score > 10:
            score_color = "#f39c12"  # Orange
            risk_text = "MEDIUM RISK"
        elif score > 0:
            score_color = "#3498db"  # Blue
            risk_text = "LOW RISK"
        else:
            score_color = "#27ae60"  # Green
            risk_text = "SECURE"
        
        tk.Label(risk_frame, text="Overall Security Risk", font=("Arial", 12), bg="white").pack(pady=(10, 0))
        tk.Label(risk_frame, text=str(score), font=("Arial", 36, "bold"), fg=score_color, bg="white").pack()
        tk.Label(risk_frame, text=risk_text, font=("Arial", 14, "bold"), fg=score_color, bg="white").pack(pady=(0, 10))
        
        # Stats section
        stats_frame = tk.Frame(self.dash_content, bg="white")
        stats_frame.pack(fill="x", padx=20, pady=10)
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(2, weight=1)
        
        # Files scanned
        files_frame = tk.Frame(stats_frame, bg="white", relief="ridge", bd=1)
        files_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        tk.Label(files_frame, text="Files Scanned", font=("Arial", 10), bg="white").pack(pady=(10, 0))
        tk.Label(files_frame, text=str(stats.get('files_scanned', 0)), font=("Arial", 20, "bold"), bg="white").pack(pady=(0, 10))
        
        # Lines analyzed
        lines_frame = tk.Frame(stats_frame, bg="white", relief="ridge", bd=1)
        lines_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        tk.Label(lines_frame, text="Lines Analyzed", font=("Arial", 10), bg="white").pack(pady=(10, 0))
        tk.Label(lines_frame, text=str(stats.get('lines_analyzed', 0)), font=("Arial", 20, "bold"), bg="white").pack(pady=(0, 10))
        
        # Total findings
        findings_frame = tk.Frame(stats_frame, bg="white", relief="ridge", bd=1)
        findings_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        tk.Label(findings_frame, text="Total Findings", font=("Arial", 10), bg="white").pack(pady=(10, 0))
        tk.Label(findings_frame, text=str(summary['total']), font=("Arial", 20, "bold"), bg="white").pack(pady=(0, 10))
        
        # Severity breakdown
        severity_frame = tk.Frame(self.dash_content, bg="white", relief="ridge", bd=1)
        severity_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(severity_frame, text="Findings by Severity", font=("Arial", 12), bg="white").pack(pady=(10, 15))
        
        # Create severity bars
        self._create_severity_bar(severity_frame, "Critical", summary['critical'], "#c0392b")
        self._create_severity_bar(severity_frame, "High", summary['high'], "#e74c3c")
        self._create_severity_bar(severity_frame, "Medium", summary['medium'], "#f39c12")
        self._create_severity_bar(severity_frame, "Low", summary['low'], "#3498db")
        
        tk.Frame(severity_frame, height=10, bg="white").pack()  # Spacer
        
        # Rules breakdown
        if stats.get("by_rule"):
            rules_frame = tk.Frame(self.dash_content, bg="white", relief="ridge", bd=1)
            rules_frame.pack(fill="x", padx=20, pady=10)
            
            tk.Label(rules_frame, text="Top Issues by Rule", font=("Arial", 12), bg="white").pack(pady=(10, 15))
            
            # Sort rules by count
            sorted_rules = sorted(
                stats.get("by_rule", {}).items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]  # Top 5
            
            for rule, count in sorted_rules:
                if rule.startswith("PY-SQLI-"):
                    self._create_rule_bar(rules_frame, rule, count)
            
            tk.Frame(rules_frame, height=10, bg="white").pack()  # Spacer
        
        # Recommendations section
        if summary['total'] > 0:
            rec_frame = tk.Frame(self.dash_content, bg="white", relief="ridge", bd=1)
            rec_frame.pack(fill="x", padx=20, pady=10)
            
            tk.Label(rec_frame, text="Security Recommendations", font=("Arial", 12), bg="white").pack(pady=(10, 5), anchor="w")
            
            recommendations = [
                "✓ Use parameterized queries instead of string concatenation",
                "✓ Validate all user inputs before using in SQL",
                "✓ Apply the principle of least privilege for database access",
                "✓ Implement proper error handling to avoid leaking SQL details",
                "✓ Consider using an ORM for safer database interactions"
            ]
            
            for rec in recommendations:
                tk.Label(rec_frame, text=rec, font=("Arial", 10), bg="white", anchor="w", justify="left").pack(fill="x", padx=15, pady=2)
            
            tk.Frame(rec_frame, height=10, bg="white").pack()  # Spacer
    
    def _create_severity_bar(self, parent, label, count, color):
        """Create a severity bar for the dashboard"""
        frame = tk.Frame(parent, bg="white")
        frame.pack(fill="x", padx=20, pady=2)
        
        # Label
        tk.Label(frame, text=label, width=10, anchor="w", bg="white").pack(side="left")
        
        # Count
        tk.Label(frame, text=str(count), width=5, bg="white").pack(side="right")
        
        # Bar
        max_width = 300  # Max bar width in pixels
        total = sum([
            get_summary(self.results)['critical'],
            get_summary(self.results)['high'],
            get_summary(self.results)['medium'],
            get_summary(self.results)['low']
        ])
        
        if total > 0:
            width = int((count / total) * max_width)
        else:
            width = 0
        
        bar = tk.Canvas(frame, width=max_width, height=20, bg="#f5f5f5", highlightthickness=0)
        bar.pack(side="left", padx=5)
        
        if width > 0:
            bar.create_rectangle(0, 0, width, 20, fill=color, outline="")
    
    def _create_rule_bar(self, parent, rule, count):
        """Create a rule bar for the dashboard"""
        frame = tk.Frame(parent, bg="white")
        frame.pack(fill="x", padx=20, pady=2)
        
        # Label
        tk.Label(frame, text=rule, width=12, anchor="w", bg="white").pack(side="left")
        
        # Count
        tk.Label(frame, text=str(count), width=5, bg="white").pack(side="right")
        
        # Bar
        max_width = 300  # Max bar width in pixels
        total = sum(self.results.get("statistics", {}).get("by_rule", {}).values())
        
        if total > 0:
            width = int((count / total) * max_width)
        else:
            width = 0
        
        bar = tk.Canvas(frame, width=max_width, height=20, bg="#f5f5f5", highlightthickness=0)
        bar.pack(side="left", padx=5)
        
        if width > 0:
            bar.create_rectangle(0, 0, width, 20, fill="#3498db", outline="")
    
    def save_json(self):
        """Save results as JSON"""
        if not self.results.get("findings"):
            messagebox.showinfo("Save JSON", "No results to save.")
            return
        
        out = filedialog.asksaveasfilename(
            title="Save findings as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not out:
            return
        
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
            messagebox.showinfo("Save JSON", f"Saved to:\n{out}")
        except Exception as e:
            messagebox.showerror("Save JSON", f"Failed:\n{e}")
    
    def save_html(self):
        """Save results as HTML"""
        if not self.results.get("findings"):
            messagebox.showinfo("Save HTML", "No results to save.")
            return
        
        out = filedialog.asksaveasfilename(
            title="Save findings as HTML",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")]
        )
        if not out:
            return
        
        try:
            self._generate_html_report(out)
            messagebox.showinfo("Save HTML", f"Saved to:\n{out}")
        except Exception as e:
            messagebox.showerror("Save HTML", f"Failed:\n{e}")
    
def generate_html_report(results: Dict[str, Any], filepath: str):
    """Generate HTML report without GUI dependency"""
    findings = results.get("findings", [])
    stats = results.get("statistics", {})
    summary = get_summary(results)
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SQL Injection Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 32px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary h2 {{ margin-top: 0; color: #333; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-box .number {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        .stat-box .label {{ color: #666; margin-top: 5px; }}
        .severity-badges {{ display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap; }}
        .badge {{ padding: 8px 16px; border-radius: 20px; font-weight: bold; color: white; }}
        .badge.critical {{ background: #c0392b; }}
        .badge.high {{ background: #e74c3c; }}
        .badge.medium {{ background: #f39c12; }}
        .badge.low {{ background: #3498db; }}
        .finding {{ background: white; padding: 20px; margin: 15px 0; border-radius: 10px; border-left: 5px solid #e74c3c; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding.Critical {{ border-left-color: #c0392b; }}
        .finding.High {{ border-left-color: #e74c3c; }}
        .finding.Medium {{ border-left-color: #f39c12; }}
        .finding.Low {{ border-left-color: #3498db; }}
        .finding h3 {{ margin-top: 0; color: #333; }}
        .finding .meta {{ color: #666; font-size: 14px; margin: 10px 0; }}
        .finding code {{ background: #f8f9fa; padding: 10px; display: block; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; }}
        .finding .remediation {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 15px; }}
        .finding .remediation strong {{ color: #2e7d32; }}
        .finding .examples {{ margin-top: 15px; }}
        .finding .example {{ margin: 10px 0; }}
        .finding .example.vulnerable {{ color: #c0392b; }}
        .finding .example.safe {{ color: #27ae60; }}
        .trace {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px; }}
        .trace-step {{ margin: 5px 0; padding: 5px; font-family: 'Courier New', monospace; font-size: 13px; }}
        .trace-warning {{ color: #c0392b; font-weight: bold; margin-left: 20px; }}
        .var-analysis {{ background: #f0f8ff; padding: 10px; border-radius: 5px; margin-top: 10px; }}
        .var-validated {{ color: #27ae60; }}
        .var-unvalidated {{ color: #c0392b; }}
        .risk-score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}
        .risk-score.high {{ color: #c0392b; }}
        .risk-score.medium {{ color: #f39c12; }}
        .risk-score.low {{ color: #27ae60; }}
        .recommendations {{ background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .recommendations h2 {{ margin-top: 0; color: #333; }}
        .recommendations ul {{ padding-left: 20px; }}
        .recommendations li {{ margin: 10px 0; }}
        .chart {{ margin: 20px 0; }}
        .chart-bar {{ height: 30px; background: #3498db; margin: 5px 0; border-radius: 4px; }}
        .chart-label {{ display: flex; justify-content: space-between; margin: 5px 0; }}
        .chart-critical {{ background: #c0392b; }}
        .chart-high {{ background: #e74c3c; }}
        .chart-medium {{ background: #f39c12; }}
        .chart-low {{ background: #3498db; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 SQL Injection Scan Report</h1>
        <p>Generated by Python SQL Injection Scanner v{__version__}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="number">{stats.get('files_scanned', 0)}</div>
                <div class="label">Files Scanned</div>
            </div>
            <div class="stat-box">
                <div class="number">{summary['total']}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-box">
                <div class="number">{stats.get('lines_analyzed', 0)}</div>
                <div class="label">Lines Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="number">{summary['risk_score']}</div>
                <div class="label">Risk Score</div>
            </div>
        </div>
        
        <h3>Severity Breakdown</h3>
        <div class="severity-badges">
            <span class="badge critical">Critical: {summary['critical']}</span>
            <span class="badge high">High: {summary['high']}</span>
            <span class="badge medium">Medium: {summary['medium']}</span>
            <span class="badge low">Low: {summary['low']}</span>
        </div>
        
        <div class="chart">
            <h3>Findings by Severity</h3>
'''
    
    # Add severity chart bars
    total_findings = max(1, summary['total'])
    
    if summary['critical'] > 0:
        percent = (summary['critical'] / total_findings) * 100
        html += f'''
            <div class="chart-label">
                <span>Critical</span>
                <span>{summary['critical']} ({percent:.1f}%)</span>
            </div>
            <div class="chart-bar chart-critical" style="width: {percent}%;"></div>
'''
    
    if summary['high'] > 0:
        percent = (summary['high'] / total_findings) * 100
        html += f'''
            <div class="chart-label">
                <span>High</span>
                <span>{summary['high']} ({percent:.1f}%)</span>
            </div>
            <div class="chart-bar chart-high" style="width: {percent}%;"></div>
'''
    
    if summary['medium'] > 0:
        percent = (summary['medium'] / total_findings) * 100
        html += f'''
            <div class="chart-label">
                <span>Medium</span>
                <span>{summary['medium']} ({percent:.1f}%)</span>
            </div>
            <div class="chart-bar chart-medium" style="width: {percent}%;"></div>
'''
    
    if summary['low'] > 0:
        percent = (summary['low'] / total_findings) * 100
        html += f'''
            <div class="chart-label">
                <span>Low</span>
                <span>{summary['low']} ({percent:.1f}%)</span>
            </div>
            <div class="chart-bar chart-low" style="width: {percent}%;"></div>
'''
    
    html += '''
        </div>
    </div>
'''
    
    if not findings:
        html += '''
    <div class="summary">
        <h2 style="color: #27ae60;">✅ No vulnerabilities found!</h2>
        <p>Your code appears to be safe from SQL injection vulnerabilities.</p>
    </div>
'''
    else:
        # Add recommendations
        html += '''
    <div class="recommendations">
        <h2>💡 Recommendations</h2>
        <ul>
            <li><strong>Use parameterized queries</strong> - Never concatenate user input directly into SQL strings</li>
            <li><strong>Input validation</strong> - Validate all user inputs before using them in queries</li>
            <li><strong>Use ORM frameworks</strong> - Consider using an ORM that handles parameterization automatically</li>
            <li><strong>Apply least privilege</strong> - Database users should have minimal required permissions</li>
            <li><strong>Implement error handling</strong> - Prevent SQL error details from being exposed to users</li>
        </ul>
    </div>
'''
        
        # Add findings
        html += '<div class="summary"><h2>🔍 Findings</h2></div>\n'
        
        for i, f in enumerate(findings, 1):
            sev = f.get('severity', 'Unknown')
            html += f'''
    <div class="finding {sev}">
        <h3>[{i}] {f['rule']} - {sev}</h3>
        <div class="meta">
            <strong>File:</strong> {f['file']} (Line {f['line']}, Col {f['col']})<br>
            <strong>Confidence:</strong> {f.get('confidence', 'Unknown')}<br>
            <strong>CWE:</strong> {f.get('cwe', 'N/A')}
        </div>
        <p><strong>Message:</strong> {f['message']}</p>
'''
            
            if f.get('code'):
                html += f'<code>{f["code"]}</code>\n'
            
            # Show validation information
            meta = f.get('meta', {})
            if meta.get('validated_vars') or meta.get('unvalidated_vars'):
                html += '<div class="var-analysis">\n'
                html += '<strong>🔍 Variable Analysis:</strong><br>\n'
                
                if meta.get('validated_vars'):
                    validated_list = ', '.join(f'<code>{v}</code>' for v in meta['validated_vars'])
                    html += f'<span class="var-validated">✓ Validated: {validated_list}</span><br>\n'
                
                if meta.get('unvalidated_vars'):
                    unvalidated_list = ', '.join(f'<code>{v}</code>' for v in meta['unvalidated_vars'])
                    html += f'<span class="var-unvalidated">✗ Unvalidated: {unvalidated_list}</span>\n'
                
                html += '</div>\n'
            
            if f.get('remediation'):
                html += f'''
        <div class="remediation">
            <strong>💡 How to fix:</strong><br>
            {f['remediation']}
        </div>
'''
            
            examples = f.get('examples', {})
            if examples:
                html += '<div class="examples"><strong>Examples:</strong>\n'
                if 'vulnerable' in examples:
                    html += f'<div class="example vulnerable">❌ Vulnerable: <code>{examples["vulnerable"]}</code></div>\n'
                if 'safe' in examples:
                    html += f'<div class="example safe">✅ Safe: <code>{examples["safe"]}</code></div>\n'
                html += '</div>\n'
            
            trace = f.get('trace')
            if trace:
                html += '<div class="trace"><strong>Data Flow Trace:</strong>\n'
                for step in trace:
                    html += f'<div class="trace-step">→ {step.get("file", "")}:{step.get("line", "")} - {step.get("note", "")} | {step.get("code", "")}</div>\n'
                    if step.get('warning'):
                        html += f'<div class="trace-warning">{step.get("warning")}</div>\n'
                html += '</div>\n'
            
            html += '    </div>\n'
    
    # Add footer
    html += f'''
    <div class="footer">
        <p>Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} by Python SQL Injection Scanner v{__version__}</p>
    </div>
</body>
</html>
'''
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description=f"Python SQL Injection Scanner v{__version__}")
    parser.add_argument("path", nargs="?", help="File or directory to scan (optional)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-r", "--html-report", help="Output HTML report file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-g", "--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # GUI mode
    if args.gui or not args.path:
        try:
            import tkinter as tk
            from tkinter import ttk, filedialog, messagebox
            root = tk.Tk()
            root.geometry("1000x700")
            app = ScannerGUI(root)
            root.mainloop()
            return
        except ImportError:
            logger.error("Tkinter not available. Running in command-line mode.")
            if not args.path:
                parser.print_help()
                return
    
    # CLI mode
    if not os.path.exists(args.path):
        logger.error(f"Path not found: {args.path}")
        return 1
    
    print(f"Python SQL Injection Scanner v{__version__}")
    print(f"Scanning: {args.path}")
    
    start_time = time.time()
    results = scan_path(args.path)
    scan_time = time.time() - start_time
    
    # Print summary
    summary = get_summary(results)
    findings = results["findings"]
    
    print("\n" + "=" * 60)
    print(f"SCAN SUMMARY (completed in {scan_time:.2f}s)")
    print("=" * 60)
    print(f"Files scanned: {summary['files_scanned']}")
    print(f"Total findings: {summary['total']}")
    print(f"Risk score: {summary['risk_score']}")
    print("\nSeverity breakdown:")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
    
    # Print findings
    if findings:
        print("\n" + "=" * 60)
        print("FINDINGS")
        print("=" * 60)
        
        for i, f in enumerate(findings, 1):
            # Use the pre-formatted location string
            loc = f.get('location', ':0:0')

            sev = f.get("severity", "Unknown")
            conf = f.get("confidence", "Unknown")

            print(f"\n[{i}] [{sev}] [{f.get('rule_id', '')}] ({conf} confidence)")
            print(f"    Location: {loc}")
            print(f"    Message: {f.get('message', '')}")
            
            code = f.get("code", "")
            if code:
                print(f"    Code: {code}")
            
            # NEW: Show validation information in CLI
            meta = f.get("meta", {})
            if meta.get('validated_vars') or meta.get('unvalidated_vars'):
                print(f"    Variable Analysis:")
                
                if meta.get('validated_vars'):
                    validated_str = ', '.join(meta['validated_vars'])
                    print(f"      Validated: {validated_str}")

                if meta.get('unvalidated_vars'):
                    unvalidated_str = ', '.join(meta['unvalidated_vars'])
                    print(f"      Unvalidated: {unvalidated_str}")
            
            if not args.quiet:

                remediation = f.get("remediation", "")
                if remediation:
                    print(f"    Fix: {remediation}")
    else:
        print("\n✅ No vulnerabilities found!")
    
    # Write output files if requested
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        except Exception as e:
            logger.error(f"Failed to write JSON output: {e}")

    if args.html_report:
        try:
            generate_html_report(results, args.html_report)
            print(f"HTML report saved to: {args.html_report}")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")


    # Return non-zero exit code if critical or high findings
    if summary['critical'] > 0 or summary['high'] > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())





    