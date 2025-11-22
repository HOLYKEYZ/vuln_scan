"""
Scanner Main Module - Ties together AST scanner + LLM providers
This replaces the broken scanner.py stub

Usage:
    from scanner import scan_file, scan_with_llm, load_provider
"""

import os
import sys
from typing import Dict, Any, Optional, List

# Import the AST scanner (scan6.py should be renamed or imported)
try:
    from large_scanner.py import scan_file as ast_scan_file, scan_path as ast_scan_path
    HAS_AST_SCANNER = True
except ImportError:
    HAS_AST_SCANNER = False
    print("Warning: large_scannner.py not found - AST scanning disabled")

# Import LLM providers
try:
    from providers import load_provider, list_providers, LLMProvider
    HAS_PROVIDERS = True
except ImportError:
    HAS_PROVIDERS = False
    print("Warning: providers.py not found - LLM analysis disabled")


# =============================================================================
# LLM SECURITY ANALYSIS
# =============================================================================

SECURITY_SYSTEM_PROMPT = """You are an expert security code reviewer specializing in SQL injection vulnerability detection.

Analyze Python code for SQL injection vulnerabilities with HIGH PRECISION. Look for:

1. **Direct SQL Injection**: User input concatenated/formatted into SQL strings
   - f-strings: f"SELECT * FROM users WHERE id={user_input}"
   - .format(): "SELECT * FROM users WHERE id={}".format(user_input)
   - % formatting: "SELECT * FROM users WHERE id=%s" % user_input
   - Concatenation: "SELECT * FROM users WHERE id=" + user_input

2. **Taint Sources** (user-controlled data):
   - request.args.get(), request.form.get(), request.values.get()
   - request.headers.get() - CRITICAL (attacker fully controls)
   - request.cookies.get(), request.data, request.json
   - session.get() - can be manipulated
   - Function parameters in web routes

3. **Dangerous Sinks** (SQL execution):
   - cursor.execute(), cursor.executemany()
   - cursor.executescript() - allows multiple statements (CRITICAL)
   - db.execute(), connection.execute()
   - Django: Model.objects.raw(), RawSQL()
   - SQLAlchemy: text(), literal_column()

4. **Weak/Bypassed Sanitization**:
   - .replace("'", "") - bypassed with nested keywords
   - .strip(), .upper(), .lower() - don't prevent SQLi
   - Blacklist-based filtering - always bypassable
   - Quote doubling ('') - database-specific, risky

5. **False Negatives to Avoid**:
   - Variables assigned from tainted sources then used later
   - Data flowing through multiple function calls
   - List/dict containing tainted data used in SQL
   - HTTP headers (User-Agent, X-Forwarded-For) in SQL

Output Format (JSON only):
{
  "findings": [
    {
      "line": <number>,
      "severity": "Critical|High|Medium|Low",
      "confidence": "High|Medium|Low",
      "rule": "SQLI-XXX",
      "message": "<clear description>",
      "code": "<vulnerable code snippet>",
      "remediation": "<specific fix>"
    }
  ],
  "summary": "<brief overall assessment>"
}

Severity Guidelines:
- Critical: HTTP headers in SQL, executescript with user data, no sanitization attempt
- High: Direct request params in SQL, weak sanitization
- Medium: Indirect taint flow, complex data paths
- Low: Potential issues needing manual review

ONLY output valid JSON. No markdown, no explanation outside JSON."""


ANALYSIS_USER_PROMPT = """Analyze this Python file for SQL injection vulnerabilities.
File: {filename}
Lines: {line_count}

Focus on tracking data flow from user input to SQL execution.
Report each distinct vulnerability with specific line numbers.

Code:
```python
{code}
```"""


def analyze_with_llm(code: str, filename: str, provider: 'LLMProvider') -> Dict[str, Any]:
    """
    Analyze code using LLM for SQL injection detection.
    
    Args:
        code: Source code to analyze
        filename: Name of the file
        provider: LLM provider instance
    
    Returns:
        Dict with 'findings' list and 'raw_response'
    """
    import json
    import re
    
    line_count = len(code.splitlines())
    user_prompt = ANALYSIS_USER_PROMPT.format(
        filename=filename,
        line_count=line_count,
        code=code
    )
    
    response = provider.ask(SECURITY_SYSTEM_PROMPT, user_prompt, "")
    
    findings = []
    
    try:
        # Extract JSON from response (handle markdown code blocks)
        json_text = response
        if "```json" in response:
            match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
            if match:
                json_text = match.group(1)
        elif "```" in response:
            match = re.search(r'```\s*([\s\S]*?)\s*```', response)
            if match:
                json_text = match.group(1)
        
        # Find JSON object
        json_match = re.search(r'\{[\s\S]*\}', json_text)
        if json_match:
            data = json.loads(json_match.group())
            
            for f in data.get("findings", []):
                findings.append({
                    "file": filename,
                    "line": f.get("line", 0),
                    "col": 0,
                    "rule": f.get("rule", "LLM-SQLI"),
                    "message": f.get("message", ""),
                    "severity": f.get("severity", "Medium"),
                    "confidence": f.get("confidence", "Medium"),
                    "code": f.get("code", ""),
                    "remediation": f.get("remediation", "Use parameterized queries"),
                    "source": "llm"
                })
    
    except json.JSONDecodeError:
        # Fallback: check for vulnerability indicators in raw text
        if any(kw in response.lower() for kw in ["sql injection", "vulnerability", "tainted", "unsafe"]):
            findings.append({
                "file": filename,
                "line": 0,
                "col": 0,
                "rule": "LLM-REVIEW",
                "message": f"LLM detected potential issues (parsing failed): {response[:300]}...",
                "severity": "Medium",
                "confidence": "Low",
                "code": "",
                "remediation": "Manual review recommended",
                "source": "llm"
            })
    
    return {
        "findings": findings,
        "raw_response": response
    }


# =============================================================================
# UNIFIED SCANNING
# =============================================================================

def scan_file(path: str, provider_name: str = None, api_key: str = None, 
              ast_only: bool = False, llm_only: bool = False) -> Dict[str, Any]:
    """
    Scan a file for SQL injection vulnerabilities.
    
    Args:
        path: Path to the Python file
        provider_name: LLM provider name (gemini, openai, claude, groq)
        api_key: API key for the provider (or use env vars)
        ast_only: Only use AST analysis
        llm_only: Only use LLM analysis
    
    Returns:
        Dict with 'findings', 'statistics', and optionally 'llm_response'
    """
    results = {
        "findings": [],
        "statistics": {
            "files_scanned": 1,
            "total_findings": 0,
            "by_severity": {},
            "by_rule": {},
            "by_source": {"ast": 0, "llm": 0}
        }
    }
    
    # Read file
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        results["findings"].append({
            "file": path,
            "line": 0,
            "rule": "SCAN-ERROR",
            "message": f"Failed to read file: {e}",
            "severity": "Info"
        })
        return results
    
    # AST Analysis
    if not llm_only and HAS_AST_SCANNER:
        ast_results = ast_scan_file(path)
        for f in ast_results.get("findings", []):
            f["source"] = "ast"
            results["findings"].append(f)
        results["statistics"]["by_source"]["ast"] = len(ast_results.get("findings", []))
    
    # LLM Analysis
    if not ast_only and provider_name and HAS_PROVIDERS:
        try:
            kwargs = {"api_key": api_key} if api_key else {}
            provider = load_provider(provider_name, **kwargs)
            llm_results = analyze_with_llm(code, path, provider)
            
            for f in llm_results.get("findings", []):
                results["findings"].append(f)
            
            results["statistics"]["by_source"]["llm"] = len(llm_results.get("findings", []))
            results["llm_response"] = llm_results.get("raw_response", "")
            
        except Exception as e:
            results["findings"].append({
                "file": path,
                "line": 0,
                "rule": "LLM-ERROR",
                "message": f"LLM analysis failed: {e}",
                "severity": "Info",
                "source": "llm"
            })
    
    # Deduplicate findings (same line + similar message)
    seen = set()
    unique_findings = []
    for f in results["findings"]:
        key = (f.get("file"), f.get("line"), f.get("rule", "")[:8])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    results["findings"] = unique_findings
    
    # Update statistics
    results["statistics"]["total_findings"] = len(results["findings"])
    for f in results["findings"]:
        sev = f.get("severity", "Unknown")
        rule = f.get("rule", "Unknown")
        results["statistics"]["by_severity"][sev] = results["statistics"]["by_severity"].get(sev, 0) + 1
        results["statistics"]["by_rule"][rule] = results["statistics"]["by_rule"].get(rule, 0) + 1
    
    return results


def scan_path(path: str, provider_name: str = None, api_key: str = None,
              ast_only: bool = False, llm_only: bool = False) -> Dict[str, Any]:
    """
    Scan a file or directory.
    
    Args:
        path: File or directory path
        provider_name: LLM provider name
        api_key: API key for provider
        ast_only: Only use AST analysis
        llm_only: Only use LLM analysis
    
    Returns:
        Combined results dict
    """
    import os
    
    if os.path.isfile(path):
        return scan_file(path, provider_name, api_key, ast_only, llm_only)
    
    # Directory scan
    results = {
        "findings": [],
        "statistics": {
            "files_scanned": 0,
            "total_findings": 0,
            "by_severity": {},
            "by_rule": {},
            "by_source": {"ast": 0, "llm": 0}
        }
    }
    
    for root, dirs, files in os.walk(path):
        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]
        
        for fname in files:
            if fname.endswith('.py'):
                fpath = os.path.join(root, fname)
                file_results = scan_file(fpath, provider_name, api_key, ast_only, llm_only)
                
                results["findings"].extend(file_results.get("findings", []))
                results["statistics"]["files_scanned"] += 1
                
                # Merge stats
                for sev, count in file_results.get("statistics", {}).get("by_severity", {}).items():
                    results["statistics"]["by_severity"][sev] = results["statistics"]["by_severity"].get(sev, 0) + count
                for rule, count in file_results.get("statistics", {}).get("by_rule", {}).items():
                    results["statistics"]["by_rule"][rule] = results["statistics"]["by_rule"].get(rule, 0) + count
                
                results["statistics"]["by_source"]["ast"] += file_results.get("statistics", {}).get("by_source", {}).get("ast", 0)
                results["statistics"]["by_source"]["llm"] += file_results.get("statistics", {}).get("by_source", {}).get("llm", 0)
    
    results["statistics"]["total_findings"] = len(results["findings"])
    return results


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--provider", "-p", choices=["gemini", "openai", "claude", "groq"],
                        help="LLM provider for enhanced analysis")
    parser.add_argument("--api-key", "-k", help="API key (or use env vars)")
    parser.add_argument("--ast-only", action="store_true", help="Only use AST analysis")
    parser.add_argument("--llm-only", action="store_true", help="Only use LLM analysis")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    print(f"Scanning: {args.path}")
    if args.provider:
        print(f"Using LLM: {args.provider}")
    
    results = scan_path(
        args.path,
        provider_name=args.provider,
        api_key=args.api_key,
        ast_only=args.ast_only,
        llm_only=args.llm_only
    )
    
    # Print summary
    stats = results["statistics"]
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Files scanned: {stats['files_scanned']}")
    print(f"Total findings: {stats['total_findings']}")
    print(f"  - From AST: {stats['by_source']['ast']}")
    print(f"  - From LLM: {stats['by_source']['llm']}")
    
    if stats["by_severity"]:
        print("\nBy Severity:")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in stats["by_severity"]:
                print(f"  {sev}: {stats['by_severity'][sev]}")
    
    # Print findings
    if results["findings"]:
        print(f"\n{'='*60}")
        print("FINDINGS")
        print(f"{'='*60}")
        
        for i, f in enumerate(results["findings"], 1):
            print(f"\n[{i}] [{f.get('severity', 'Unknown')}] {f.get('rule', 'Unknown')}")
            print(f"    File: {f.get('file')}:{f.get('line')}")
            print(f"    {f.get('message', '')}")
            if f.get('code'):
                print(f"    Code: {f.get('code')[:100]}")
            if args.verbose and f.get('remediation'):
                print(f"    Fix: {f.get('remediation')}")
    else:
        print("\n✅ No vulnerabilities found!")
    
    # Save output
    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")
    
    # Exit code based on findings
    critical_high = sum(1 for f in results["findings"] if f.get("severity") in ("Critical", "High"))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()