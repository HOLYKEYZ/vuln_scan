"""
Scanner Main Module - Ties together AST scanner + LLM providers
"""

import os
import sys
import json
import re
from typing import Dict, Any, Optional, List

# Import the AST scanner
try:
    from large_scanner import scan_file as ast_scan_file, scan_path as ast_scan_path
    HAS_AST_SCANNER = True
except ImportError:
    HAS_AST_SCANNER = False
    print("Warning: large_scanner.py not found - AST scanning disabled")

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

SECURITY_SYSTEM_PROMPT = """You are an expert security code reviewer. Analyze Python code for SQL injection vulnerabilities.

Output JSON only:
{
  "findings": [
    {"line": <num>, "severity": "Critical|High|Medium|Low", "message": "<description>", "code": "<snippet>", "remediation": "<fix>"}
  ],
  "summary": "<brief assessment>"
}

Focus on: f-strings with SQL, .format(), % formatting, string concatenation, request.args/form/headers in SQL, weak sanitization (.replace, .strip)."""


def analyze_with_llm(code: str, filename: str, provider) -> Dict[str, Any]:
    """Analyze code using LLM"""
    user_prompt = f"Analyze this file for SQL injection: {filename}\n\n```python\n{code}\n```"
    
    response = provider.ask(SECURITY_SYSTEM_PROMPT, user_prompt, "")
    findings = []
    
    try:
        # Extract JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            data = json.loads(json_match.group())
            for f in data.get("findings", []):
                findings.append({
                    "file": filename, "line": f.get("line", 0), "col": 0,
                    "rule": "LLM-SQLI", "message": f.get("message", ""),
                    "severity": f.get("severity", "Medium"),
                    "confidence": "Medium", "code": f.get("code", ""),
                    "remediation": f.get("remediation", "Use parameterized queries"),
                    "source": "llm"
                })
    except json.JSONDecodeError:
        if "sql injection" in response.lower() or "vulnerability" in response.lower():
            findings.append({
                "file": filename, "line": 0, "col": 0, "rule": "LLM-REVIEW",
                "message": f"LLM detected issues: {response[:200]}...",
                "severity": "Medium", "confidence": "Low", "source": "llm"
            })
    
    return {"findings": findings, "raw_response": response}


# =============================================================================
# UNIFIED SCANNING
# =============================================================================

def scan_file(path: str, provider_name: str = None, api_key: str = None,
              ast_only: bool = False, llm_only: bool = False) -> Dict[str, Any]:
    """Scan a file for SQL injection vulnerabilities."""
    results = {
        "findings": [],
        "statistics": {
            "files_scanned": 1, "total_findings": 0,
            "by_severity": {}, "by_rule": {},
            "by_source": {"ast": 0, "llm": 0}
        }
    }
    
    # Read file
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        results["findings"].append({"file": path, "line": 0, "rule": "SCAN-ERROR",
                                    "message": f"Failed to read: {e}", "severity": "Info"})
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
            results["findings"].append({"file": path, "line": 0, "rule": "LLM-ERROR",
                                        "message": f"LLM failed: {e}", "severity": "Info", "source": "llm"})
    
    # Deduplicate
    seen = set()
    unique = []
    for f in results["findings"]:
        key = (f.get("file"), f.get("line"), f.get("rule", "")[:8])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    results["findings"] = unique
    
    # Update stats
    results["statistics"]["total_findings"] = len(results["findings"])
    for f in results["findings"]:
        sev = f.get("severity", "Unknown")
        rule = f.get("rule", "Unknown")
        results["statistics"]["by_severity"][sev] = results["statistics"]["by_severity"].get(sev, 0) + 1
        results["statistics"]["by_rule"][rule] = results["statistics"]["by_rule"].get(rule, 0) + 1
    
    return results


def scan_path(path: str, provider_name: str = None, api_key: str = None,
              ast_only: bool = False, llm_only: bool = False) -> Dict[str, Any]:
    """Scan a file or directory."""
    if os.path.isfile(path):
        return scan_file(path, provider_name, api_key, ast_only, llm_only)
    
    results = {
        "findings": [],
        "statistics": {"files_scanned": 0, "total_findings": 0,
                       "by_severity": {}, "by_rule": {}, "by_source": {"ast": 0, "llm": 0}}
    }
    
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]
        for fname in files:
            if fname.endswith('.py'):
                fpath = os.path.join(root, fname)
                file_results = scan_file(fpath, provider_name, api_key, ast_only, llm_only)
                results["findings"].extend(file_results.get("findings", []))
                results["statistics"]["files_scanned"] += 1
                for sev, cnt in file_results.get("statistics", {}).get("by_severity", {}).items():
                    results["statistics"]["by_severity"][sev] = results["statistics"]["by_severity"].get(sev, 0) + cnt
                for rule, cnt in file_results.get("statistics", {}).get("by_rule", {}).items():
                    results["statistics"]["by_rule"][rule] = results["statistics"]["by_rule"].get(rule, 0) + cnt
                results["statistics"]["by_source"]["ast"] += file_results.get("statistics", {}).get("by_source", {}).get("ast", 0)
                results["statistics"]["by_source"]["llm"] += file_results.get("statistics", {}).get("by_source", {}).get("llm", 0)
    
    results["statistics"]["total_findings"] = len(results["findings"])
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--provider", "-p", choices=["gemini", "openai", "claude", "groq"], help="LLM provider")
    parser.add_argument("--api-key", "-k", help="API key")
    parser.add_argument("--ast-only", action="store_true", help="AST analysis only")
    parser.add_argument("--llm-only", action="store_true", help="LLM analysis only")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    print(f"Scanning: {args.path}")
    if args.provider:
        print(f"Using LLM: {args.provider}")
    
    results = scan_path(args.path, args.provider, args.api_key, args.ast_only, args.llm_only)
    stats = results["statistics"]
    
    print(f"\n{'='*50}\nSCAN COMPLETE\n{'='*50}")
    print(f"Files: {stats['files_scanned']} | Findings: {stats['total_findings']}")
    print(f"  AST: {stats['by_source']['ast']} | LLM: {stats['by_source']['llm']}")
    
    if stats["by_severity"]:
        print("\nSeverity:", " | ".join(f"{k}: {v}" for k, v in stats["by_severity"].items()))
    
    if results["findings"]:
        print(f"\n{'='*50}\nFINDINGS\n{'='*50}")
        for i, f in enumerate(results["findings"], 1):
            print(f"\n[{i}] [{f.get('severity')}] {f.get('rule')}")
            print(f"    {f.get('file')}:{f.get('line')}")
            print(f"    {f.get('message', '')[:100]}")
    else:
        print("\n✅ No vulnerabilities found!")
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved: {args.output}")
    
    sys.exit(1 if any(f.get("severity") in ("Critical", "High") for f in results["findings"]) else 0)


if __name__ == "__main__":
    main()