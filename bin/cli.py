#!/usr/bin/env python3
"""
CLI wrapper for vulnerability scanner
Run from project root: python bin/cli.py <file> [--provider gemini]
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse

# Import scanner
try:
    from scanner import scan_file, scan_path
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False

try:
    from large_scanner import scan_file as ast_scan, scan_path as ast_scan_path
    HAS_AST = True
except ImportError:
    HAS_AST = False

try:
    from providers import load_provider
    HAS_PROVIDERS = True
except ImportError:
    HAS_PROVIDERS = False


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner CLI")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--provider", "-p", choices=["gemini", "openai", "claude", "groq"],
                        help="LLM provider for enhanced analysis")
    parser.add_argument("--ast-only", action="store_true", help="AST analysis only")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()
    
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    print(f"Scanning: {args.path}")
    
    # Use combined scanner if available
    if HAS_SCANNER and not args.ast_only:
        from scanner import scan_path
        results = scan_path(str(path), provider_name=args.provider, ast_only=args.ast_only)
    elif HAS_AST:
        results = ast_scan_path(str(path)) if path.is_dir() else ast_scan(str(path))
    else:
        print("Error: No scanner available")
        sys.exit(1)
    
    # Print results
    findings = results.get("findings", [])
    stats = results.get("statistics", {})
    
    print(f"\n{'='*50}")
    print(f"Files: {stats.get('files_scanned', 1)} | Findings: {len(findings)}")
    
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"\n[{i}] [{f.get('severity', '?')}] {f.get('rule', '?')}")
            print(f"    {f.get('file', '')}:{f.get('line', 0)}")
            print(f"    {f.get('message', '')[:80]}")
    else:
        print("\n✅ No vulnerabilities found!")
    
    # Save output
    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved: {args.output}")
    
    # Exit code
    critical_high = sum(1 for f in findings if f.get("severity") in ("Critical", "High"))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()