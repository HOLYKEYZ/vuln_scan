import os
import re
import sys
import json
import time
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Union

# Try importing OpenAI, handle if missing
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# 🔑 API KEY CONFIGURATION
# Leave empty to use environment variable 'OPENAI_API_KEY' or manual input
API_KEY = "" 

# Model to use for deep analysis
MODEL_NAME = "gpt-4o"  # Or "gpt-3.5-turbo", etc.

# ==============================================================================
# SYSTEM PROMPT (derived from your expert analyst instructions)
# ==============================================================================

SYSTEM_PROMPT = """
CRITICAL INSTRUCTION: You are an expert application security analyst. 
Conduct a thorough security assessment with precision, context-awareness, and responsible disclosure.

## EXECUTION MODE
1. Phase 1: Context Assessment (Production vs Demo)
2. Phase 2: Systematic Vulnerability Scan
3. Phase 3-7: Complete Reporting

## MANDATORY SCAN CATEGORIES:
1. Authentication & Session (Rate limiting, CSRF, Session fixation, Weak Crypto)
2. Injection (SQLi, Command Injection vs Path Traversal, XSS)
3. Authorization (IDOR, Privilege Escalation)
4. Security Misconfiguration (Debug mode, Secret keys, CSP)

## OUTPUT FORMAT
Provide the output in strict Markdown format.
Include a 'Vulnerability Coverage Matrix' and 'Critical Vulnerabilities' detailed section.
Do NOT include weaponized exploits. Use conceptual descriptions only.
"""

# ==============================================================================
# 1. LOCAL STATIC ANALYSIS ENGINE (Regex/Pattern Matching)
# ==============================================================================

class LocalScanner:
    """
    Performs fast, local pattern matching for basic vulnerabilities.
    Does not require an API key.
    """
    
    PATTERNS = {
        "Hardcoded Secret": r"(?i)(api_key|secret|password|token)\s*=\s*['\"][a-zA-Z0-9_\-]{10,}['\"]",
        "Debug Mode Enabled": r"(?i)(debug\s*=\s*True|app\.run\(.*debug=True.*\))",
        "Weak Hashing (MD5/SHA1)": r"(?i)hashlib\.(md5|sha1)\(",
        "Dangerous Subprocess (Shell=True)": r"(?i)subprocess\..*(shell\s*=\s*True)",
        "Potential SQL Injection": r"(?i)(execute|cursor)\s*\(\s*f['\"](SELECT|INSERT|UPDATE|DELETE)",
        "Insecure IP Binding": r"(?i)host\s*=\s*['\"]0\.0\.0\.0['\"]",
        "Flask Secret Key Hardcoded": r"(?i)app\.config\['SECRET_KEY'\]\s*=\s*['\"][^'\"]+['\"]",
    }

    @staticmethod
    def scan(content: str) -> List[Dict]:
        findings = []
        lines = content.split('\n')
        
        for name, pattern in LocalScanner.PATTERNS.items():
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    findings.append({
                        "type": "Basic Finding (Local)",
                        "vulnerability": name,
                        "line": i + 1,
                        "snippet": line.strip()[:100],
                        "severity": "High" if "Secret" in name or "Shell" in name else "Medium"
                    })
        return findings

# ==============================================================================
# 2. AI DEEP ANALYSIS ENGINE (LLM Wrapper)
# ==============================================================================

class AIScanner:
    """
    Uses an LLM to perform deep context analysis and find complex logic flaws.
    """
    def __init__(self, api_key: str):
        if not OpenAI:
            print("❌ Error: 'openai' library not installed. Run: pip install openai")
            sys.exit(1)
        self.client = OpenAI(api_key=api_key)

    def analyze(self, code_content: str, filename: str) -> str:
        try:
            print(f"🧠 Initiating Deep Scan on {filename}...")
            response = self.client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"CODE TO ANALYZE ({filename}):\n\n{code_content}"}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"❌ AI Analysis Failed: {str(e)}"

# ==============================================================================
# MAIN TOOL CLASS
# ==============================================================================

class SecurityTool:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or API_KEY or os.environ.get("OPENAI_API_KEY")
        self.local_scanner = LocalScanner()
        self.ai_scanner = AIScanner(self.api_key) if self.api_key else None

    def scan_file(self, filepath: str, output_format: str = "cli"):
        if not os.path.exists(filepath):
            print(f"❌ File not found: {filepath}")
            return

        print(f"\n🔍 Scanning: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"❌ Could not read file: {e}")
            return

        # 1. Run Local Scan
        print("⚡ Running Local Pattern Matcher...")
        local_findings = self.local_scanner.scan(content)
        
        # 2. Run AI Scan (if key exists)
        ai_report = None
        if self.ai_scanner:
            print("🤖 Running AI Context Analysis (this may take a moment)...")
            ai_report = self.ai_scanner.analyze(content, os.path.basename(filepath))
        else:
            print("⚠️  Skipping AI Analysis (No API Key provided).")

        # 3. Output Results
        self._generate_output(filepath, local_findings, ai_report, output_format)

    def _generate_output(self, filepath, local_findings, ai_report, output_format):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # CLI Output
        print("\n" + "="*60)
        print(f"🛡️  SECURITY SCAN REPORT - {timestamp}")
        print(f"📂 File: {filepath}")
        print("="*60)
        
        print(f"\n🔸 LOCAL FINDINGS ({len(local_findings)}):")
        if local_findings:
            for f in local_findings:
                print(f"   [{f['severity']}] {f['vulnerability']} (Line {f['line']})")
                print(f"     Example: {f['snippet']}")
        else:
            print("   No basic patterns detected.")

        if ai_report:
            print("\n" + "="*60)
            print("🔹 DEEP AI ANALYSIS:")
            print("="*60)
            print(ai_report)
            
            # Save to Markdown file
            report_filename = f"report_{os.path.basename(filepath)}_{int(time.time())}.md"
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(f"# Security Report: {filepath}\nDate: {timestamp}\n\n")
                f.write("## Local Static Analysis\n")
                f.write(json.dumps(local_findings, indent=2))
                f.write("\n\n## AI Deep Analysis\n")
                f.write(ai_report)
            print(f"\n✅ Full report saved to: {report_filename}")

def main():
    parser = argparse.ArgumentParser(description="Cyber Security Code Scanner")
    parser.add_argument("file", nargs="?", help="File to scan")
    parser.add_argument("--key", help="API Key (optional, overrides config)")
    args = parser.parse_args()

    print("""
   _____            _       
  / ____|          | |      
 | (___   ___ _ __ | |_ ___ 
  \___ \ / _ \ '_ \| __/ __|
  ____) |  __/ | | | |_\__ \\
 |_____/ \___|_| |_|\__|___/
    """)

    target_file = args.file
    
    # Interactive mode if no args
    if not target_file:
        target_file = input("📝 Enter path to file to scan: ").strip()
        # Remove quotes if user dragged/dropped file
        target_file = target_file.replace('"', '').replace("'", "")

    tool = SecurityTool(api_key=args.key)
    tool.scan_file(target_file)

if __name__ == "__main__":
    main()