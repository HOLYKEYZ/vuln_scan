#!/usr/bin/env python3
import argparse
from scanner import load_provider
from pathlib import Path

parser = argparse.ArgumentParser(description="LLM-powered vulnerability scanner")
parser.add_argument("file", help="Path to file to scan")
parser.add_argument("--provider", default="gemini", help="Provider name (gemini, openai, claude, groq, openrouter, ollama)")
args = parser.parse_args()

p = Path(args.file)
if not p.exists():
    print("File not found:", args.file)
    raise SystemExit(1)

content = p.read_text(encoding="utf-8", errors="ignore")
provider = load_provider(args.provider)
system_prompt = "You are a world-class security analysis AI."
user_prompt = "Perform a complete vulnerability scan."

print("Scanning with", args.provider)
out = provider.ask(system_prompt, user_prompt, content)
print("\n=== SCAN OUTPUT ===\n")
print(out)
