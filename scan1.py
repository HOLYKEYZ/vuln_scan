#!/usr/bin/env python3
"""
Gemini File Analyzer - NO SDK REQUIRED (uses requests only)
Auto-discovers available models from Google API
"""

import os
import sys
import tkinter as tk
from tkinter import filedialog
import requests
import json

# Try to load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# =============================================================================
# CONFIG
# =============================================================================

API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GROQ_KEY")

# Updated fallback models (will try auto-discovery first)
FALLBACK_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-2.0-flash-001",
    "gemini-1.5-flash-002",
    "gemini-1.5-flash-001",
    "gemini-1.5-flash",
    "gemini-1.5-pro-002",
    "gemini-1.5-pro-001",
    "gemini-1.5-pro",
]

OUTPUT_FILE = "Google_AI_output.txt"

# =============================================================================
# MODEL DISCOVERY
# =============================================================================

def get_available_models(api_key: str) -> list:
    """
    Fetch list of available models from Google API.
    Returns list of model names that support generateContent.
    """
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        resp = requests.get(url, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            models = []
            
            for m in data.get("models", []):
                name = m.get("name", "").replace("models/", "")
                methods = m.get("supportedGenerationMethods", [])
                
                # Only use models that support generateContent
                if "generateContent" in methods:
                    models.append(name)
            
            # Sort by preference (2.5 > 2.0 > 1.5, flash > pro)
            def model_priority(model_name):
                score = 0
                if "2.5" in model_name:
                    score += 300
                elif "2.0" in model_name:
                    score += 200
                elif "1.5" in model_name:
                    score += 100
                
                if "flash" in model_name:
                    score += 50
                elif "pro" in model_name:
                    score += 10
                
                # Prefer non-exp versions
                if "exp" not in model_name:
                    score += 5
                
                return -score  # Negative for descending sort
            
            models.sort(key=model_priority)
            
            return models
        
        return []
        
    except Exception as e:
        print(f"⚠ Warning: Could not fetch models ({e})")
        return []


# =============================================================================
# GEMINI API (requests only - no SDK)
# =============================================================================

def call_gemini(system_prompt: str, user_prompt: str, file_content: str, models_to_try: list) -> str:
    """
    Call Gemini API using requests - tries multiple model names.
    Returns the response or error message.
    """
    if not API_KEY:
        return "❌ Error: Set GOOGLE_API_KEY or GEMINI_KEY in .env or environment"
    
    # Build full prompt
    full_prompt = f"{system_prompt}\n\n{user_prompt}\n\n--- FILE CONTENT ---\n{file_content}"
    
    payload = {
        "contents": [{
            "parts": [{"text": full_prompt}]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 8192,
            "topP": 0.95,
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
    }
    
    last_error = None
    rate_limited = []
    not_found = []
    forbidden = []
    
    # Try each model until one works
    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={API_KEY}"
        
        try:
            print(f"  Trying model: {model}...", end=" ", flush=True)
            resp = requests.post(
                url, 
                json=payload, 
                headers={"Content-Type": "application/json"}, 
                timeout=120
            )
            
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    
                    if parts:
                        text = parts[0].get("text", "")
                        if text:
                            print("✓ SUCCESS")
                            return text
                
                # If we got 200 but no text, try next model
                last_error = f"{model}: Empty response"
                print("(empty)")
                
            elif resp.status_code == 429:
                # Rate limited - track but keep trying
                rate_limited.append(model)
                print("✗ Rate limited")
                
            elif resp.status_code == 403:
                # Forbidden - track but keep trying
                forbidden.append(model)
                print("✗ Forbidden (quota issue)")
                
            elif resp.status_code == 404:
                # Not found - track but keep trying
                not_found.append(model)
                print("✗ Not found")
                
            else:
                # Other error
                error_data = resp.json() if resp.text else {}
                error_msg = error_data.get("error", {}).get("message", resp.text[:100])
                last_error = f"{model}: {resp.status_code} - {error_msg}"
                print(f"✗ {resp.status_code}")
            
        except requests.exceptions.Timeout:
            last_error = f"{model}: Request timed out"
            print("✗ Timeout")
        except requests.exceptions.ConnectionError:
            last_error = f"{model}: Connection error"
            print("✗ Connection error")
        except Exception as e:
            last_error = f"{model}: {str(e)}"
            print(f"✗ {str(e)[:50]}")
    
    # All models failed - build helpful error message
    error_msg = f"❌ All {len(models_to_try)} models failed.\n\n"
    
    if rate_limited:
        error_msg += f"⚠ Rate limited models ({len(rate_limited)}): {', '.join(rate_limited[:3])}\n"
        error_msg += "  → Try again in a few minutes or upgrade your API quota\n\n"
    
    if forbidden:
        error_msg += f"⚠ Forbidden/Quota models ({len(forbidden)}): {', '.join(forbidden[:3])}\n"
        error_msg += "  → Check your billing settings or API quota\n\n"
    
    if not_found:
        error_msg += f"⚠ Models not found ({len(not_found)}): {', '.join(not_found[:3])}\n"
        error_msg += "  → These models may not be available in your region\n\n"
    
    if last_error:
        error_msg += f"Last error: {last_error}\n\n"
    
    error_msg += "Try these fixes:\n"
    error_msg += "1. Verify your API key at https://aistudio.google.com/app/apikey\n"
    error_msg += "2. Check if you've exceeded free tier limits\n"
    error_msg += "3. Try again in a few minutes (rate limits reset)\n"
    error_msg += "4. Check your internet connection\n"
    error_msg += "5. If 403 errors, check billing settings at https://console.cloud.google.com/billing"
    
    return error_msg


# =============================================================================
# FILE HANDLING
# =============================================================================

def select_file() -> str:
    """Open file dialog to select a file"""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    
    print("📂 Opening file dialog...")
    
    path = filedialog.askopenfilename(
        title="Select a file to analyze",
        filetypes=[
            ("Python Files", "*.py"),
            ("All Files", "*.*"),
            ("Text Files", "*.txt"),
            ("Markdown", "*.md"),
            ("JSON Files", "*.json"),
        ]
    )
    
    root.destroy()
    return path if path else None


def read_file(path: str) -> str:
    """Read file with multiple encoding attempts"""
    for enc in ["utf-8", "latin-1", "cp1252", "iso-8859-1"]:
        try:
            with open(path, "r", encoding=enc) as f:
                content = f.read()
                print(f"✓ Read file using {enc} encoding")
                return content
        except (UnicodeDecodeError, FileNotFoundError):
            continue
    return None


def save_output(text: str, src_path: str):
    """Save analysis output to file"""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("GEMINI AI ANALYSIS\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Source File: {src_path}\n")
        f.write(f"Analyzed: {os.path.basename(src_path)}\n")
        f.write("-" * 60 + "\n\n")
        f.write(text)
    
    print(f"\n✓ Output saved to: {OUTPUT_FILE}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 60)
    print("  GEMINI FILE ANALYZER")
    print("  No SDK Required - Auto-discovers models")
    print("=" * 60)
    print()
    
    # Check API key
    if not API_KEY:
        print("❌ ERROR: No API key found!")
        print()
        print("Set your API key in one of these ways:")
        print("  1. Create .env file with: GOOGLE_API_KEY=your_key_here")
        print("  2. Set environment variable: GOOGLE_API_KEY=your_key_here")
        print()
        print("Get your API key from:")
        print("  https://aistudio.google.com/app/apikey")
        print()
        return
    
    print(f"✓ API Key found (ends with ...{API_KEY[-4:]})")
    print()
    
    # Auto-discover available models
    print("🔍 Discovering available models...")
    available_models = get_available_models(API_KEY)
    
    if available_models:
        print(f"✓ Found {len(available_models)} models")
        print(f"  Top choices: {', '.join(available_models[:5])}")
        models_to_use = available_models[:10]  # Use top 10
    else:
        print(f"⚠ Auto-discovery failed, using {len(FALLBACK_MODELS)} fallback models")
        models_to_use = FALLBACK_MODELS
    
    print()
    
    # Select file
    file_path = select_file()
    if not file_path:
        print("❌ No file selected. Exiting.")
        return
    
    print(f"✓ Selected: {file_path}")
    
    # Read file
    content = read_file(file_path)
    if not content:
        print("❌ Could not read file with any encoding.")
        return
    
    print(f"✓ File stats: {len(content)} chars, {len(content.splitlines())} lines")
    print()
    
    # Choose analysis type
    print("=" * 60)
    print("Analysis Options:")
    print("=" * 60)
    print("  [1] Security Analysis (SQL injection, vulnerabilities)")
    print("  [2] General Code Analysis (purpose, quality, improvements)")
    print("  [3] Custom Prompt (enter your own)")
    print()
    
    choice = input("Enter choice (1-3, default=1): ").strip() or "1"
    
    if choice == "1":
        system = "You are an expert security code reviewer specializing in vulnerability detection."
        user = """Analyze this code for security vulnerabilities. Focus on:
- SQL injection (f-strings, .format(), concatenation with user input)
- Command injection (os.system, subprocess with user input)
- Path traversal (user input in file paths)
- Authentication/authorization issues
- Data exposure risks

For each issue found, provide:
- Line number (if possible)
- Severity (Critical/High/Medium/Low)
- Description
- How to fix it"""
        
    elif choice == "2":
        system = "You are an expert code reviewer with deep knowledge of software engineering best practices."
        user = """Analyze this code and provide:
1. Overall purpose and functionality
2. Code quality assessment
3. Potential bugs or issues
4. Performance considerations
5. Recommended improvements
6. Best practice violations"""
        
    elif choice == "3":
        print()
        system = input("System prompt (what role should AI take?): ").strip() or "You are an expert code reviewer."
        user = input("User prompt (what should AI analyze?): ").strip() or "Analyze this code."
        
    else:
        print("Invalid choice, using default security analysis.")
        system = "You are an expert security code reviewer."
        user = "Analyze this code for security vulnerabilities."
    
    print()
    print("=" * 60)
    print("🔍 ANALYZING...")
    print("=" * 60)
    print()
    
    # Call Gemini
    result = call_gemini(system, user, content, models_to_use)
    
    # Display result
    print()
    print("=" * 60)
    print("📊 ANALYSIS RESULT")
    print("=" * 60)
    print()
    print(result)
    print()
    print("=" * 60)
    
    # Save output
    save_output(result, file_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)