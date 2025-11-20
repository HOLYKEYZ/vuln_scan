# ======================================================================
# Google AI (Gemini) File Processor - FINAL WORKING VERSION (2025)
# Compatible with google-genai 1.51.0
# ======================================================================

import os
import tkinter as tk
from tkinter import filedialog
from google import genai

# ---------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------
API_KEY = os.getenv("GOOGLE_API_KEY")

# Fallback if environment variable not set
if not API_KEY:
    API_KEY = "REPLACE_WITH_YOUR_API_KEY"

MODEL_NAME = "gemini-1.5-flash"
OUTPUT_FILE = "Google_AI_output.txt"

# Initialize Google GenAI client
client = genai.Client(api_key=API_KEY)


# ---------------------------------------------------------------
# SELECT FILE
# ---------------------------------------------------------------
def select_file():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    print("Select a file...")

    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[
            ("All Files", "*.*"),
            ("Text Files", "*.txt"),
            ("Markdown", "*.md"),
            ("Python Files", "*.py"),
            ("JSON Files", "*.json"),
            ("CSV Files", "*.csv"),
        ],
    )

    root.destroy()
    return file_path if file_path else None


# ---------------------------------------------------------------
# READ FILE SAFELY
# ---------------------------------------------------------------
def read_file(path):
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except:
            continue
    return None


# ---------------------------------------------------------------
# PROCESS WITH GOOGLE GEMINI (CORRECT FOR SDK 1.51.0)
# ---------------------------------------------------------------
def process_with_google(system_prompt, user_prompt, file_content):
    try:
        response = client.chats.create(
            model=MODEL_NAME,
                input=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"FILE CONTENT:\n{file_content}\n\nINSTRUCTION:\n{user_prompt}",
                },
            ],
        )

        return response.output_text

    except Exception as e:
        return f"API ERROR: {str(e)}"


# ---------------------------------------------------------------
# SAVE OUTPUT
# ---------------------------------------------------------------
def save_output(text, src_path):
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("Google AI Response\n")
            f.write(f"Source File: {src_path}\n")
            f.write("=" * 60 + "\n\n")
            f.write(text)

        print(f"Output saved to {OUTPUT_FILE}")
    except:
        print("Failed to save output.")


# ---------------------------------------------------------------
# MAIN WORKFLOW
# ---------------------------------------------------------------
def main():
    print("=== Google AI File Processor ===\n")

    file_path = select_file()
    if not file_path:
        print("No file chosen.")
        return

    print(f"File selected: {file_path}")

    content = read_file(file_path)
    if not content:
        print("Could not read file.")
        return

    system_prompt = "You are a powerful AI that analyzes file content with precision."
    user_prompt = "Analyze this file and give a clear explanation."

    print("Processing...")
    result = process_with_google(system_prompt, user_prompt, content)

    print("\n=== AI RESPONSE ===")
    print(result)
    print("===================\n")

    save_output(result, file_path)


if __name__ == "__main__":
    main()
