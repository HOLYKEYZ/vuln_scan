# ======================================================================
# Google AI (Gemini) File Processor - FINAL ZERO-ERROR VERSION (2025)
# Using google-genai 1.51.0 actual behavior
# ======================================================================

import os
import tkinter as tk
from tkinter import filedialog
from google import genai
from dotenv import load_dotenv

# ---------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------

load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GROQ_KEY")


if not API_KEY:
    raise Exception("❌ Neither GOOGLE_API_KEY nor GROQ_KEY is set in .env file")

MODEL_NAME = "gemini-1.5-flash"
OUTPUT_FILE = "Google_AI_output.txt"

# Initialize client
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
            ("Markdown", "*.md"),
            ("Text Files", "*.txt"),
            ("Python Files", "*.py"),
            ("JSON Files", "*.json"),
        ],
    )

    root.destroy()
    return file_path if file_path else None


# ---------------------------------------------------------------
# READ FILE
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
# PROCESS WITH GEMINI
# ---------------------------------------------------------------
def process_with_google(system_prompt, user_prompt, file_content):
    try:
        # STEP 1: Create chat session with system prompt only
        chat = client.chats.create(
            model=MODEL_NAME,
            config={"system_instruction": system_prompt}
        )

        # STEP 2: Send the actual user message (this returns model output)
        message_text = f"{user_prompt}\n\n------ FILE CONTENT BELOW ------\n{file_content}"
        response = chat.send_message(message_text)

        # STEP 3: Extract response text safely
        if hasattr(response, "text"):
            return response.text
        return "❌ Model returned no text."

    except Exception as e:
        return f"API ERROR: {str(e)}"


# ---------------------------------------------------------------
# SAVE OUTPUT
# ---------------------------------------------------------------
def save_output(text, src_path):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("Google AI Response\n")
        f.write(f"Source File: {src_path}\n")
        f.write("=" * 60 + "\n\n")
        f.write(text)

    print(f"Output saved to {OUTPUT_FILE}")


# ---------------------------------------------------------------
# MAIN
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

    system_prompt = "You are an advanced AI for file analysis."
    user_prompt = "Analyze the file and provide insights."

    print("Processing...")
    result = process_with_google(system_prompt, user_prompt, content)

    print("\n=== AI RESPONSE ===")
    print(result)
    print("===================\n")

    save_output(result, file_path)


if __name__ == "__main__":
    main()
