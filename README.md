# LLM Vulnerability Scanner (Full Stack)

This project contains:
- providers/ : LLM provider adapters (Gemini, OpenAI, Claude, Groq, OpenRouter, Ollama)
- bin/cli.py : Command-line scanner
- vscode_extension/ : simple VS Code extension scaffold that calls the CLI
- web_dashboard/ : Flask web UI for file uploads
- api_backend/ : FastAPI backend exposing /scan endpoint
- scanner.py : provider loader
- SAMPLE file url: file:///mnt/data/temp3.md

## Quick start

1. Copy project, set environment variables for the providers you intend to use:
    - GEMINI_KEY
    - OPENAI_KEY
    - CLAUDE_KEY
    - GROQ_KEY and GROQ_API_URL
    - OPENROUTER_KEY
    - OLLAMA_HOST

2. Run CLI:
    ```
    python bin/cli.py path/to/file --provider gemini
    ```

3. Run web dashboard:
    ```
    pip install flask
    python web_dashboard/app.py
    ```

4. Run API backend:
    ```
    pip install fastapi uvicorn
    python api_backend/app.py
    ```

## Sample file (from your session)
Example local path used in this project for testing:
`file:///mnt/data/temp3.md`
