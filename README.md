# Python SQL Injection Scanner

Fast, accurate SQL injection, vulnerabilities, malware and bugs detection using AST analysis with optional LLM enhancement.

## Features

✅ **AST Scanner** - Static analysis, no API needed, 10+ vulnerability patterns  
✅ **LLM Analysis** - AI-powered review (Gemini, OpenAI, Claude, Groq)  
✅ **GUI & CLI** - Desktop GUI or command-line interface  
✅ **Web Dashboard** - Browser-based scanning  
✅ **No SDK Dependencies** - LLM providers use `requests` only  
✅ **Detailed Reports** - JSON and HTML output with remediation steps

## Quick Start

```bash
# Clone repo
git clone https://github.com/yourusername/vuln_scan.git
cd vuln_scan

# AST scan (no setup needed)
python large_scanner.py your_code.py

# With GUI
python large_scanner.py --gui

# Combined AST + LLM
python scanner.py your_code.py --provider gemini
```

## Installation

### Minimal (AST only)

```bash
# No dependencies needed - AST scanner works out of the box
python large_scanner.py
```

### Full (with LLM support)

```bash
pip install requests python-dotenv flask
```

## Configuration

Create `.env` file for LLM providers (optional):

```env
GOOGLE_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_claude_key_here
GROQ_API_KEY=your_groq_key_here
```

Get API keys:

- Gemini: https://makersuite.google.com/app/apikey
- OpenAI: https://platform.openai.com/api-keys
- Claude: https://console.anthropic.com/
- Groq: https://console.groq.com/

## Usage

### 1. AST Scanner (Recommended for daily use)

```bash
# Scan single file
python large_scanner.py app.py

# Scan directory
python large_scanner.py ./src/

# Output to JSON
python large_scanner.py ./src/ -o results.json

# Generate HTML report
python large_scanner.py ./src/ -r report.html

# Launch GUI
python large_scanner.py --gui
```

### 2. Combined Scanner (AST + LLM)

```bash
# AST only
python scanner.py app.py --ast-only

# AST + Gemini
python scanner.py app.py --provider gemini

# AST + OpenAI
python scanner.py app.py --provider openai

# LLM only
python scanner.py app.py --llm-only --provider claude

# Save results
python scanner.py app.py --provider gemini -o scan_results.json
```

### 3. Web Dashboard

```bash
# Start server (from project root)
python web_dashboard/app.py

# Or from web_dashboard directory
cd web_dashboard
python app.py

# Open browser: http://localhost:5000
```

### 4. Gemini File Analyzer

```bash
python scan1.py
# Opens file dialog, analyzes selected file
```

### 5. CLI Wrapper

```bash
# From project root
python bin/cli.py path/to/file.py

# With LLM
python bin/cli.py path/to/file.py --provider gemini

# Output to file
python bin/cli.py path/to/file.py --provider openai -o results.json
```

## Project Structure

```
vuln_scan/
├── large_scanner.py      # Main AST scanner (4k lines, full-featured)
├── scanner.py            # Combined AST + LLM scanner
├── scan1.py              # Gemini file analyzer (GUI)
├── providers.py          # LLM providers (no SDK, requests only)
├── web_dashboard/
│   └── app.py            # Flask web interface
├── bin/
│   └── cli.py            # CLI wrapper
├── .env                  # API keys (create this)
└── README.md             # This file
```

## Detection Rules

| Rule ID     | Description                                      | Severity |
| ----------- | ------------------------------------------------ | -------- |
| PY-SQLI-001 | Unsanitized user input in SQL query              | High     |
| PY-SQLI-002 | SQL identifier injection (table/column names)    | Medium   |
| PY-SQLI-003 | SQLAlchemy raw SQL with user input               | High     |
| PY-SQLI-004 | Django raw() with unsafe parameters              | High     |
| PY-SQLI-005 | executescript() with dynamic content             | Critical |
| PY-SQLI-006 | String formatting in SQL (f-strings, .format, %) | High     |
| PY-SQLI-007 | String manipulation doesn't prevent SQLi         | High     |
| PY-SQLI-008 | Weak sanitization (.replace, .strip)             | Critical |
| PY-SQLI-009 | Unvalidated date/time in WHERE clause            | Critical |
| PY-SQLI-010 | HTTP header used directly in SQL                 | Critical |

## Tool Comparison

| Feature          | large_scanner.py   | scanner.py    | scan1.py        | Web Dashboard |
| ---------------- | ------------------ | ------------- | --------------- | ------------- |
| AST Analysis     | ✅                 | ✅            | ❌              | ✅            |
| LLM Analysis     | ❌                 | ✅            | ✅              | ✅            |
| GUI              | ✅                 | ❌            | ✅              | ✅ (Web)      |
| API Key Required | ❌                 | Optional      | ✅              | Optional      |
| Best For         | Daily scans, CI/CD | Deep analysis | Quick AI review | Teams         |
| Speed            | ⚡ Fast            | 🐢 Depends    | 🐢 Slow         | 🔄 Varies     |

## When to Use What

### Use `large_scanner.py` when:

- Scanning entire projects/folders
- Running in CI/CD pipelines
- No API key available
- Need fast results
- Want GUI with charts

### Use `scanner.py --provider X` when:

- Need both AST and AI analysis
- Want to verify AST findings
- Complex code patterns
- Need detailed explanations

### Use `scan1.py` when:

- Quick AI-only analysis of single file
- Want conversational analysis
- Prefer GUI file picker
- Testing different prompts

### Use Web Dashboard when:

- Working in teams
- Non-technical users
- Want browser-based interface
- Need visual reports

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: "3.9"

      - name: Run SQL Injection Scanner
        run: |
          python large_scanner.py ./src/ -o results.json

      - name: Check for Critical/High findings
        run: |
          python large_scanner.py ./src/ --fail-on high
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
python large_scanner.py $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')
```

## Troubleshooting

### ModuleNotFoundError: No module named 'scanner'

```bash
# Run from project root, not from subdirectories
cd /path/to/vuln_scan
python scanner.py file.py
```

### Gemini API Error 404: models/gemini-1.5-flash is not found

```bash
# scan1.py now tries multiple model names automatically
# Just make sure GOOGLE_API_KEY is set correctly
```

### Web dashboard can't find scanner modules

```bash
# Always run from project root
python web_dashboard/app.py

# NOT from inside web_dashboard/
```

### LLM provider errors

```bash
# Check .env file exists and has correct API keys
cat .env

# Test provider directly
python -c "from providers import load_provider; p = load_provider('gemini'); print(p.ask('test', 'hi', ''))"
```

## Examples

### Example 1: Vulnerable Code

```python
# app.py
import sqlite3
from flask import request

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()

    # VULNERABLE - SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchone()
```

**Scanner Output:**

```
[CRITICAL] PY-SQLI-001
  app.py:9
  SQL injection: user_id used in execute() without parameterization
  Fix: Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

### Example 2: Fixed Code

```python
# app_fixed.py
import sqlite3
from flask import request

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()

    # SAFE - parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    return cursor.fetchone()
```

**Scanner Output:**

```
✅ No vulnerabilities found!
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- AST-based detection inspired by Bandit and Semgrep
- LLM integration uses Claude, GPT, Gemini, and Groq APIs
- Built with Flask, tkinter, and Python's ast module

---

**Made with ❤️ for secure Python applications**
