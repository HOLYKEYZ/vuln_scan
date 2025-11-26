"""
Web Dashboard for Vulnerability Scanner
Run from project root: python web_dashboard/app.py
Or from this dir: python app.py
"""

import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path so we can import from project root
parent_dir = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(parent_dir))

from flask import Flask, request, render_template_string, jsonify

# Import from parent directory
try:
    from providers import load_provider, list_providers
    HAS_PROVIDERS = True
except ImportError:
    HAS_PROVIDERS = False
    print("⚠ Warning: providers.py not found - LLM analysis disabled")

try:
    from large_scanner import scan_file as ast_scan, scan_path as ast_scan_path
    HAS_AST = True
except ImportError:
    HAS_AST = False
    print("⚠ Warning: large_scanner.py not found - AST analysis disabled")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# =============================================================================
# HTML TEMPLATE
# =============================================================================

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SQL Injection Scanner</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2358a6ff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-color: #58a6ff;
            --accent-hover: #79c0ff;
            --success-color: #238636;
            --danger-color: #da3633;
            --warning-color: #d29922;
            --info-color: #3fb950;
            --font-main: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', 'Courier New', monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: var(--font-main);
            background-color: var(--bg-color);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            padding: 40px 0;
            margin-bottom: 20px;
        }
        
        header h1 {
            font-size: 2.5em;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        header h1 .shield-icon {
            width: 1.2em;
            height: 1.2em;
            vertical-align: text-bottom;
            margin-right: 10px;
        }
        
        header p {
            color: var(--text-secondary);
            font-size: 1.1em;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .section-title {
            font-size: 1.25em;
            font-weight: 600;
            color: var(--accent-color);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 6px;
            padding: 40px;
            text-align: center;
            transition: all 0.2s;
            cursor: pointer;
            background: rgba(255,255,255,0.02);
        }

        .upload-area:hover {
            border-color: var(--accent-color);
            background: rgba(88, 166, 255, 0.05);
        }

        input[type="file"] {
            display: none;
        }

        .file-label {
            display: block;
            font-size: 1.1em;
            color: var(--text-primary);
            cursor: pointer;
        }

        .file-label span {
            color: var(--accent-color);
            font-weight: 600;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }

        .form-group label {
            display: block;
            font-size: 0.9em;
            color: var(--text-secondary);
            margin-bottom: 8px;
            font-weight: 500;
        }

        select {
            width: 100%;
            padding: 10px 12px;
            background: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-family: var(--font-main);
            font-size: 0.95em;
            appearance: none;
            background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%238b949e%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22%2F%3E%3C%2Fsvg%3E");
            background-repeat: no-repeat;
            background-position: right 12px top 50%;
            background-size: 10px auto;
        }

        select:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        button[type="submit"] {
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: var(--success-color);
            color: white;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 6px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }

        button[type="submit"]:hover {
            background: #2ea043;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 24px;
        }

        .stat-box {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }

        .stat-number {
            font-size: 2em;
            font-weight: 700;
            display: block;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.85em;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-box.critical .stat-number { color: var(--danger-color); }
        .stat-box.high .stat-number { color: #ff7b72; }
        .stat-box.medium .stat-number { color: var(--warning-color); }
        .stat-box.low .stat-number { color: var(--accent-color); }

        .finding-card {
            background: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 16px;
            overflow: hidden;
        }

        .finding-header {
            padding: 12px 16px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .finding-title {
            font-family: var(--font-mono);
            font-size: 0.9em;
            color: var(--text-primary);
            font-weight: 600;
        }

        .badge {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            border: 1px solid transparent;
        }

        .badge.Critical { background: rgba(218, 54, 51, 0.15); color: #ff7b72; border-color: rgba(218, 54, 51, 0.4); }
        .badge.High { background: rgba(210, 153, 34, 0.15); color: #d29922; border-color: rgba(210, 153, 34, 0.4); }
        .badge.Medium { background: rgba(210, 153, 34, 0.15); color: #d29922; border-color: rgba(210, 153, 34, 0.4); }
        .badge.Low { background: rgba(56, 139, 253, 0.15); color: #58a6ff; border-color: rgba(56, 139, 253, 0.4); }
        .badge.Info { background: rgba(139, 148, 158, 0.15); color: #8b949e; border-color: rgba(139, 148, 158, 0.4); }

        .finding-body {
            padding: 16px;
        }

        .finding-desc {
            color: var(--text-secondary);
            font-size: 0.95em;
            margin-bottom: 12px;
        }

        .code-block {
            background: #000;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 12px;
            font-family: var(--font-mono);
            font-size: 0.85em;
            color: #e6edf3;
            overflow-x: auto;
            margin-bottom: 12px;
        }

        .remediation-box {
            background: rgba(35, 134, 54, 0.1);
            border: 1px solid rgba(35, 134, 54, 0.4);
            border-radius: 4px;
            padding: 12px;
            font-size: 0.9em;
            color: #7ee787;
        }

        .llm-output {
            background: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 20px;
            font-family: var(--font-mono);
            font-size: 0.9em;
            color: var(--text-secondary);
            white-space: pre-wrap;
            max-height: 500px;
            overflow-y: auto;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        footer {
            text-align: center;
            padding: 40px 0;
            color: var(--text-secondary);
            font-size: 0.85em;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: var(--bg-color);
        }
        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #58a6ff;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <svg class="shield-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="shield-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:#00d2ff;stop-opacity:1" />
                            <stop offset="100%" style="stop-color:#3a7bd5;stop-opacity:1" />
                        </linearGradient>
                    </defs>
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#shield-gradient)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Vulnerability Scanner
            </h1>
            <p>Advanced SQL Injection & Vulnerability Scanner</p>
        </header>
        
        <div class="card">
            <form method="post" enctype="multipart/form-data">
                <div class="upload-area" onclick="document.getElementById('file').click()">
                    <input type="file" id="file" name="file" accept=".py" required onchange="document.getElementById('file-name').textContent = this.files[0].name">
                    <label class="file-label">
                        Drop your Python file here or <span>browse</span>
                    </label>
                    <div id="file-name" style="margin-top: 10px; color: var(--accent-color); font-family: var(--font-mono);"></div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="mode">ANALYSIS MODE</label>
                        <select id="mode" name="mode">
                            <option value="ast" {% if not has_providers %}selected{% endif %}>AST Static Analysis (Fast)</option>
                            {% if has_providers %}
                            <option value="llm">LLM Deep Analysis</option>
                            <option value="both" selected>Hybrid (AST + LLM)</option>
                            {% endif %}
                        </select>
                    </div>
                    
                    {% if has_providers %}
                    <div class="form-group">
                        <label for="provider">AI ENGINE</label>
                        <select id="provider" name="provider">
                            <option value="gemini">Google Gemini</option>
                            <option value="openai">OpenAI GPT-4</option>
                            <option value="claude">Anthropic Claude</option>
                            <option value="groq">Groq (Llama 3)</option>
                        </select>
                    </div>
                    {% endif %}
                </div>
                
                <button type="submit">INITIATE SCAN</button>
            </form>
        </div>
        
        {% if stats %}
        <div class="section-title">Scan Results</div>
        <div class="stats-grid">
            <div class="stat-box critical">
                <span class="stat-number">{{ stats.critical }}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-box high">
                <span class="stat-number">{{ stats.high }}</span>
                <span class="stat-label">High</span>
            </div>
            <div class="stat-box medium">
                <span class="stat-number">{{ stats.medium }}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-box low">
                <span class="stat-number">{{ stats.low }}</span>
                <span class="stat-label">Low</span>
            </div>
            <div class="stat-box">
                <span class="stat-number">{{ stats.total }}</span>
                <span class="stat-label">Total Issues</span>
            </div>
        </div>
        {% endif %}
        
        {% if findings %}
        <div class="card">
            <div class="section-title">Vulnerabilities Detected</div>
            {% for f in findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-title">{{ f.rule }}</span>
                    <span class="badge {{ f.severity }}">{{ f.severity }}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-desc">
                        <strong>Location:</strong> {{ f.file }}:{{ f.line }}<br>
                        {{ f.message }}
                    </div>
                    {% if f.code %}
                    <div class="code-block">{{ f.code }}</div>
                    {% endif %}
                    {% if f.remediation %}
                    <div class="remediation-box">
                        <strong>RECOMMENDATION:</strong> {{ f.remediation }}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        {% elif scanned %}
        <div class="card" style="text-align: center; border-color: var(--success-color);">
            <h3 style="color: var(--success-color); margin-bottom: 10px;">✅ System Secure</h3>
            <p style="color: var(--text-secondary);">No obvious SQL injection vulnerabilities detected in the scanned file.</p>
        </div>
        {% endif %}
        
        {% if llm_response %}
        <div class="card">
            <div class="section-title">AI Analysis Log</div>
            <div class="llm-output">{{ llm_response }}</div>
        </div>
        {% endif %}
        
        {% if not scanned %}
        <div class="empty-state">
            <p>Ready to scan. Upload a file to begin security assessment.</p>
        </div>
        {% endif %}
        
        <footer>
            <p>SECURE CODE SCANNER v2.0 | PROTECT YOUR INFRASTRUCTURE</p>
        </footer>
    </div>
</body>
</html>
"""


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/', methods=['GET', 'POST'])
def index():
    findings = []
    llm_response = None
    stats = None
    scanned = False
    
    if request.method == 'POST':
        file = request.files.get('file')
        mode = request.form.get('mode', 'ast')
        provider_name = request.form.get('provider', 'gemini')
        
        if file and file.filename.endswith('.py'):
            scanned = True
            
            # Read uploaded file
            try:
                code = file.read().decode('utf-8', errors='ignore')
            except Exception as e:
                findings.append({
                    'file': file.filename,
                    'line': 0,
                    'col': 0,
                    'rule': 'FILE-ERROR',
                    'message': f'Could not read file: {e}',
                    'severity': 'Info',
                    'code': '',
                    'remediation': '',
                    'source': 'system'
                })
                stats = {'total': 1, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                return render_template_string(
                    HTML_TEMPLATE,
                    findings=findings,
                    stats=stats,
                    scanned=scanned,
                    has_ast=HAS_AST,
                    has_providers=HAS_PROVIDERS
                )
            
            # Create temp file for AST scanner
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                    tmp.write(code)
                    tmp_path = tmp.name
                
                # AST Analysis
                if mode in ('ast', 'both') and HAS_AST:
                    try:
                        result = ast_scan(tmp_path)
                        for finding in result.get('findings', []):
                            finding['source'] = 'ast'
                            finding['file'] = file.filename
                            findings.append(finding)
                    except Exception as e:
                        findings.append({
                            'file': file.filename,
                            'line': 0,
                            'rule': 'AST-ERROR',
                            'message': f'AST analysis failed: {e}',
                            'severity': 'Info',
                            'source': 'ast'
                        })
                
                # LLM Analysis
                if mode in ('llm', 'both') and HAS_PROVIDERS:
                    try:
                        provider = load_provider(provider_name)
                        system = "You are a security expert. Analyze Python code for SQL injection. Output JSON with findings array."
                        user = f"Analyze this code for SQL injection:\n\n{code}"
                        llm_response = provider.ask(system, user, "")
                        
                        # Try to parse JSON from LLM response
                        import json
                        import re
                        json_match = re.search(r'\{[\s\S]*\}', llm_response)
                        if json_match:
                            try:
                                data = json.loads(json_match.group())
                                for f in data.get('findings', []):
                                    findings.append({
                                        'file': file.filename,
                                        'line': f.get('line', 0),
                                        'col': 0,
                                        'rule': f.get('rule', 'LLM-SQLI'),
                                        'message': f.get('message', ''),
                                        'severity': f.get('severity', 'Medium'),
                                        'code': f.get('code', ''),
                                        'remediation': f.get('remediation', ''),
                                        'source': 'llm'
                                    })
                            except json.JSONDecodeError:
                                pass
                        
                    except Exception as e:
                        llm_response = f"LLM Error: {e}\n\nMake sure your API key is set in .env file."
            
            finally:
                # Cleanup temp file
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            
            # Calculate stats
            stats = {
                'total': len(findings),
                'critical': sum(1 for f in findings if f.get('severity') == 'Critical'),
                'high': sum(1 for f in findings if f.get('severity') == 'High'),
                'medium': sum(1 for f in findings if f.get('severity') == 'Medium'),
                'low': sum(1 for f in findings if f.get('severity') == 'Low'),
            }
    
    return render_template_string(
        HTML_TEMPLATE,
        findings=findings,
        llm_response=llm_response,
        stats=stats,
        scanned=scanned,
        has_ast=HAS_AST,
        has_providers=HAS_PROVIDERS
    )


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'ast_available': HAS_AST,
        'llm_available': HAS_PROVIDERS,
        'providers': list_providers() if HAS_PROVIDERS else []
    })


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("🔒 SQL Injection Scanner - Web Dashboard")
    print("=" * 60)
    print(f"AST Scanner: {'✓ Available' if HAS_AST else '✗ Not found'}")
    print(f"LLM Providers: {'✓ Available' if HAS_PROVIDERS else '✗ Not found'}")
    print()
    print("Starting server on http://localhost:8000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    port = int(os.getenv('PORT', 8000))
    debug = os.getenv('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)