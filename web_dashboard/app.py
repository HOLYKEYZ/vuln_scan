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
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .content {
            padding: 40px;
        }
        
        .upload-form {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            color: #333;
        }
        
        input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 2px dashed #667eea;
            border-radius: 6px;
            background: white;
            cursor: pointer;
        }
        
        input[type="file"]:hover {
            border-color: #764ba2;
            background: #f0f0ff;
        }
        
        .form-row {
            display: flex;
            gap: 15px;
        }
        
        .form-row > div {
            flex: 1;
        }
        
        select {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            background: white;
        }
        
        button[type="submit"] {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        button[type="submit"]:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        button[type="submit"]:active {
            transform: translateY(0);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }
        
        .stat-card .label {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 5px;
        }
        
        .stat-card.critical { background: linear-gradient(135deg, #c0392b 0%, #8e44ad 100%); }
        .stat-card.high { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .stat-card.low { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        
        .findings {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .findings h2 {
            color: #333;
            margin-bottom: 20px;
        }
        
        .finding {
            background: white;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 6px 6px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .finding.Critical { border-left-color: #c0392b; }
        .finding.High { border-left-color: #e74c3c; }
        .finding.Medium { border-left-color: #f39c12; }
        .finding.Low { border-left-color: #3498db; }
        .finding.Info { border-left-color: #95a5a6; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-weight: 600;
            color: #333;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }
        
        .severity-badge.Critical { background: #c0392b; }
        .severity-badge.High { background: #e74c3c; }
        .severity-badge.Medium { background: #f39c12; }
        .severity-badge.Low { background: #3498db; }
        .severity-badge.Info { background: #95a5a6; }
        
        .finding-location {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 8px;
        }
        
        .finding-message {
            color: #555;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        
        .finding-code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin-top: 10px;
        }
        
        .success {
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.2em;
        }
        
        .llm-response {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .llm-response h2 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .llm-response pre {
            background: white;
            padding: 20px;
            border-radius: 6px;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.6;
            color: #333;
            overflow-x: auto;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 SQL Injection Scanner</h1>
            <p>AST Analysis + LLM Enhancement</p>
        </header>
        
        <div class="content">
            {% if not has_ast and not has_providers %}
            <div class="warning">
                <strong>⚠️ Warning:</strong> No scanners available. Please check that large_scanner.py and providers.py exist in the project root.
            </div>
            {% endif %}
            
            <form method="post" enctype="multipart/form-data" class="upload-form">
                <div class="form-group">
                    <label for="file">📂 Upload Python File:</label>
                    <input type="file" id="file" name="file" accept=".py" required>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="mode">🔍 Analysis Mode:</label>
                        <select id="mode" name="mode">
                            <option value="ast" {% if not has_providers %}selected{% endif %}>AST Only (Fast, Free)</option>
                            {% if has_providers %}
                            <option value="llm">LLM Only (AI Analysis)</option>
                            <option value="both" selected>AST + LLM (Best)</option>
                            {% endif %}
                        </select>
                    </div>
                    
                    {% if has_providers %}
                    <div class="form-group">
                        <label for="provider">🤖 LLM Provider:</label>
                        <select id="provider" name="provider">
                            <option value="gemini">Gemini (Google)</option>
                            <option value="openai">OpenAI (GPT)</option>
                            <option value="claude">Claude (Anthropic)</option>
                            <option value="groq">Groq (Fast)</option>
                        </select>
                    </div>
                    {% endif %}
                </div>
                
                <button type="submit">🔍 Scan File</button>
            </form>
            
            {% if stats %}
            <div class="stats">
                <div class="stat-card">
                    <span class="number">{{ stats.total }}</span>
                    <span class="label">Total Findings</span>
                </div>
                <div class="stat-card critical">
                    <span class="number">{{ stats.critical }}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat-card high">
                    <span class="number">{{ stats.high }}</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-card medium">
                    <span class="number">{{ stats.medium }}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="stat-card low">
                    <span class="number">{{ stats.low }}</span>
                    <span class="label">Low</span>
                </div>
            </div>
            {% endif %}
            
            {% if findings %}
            <div class="findings">
                <h2>🔴 Vulnerabilities Found ({{ findings|length }})</h2>
                {% for f in findings %}
                <div class="finding {{ f.severity }}">
                    <div class="finding-header">
                        <span class="finding-title">{{ f.rule }} - {{ f.message[:80] }}</span>
                        <span class="severity-badge {{ f.severity }}">{{ f.severity }}</span>
                    </div>
                    <div class="finding-location">
                        📄 {{ f.file }} : Line {{ f.line }}
                        {% if f.source %} | Source: {{ f.source|upper }}{% endif %}
                    </div>
                    <div class="finding-message">{{ f.message }}</div>
                    {% if f.code %}
                    <div class="finding-code">{{ f.code }}</div>
                    {% endif %}
                    {% if f.remediation %}
                    <div style="margin-top: 10px; padding: 10px; background: #e8f5e9; border-radius: 4px; font-size: 0.9em;">
                        <strong>💡 Fix:</strong> {{ f.remediation }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% elif scanned %}
            <div class="success">
                ✅ No vulnerabilities found! Your code looks safe.
            </div>
            {% endif %}
            
            {% if llm_response %}
            <div class="llm-response">
                <h2>🤖 LLM Analysis</h2>
                <pre>{{ llm_response }}</pre>
            </div>
            {% endif %}
            
            {% if not scanned %}
            <div class="info-box">
                <strong>ℹ️ How to use:</strong>
                <ul style="margin-top: 10px; padding-left: 20px;">
                    <li>Upload a Python file to scan for SQL injection vulnerabilities</li>
                    <li>Choose AST for fast, offline analysis</li>
                    <li>Choose LLM for AI-powered deep analysis (requires API key)</li>
                    <li>Choose Both for comprehensive scanning</li>
                </ul>
            </div>
            {% endif %}
        </div>
        
        <footer>
            VulnScan Web Dashboard | Python SQL Injection Scanner
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
    
    port = int(os.getenv('PORT',8000))
    app.run(debug=True, host='0.0.0.0', port=port)