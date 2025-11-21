from flask import Flask, request, render_template_string
from scanner import load_provider
import os

app = Flask(__name__)

TEMPLATE = """<!doctype html>
<title>LLM Vulnerability Scanner</title>
<h1>Upload file to scan</h1>
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <select name=provider>
    <option value=gemini>gemini</option>
    <option value=openai>openai</option>
    <option value=claude>claude</option>
    <option value=groq>groq</option>
  </select>
  <input type=submit value=Scan>
</form>
{% if result %}
<h2>Result</h2>
<pre>{{result}}</pre>
{% endif %}
"""

@app.route('/', methods=['GET','POST'])
def index():
    result = None
    if request.method == 'POST':
        f = request.files.get('file')
        provider_name = request.form.get('provider') or 'gemini'
        if f:
            text = f.read().decode('utf-8', errors='ignore')
            provider = load_provider(provider_name)
            result = provider.ask('You are a world-class security analysis AI.', 'Perform a complete vulnerability scan.', text)
    return render_template_string(TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(debug=True, port=int(os.getenv('PORT', 5000)))
