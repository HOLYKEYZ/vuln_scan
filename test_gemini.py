import requests
import json

API_KEY = "AIzaSyCQCEjfIzFHZ5UppwIZZcBbHSxSLpMDUpo"

print("Fetching available models...")
resp = requests.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={API_KEY}")

if resp.status_code == 200:
    data = resp.json()
    models = []
    for m in data.get("models", []):
        name = m.get("name", "").replace("models/", "")
        methods = m.get("supportedGenerationMethods", [])
        if "generateContent" in methods:
            models.append(name)
    
    print(f"\n✓ Found {len(models)} working models:")
    for m in models[:10]:  # Show first 10
        print(f"  - {m}")
else:
    print(f"❌ Error {resp.status_code}: {resp.text}")