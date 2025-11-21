import os
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from scanner import load_provider

app = FastAPI()

@app.post('/scan')
async def scan(file: UploadFile = File(...), provider: str = Form('gemini')):
    content = (await file.read()).decode('utf-8', errors='ignore')
    provider_inst = load_provider(provider)
    result = provider_inst.ask('You are a world-class security analysis AI.', 'Perform a complete vulnerability scan.', content)
    return JSONResponse({'result': result})

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 8000)))
