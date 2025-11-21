import os
import requests
from providers.base import LLMProvider

class OllamaProvider(LLMProvider):
    def __init__(self, host=None, model=None):
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama")

    def ask(self, system_prompt, user_prompt, context):
        prompt = f"{system_prompt}\n\n{user_prompt}\n\nFILE CONTENT:\n{context}"
        r = requests.post(f"{self.host}/api/generate", json={"model": self.model, "prompt": prompt}, timeout=60)
        r.raise_for_status()
        return r.json()
