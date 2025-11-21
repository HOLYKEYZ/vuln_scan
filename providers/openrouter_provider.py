import os
import requests
from providers.base import LLMProvider

class OpenRouterProvider(LLMProvider):
    def __init__(self, api_key=None, model=None):
        self.api_key = api_key or os.getenv("OPENROUTER_KEY")
        self.api_url = os.getenv("OPENROUTER_API_URL", "https://api.openrouter.ai/v1")
        self.model = model or os.getenv("OPENROUTER_MODEL", "gpt-4o-mini")
        if not self.api_key:
            raise Exception("OPENROUTER_KEY not set")

    def ask(self, system_prompt, user_prompt, context):
        prompt = f"{system_prompt}\n\n{user_prompt}\n\nFILE CONTENT:\n{context}"
        payload = {"model": self.model, "input": prompt}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        r = requests.post(f"{self.api_url}/outputs", json=payload, headers=headers, timeout=60)
        r.raise_for_status()
        return r.json()
