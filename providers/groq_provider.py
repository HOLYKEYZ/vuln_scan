import os
import requests
from providers.base import LLMProvider

class GroqProvider(LLMProvider):
    def __init__(self, api_key=None, model=None):
        self.api_key = api_key or os.getenv("GROQ_KEY")
        self.api_url = os.getenv("GROQ_API_URL")  # e.g. https://api.groq.ai/v1
        self.model = model or os.getenv("GROQ_MODEL", "llama-3-1b")
        if not self.api_key or not self.api_url:
            raise Exception("GROQ_KEY and GROQ_API_URL must be set in env")

    def ask(self, system_prompt, user_prompt, context):
        payload = {
            "model": self.model,
            "input": f"{system_prompt}\n\n{user_prompt}\n\nFILE CONTENT:\n{context}"
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        r = requests.post(f"{self.api_url}/models/{self.model}/outputs", json=payload, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()
        # groq responses vary — try common fields
        if isinstance(data, dict):
            if "output" in data:
                return data["output"]
            if "text" in data:
                return data["text"]
        return str(data)
