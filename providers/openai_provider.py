# Note: requires 'openai' package compatible with your environment
from openai import OpenAI
from providers.base import LLMProvider
import os

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key=None, model=None):
        api_key = api_key or os.getenv("OPENAI_KEY")
        if not api_key:
            raise Exception("OPENAI_KEY not set")
        self.client = OpenAI(api_key=api_key)
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def ask(self, system_prompt, user_prompt, context):
        prompt = f"{system_prompt}\n\n{user_prompt}\n\nFILE CONTENT:\n{context}"
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        # adapt to different SDKs if necessary
        try:
            return resp.choices[0].message["content"]
        except Exception:
            return str(resp)
