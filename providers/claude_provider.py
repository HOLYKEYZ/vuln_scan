# Note: requires 'anthropic' package
from anthropic import Anthropic
from providers.base import LLMProvider
import os

class ClaudeProvider(LLMProvider):
    def __init__(self, api_key=None, model=None):
        api_key = api_key or os.getenv("CLAUDE_KEY")
        if not api_key:
            raise Exception("CLAUDE_KEY not set")
        self.client = Anthropic(api_key=api_key)
        self.model = model or os.getenv("CLAUDE_MODEL", "claude-3-opus-20240229")

    def ask(self, system_prompt, user_prompt, context):
        prompt = f"{system_prompt}\n\n{user_prompt}\n\nFILE CONTENT:\n{context}"
        resp = self.client.messages.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        try:
            return resp.content[0].text
        except Exception:
            return str(resp)
