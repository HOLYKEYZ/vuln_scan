from google import genai
from providers.base import LLMProvider
import os

class GeminiProvider(LLMProvider):
    def __init__(self, api_key=None, model=None):
        api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise Exception("GEMINI_KEY not set")
        self.client = genai.Client(api_key=api_key)
        self.model = model or os.getenv("GEMINI_MODEL", "models/gemini-pro")

    def ask(self, system_prompt, user_prompt, context):
        # Create chat and then send message (matches inspected SDK behavior)
        chat = self.client.chats.create(
            model=self.model,
            config={"system_instruction": system_prompt}
        )
        message = f"{user_prompt}\n\n------ FILE CONTENT ------\n{context}"
        resp = chat.send_message(message)
        return getattr(resp, "text", "No response text.")
