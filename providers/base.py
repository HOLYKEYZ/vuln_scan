class LLMProvider:
    def ask(self, system_prompt: str, user_prompt: str, context: str) -> str:
        raise NotImplementedError
