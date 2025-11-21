import os
from providers.gemini_provider import GeminiProvider
from providers.openai_provider import OpenAIProvider
from providers.claude_provider import ClaudeProvider
from providers.groq_provider import GroqProvider
from providers.openrouter_provider import OpenRouterProvider
from providers.ollama_provider import OllamaProvider

def load_provider(name):
    name = name.lower()
    if name == "gemini":
        return GeminiProvider(os.getenv("GOOGLE_API_KEY"), os.getenv("GEMINI_MODEL"))
    elif name == "openai":
        return OpenAIProvider(os.getenv("OPENAI_KEY"), os.getenv("OPENAI_MODEL"))
    elif name == "claude":
        return ClaudeProvider(os.getenv("CLAUDE_KEY"), os.getenv("CLAUDE_MODEL"))
    elif name == "groq":
        return GroqProvider(os.getenv("GROQ_KEY"), os.getenv("GROQ_MODEL"))
    elif name == "openrouter":
        return OpenRouterProvider(os.getenv("OPENROUTER_KEY"), os.getenv("OPENROUTER_MODEL"))
    elif name == "ollama":
        return OllamaProvider(os.getenv("OLLAMA_HOST"), os.getenv("OLLAMA_MODEL"))
    else:
        raise Exception("Unknown provider: " + name)
