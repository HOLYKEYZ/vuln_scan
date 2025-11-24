"""
LLM Providers using only requests - NO SDK REQUIRED
This single file REPLACES the entire providers/ folder.

Just set your API keys as environment variables:
    GOOGLE_API_KEY                  - for Gemini
    OPENAI_API_KEY                  - for OpenAI
    ANTHROPIC_API_KEY or CLAUDE_KEY - for Claude  
    GROQ_KEY                    - for Groq
    OPENROUTER_API_KEY              - for OpenRouter

Or pass api_key directly to the provider constructor.
"""

import os
import requests
import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod

class LLMProvider(ABC):
    """Base class for all LLM providers"""
    
    @abstractmethod
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        """Send a prompt and get a response"""
        pass
    
    def _build_prompt(self, system: str, user: str, context: str) -> str:
        """Helper to build full prompt"""
        parts = [system, user]
        if context:
            parts.append(f"\n--- FILE CONTENT ---\n{context}")
        return "\n\n".join(parts)


class GeminiProvider(LLMProvider):
    """Google Gemini API - requests only"""
    
    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY required")
        
        # Use gemini-1.5-flash or gemini-pro
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        url = self.API_URL.format(model=self.model)
        
        # Build the prompt
        full_prompt = self._build_prompt(system_prompt, user_prompt, context)
        
        payload = {
            "contents": [{
                "parts": [{"text": full_prompt}]
            }],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 8192
            }
        }
        
        # Add system instruction if supported
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}]
            }
        
        try:
            resp = requests.post(
                f"{url}?key={self.api_key}",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            # Extract text from response
            candidates = data.get("candidates", [])
            if candidates:
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                if parts:
                    return parts[0].get("text", "No response text")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


class OpenAIProvider(LLMProvider):
    """OpenAI API - requests only"""
    
    API_URL = "https://api.openai.com/v1/chat/completions"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY required")
        
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        user_content = user_prompt
        if context:
            user_content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        messages.append({"role": "user", "content": user_content})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 4096
        }
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


class ClaudeProvider(LLMProvider):
    """Anthropic Claude API - requests only"""
    
    API_URL = "https://api.anthropic.com/v1/messages"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY or CLAUDE_KEY required")
        
        self.model = model or os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        user_content = user_prompt
        if context:
            user_content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": user_content}]
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            content = data.get("content", [])
            if content:
                return content[0].get("text", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


class GroqProvider(LLMProvider):
    """Groq API - requests only"""
    
    API_URL = "https://api.groq.com/openai/v1/chat/completions"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_KEY")
        if not self.api_key:
            raise ValueError("GROQ_KEY required")
        
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        user_content = user_prompt
        if context:
            user_content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        messages.append({"role": "user", "content": user_content})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 4096
        }
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


class OllamaProvider(LLMProvider):
    """Ollama local API - requests only"""
    
    def __init__(self, host: Optional[str] = None, model: Optional[str] = None):
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        full_prompt = self._build_prompt(system_prompt, user_prompt, context)
        
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False
        }
        
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=300
            )
            resp.raise_for_status()
            data = resp.json()
            
            return data.get("response", f"Unexpected: {json.dumps(data)[:500]}")
            
        except Exception as e:
            return f"Error: {str(e)}"


class OpenRouterProvider(LLMProvider):
    """OpenRouter API - access multiple models"""
    
    API_URL = "https://openrouter.ai/api/v1/chat/completions"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY required")
        
        self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        user_content = user_prompt
        if context:
            user_content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        messages.append({"role": "user", "content": user_content})
        
        payload = {
            "model": self.model,
            "messages": messages
        }
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


# Provider registry
PROVIDERS = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
    "groq": GroqProvider,
    "ollama": OllamaProvider,
    "openrouter": OpenRouterProvider,
}


def load_provider(name: str, **kwargs) -> LLMProvider:
    """Load a provider by name"""
    name = name.lower()
    if name not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}")
    return PROVIDERS[name](**kwargs)


def list_providers() -> list:
    """List available providers"""
    return list(PROVIDERS.keys())