from google import genai
import inspect
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")
client = genai.Client(api_key=API_KEY)

chat = client.chats.create(
    model="gemini-1.5-flash",
    history=[
        {
            "role": "user",
            "parts": [{"text": "Hello"}]
        }
    ],
    config={"system_instruction": "test system prompt"}
)

print("=== TYPE OF CHAT OBJECT ===")
print(type(chat))

print("\n=== DIR(chat) ===")
print(dir(chat))

print("\n=== chat.__dict__ ===")
print(chat.__dict__)
