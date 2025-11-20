from google import genai
client = genai.Client(api_key="test")

import inspect

print("=== AVAILABLE METHODS IN client.chats ===")
print(dir(client.chats))

print("\n=== SIGNATURE OF chats.create ===")
print(inspect.signature(client.chats.create))
