from google import genai

client = genai.Client(api_key="test")
print(dir(client))
