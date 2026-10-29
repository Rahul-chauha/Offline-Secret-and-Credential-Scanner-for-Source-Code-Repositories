import requests

# OpenAI API Integration
OPENAI_API_KEY = "sk-proj-9876543210abcdef9876543210abcdef123456"

# High Entropy Hex Token
client_secret = "4f8a9b2c3d1e7f6a5b4c3d2e1f0a9b8c"

def fetch_data():
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
    return requests.get("https://api.openai.com/v1/models", headers=headers)
