import os
import httpx
from dotenv import load_dotenv

load_dotenv()

base_url = os.getenv("ORANGEHRM_BASE_URL")
client_id = os.getenv("ORANGEHRM_CLIENT_ID")
client_secret = os.getenv("ORANGEHRM_CLIENT_SECRET")
redirect_uri = os.getenv("ORANGEHRM_REDIRECT_URI")

token_url = f"{base_url}/oauth2/token"

data = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
}

response = httpx.post(token_url, data=data)

print("Status:", response.status_code)
print("Response:", response.text)
