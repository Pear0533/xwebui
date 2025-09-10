import os, json

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("dotenv not installed, skipping...")

WEBUI_URL = os.getenv("WEBUI_URL", "http://localhost:8080")
TOKEN = os.getenv("TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1NTRmZTU1LTQ5YjEtNDdlMS1hYWNiLTY2MzA4MjIxNjA3OSJ9.C3h6NeXOfWycXRO29kqdjeQoPP-ZhBHpCPvUP7sj92s")
COMFY_ADDRESS = os.getenv("COMFY_ADDRESS", "localhost:8000")
MAP_CHANNEL_NAME_WORKFLOW = os.getenv("MAP_CHANNEL_NAME_WORKFLOW", '{"image-edit": "image_edit.json"}')
LAZY_IMAGE_URLS = os.getenv("LAZY_IMAGE_URLS", "0").strip() != "0"


COMFY_ADDRESS = COMFY_ADDRESS.lower().removesuffix('/').removeprefix("http://")
MAP_CHANNEL_NAME_WORKFLOW = json.loads(MAP_CHANNEL_NAME_WORKFLOW)
