"""
main.py - Central application server (FastAPI on 127.0.0.1:8000).
Imports and mounts wrapper modules per architecture:
  - rustPolish.py: gateway communication, internal endpoints, read-only helpers
  - scripted.py: frontend file serving and browser-facing /api/* endpoints
  - candyWrapper.py: OCR, face check, sqlite, encrypted storage, audit chain
  - upstream.py: uploads and identity verification
"""

import os
import uvicorn
from fastapi import FastAPI

import candyWrapper
import rustPolish
import scripted
import upstream

app = FastAPI(title="LockOut-TagOut App Vault", version="0.1.0")

# Mount internal endpoints from rustPolish (/internal/*)
app.include_router(rustPolish.router)

# Mount frontend and API endpoints from scripted (/ and /api/*)
app.include_router(scripted.api_router)
app.include_router(scripted.router)

# Initialize database on startup
@app.on_event("startup")
def on_startup():
    candyWrapper.init_db()


if __name__ == "__main__":
    host = os.environ.get("LOT_APP_HOST", "127.0.0.1")
    port = int(os.environ.get("LOT_APP_PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, log_level="warning")
