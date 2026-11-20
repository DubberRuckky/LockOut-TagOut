# Deploying LockOut-TagOut (LOTO) with Vercel (Post-Milestone P6 Guide)

> **Architectural Constraint Notice:** Per [docs/SPEC.md](file:///docs/SPEC.md), the core LockOut-TagOut gateway (`user_gateway`) and application server (`main.py`) rely on **persistent long-running processes**, in-memory ratchet state, atomic filesystem writes (`lock-state.json`), SQLite, WebSocket connections (`/ws`), and host-only terminal recovery (`lotoctl tagout` and `lotoctl restore`). Standard Vercel serverless environments are ephemeral, stateless, and do not support background daemons or host terminal lockdown.
> 
> Therefore, post-Milestone P6 hosting with Vercel uses a **Hybrid Edge Architecture**: Vercel serves the frontend static client over HTTPS (satisfying browser camera security requirements), while rewrites or API routes proxy traffic to a persistent backend host.

---

## 1. Hybrid Architecture Overview

```
                      ┌───────────────────────────────────────────────┐
                      │                 Vercel Cloud                  │
                      │                                               │
  User Browser ──────►│  • HTTPS Static Assets (/ui/*, /index.html)   │
(WebCam / WebCrypto)  │  • Edge Rewrites / Secure Reverse Proxy       │
                      └──────────────────────┬────────────────────────┘
                                             │ HTTPS / WSS
                                             ▼
                      ┌───────────────────────────────────────────────┐
                      │    Persistent Host (Linux / Windows VPS)      │
                      │                                               │
                      │  • Port 8080: lot-gateway (Rust daemon)        │
                      │  • Port 8000: main.py (FastAPI case vault)    │
                      │  • Localhost loopback: X-Gateway-Token trust  │
                      │  • Host Terminal: lotoctl (Tagout / Restore)  │
                      └───────────────────────────────────────────────┘
```

### Why HTTPS is Required
Modern browsers (`navigator.mediaDevices.getUserMedia`) strictly require a **Secure Context** (`https://` or `http://localhost`). Deploying the frontend to Vercel provides automatic SSL/TLS certificates, enabling field officers on laptops or tablets to access the camera feed securely.

---

## 2. Setting Up the Persistent Backend

Before configuring Vercel, host the backend (`lot-gateway` and `main.py`) on a persistent server (e.g., Fly.io, Railway, AWS EC2, DigitalOcean, or an on-premise secured police server):

1. **Build and Run the Services:**
   ```bash
   # On the persistent host:
   cd user_gateway
   cargo build --release
   ./target/release/lot-gateway &

   # Run the Mid-Backend app:
   python3 -m uvicorn main:app --host 127.0.0.1 --port 8000 &
   ```

2. **Expose Gateway via Secure Reverse Proxy:**
   Expose the gateway port (`8080`) over HTTPS/WSS (e.g., using Caddy, Nginx, or Cloudflare Tunnel) to a domain such as `api.loto-vault.internal` or `https://gateway.yourdomain.com`.

---

## 3. Vercel Configuration (`vercel.json`)

Create a `vercel.json` file in your deployment repository to route public traffic and forward protected endpoints to the gateway:

```json
{
  "version": 2,
  "public": true,
  "cleanUrls": true,
  "rewrites": [
    {
      "source": "/",
      "destination": "/frontend/index.html"
    },
    {
      "source": "/ui/:path*",
      "destination": "/frontend/:path*"
    },
    {
      "source": "/status",
      "destination": "https://gateway.yourdomain.com/status"
    },
    {
      "source": "/auth/:path*",
      "destination": "https://gateway.yourdomain.com/auth/:path*"
    },
    {
      "source": "/api/:path*",
      "destination": "https://gateway.yourdomain.com/api/:path*"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "nosniff" },
        { "key": "Permissions-Policy", "value": "camera=(self)" }
      ]
    }
  ]
}
```

---

## 4. Deploying to Vercel via CLI

```bash
# 1. Install Vercel CLI (if not installed)
npm install -g vercel

# 2. Deploy from repo root
vercel --prod
```

---

## 5. Security & Isolation Considerations

1. **Tagout Protocol Guarantees:**
   - When an Inspector or Superintendent triggers a **TAGOUT**, the gateway terminates all network sessions and answers `503 Service Unavailable` on all network routes.
   - Server restoration (`lotoctl restore`) must strictly be performed in a physical terminal on the persistent backend server. Vercel cannot bypass this lockdown.
2. **Local Token Integrity:**
   - The `X-Gateway-Token` is strictly retained on loopback (`127.0.0.1`) between `lot-gateway` and `main.py`.
   - Vercel forwards requests to `lot-gateway`, which strips any incoming client `X-Gateway-Token` headers to prevent header injection.
3. **Biometric Face Capture Retention:**
   - Frames transmitted through `/auth/face` remain encrypted at rest with AES-GCM on the persistent host. No biometric frames are stored in Vercel's edge cache.
