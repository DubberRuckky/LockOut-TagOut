#!/usr/bin/env python3
"""
Temporary Smoke-Test Dashboard Server for LockOut-TagOut (lot-gateway)
Uses only Python 3 standard library (no pip packages needed).
"""

import http.server
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict

PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
USER_GATEWAY_DIR = BASE_DIR / "user_gateway"
DATA_DIR = USER_GATEWAY_DIR / "lot-data"
LOTOCTL_EXE = USER_GATEWAY_DIR / "target" / "debug" / "lotoctl.exe"

# If lotoctl.exe is not found, fallback to "cargo run --bin lotoctl --"
USE_CARGO = not LOTOCTL_EXE.exists()


def run_lotoctl(args: list[str]) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["LOT_DATA_DIR"] = str(DATA_DIR)

    if USE_CARGO:
        cmd = ["cargo", "run", "--quiet", "--bin", "lotoctl", "--"] + args
        cwd = str(USER_GATEWAY_DIR)
    else:
        cmd = [str(LOTOCTL_EXE)] + args
        cwd = str(USER_GATEWAY_DIR)

    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def http_request(
    url: str, method: str = "GET", data: Dict[str, Any] | None = None
) -> tuple[int, Dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = {"raw": content}
            return status, parsed
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"raw": content, "error": str(e)}
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)}


class SmokeTestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(pathlib.Path(__file__).parent), **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            return super().do_GET()
        elif self.path == "/api/status":
            self.handle_get_status()
        elif self.path == "/api/users":
            self.handle_get_users()
        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            body = {}

        if self.path == "/api/users/create":
            self.handle_create_user(body)
        elif self.path == "/api/users/revoke":
            self.handle_revoke_user(body)
        elif self.path == "/api/handshake/challenge":
            self.handle_challenge(body)
        elif self.path == "/api/handshake/login":
            self.handle_login(body)
        elif self.path == "/api/handshake/auto-login":
            self.handle_auto_login(body)
        elif self.path == "/api/ratchet/sign":
            self.handle_ratchet_sign(body)
        elif self.path == "/api/lock":
            self.handle_lock()
        elif self.path == "/api/unlock":
            self.handle_unlock()
        elif self.path == "/api/simulate-bad-logins":
            self.handle_simulate_bad_logins(body)
        else:
            self.send_error(404, "Endpoint not found")

    def send_json(self, status: int, data: Dict[str, Any]):
        response = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def handle_get_status(self):
        status_code, status_data = http_request(f"{GATEWAY_URL}/status")
        health_code, health_data = http_request(f"{GATEWAY_URL}/health")
        running = status_code != 0

        self.send_json(
            200,
            {
                "gateway_running": running,
                "gateway_url": GATEWAY_URL,
                "status_code": status_code,
                "status": status_data,
                "health": health_data,
            },
        )

    def handle_get_users(self):
        store_path = DATA_DIR / "store.json"
        officers = []
        devices = []
        if store_path.exists():
            try:
                store_data = json.loads(store_path.read_text(encoding="utf-8"))
                officers = store_data.get("officers", [])
                devices = store_data.get("devices", [])
            except Exception as e:
                return self.send_json(500, {"error": f"Failed to read store.json: {e}"})

        # Match keyfiles
        keyfiles = []
        for path in USER_GATEWAY_DIR.glob("*.keyfile.json"):
            try:
                kf = json.loads(path.read_text(encoding="utf-8"))
                keyfiles.append(
                    {
                        "path": str(path),
                        "filename": path.name,
                        "officer_id": kf.get("officer_id"),
                        "device_id": kf.get("device_id"),
                    }
                )
            except Exception:
                pass

        self.send_json(
            200,
            {
                "officers": officers,
                "devices": devices,
                "keyfiles": keyfiles,
            },
        )

    def handle_create_user(self, body: Dict[str, Any]):
        officer_id = body.get("officer_id", "").strip()
        if not officer_id:
            return self.send_json(400, {"error": "officer_id is required"})

        keyfile_path = USER_GATEWAY_DIR / f"{officer_id}.keyfile.json"
        if keyfile_path.exists():
            return self.send_json(
                400, {"error": f"Keyfile {keyfile_path.name} already exists"}
            )

        code, out, err = run_lotoctl(
            ["user", "add", officer_id, "--keyfile", str(keyfile_path)]
        )
        if code != 0:
            return self.send_json(400, {"error": err or out})

        # Load generated keyfile info
        try:
            kf = json.loads(keyfile_path.read_text(encoding="utf-8"))
            device_id = kf.get("device_id")
        except Exception:
            device_id = None

        self.send_json(
            200,
            {
                "ok": True,
                "officer_id": officer_id,
                "device_id": device_id,
                "keyfile": str(keyfile_path),
                "message": out,
            },
        )

    def handle_revoke_user(self, body: Dict[str, Any]):
        officer_id = body.get("officer_id", "").strip()
        if not officer_id:
            return self.send_json(400, {"error": "officer_id is required"})

        code, out, err = run_lotoctl(["user", "revoke", officer_id])
        if code != 0:
            return self.send_json(400, {"error": err or out})
        self.send_json(200, {"ok": True, "message": out})

    def handle_challenge(self, body: Dict[str, Any]):
        device_id = body.get("device_id", "").strip()
        if not device_id:
            return self.send_json(400, {"error": "device_id is required"})

        status, resp = http_request(
            f"{GATEWAY_URL}/auth/challenge",
            method="POST",
            data={"device_id": device_id},
        )
        self.send_json(status, resp)

    def handle_login(self, body: Dict[str, Any]):
        keyfile = body.get("keyfile", "").strip()
        nonce = body.get("nonce", "").strip()
        if not keyfile or not nonce:
            return self.send_json(400, {"error": "keyfile and nonce are required"})

        # Run sign-login to generate payload
        code, out, err = run_lotoctl(
            ["sign-login", "--keyfile", keyfile, "--nonce", nonce]
        )
        if code != 0:
            return self.send_json(400, {"error": f"sign-login failed: {err or out}"})

        try:
            login_payload = json.loads(out)
        except Exception as e:
            return self.send_json(
                500, {"error": f"Failed to parse sign-login output: {e}"}
            )

        status, resp = http_request(
            f"{GATEWAY_URL}/auth/login", method="POST", data=login_payload
        )
        self.send_json(
            status,
            {
                "status_code": status,
                "response": resp,
                "signed_payload": login_payload,
            },
        )

    def handle_auto_login(self, body: Dict[str, Any]):
        officer_id = body.get("officer_id", "").strip()
        keyfile_path = USER_GATEWAY_DIR / f"{officer_id}.keyfile.json"
        if not keyfile_path.exists():
            return self.send_json(
                404, {"error": f"Keyfile for {officer_id} not found ({keyfile_path.name})"}
            )

        try:
            kf = json.loads(keyfile_path.read_text(encoding="utf-8"))
            device_id = kf["device_id"]
        except Exception as e:
            return self.send_json(400, {"error": f"Invalid keyfile: {e}"})

        # Step 1: Request Challenge
        status, challenge_resp = http_request(
            f"{GATEWAY_URL}/auth/challenge",
            method="POST",
            data={"device_id": device_id},
        )
        if status != 200 or "nonce" not in challenge_resp:
            return self.send_json(
                status or 500,
                {"error": "Challenge failed", "challenge_response": challenge_resp},
            )

        nonce = challenge_resp["nonce"]

        # Step 2: Sign Login
        code, out, err = run_lotoctl(
            ["sign-login", "--keyfile", str(keyfile_path), "--nonce", nonce]
        )
        if code != 0:
            return self.send_json(400, {"error": f"sign-login failed: {err or out}"})

        login_payload = json.loads(out)

        # Step 3: Submit Login
        status, login_resp = http_request(
            f"{GATEWAY_URL}/auth/login", method="POST", data=login_payload
        )
        self.send_json(
            status,
            {
                "ok": status == 200,
                "officer_id": officer_id,
                "device_id": device_id,
                "nonce": nonce,
                "session_id": login_resp.get("session_id"),
                "login_response": login_resp,
                "signed_payload": login_payload,
            },
        )

    def handle_ratchet_sign(self, body: Dict[str, Any]):
        keyfile = body.get("keyfile", "").strip()
        nonce = body.get("nonce", "").strip()
        session_id = body.get("session_id", "").strip()
        counter = body.get("counter", 1)

        code, out, err = run_lotoctl(
            [
                "sign-request",
                "--keyfile",
                keyfile,
                "--nonce",
                nonce,
                "--session-id",
                session_id,
                "--counter",
                str(counter),
            ]
        )
        if code != 0:
            return self.send_json(400, {"error": err or out})

        headers_dict = {}
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()

        # Also get curl snippet
        _, curl_out, _ = run_lotoctl(
            [
                "sign-request",
                "--keyfile",
                keyfile,
                "--nonce",
                nonce,
                "--session-id",
                session_id,
                "--counter",
                str(counter),
                "--curl",
            ]
        )

        self.send_json(
            200,
            {
                "ok": True,
                "counter": counter,
                "headers": headers_dict,
                "curl": curl_out,
            },
        )

    def handle_lock(self):
        code, out, err = run_lotoctl(["lock"])
        if code != 0:
            return self.send_json(400, {"error": err or out})
        self.send_json(200, {"ok": True, "message": out})

    def handle_unlock(self):
        lock_file = DATA_DIR / "lock-state.json"
        try:
            if lock_file.exists():
                lock_file.unlink()
            self.send_json(200, {
                "ok": True,
                "message": "lock-state.json removed. Restart lot-gateway to return to NORMAL state."
            })
        except Exception as e:
            self.send_json(500, {"error": f"Failed to reset lock file: {e}"})

    def handle_simulate_bad_logins(self, body: Dict[str, Any]):
        device_id = body.get("device_id", "").strip()
        count = int(body.get("count", 3))
        results = []

        for i in range(count):
            # Challenge
            st, chal = http_request(
                f"{GATEWAY_URL}/auth/challenge",
                method="POST",
                data={"device_id": device_id},
            )
            nonce = chal.get("nonce", "00" * 32)
            # Bad signature
            bad_payload = {
                "device_id": device_id,
                "nonce": nonce,
                "signature": "00" * 64,
                "config_hash": "a54805240cf01db5baa2b66c692b84b34c91e55a2c96626905784eafab8f047d",
            }
            login_st, login_resp = http_request(
                f"{GATEWAY_URL}/auth/login", method="POST", data=bad_payload
            )
            results.append(
                {
                    "attempt": i + 1,
                    "status_code": login_st,
                    "response": login_resp,
                }
            )

        self.send_json(200, {"ok": True, "attempts": results})


def main():
    print("=" * 60)
    print(" LockOut-TagOut Smoke-Test Web Dashboard")
    print(f" Dashboard URL : http://127.0.0.1:{PORT}")
    print(f" Rust Gateway  : {GATEWAY_URL}")
    print(f" Data Dir      : {DATA_DIR}")
    print(f" Using Tool    : {'cargo run' if USE_CARGO else str(LOTOCTL_EXE)}")
    print("=" * 60)

    server = http.server.HTTPServer(("127.0.0.1", PORT), SmokeTestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
        server.server_close()


if __name__ == "__main__":
    main()
