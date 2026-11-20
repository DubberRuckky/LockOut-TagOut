#!/usr/bin/env python3
"""
tests/test_wiring.py - End-to-end integration test for P1 Wiring (stdlib only).

Checks:
1. Gateway health
2. Token auth
3. A seal reaches the app
4. Lock through rustPolish
5. /api/* refused while locked
6. A wrong token gets 401
Round trip must pass end to end.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
GATEWAY_PORT = 8180
APP_PORT = 8100
GATEWAY_URL = f"http://127.0.0.1:{GATEWAY_PORT}"
APP_URL = f"http://127.0.0.1:{APP_PORT}"
DATA_DIR = REPO_ROOT / "tests" / "test-data" / "wiring"
GATEWAY_EXE = REPO_ROOT / "user_gateway" / "target" / "debug" / "lot-gateway.exe"
LOTOCTL_EXE = REPO_ROOT / "user_gateway" / "target" / "debug" / "lotoctl.exe"


def http_get(url: str, headers: dict = None) -> tuple[int, dict | str]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(data)
            except Exception:
                return resp.status, data
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, data


def http_post(url: str, body: dict = None, headers: dict = None) -> tuple[int, dict | str]:
    raw = json.dumps(body or {}).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=raw, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(data)
            except Exception:
                return resp.status, data
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, data


def wait_port(url: str, timeout: float = 10.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status in (200, 404, 503):
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def main():
    print("=== Starting P1 Wiring End-to-End Tests ===")
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR, ignore_errors=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Enrol an initial test officer using lotoctl so store.json has data
    keyfile = DATA_DIR / "alice.keyfile.json"
    enrol_env = os.environ.copy()
    enrol_env["LOT_DATA_DIR"] = str(DATA_DIR)
    subprocess.run(
        [str(LOTOCTL_EXE), "user", "add", "alice", "--keyfile", str(keyfile)],
        env=enrol_env,
        check=True,
        capture_output=True,
    )
    print("[+] Enrolled test officer 'alice'")

    # 2. Start App (main.py) on APP_PORT
    app_env = os.environ.copy()
    app_env["LOT_DATA_DIR"] = str(DATA_DIR)
    app_env["LOT_APP_PORT"] = str(APP_PORT)
    app_env["LOT_GATEWAY_URL"] = GATEWAY_URL

    app_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(APP_PORT), "--log-level", "warning"],
        cwd=str(REPO_ROOT),
        env=app_env,
    )

    # 3. Start Gateway on GATEWAY_PORT
    gw_env = os.environ.copy()
    gw_env["LOT_BIND"] = f"127.0.0.1:{GATEWAY_PORT}"
    gw_env["LOT_UPSTREAM"] = APP_URL
    gw_env["LOT_DATA_DIR"] = str(DATA_DIR)

    gw_proc = subprocess.Popen(
        [str(GATEWAY_EXE)],
        cwd=str(REPO_ROOT),
        env=gw_env,
    )

    try:
        # Wait for both services to be ready
        if not wait_port(f"{APP_URL}/api/health", timeout=10):
            raise RuntimeError(f"App at {APP_URL} did not start in time")
        if not wait_port(f"{GATEWAY_URL}/health", timeout=10):
            raise RuntimeError(f"Gateway at {GATEWAY_URL} did not start in time")
        print("[+] Both Gateway and App are online")

        # Read the generated gateway.token
        token_file = DATA_DIR / "gateway.token"
        start_wait = time.time()
        while not token_file.exists() and time.time() - start_wait < 5:
            time.sleep(0.1)
        token = token_file.read_text(encoding="utf-8").strip()
        assert len(token) == 64, f"Expected 64-char hex token, got {token}"
        print(f"[+] Verified gateway.token created with length {len(token)}")

        # Configure rustPolish for client tests
        os.environ["LOT_GATEWAY_URL"] = GATEWAY_URL
        os.environ["LOT_GATEWAY_TOKEN"] = token
        os.environ["LOT_DATA_DIR"] = str(DATA_DIR)
        import rustPolish

        # --- Check 1: Gateway health ---
        status, body = http_get(f"{GATEWAY_URL}/health")
        assert status == 200, f"Expected 200, got {status}"
        assert body.get("status") == "ok", f"Expected status ok, got {body}"
        print("[CHECK 1 PASS] Gateway health returned 200 OK")

        # --- Check 2: Token auth ---
        status, body = http_get(
            f"{GATEWAY_URL}/admin/users",
            headers={"X-Gateway-Token": token},
        )
        assert status == 200, f"Expected 200 on valid token, got {status}"
        assert isinstance(body, list) and len(body) >= 1, f"Expected officers list, got {body}"
        assert body[0].get("officer_id") == "alice"
        print(f"[CHECK 2 PASS] Token auth succeeded on /admin/users: found officer {body[0]['officer_id']}")

        # --- Check 6: A wrong token gets 401 ---
        # 6a: Wrong token to gateway admin endpoint
        status, body = http_get(
            f"{GATEWAY_URL}/admin/users",
            headers={"X-Gateway-Token": "0000000000000000000000000000000000000000000000000000000000000000"},
        )
        assert status == 401, f"Expected 401 on wrong token to gateway, got {status}"

        # 6b: Wrong token to app internal endpoint
        status, body = http_post(
            f"{APP_URL}/internal/seal",
            body={"reason": "test"},
            headers={"X-Gateway-Token": "badtoken"},
        )
        assert status == 401, f"Expected 401 on wrong token to app, got {status}"
        print("[CHECK 6 PASS] Wrong token receives 401 on both gateway and app")

        # --- Static asset proxy check ---
        status, html = http_get(f"{GATEWAY_URL}/")
        assert status == 200, f"Expected 200 for static proxy, got {status}"
        assert "LockOut-TagOut" in str(html), "Expected frontend HTML from static proxy"
        print("[CHECK STATIC PASS] GET / successfully proxies static frontend assets")

        # --- Check 4: Lock through rustPolish ---
        lock_res = rustPolish.lock("wiring_test_manual")
        assert lock_res.get("ok") is True, f"lock returned {lock_res}"
        assert rustPolish.is_locked() is True, "rustPolish.is_locked() should be True after lock"
        gw_status = rustPolish.gateway_status()
        assert gw_status.get("state") == "LOCKED", f"Expected LOCKED state, got {gw_status}"
        print(f"[CHECK 4 PASS] lock through rustPolish succeeded: state is {gw_status.get('state')}")

        # Wait up to 3 seconds for gateway's background seal_with_retry to reach app
        time.sleep(1.0)

        # --- Check 3: A seal reaches the app ---
        app_status_code, app_status_body = http_get(f"{APP_URL}/api/status")
        assert app_status_code == 200, f"Expected 200 from app status, got {app_status_code}"
        assert app_status_body.get("vault_sealed") is True, f"Expected vault_sealed True, got {app_status_body}"
        print("[CHECK 3 PASS] Seal from gateway reached the app (vault_sealed = True)")

        # --- Check 5: /api/* refused while locked ---
        # 5a: Refused through gateway
        gw_api_status, _ = http_get(f"{GATEWAY_URL}/api/health")
        assert gw_api_status == 503, f"Expected 503 from locked gateway /api/health, got {gw_api_status}"

        # 5b: Refused on sealed app directly
        app_api_status, _ = http_get(f"{APP_URL}/api/health")
        assert app_api_status == 503, f"Expected 503 from sealed app /api/health, got {app_api_status}"
        print("[CHECK 5 PASS] /api/* refused with 503 while locked (both through gateway and on app)")

        print("=== ALL 6 CHECKS PASSED END-TO-END ===")

    finally:
        gw_proc.terminate()
        app_proc.terminate()
        try:
            gw_proc.wait(timeout=2)
        except Exception:
            gw_proc.kill()
        try:
            app_proc.wait(timeout=2)
        except Exception:
            app_proc.kill()


if __name__ == "__main__":
    main()
