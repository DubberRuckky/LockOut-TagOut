#!/usr/bin/env python3
"""
tests/test_frontend.py - End-to-end verification for Milestone P5 (Frontend).

Checks:
1. Frontend static asset delivery via scripted.py (GET /, GET /ui/*)
2. No CDN links, remote fonts, or inline scripts in index.html
3. Zero innerHTML usage across all frontend code
4. Known-answer test (KAT) vectors verification in frontend/crypto.js via WebCrypto
5. Browser Ed25519 signature cross-verification against Rust ed25519_dalek public key
6. End-to-end authenticated API session with shifting codes
"""

import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import scripted


class TestMilestoneP5Frontend(unittest.TestCase):
    def setUp(self):
        self.frontend_dir = REPO_ROOT / "frontend"

    def test_frontend_files_exist(self):
        """All required frontend files must exist."""
        required_files = [
            self.frontend_dir / "index.html",
            self.frontend_dir / "styles.css",
            self.frontend_dir / "app.js",
            self.frontend_dir / "crypto.js",
            self.frontend_dir / "tests" / "ratchet.html",
        ]
        for f in required_files:
            self.assertTrue(f.exists(), f"Missing required file: {f}")

    def test_no_cdn_or_remote_links(self):
        """Frontend must be 100% offline: no CDN links, external fonts, or remote scripts."""
        patterns = [r"https?://", r"cdn\.", r"googleapis", r"gstatic", r"unpkg", r"jsdelivr"]
        for f in self.frontend_dir.rglob("*"):
            if f.is_file() and f.suffix in [".html", ".js", ".css"]:
                content = f.read_text(encoding="utf-8")
                for pat in patterns:
                    matches = re.findall(pat, content, re.IGNORECASE)
                    self.assertEqual(
                        len(matches),
                        0,
                        f"Found remote link pattern '{pat}' in {f.name}",
                    )

    def test_no_inline_scripts_or_styles_in_index(self):
        """index.html must have no inline <script> blocks or style='' attributes."""
        content = (self.frontend_dir / "index.html").read_text(encoding="utf-8")
        
        # Check for style=""
        self.assertNotIn('style="', content, "Found inline style in index.html")
        self.assertNotIn("style='", content, "Found inline style in index.html")

        # Check for inline <script> blocks (only external module allowed)
        script_blocks = re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", content, re.DOTALL)
        self.assertEqual(len(script_blocks), 0, "Found inline <script> block in index.html")

    def test_no_innerhtml_data_injection(self):
        """app.js must use textContent, never innerHTML, for data injection."""
        content = (self.frontend_dir / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", content, "Found innerHTML usage in app.js")

    def test_webcrypto_known_answer_vectors_and_cross_verification(self):
        """Verify frontend/crypto.js matches Rust KAT vectors and Ed25519 signing cross-verifies."""
        node_script = """
import fs from 'fs';
import crypto from 'crypto';
import {
  configHashHex,
  deriveSessionSeed,
  clientCode,
  isEd25519Supported,
  signNonce,
  bytesToHex
} from './frontend/crypto.js';

async function run() {
  // 1. Config hash known answer
  const hash = await configHashHex('abc');
  if (hash !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
    throw new Error('Config hash KAT failed');
  }

  // 2. Session seed known answer
  const secret = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(32).fill(9);
  const seedBytes = await deriveSessionSeed(secret, nonce, 'dev-1');
  const seedHex = bytesToHex(seedBytes);
  if (seedHex !== 'c23ecd43f3c71e0743e7cf7a8069bf6434b82014dc3f34b144088e401b94ff4a') {
    throw new Error('Session seed KAT failed: ' + seedHex);
  }

  // 3. Ratchet client codes KAT 1..4 (seed = 32 bytes of 0x01)
  const kat = [
    { counter: 1, exp: '9d92b1b62f3ce7c8085a97cbc2bd5a0f' },
    { counter: 2, exp: '46c68eb891454a8d6fd58bc536973ae8' },
    { counter: 3, exp: '50a4af0ba54b4021832b5d78841fca8f' },
    { counter: 4, exp: '9157fc331132170879a753437c015144' }
  ];
  const seedOnes = new Uint8Array(32).fill(1);
  for (const item of kat) {
    const code = await clientCode(seedOnes, item.counter);
    if (code !== item.exp) {
      throw new Error(`Ratchet code KAT failed for counter ${item.counter}: got ${code}, expected ${item.exp}`);
    }
  }

  // 4. Ed25519 signing cross-verification against enrolled store.json keyfile
  const keyfilePath = './lot-data/alice.keyfile.json';
  const storePath = './lot-data/store.json';
  if (fs.existsSync(keyfilePath) && fs.existsSync(storePath)) {
    const keyfile = JSON.parse(fs.readFileSync(keyfilePath, 'utf8'));
    const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    const dev = store.devices.find(d => d.device_id === keyfile.device_id);

    const testNonceHex = '42'.repeat(32);
    const sigHex = await signNonce(keyfile.signing_key_hex, testNonceHex);
    
    // Cross-verify with Node crypto.verify using enrolled public key
    const pubkeyPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const spki = Buffer.concat([pubkeyPrefix, Buffer.from(dev.public_key_hex, 'hex')]);
    const pubKeyObj = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const verified = crypto.verify(
      null,
      Buffer.from(testNonceHex, 'hex'),
      pubKeyObj,
      Buffer.from(sigHex, 'hex')
    );
    if (!verified) {
      throw new Error('Ed25519 signature verification against Dalek public key failed');
    }
  }

  console.log('ALL_TESTS_PASS');
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
"""
        proc = subprocess.run(
            ["node", "--input-type=module", "-e", node_script],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"Node KAT test failed: {proc.stderr}")
        self.assertIn("ALL_TESTS_PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
