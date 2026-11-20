"""
tests/test_mid_backend.py - Comprehensive test suite for Level 2 Mid Backend.
Tests candyWrapper.py and upstream.py against all requirements in docs/SPEC.md:
  1. SQLite schema & CRUD (cases, files, amendments, captures, audit)
  2. Encrypted content-addressed storage (AES-GCM) & file verification
  3. Cryptographic audit hash chain & tamper detection
  4. OCR graceful degradation & keyword classification
  5. Case lifecycle, archive proof & case_hash calculation
  6. User-dependent editing (RBAC by rank tier)
  7. Upstream file validation (size, extension, magic bytes) & identity checks
  8. Face presence checking (blocked frame, no-face, real face photo)
  9. Fail closed behavior on vault seal
"""

import base64
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import tempfile
import unittest

import candyWrapper
import rustPolish
import upstream

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"


class TestMidBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="lot-mid-test-"))
        os.environ["LOT_DATA_DIR"] = str(cls.temp_dir)
        os.environ["LOT_DB_PATH"] = str(cls.temp_dir / "vault.db")
        os.environ["LOT_STORAGE_DIR"] = str(cls.temp_dir / "vault_storage")
        os.environ["LOT_GATEWAY_TOKEN"] = "a" * 64

        candyWrapper.init_db()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        rustPolish.unseal_vault()

    # -------------------------------------------------------------
    # 1. SQLite Database & Case Creation
    # -------------------------------------------------------------
    def test_01_case_creation_and_witness_masking(self):
        # Case with witness protection
        c1 = candyWrapper.create_case(
            title="Robbery Case",
            case_type="Theft",
            witness_protection=True,
            complainant_name="Alice Smith",
            created_by="officer_alice",
        )
        self.assertEqual(c1["complainant_name"], "John Doe")
        self.assertEqual(c1["status"], "open")
        self.assertTrue(c1["witness_protection"])

        # Case without witness protection
        c2 = candyWrapper.create_case(
            title="Public Disturbance",
            case_type="Public Order",
            witness_protection=False,
            complainant_name="Bob Jones",
            created_by="officer_bob",
        )
        self.assertEqual(c2["complainant_name"], "Bob Jones")
        self.assertFalse(c2["witness_protection"])

        # Fetch case
        fetched = candyWrapper.get_case(c1["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["title"], "Robbery Case")
        self.assertEqual(fetched["complainant_name"], "John Doe")

    # -------------------------------------------------------------
    # 2. Encrypted Content-Addressed Storage & Verification
    # -------------------------------------------------------------
    def test_02_encrypted_storage_and_tamper_detection(self):
        payload = b"Top secret forensic analysis report: weapon recovered at site."
        expected_sha256 = hashlib.sha256(payload).hexdigest()

        sha256 = candyWrapper.store_file(payload)
        self.assertEqual(sha256, expected_sha256)

        # File on disk must be encrypted (.enc) and not contain raw plaintext
        enc_file = candyWrapper.get_storage_dir() / f"{sha256}.enc"
        self.assertTrue(enc_file.exists())
        self.assertNotIn(b"Top secret forensic analysis", enc_file.read_bytes())

        # Retrieve and decrypt
        decrypted = candyWrapper.retrieve_file(sha256)
        self.assertEqual(decrypted, payload)

        # Add file record in case and verify
        c = candyWrapper.create_case("Case Storage", "Evidence", False, "Compl", "off1")
        f = candyWrapper.add_file(c["id"], "evidence.txt", payload, "off1", "dev1")
        self.assertTrue(candyWrapper.verify_file(f["id"]))

        # Tampering with encrypted file fails verification
        enc_content = bytearray(enc_file.read_bytes())
        enc_content[15] ^= 0xFF  # flip byte
        enc_file.write_bytes(enc_content)
        self.assertFalse(candyWrapper.verify_file(f["id"]))

        # Restore original
        candyWrapper.store_file(payload)
        self.assertTrue(candyWrapper.verify_file(f["id"]))

    # -------------------------------------------------------------
    # 3. Cryptographic Audit Hash Chain
    # -------------------------------------------------------------
    def test_03_audit_hash_chain_and_verification(self):
        initial_status = candyWrapper.audit_verify()
        self.assertTrue(initial_status["valid"])
        initial_len = initial_status["length"]

        # Record audit events
        e1 = candyWrapper.record_audit_event({"actor": "officer_1", "action": "test_action_1"})
        e2 = candyWrapper.record_audit_event({"actor": "officer_2", "action": "test_action_2"})
        self.assertEqual(e2["prev_hash"], e1["hash"])

        status = candyWrapper.audit_verify()
        self.assertTrue(status["valid"])
        self.assertEqual(status["length"], initial_len + 2)
        self.assertIsNone(status["first_broken_seq"])

        # Tampering with an audit entry in DB breaks the chain
        with candyWrapper.get_db() as conn:
            conn.execute("UPDATE audit SET actor = 'forged_actor' WHERE seq = ?", (e1["seq"],))
            conn.commit()

        broken = candyWrapper.audit_verify()
        self.assertFalse(broken["valid"])
        self.assertEqual(broken["first_broken_seq"], e1["seq"])

        # Restore DB
        with candyWrapper.get_db() as conn:
            conn.execute("UPDATE audit SET actor = ? WHERE seq = ?", (e1["actor"], e1["seq"]))
            conn.commit()
        self.assertTrue(candyWrapper.audit_verify()["valid"])

    # -------------------------------------------------------------
    # 4. OCR & Classification
    # -------------------------------------------------------------
    def test_04_ocr_classification_and_review_queue(self):
        # 1. FIR document classification
        fir_text = "FIRST INFORMATION REPORT under section 154 CrPC, Police Station Central PS."
        cat, tags, conf, status = candyWrapper.classify_document(fir_text, "fir_report.txt")
        self.assertEqual(cat, "FIR")
        self.assertGreaterEqual(conf, 0.85)
        self.assertEqual(status, "classified")

        # 2. Forensic document classification
        forensic_text = "Autopsy and post-mortem report: chemical toxicology and DNA findings."
        cat, tags, conf, status = candyWrapper.classify_document(forensic_text, "autopsy.txt")
        self.assertEqual(cat, "FORENSIC")
        self.assertGreaterEqual(conf, 0.85)
        self.assertEqual(status, "classified")

        # 3. Low confidence goes to review queue
        generic_text = "Meeting minutes regarding general office schedule."
        cat, tags, conf, status = candyWrapper.classify_document(generic_text, "memo.txt")
        self.assertEqual(cat, "GENERAL")
        self.assertLess(conf, 0.70)
        self.assertEqual(status, "needs_review")

        # 4. Graceful OCR degradation
        txt, ocr_stat = candyWrapper.extract_ocr_text(b"some binary data", "document.pdf")
        self.assertIn(ocr_stat, ("ok", "OCR unavailable", "unsupported_ocr_type"))

    # -------------------------------------------------------------
    # 5. User-dependent Editing (RBAC by Rank Tier)
    # -------------------------------------------------------------
    def test_05_user_dependent_editing_rbac(self):
        # Create case by officer_tier3
        c = candyWrapper.create_case("Case 101", "Assault", False, "Citizen", "tier3_user")
        case_id = c["id"]

        # Tier 1 officer proposes an amendment (status: pending)
        amd1 = candyWrapper.propose_amendment(
            case_id,
            {"title": "Amended Assault Title"},
            officer_id="tier1_user",
            officer_tier=1,
        )
        self.assertEqual(amd1["status"], "pending")
        # Case title is not changed yet
        self.assertEqual(candyWrapper.get_case(case_id)["title"], "Case 101")

        # Tier 1 cannot approve or reject amendment
        with self.assertRaises(PermissionError):
            candyWrapper.review_amendment(amd1["id"], "approved", "tier1_user", officer_tier=1)

        # Tier 3 officer editing someone else's case -> amendment is pending
        c_other = candyWrapper.create_case("Other Case", "Fraud", False, "Citizen", "tier2_creator")
        amd_other = candyWrapper.propose_amendment(
            c_other["id"],
            {"title": "New Title"},
            officer_id="tier3_user",
            officer_tier=3,
        )
        self.assertEqual(amd_other["status"], "pending")

        # Tier 3 editing own created case -> applied directly
        direct = candyWrapper.propose_amendment(
            case_id,
            {"title": "Directly Updated by Creator"},
            officer_id="tier3_user",
            officer_tier=3,
        )
        self.assertEqual(direct["status"], "approved")
        self.assertEqual(candyWrapper.get_case(case_id)["title"], "Directly Updated by Creator")

        # Tier 4 approves amendment amd1
        rev = candyWrapper.review_amendment(amd1["id"], "approved", "tier4_sup", officer_tier=4)
        self.assertEqual(rev["status"], "approved")
        self.assertEqual(candyWrapper.get_case(case_id)["title"], "Amended Assault Title")

    # -------------------------------------------------------------
    # 6. Archive Proof & Case Closing
    # -------------------------------------------------------------
    def test_06_case_closing_and_archive_proof(self):
        c = candyWrapper.create_case("Archive Test Case", "Burglary", False, "Store", "off_lead")
        case_id = c["id"]

        # Upload files to case
        f1 = candyWrapper.add_file(case_id, "file1.txt", b"evidence item 1", "off_lead", "dev1")
        f2 = candyWrapper.add_file(case_id, "file2.txt", b"evidence item 2", "off_lead", "dev1")

        # Lookup before close returns False
        lookup_before = candyWrapper.archive_lookup(f1["sha256"])
        self.assertFalse(lookup_before["proved"])

        # Tier 1 cannot close case
        with self.assertRaises(PermissionError):
            candyWrapper.close_case(case_id, "constable_1", officer_tier=1)

        # Tier 4 closes case
        closed = candyWrapper.close_case(case_id, "inspector_4", officer_tier=4)
        self.assertEqual(closed["status"], "closed")
        self.assertIsNotNone(closed["case_hash"])

        # Archive lookup proves file belongs to closed case
        lookup_after = candyWrapper.archive_lookup(f1["sha256"])
        self.assertTrue(lookup_after["proved"])
        self.assertEqual(lookup_after["case_id"], case_id)
        self.assertEqual(lookup_after["case_hash"], closed["case_hash"])

        # Closed case cannot accept new files or amendments
        with self.assertRaises(ValueError):
            candyWrapper.add_file(case_id, "late.txt", b"late data", "off_lead", "dev1")
        with self.assertRaises(ValueError):
            candyWrapper.propose_amendment(case_id, {"title": "new"}, "off_lead", 4)

    # -------------------------------------------------------------
    # 7. Upstream Upload Validation & Identity Checks
    # -------------------------------------------------------------
    def test_07_upstream_validation(self):
        # Disallowed extension
        ok, reason = upstream.validate_file_bytes("exploit.exe", b"\x4d\x5a\x90\x00")
        self.assertFalse(ok)
        self.assertIn("not allowed", reason)

        # PNG with invalid magic bytes
        ok, reason = upstream.validate_file_bytes("fake.png", b"not a png image")
        self.assertFalse(ok)
        self.assertIn("Invalid PNG signature", reason)

        # Valid PNG magic bytes
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
        ok, _ = upstream.validate_file_bytes("valid.png", valid_png)
        self.assertTrue(ok)

        # Text with binary null byte
        ok, reason = upstream.validate_file_bytes("bad.txt", b"hello\x00world")
        self.assertFalse(ok)
        self.assertIn("null bytes", reason)

        # Uploader identity mismatch check
        with self.assertRaises(Exception):
            upstream.verify_uploader_match(header_officer="alice", declared_officer="bob")
        # Match succeeds
        upstream.verify_uploader_match(header_officer="alice", declared_officer="alice")

    # -------------------------------------------------------------
    # 8. Face Presence Checking
    # -------------------------------------------------------------
    def test_08_face_presence_checking(self):
        black_bytes = (DATA_DIR / "black_frame.jpg").read_bytes()
        flat_bytes = (DATA_DIR / "flat_frame.jpg").read_bytes()
        no_face_bytes = (DATA_DIR / "no_face_frame.jpg").read_bytes()
        face_bytes = (DATA_DIR / "face_photo.jpg").read_bytes()

        b64_black = base64.b64encode(black_bytes).decode("ascii")
        b64_flat = base64.b64encode(flat_bytes).decode("ascii")
        b64_no_face = base64.b64encode(no_face_bytes).decode("ascii")
        b64_face = base64.b64encode(face_bytes).decode("ascii")

        # 1. Blocked: near-black frames
        res_black = candyWrapper.check_face([b64_black] * 4, "nonce1", "dev_1", "off_1")
        self.assertFalse(res_black["ok"])
        self.assertEqual(res_black["reason"], "blocked")

        # 2. Blocked: near-uniform (flat) frames
        res_flat = candyWrapper.check_face([b64_flat] * 4, "nonce2", "dev_1", "off_1")
        self.assertFalse(res_flat["ok"])
        self.assertEqual(res_flat["reason"], "blocked")

        # 3. No face frame: not blocked, but no faces found
        res_no_face = candyWrapper.check_face([b64_no_face] * 4, "nonce3", "dev_1", "off_1")
        self.assertFalse(res_no_face["ok"])
        self.assertEqual(res_no_face["reason"], "no_face")

        # 4. Real face photo in 3+ frames: passes face check
        res_face = candyWrapper.check_face([b64_face] * 3, "nonce4", "dev_1", "off_1")
        self.assertTrue(res_face["ok"])
        self.assertEqual(res_face["reason"], "ok")
        self.assertGreaterEqual(res_face["frames_with_face"], 3)
        self.assertTrue(len(res_face["capture_id"]) > 0)

        # 5. Capture is stored and viewable by tier >= 4
        cap = candyWrapper.get_capture(res_face["capture_id"], "super_4", requester_tier=4, reason="audit_review")
        self.assertEqual(cap["capture_id"], res_face["capture_id"])
        self.assertEqual(cap["verdict"], "ok")
        self.assertGreater(len(cap["image_bytes"]), 0)

        # 6. Tier 1-3 cannot view capture image
        with self.assertRaises(PermissionError):
            candyWrapper.get_capture(res_face["capture_id"], "constable_1", requester_tier=2, reason="browse")

    # -------------------------------------------------------------
    # 9. Fail Closed on Vault Seal
    # -------------------------------------------------------------
    def test_09_fail_closed_on_seal(self):
        c = candyWrapper.create_case("Seal Test", "Safety", False, "None", "off1")
        rustPolish.seal_vault("test_lockout")

        orig_is_locked = rustPolish.is_locked
        try:
            # When sealed, upload fails closed with 503
            with self.assertRaises(Exception) as ctx:
                upstream.handle_upload(c["id"], "doc.txt", b"valid text content", "off1", "dev1")
            self.assertEqual(ctx.exception.status_code, 503)

            # Unseal restores functionality (when gateway is also not locked)
            rustPolish.unseal_vault()
            rustPolish.is_locked = lambda: False
            res = upstream.handle_upload(c["id"], "doc.txt", b"valid text content", "off1", "dev1")
            self.assertIn(res["status"], ("classified", "needs_review"))
        finally:
            rustPolish.is_locked = orig_is_locked


if __name__ == "__main__":
    unittest.main()
