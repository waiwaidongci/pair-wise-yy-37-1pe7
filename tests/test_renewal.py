import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.rules import STATES, TRANSITION_ROLES
from src.service import Service


class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _approved_item(self, external_ref="REN-ITEM-1"):
        item = self.service.create_item({
            "title": "renewal item", "description": "permit to renew",
            "severity": "high", "quantity": 12, "threshold": 6,
            "external_ref": external_ref,
        }, "creator", "applicant")
        current = item
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"], "reviewer",
                TRANSITION_ROLES[target][0])
        return current

    def _payload(self, item, renewal_no="RN-1", **overrides):
        payload = {
            "renewal_no": renewal_no,
            "expected_version": item["version"],
            "inspection_detail": "现场检查通过，排口达标",
            "rectification_note": "历史整改已核实",
            "new_quantity": 20,
            "new_threshold": 10,
        }
        payload.update(overrides)
        return payload

    def test_handover_bundles_steps_and_deactivates_old_quota(self):
        item = self._approved_item()
        self.service.add_record(item["id"], {
            "kind": "rectification", "detail": "待整改：除尘效率不足",
            "status": "open", "external_ref": "RECT-1",
        }, "inspector", "inspector")
        result = self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        self.assertFalse(result["idempotent"])
        self.assertEqual(result["closed_records"], 1)
        old_item = result["old_item"]
        new_item = result["new_item"]
        self.assertEqual(old_item["quota_status"], "deactivated")
        self.assertEqual(new_item["status"], "approved")
        self.assertEqual(new_item["quota_status"], "active")
        self.assertEqual(new_item["renewal_of"], item["id"])
        self.assertEqual(new_item["renewal_no"], "RN-1")
        self.assertEqual(new_item["quantity"], 20)
        kinds = [record["kind"] for record in result["records"]]
        self.assertEqual(kinds, ["quota_freeze", "inspection", "rectification_close"])
        records = self.service.list_records(item["id"], "viewer")
        self.assertTrue(all(r["status"] == "closed" for r in records))
        self.assertTrue(self.repo.verify_audit_chain())
        actions = [e["action"] for e in self.service.audit("viewer", item["id"])]
        self.assertIn("renewal", actions)

    def test_same_number_replay_returns_first_result(self):
        item = self._approved_item()
        first = self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        replay = self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["new_item_id"], first["new_item_id"])
        self.assertEqual(len(self.service.list_items("viewer")), 2)
        records = self.service.list_records(item["id"], "viewer")
        self.assertEqual(
            len([r for r in records if r["kind"] == "quota_freeze"]), 1)

    def test_same_number_different_content_leaves_conflict(self):
        item = self._approved_item()
        self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item["id"], self._payload(item, new_quantity=99),
                "manager-a", "compliance_manager")
        self.assertIn("冲突已留档", str(ctx.exception))
        overview = self.service.list_renewals(item["id"], "viewer")
        self.assertEqual(len(overview["renewals"]), 1)
        self.assertEqual(len(overview["conflicts"]), 1)
        self.assertEqual(overview["conflicts"][0]["renewal_no"], "RN-1")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_second_reviewer_gets_version_conflict(self):
        item = self._approved_item()
        self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item["id"], self._payload(item), "manager-b", "compliance_manager")
        self.assertIn("版本冲突", str(ctx.exception))
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item["id"], self._payload(item, renewal_no="RN-2"),
                "manager-b", "compliance_manager")
        self.assertIn("停用", str(ctx.exception))

    def test_stale_expected_version_rejected(self):
        item = self._approved_item()
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item["id"], self._payload(item, expected_version=99),
                "manager-a", "compliance_manager")
        self.assertIn("版本冲突", str(ctx.exception))

    def test_concurrent_reviewers_first_submission_wins(self):
        item = self._approved_item()
        payload = self._payload(item)
        barrier = threading.Barrier(2)
        outcomes = {"ok": [], "conflict": []}

        def submit(actor):
            try:
                barrier.wait(timeout=5)
                outcomes["ok"].append(self.service.submit_renewal(
                    item["id"], dict(payload), actor, "compliance_manager"))
            except ConflictError as exc:
                outcomes["conflict"].append(str(exc))

        threads = [threading.Thread(target=submit, args=(f"manager-{n}",))
                   for n in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(outcomes["ok"]), 1)
        self.assertEqual(len(outcomes["conflict"]), 1)
        self.assertIn("版本冲突", outcomes["conflict"][0])
        self.assertEqual(len(self.service.list_items("viewer")), 2)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_failure_rolls_back_everything_and_allows_retry(self):
        item = self._approved_item()
        self.service.create_item({
            "title": "other", "description": "taken ref", "severity": "low",
            "quantity": 1, "threshold": 5, "external_ref": "TAKEN",
        }, "creator", "applicant")
        self.service.add_record(item["id"], {
            "kind": "rectification", "detail": "待整改", "status": "open",
            "external_ref": "RECT-OPEN",
        }, "inspector", "inspector")
        version_before = item["version"]
        with self.assertRaises(ConflictError):
            self.service.submit_renewal(
                item["id"], self._payload(item, new_external_ref="TAKEN"),
                "manager-a", "compliance_manager")
        restored = self.service.get_item(item["id"], "viewer")
        self.assertEqual(restored["quota_status"], "active")
        self.assertEqual(restored["version"], version_before)
        self.assertEqual(restored["status"], "approved")
        records = self.service.list_records(item["id"], "viewer")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "open")
        self.assertEqual(len(self.service.list_items("viewer")), 2)
        overview = self.service.list_renewals(item["id"], "viewer")
        self.assertEqual(overview["renewals"], [])
        retry = self.service.submit_renewal(
            item["id"], self._payload(item), "manager-a", "compliance_manager")
        self.assertFalse(retry["idempotent"])
        self.assertEqual(retry["old_item"]["quota_status"], "deactivated")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_renewal_requires_approval_role_and_payload(self):
        item = self._approved_item()
        with self.assertRaises(PermissionDenied):
            self.service.submit_renewal(
                item["id"], self._payload(item), "applicant-1", "applicant")
        with self.assertRaises(ValidationError):
            self.service.submit_renewal(
                item["id"], self._payload(item, renewal_no="  "),
                "manager-a", "compliance_manager")
        with self.assertRaises(ValueError):
            self.service.submit_renewal(
                item["id"], self._payload(item, expected_version=0),
                "manager-a", "compliance_manager")
        draft = self.service.create_item({
            "title": "draft", "description": "not approved", "severity": "low",
            "quantity": 1, "threshold": 5,
        }, "creator", "applicant")
        with self.assertRaises(ConflictError):
            self.service.submit_renewal(
                draft["id"], self._payload(draft, renewal_no="RN-DRAFT"),
                "manager-a", "compliance_manager")


class LegacyMigrationTest(unittest.TestCase):
    def test_upgrade_backfills_historical_baseline(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = str(Path(tmp.name) / "legacy.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, description TEXT NOT NULL,
                severity TEXT NOT NULL, quantity REAL NOT NULL DEFAULT 0,
                threshold REAL NOT NULL DEFAULT 1,
                status TEXT NOT NULL CHECK(status IN
                    ('draft','submitted','inspection','correction','approved')),
                version INTEGER NOT NULL DEFAULT 1,
                external_ref TEXT, created_by TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, detail TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open','closed')),
                external_ref TEXT, created_by TEXT NOT NULL,
                created_at TEXT NOT NULL, UNIQUE(item_id, external_ref)
            )""")
        conn.execute("""
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL, entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL, actor TEXT NOT NULL,
                detail TEXT NOT NULL, previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
            )""")
        conn.execute(
            """INSERT INTO items(title, description, severity, quantity, threshold,
               status, version, external_ref, created_by, created_at, updated_at)
               VALUES('legacy permit', 'old schema', 'medium', 8, 4, 'approved',
                      3, 'LEG-1', 'old-system', '2024-01-01T00:00:00+00:00',
                      '2024-01-01T00:00:00+00:00')""")
        conn.commit()
        conn.close()

        repo = Repository(db_path)
        try:
            item = repo.get_item(1)
            self.assertEqual(item["quota_status"], "active")
            self.assertIsNone(item["renewal_of"])
            records = repo.list_records(1)
            baselines = [r for r in records if r["kind"] == "baseline"]
            self.assertEqual(len(baselines), 1)
            self.assertIn("历史基线", baselines[0]["detail"])
            self.assertIn("status=approved", baselines[0]["detail"])
            self.assertTrue(repo.verify_audit_chain())
        finally:
            repo.close()

        repo = Repository(db_path)
        try:
            records = repo.list_records(1)
            self.assertEqual(
                len([r for r in records if r["kind"] == "baseline"]), 1)
        finally:
            repo.close()


if __name__ == "__main__":
    unittest.main()
