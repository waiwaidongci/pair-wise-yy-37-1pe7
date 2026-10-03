import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _make_approved_item(self, external_ref="REN-ITEM-1"):
        item = self.service.create_item(
            {"title": "renewal item", "description": "renewal test",
             "severity": "high", "quantity": 100, "threshold": 50,
             "external_ref": external_ref},
            "creator", "applicant")
        self.service.add_record(
            item["id"],
            {"kind": "evidence", "detail": "initial evidence",
             "status": "closed", "external_ref": "EV-" + external_ref},
            "recorder", "applicant")
        current = item
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        return current

    def _renewal_payload(self, renewal_no, version, new_quota=200.0,
                         inspection=None, close_rectifications=True):
        if inspection is None:
            inspection = {"result": "pass", "detail": "annual inspection"}
        return {
            "renewal_no": renewal_no,
            "expected_version": version,
            "new_quota": new_quota,
            "inspection": inspection,
            "close_rectifications": close_rectifications,
        }

    def test_renewal_handoff_freezes_inspects_closes_and_approves(self):
        item = self._make_approved_item()
        self.service.add_record(
            item["id"],
            {"kind": "rectification", "detail": "open rectification",
             "status": "open", "external_ref": "REC-1"},
            "recorder", "applicant")
        payload = self._renewal_payload("REN-1", item["version"])
        result = self.service.submit_renewal(
            item["id"], payload, "reviewer", "compliance_manager")
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["frozen_quota"], 100.0)
        self.assertEqual(result["new_quota"], 200.0)
        # 额度冻结
        freezes = self.repo.conn.execute(
            "SELECT * FROM quota_freezes WHERE item_id=?", (item["id"],)
        ).fetchall()
        self.assertEqual(len(freezes), 1)
        self.assertEqual(freezes[0]["status"], "frozen")
        self.assertEqual(freezes[0]["frozen_quota"], 100.0)
        # 现场检查记录
        records = self.service.list_records(item["id"], "viewer")
        inspections = [r for r in records if r["kind"] == "inspection"]
        self.assertEqual(len(inspections), 1)
        self.assertEqual(inspections[0]["status"], "closed")
        # 整改关闭
        rects = [r for r in records if r["kind"] == "rectification"]
        self.assertTrue(all(r["status"] == "closed" for r in rects))
        # 额度冻结标记
        self.assertEqual(self.repo.get_item(item["id"])["quota_frozen"], 1)
        # 续期通过：旧额度停用，新额度生效
        approved = self.service.approve_renewal(
            "REN-1", result["version"], "approver", "compliance_manager")
        self.assertEqual(approved["status"], "approved")
        updated = self.repo.get_item(item["id"])
        self.assertEqual(updated["quantity"], 200.0)
        self.assertEqual(updated["quota_frozen"], 0)
        freezes = self.repo.conn.execute(
            "SELECT * FROM quota_freezes WHERE item_id=?", (item["id"],)
        ).fetchall()
        self.assertEqual(len(freezes), 1)
        self.assertEqual(freezes[0]["status"], "deactivated")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_duplicate_renewal_only_first_accepted(self):
        item = self._make_approved_item()
        payload = self._renewal_payload("REN-DUP", item["version"])
        first = self.service.submit_renewal(
            item["id"], payload, "reviewer", "compliance_manager")
        self.assertEqual(first["renewal_no"], "REN-DUP")
        # 重试：使用更新后的版本号，内容相同 -> 幂等返回第一笔
        updated = self.repo.get_item(item["id"])
        retry_payload = self._renewal_payload("REN-DUP", updated["version"])
        second = self.service.submit_renewal(
            item["id"], retry_payload, "reviewer", "compliance_manager")
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["renewal_no"], "REN-DUP")
        renewals = self.service.list_renewals(item["id"], "viewer")
        self.assertEqual(len(renewals), 1)

    def test_duplicate_renewal_different_content_records_conflict(self):
        item = self._make_approved_item()
        payload = self._renewal_payload("REN-CF", item["version"], new_quota=200.0)
        self.service.submit_renewal(
            item["id"], payload, "reviewer", "compliance_manager")
        updated = self.repo.get_item(item["id"])
        diff_payload = self._renewal_payload(
            "REN-CF", updated["version"], new_quota=999.0)
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item["id"], diff_payload, "reviewer", "compliance_manager")
        self.assertIn("内容不一致", str(ctx.exception))
        conflicts = self.service.list_renewal_conflicts("viewer")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["renewal_no"], "REN-CF")
        # 原续期不受影响
        renewals = self.service.list_renewals(item["id"], "viewer")
        self.assertEqual(len(renewals), 1)
        self.assertEqual(renewals[0]["new_quota"], 200.0)

    def test_concurrent_submission_first_wins_second_gets_version_conflict(self):
        item = self._make_approved_item()
        payload = self._renewal_payload("REN-CONC", item["version"])
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def submit():
            barrier.wait()
            try:
                r = self.service.submit_renewal(
                    item["id"], dict(payload), "reviewer", "compliance_manager")
                results.append(r)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=submit)
        t2 = threading.Thread(target=submit)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ConflictError)
        self.assertIn("版本冲突", str(errors[0]))
        renewals = self.service.list_renewals(item["id"], "viewer")
        self.assertEqual(len(renewals), 1)
        self.assertEqual(self.repo.get_item(item["id"])["quota_frozen"], 1)

    def test_submission_failure_rolls_back_and_retryable(self):
        item = self._make_approved_item()
        self.service.add_record(
            item["id"],
            {"kind": "rectification", "detail": "open rect",
             "status": "open", "external_ref": "REC-1"},
            "recorder", "applicant")
        # 制造检查记录外部标识冲突，使交接事务失败
        self.service.add_record(
            item["id"],
            {"kind": "other", "detail": "collision",
             "status": "closed", "external_ref": "INS-REN-FAIL"},
            "recorder", "applicant")
        payload = self._renewal_payload("REN-FAIL", item["version"])
        with self.assertRaises(Exception):
            self.service.submit_renewal(
                item["id"], payload, "reviewer", "compliance_manager")
        # 整笔回滚：无续期、无冻结、整改未关闭、额度未冻结
        self.assertEqual(self.service.list_renewals(item["id"], "viewer"), [])
        self.assertEqual(self.repo.get_item(item["id"])["quota_frozen"], 0)
        records = self.service.list_records(item["id"], "viewer")
        self.assertTrue(any(r["status"] == "open" and r["kind"] == "rectification"
                            for r in records))
        # 排除故障后按原编号重试成功
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "DELETE FROM records WHERE item_id=? AND external_ref=?",
                (item["id"], "INS-REN-FAIL"))
        retry = self.service.submit_renewal(
            item["id"], payload, "reviewer", "compliance_manager")
        self.assertEqual(retry["status"], "submitted")
        self.assertEqual(len(self.service.list_renewals(item["id"], "viewer")), 1)

    def test_duplicate_approval_rejected(self):
        item = self._make_approved_item()
        payload = self._renewal_payload("REN-APP", item["version"])
        result = self.service.submit_renewal(
            item["id"], payload, "reviewer", "compliance_manager")
        self.service.approve_renewal(
            "REN-APP", result["version"], "approver", "compliance_manager")
        with self.assertRaises(ConflictError):
            self.service.approve_renewal(
                "REN-APP", result["version"], "approver", "compliance_manager")

    def test_baseline_upgrade_supplements_history(self):
        item = self._make_approved_item(external_ref="OLD-ITEM")
        self.assertFalse(self.repo.has_baseline(item["id"]))
        baseline = self.service.upgrade_baseline(
            item["id"], "migrator", "compliance_manager")
        self.assertTrue(self.repo.has_baseline(item["id"]))
        self.assertEqual(baseline["renewal_no"], "BASELINE-" + str(item["id"]))
        self.assertEqual(baseline["status"], "approved")
        self.assertEqual(baseline["frozen_quota"], 100.0)
        self.assertEqual(baseline["new_quota"], 100.0)
        freezes = self.repo.conn.execute(
            "SELECT * FROM quota_freezes WHERE item_id=?", (item["id"],)
        ).fetchall()
        self.assertEqual(len(freezes), 1)
        self.assertEqual(freezes[0]["status"], "deactivated")
        # 重复升级被拒绝
        with self.assertRaises(ConflictError):
            self.service.upgrade_baseline(
                item["id"], "migrator", "compliance_manager")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_bulk_baseline_upgrade(self):
        item1 = self._make_approved_item(external_ref="OLD-1")
        item2 = self._make_approved_item(external_ref="OLD-2")
        upgraded = self.service.upgrade_all_baselines(
            "migrator", "compliance_manager")
        self.assertEqual(len(upgraded), 2)
        self.assertTrue(self.repo.has_baseline(item1["id"]))
        self.assertTrue(self.repo.has_baseline(item2["id"]))
        # 再次批量升级不重复
        upgraded2 = self.service.upgrade_all_baselines(
            "migrator", "compliance_manager")
        self.assertEqual(len(upgraded2), 0)

    def test_renewal_requires_renewable_state(self):
        item = self.service.create_item(
            {"title": "draft item", "description": "draft",
             "severity": "low", "quantity": 10, "threshold": 5,
             "external_ref": "DRAFT-1"},
            "creator", "applicant")
        payload = self._renewal_payload("REN-DRAFT", item["version"])
        with self.assertRaises(ConflictError):
            self.service.submit_renewal(
                item["id"], payload, "reviewer", "compliance_manager")

    def test_renewal_no_reused_on_different_item_conflicts(self):
        item1 = self._make_approved_item(external_ref="CROSS-1")
        item2 = self._make_approved_item(external_ref="CROSS-2")
        payload1 = self._renewal_payload("REN-CROSS", item1["version"])
        self.service.submit_renewal(
            item1["id"], payload1, "reviewer", "compliance_manager")
        payload2 = self._renewal_payload("REN-CROSS", item2["version"])
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_renewal(
                item2["id"], payload2, "reviewer", "compliance_manager")
        self.assertIn("其他项目", str(ctx.exception))
        conflicts = self.service.list_renewal_conflicts("viewer")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["renewal_no"], "REN-CROSS")


if __name__ == "__main__":
    unittest.main()
