from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    RENEWAL_APPROVE_ROLES, RENEWAL_SUBMIT_ROLES,
                    RENEWAL_UPGRADE_ROLES, RENEWAL_VIEW_ROLES, TITLE,
                    VIEW_ROLES, can_renew, completion_blockers,
                    escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def submit_renewal(self, item_id: int, payload: Dict[str, Any], actor: str,
                       role: str) -> Dict[str, Any]:
        """许可续期交接：额度冻结、现场检查、整改关闭一次完成，可回滚。"""
        ensure_role(role, RENEWAL_SUBMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        renewal_no = require_text(payload.get("renewal_no"), "renewal_no", 100)
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        item = self.repository.get_item(item_id)
        if not can_renew(item["status"]):
            raise ConflictError("当前状态不允许续期")
        new_quota = payload.get("new_quota")
        if new_quota is not None:
            new_quota = require_number(new_quota, "new_quota", 0)
        new_threshold = payload.get("new_threshold")
        if new_threshold is not None:
            new_threshold = require_number(new_threshold, "new_threshold", 0.000001)
        inspection = payload.get("inspection")
        if inspection is not None:
            if not isinstance(inspection, dict):
                raise ValueError("inspection必须是对象")
            inspection = {
                "result": require_text(inspection.get("result", "pass"), "inspection.result", 50),
                "detail": require_text(inspection.get("detail", ""), "inspection.detail", 2000),
            }
        close_rectifications = payload.get("close_rectifications", True)
        if not isinstance(close_rectifications, bool):
            raise ValueError("close_rectifications必须是布尔值")
        renewal_payload = {
            "new_quota": new_quota,
            "new_threshold": new_threshold,
            "inspection": inspection,
            "close_rectifications": close_rectifications,
        }
        return self.repository.submit_renewal(
            item_id, renewal_no, expected_version, renewal_payload, actor)

    def approve_renewal(self, renewal_no: str, expected_version: int,
                         actor: str, role: str) -> Dict[str, Any]:
        """续期通过：旧额度停用，新额度生效。"""
        ensure_role(role, RENEWAL_APPROVE_ROLES)
        actor = require_text(actor, "actor", 100)
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        return self.repository.approve_renewal(renewal_no, expected_version, actor)

    def list_renewals(self, item_id: int, role: str) -> list:
        ensure_role(role, RENEWAL_VIEW_ROLES)
        return self.repository.list_renewals(item_id)

    def list_renewal_conflicts(self, role: str) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_renewal_conflicts()

    def upgrade_baseline(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        """旧数据按许可升级补历史基线。"""
        ensure_role(role, RENEWAL_UPGRADE_ROLES)
        actor = require_text(actor, "actor", 100)
        return self.repository.upgrade_item_baseline(item_id, actor)

    def upgrade_all_baselines(self, actor: str, role: str) -> list:
        """批量为缺少基线的旧许可补历史基线。"""
        ensure_role(role, RENEWAL_UPGRADE_ROLES)
        actor = require_text(actor, "actor", 100)
        return self.repository.upgrade_all_baselines(actor)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
