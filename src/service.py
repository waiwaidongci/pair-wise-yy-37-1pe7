from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    RENEWABLE_STATES, RENEWAL_ROLES, TITLE, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
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

    def submit_renewal(self, item_id: int, payload: Dict[str, Any], actor: str,
                       role: str) -> Dict[str, Any]:
        """许可续期交接：一次可回滚事务完成续期、额度冻结、现场检查、整改关闭，
        并在续期通过时停用旧额度。同一续期编号幂等，内容不同单独留冲突。"""
        ensure_role(role, RENEWAL_ROLES)
        actor = require_text(actor, "actor", 100)
        renewal_no = require_text(payload.get("renewal_no"), "renewal_no", 100)
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        inspection_detail = require_text(
            payload.get("inspection_detail"), "inspection_detail")
        rectification_note = payload.get("rectification_note")
        if rectification_note is not None:
            rectification_note = require_text(
                rectification_note, "rectification_note")
        item = self.repository.get_item(item_id)
        if item["status"] not in RENEWABLE_STATES:
            raise ConflictError(f"当前状态{item['status']}不允许续期交接")
        new_external_ref = payload.get("new_external_ref")
        if new_external_ref is not None:
            new_external_ref = require_text(new_external_ref, "new_external_ref", 100)
        new_permit = {
            "title": require_text(payload.get("title") or item["title"], "title", 200),
            "description": require_text(
                payload.get("description") or item["description"], "description"),
            "severity": normalize_severity(payload.get("severity") or item["severity"]),
            "quantity": require_number(
                payload.get("new_quantity", item["quantity"]), "new_quantity"),
            "threshold": require_number(
                payload.get("new_threshold", item["threshold"]), "new_threshold",
                0.000001),
            "external_ref": new_external_ref,
        }
        content_hash = hashlib.sha256(json.dumps({
            "renewal_no": renewal_no, "item_id": item_id,
            "expected_version": expected_version,
            "inspection_detail": inspection_detail,
            "rectification_note": rectification_note,
            "new_permit": new_permit,
        }, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        result = self.repository.submit_renewal(
            item_id, renewal_no, content_hash, expected_version, actor,
            inspection_detail, rectification_note, new_permit)
        result["old_item"] = self.enrich(result["old_item"])
        result["new_item"] = self.enrich(result["new_item"])
        return result

    def list_renewals(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.repository.list_renewals(item_id)

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

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
