from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import hash_payload, make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (BASELINE_RENEWAL_PREFIX, FREEZE_STATES, RENEWAL_STATES,
                    STATES, baseline_renewal_no)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        renewal_states = ",".join("'" + s.replace("'", "''") + "'" for s in RENEWAL_STATES)
        freeze_states = ",".join("'" + s.replace("'", "''") + "'" for s in FREEZE_STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS renewals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    renewal_no TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'submitted'
                        CHECK(status IN ({renewal_states})),
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    frozen_quota REAL,
                    new_quota REAL,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS renewal_conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    renewal_no TEXT NOT NULL,
                    item_id INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quota_freezes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    renewal_id INTEGER REFERENCES renewals(id) ON DELETE CASCADE,
                    frozen_quota REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'frozen'
                        CHECK(status IN ({freeze_states})),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    deactivated_at TEXT
                );
            """)
        self._ensure_column("items", "quota_frozen",
                           "ALTER TABLE items ADD COLUMN quota_frozen INTEGER NOT NULL DEFAULT 0")

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        cols = [row[1] for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if column not in cols:
            with self.conn:
                self.conn.execute(ddl)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ---- 许可续期交接 ----

    def _append_audit_tx(self, action: str, entity_type: str, entity_id: int,
                         actor: str, detail: dict, now: str) -> dict:
        """在当前事务内追加审计事件（不另开事务），保证审计与业务数据同生共死。"""
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        return event

    @staticmethod
    def _renewal_dict(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def get_renewal(self, renewal_no: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM renewals WHERE renewal_no=?", (renewal_no,)
            ).fetchone()
        if row is None:
            raise NotFoundError("续期不存在")
        return self._renewal_dict(row)

    def list_renewals(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM renewals WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [self._renewal_dict(row) for row in rows]

    def list_renewal_conflicts(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM renewal_conflicts ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def has_baseline(self, item_id: int) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM renewals WHERE renewal_no=?",
                (baseline_renewal_no(item_id),),
            ).fetchone()
        return row is not None

    def submit_renewal(self, item_id: int, renewal_no: str, expected_version: int,
                       payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
        """许可续期、额度冻结、现场检查、整改关闭一次交接。

        同一续期编号重复提交只认第一次（幂等）；内容不同单独留冲突。
        两位审核人同时提交同一续期时，先到的一笔提交成功，后到的拿到版本冲突原因。
        提交失败整笔回滚，可按原编号重试。
        """
        now = utc_now()
        payload_hash = hash_payload(payload)
        with self._lock:
            item_row = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if item_row is None:
                raise NotFoundError("项目不存在")
            item = dict(item_row)
            if item["version"] != expected_version:
                raise ConflictError("版本冲突：项目已被其他操作修改，请刷新后重试")
            existing = self.conn.execute(
                "SELECT * FROM renewals WHERE renewal_no=?", (renewal_no,)
            ).fetchone()
            if existing is not None:
                existing = dict(existing)
                if existing["item_id"] != item_id:
                    with self.conn:
                        self.conn.execute(
                            """INSERT INTO renewal_conflicts(renewal_no, item_id, payload_hash,
                               payload, reason, created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                            (renewal_no, item_id, payload_hash,
                             json.dumps(payload, ensure_ascii=False),
                             "续期编号已被其他项目使用", actor, now),
                        )
                        self._append_audit_tx(
                            "renewal_conflict", "renewal", existing["id"], actor,
                            {"renewal_no": renewal_no, "item_id": item_id,
                             "reason": "续期编号已被其他项目使用"}, now,
                        )
                    raise ConflictError("续期编号已被其他项目使用，冲突已单独记录")
                if existing["payload_hash"] == payload_hash:
                    return self._renewal_dict(existing)
                with self.conn:
                    self.conn.execute(
                        """INSERT INTO renewal_conflicts(renewal_no, item_id, payload_hash,
                           payload, reason, created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                        (renewal_no, item_id, payload_hash,
                         json.dumps(payload, ensure_ascii=False),
                         "续期编号已存在但内容不一致", actor, now),
                    )
                    self._append_audit_tx(
                        "renewal_conflict", "renewal", existing["id"], actor,
                        {"renewal_no": renewal_no, "item_id": item_id,
                         "reason": "续期编号已存在但内容不一致"}, now,
                    )
                raise ConflictError("续期编号已存在且内容不一致，冲突已单独记录")
            with self.conn:
                cur = self.conn.execute(
                    "SELECT version FROM items WHERE id=?", (item_id,)
                ).fetchone()
                if cur is None:
                    raise NotFoundError("项目不存在")
                if cur["version"] != expected_version:
                    raise ConflictError("版本冲突：项目已被其他操作修改，请刷新后重试")
                dup = self.conn.execute(
                    "SELECT 1 FROM renewals WHERE renewal_no=?", (renewal_no,)
                ).fetchone()
                if dup is not None:
                    raise ConflictError("续期编号已存在")
                frozen_quota = float(item["quantity"])
                freeze_cur = self.conn.execute(
                    """INSERT INTO quota_freezes(item_id, renewal_id, frozen_quota, status,
                       created_by, created_at) VALUES(?,?,?,?,?,?)""",
                    (item_id, None, frozen_quota, "frozen", actor, now),
                )
                freeze_id = int(freeze_cur.lastrowid)
                inspection = payload.get("inspection")
                if inspection is not None:
                    self.conn.execute(
                        """INSERT INTO records(item_id, kind, detail, status, external_ref,
                           created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                        (item_id, "inspection",
                         json.dumps(inspection, ensure_ascii=False), "closed",
                         f"INS-{renewal_no}", actor, now),
                    )
                closed_ids: List[int] = []
                if payload.get("close_rectifications", True):
                    rows = self.conn.execute(
                        "SELECT id FROM records WHERE item_id=? AND status='open'",
                        (item_id,),
                    ).fetchall()
                    for r in rows:
                        self.conn.execute(
                            "UPDATE records SET status='closed' WHERE id=?", (r["id"],)
                        )
                        closed_ids.append(int(r["id"]))
                self.conn.execute(
                    "UPDATE quota_freezes SET renewal_id=? WHERE id=?",
                    (None, freeze_id),
                )
                ren_cur = self.conn.execute(
                    """INSERT INTO renewals(renewal_no, item_id, status, payload, payload_hash,
                       frozen_quota, new_quota, version, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (renewal_no, item_id, "submitted",
                     json.dumps(payload, ensure_ascii=False), payload_hash,
                     frozen_quota, payload.get("new_quota"), 1, actor, now, now),
                )
                renewal_id = int(ren_cur.lastrowid)
                self.conn.execute(
                    "UPDATE quota_freezes SET renewal_id=? WHERE id=?",
                    (renewal_id, freeze_id),
                )
                self.conn.execute(
                    "UPDATE items SET quota_frozen=1, version=version+1, updated_at=? WHERE id=?",
                    (now, item_id),
                )
                self._append_audit_tx(
                    "renewal_submit", "renewal", renewal_id, actor,
                    {"renewal_no": renewal_no, "item_id": item_id,
                     "frozen_quota": frozen_quota,
                     "closed_rectification_ids": closed_ids}, now,
                )
        return self.get_renewal(renewal_no)

    def approve_renewal(self, renewal_no: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        """续期通过：旧额度停用，新额度生效。"""
        now = utc_now()
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM renewals WHERE renewal_no=?", (renewal_no,)
            ).fetchone()
            if row is None:
                raise NotFoundError("续期不存在")
            renewal = dict(row)
            if renewal["status"] != "submitted":
                raise ConflictError("续期已处理，不能重复批准")
            if renewal["version"] != expected_version:
                raise ConflictError("版本冲突：续期已被其他操作修改，请刷新后重试")
            with self.conn:
                self.conn.execute(
                    """UPDATE quota_freezes SET status='deactivated', deactivated_at=?
                       WHERE renewal_id=? AND status='frozen'""",
                    (now, renewal["id"]),
                )
                payload = json.loads(renewal["payload"])
                new_quota = payload.get("new_quota")
                new_threshold = payload.get("new_threshold")
                if new_quota is not None and new_threshold is not None:
                    self.conn.execute(
                        """UPDATE items SET quantity=?, threshold=?, quota_frozen=0,
                           version=version+1, updated_at=? WHERE id=?""",
                        (float(new_quota), float(new_threshold), now, renewal["item_id"]),
                    )
                elif new_quota is not None:
                    self.conn.execute(
                        """UPDATE items SET quantity=?, quota_frozen=0, version=version+1,
                           updated_at=? WHERE id=?""",
                        (float(new_quota), now, renewal["item_id"]),
                    )
                else:
                    self.conn.execute(
                        """UPDATE items SET quota_frozen=0, version=version+1, updated_at=?
                           WHERE id=?""",
                        (now, renewal["item_id"]),
                    )
                self.conn.execute(
                    "UPDATE renewals SET status='approved', version=version+1, updated_at=? WHERE id=?",
                    (now, renewal["id"]),
                )
                self._append_audit_tx(
                    "renewal_approve", "renewal", renewal["id"], actor,
                    {"renewal_no": renewal_no, "item_id": renewal["item_id"],
                     "deactivated_quota": renewal["frozen_quota"],
                     "new_quota": new_quota}, now,
                )
        return self.get_renewal(renewal_no)

    def upgrade_item_baseline(self, item_id: int, actor: str) -> Dict[str, Any]:
        """旧数据按许可升级补历史基线。"""
        now = utc_now()
        baseline_no = baseline_renewal_no(item_id)
        with self._lock:
            item_row = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if item_row is None:
                raise NotFoundError("项目不存在")
            item = dict(item_row)
            exists = self.conn.execute(
                "SELECT 1 FROM renewals WHERE renewal_no=?", (baseline_no,)
            ).fetchone()
            if exists is not None:
                raise ConflictError("已存在历史基线，不能重复升级")
            with self.conn:
                payload = {"baseline": True, "new_quota": item["quantity"]}
                payload_hash = hash_payload(payload)
                ren_cur = self.conn.execute(
                    """INSERT INTO renewals(renewal_no, item_id, status, payload, payload_hash,
                       frozen_quota, new_quota, version, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (baseline_no, item_id, "approved",
                     json.dumps(payload, ensure_ascii=False), payload_hash,
                     item["quantity"], item["quantity"], 1, actor, now, now),
                )
                renewal_id = int(ren_cur.lastrowid)
                self.conn.execute(
                    """INSERT INTO quota_freezes(item_id, renewal_id, frozen_quota, status,
                       created_by, created_at, deactivated_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, renewal_id, item["quantity"], "deactivated", actor, now, now),
                )
                self._append_audit_tx(
                    "baseline_upgrade", "item", item_id, actor,
                    {"renewal_no": baseline_no, "frozen_quota": item["quantity"]}, now,
                )
        return self.get_renewal(baseline_no)

    def upgrade_all_baselines(self, actor: str) -> List[Dict[str, Any]]:
        """批量为缺少基线的旧许可补历史基线。"""
        with self._lock:
            rows = self.conn.execute("SELECT id FROM items ORDER BY id").fetchall()
        upgraded = []
        for row in rows:
            item_id = int(row["id"])
            if not self.has_baseline(item_id):
                upgraded.append(self.upgrade_item_baseline(item_id, actor))
        return upgraded

    def close(self) -> None:
        with self._lock:
            self.conn.close()
