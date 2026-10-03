from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ENTITY, ID_PREFIX, KIND_BASELINE, KIND_INSPECTION,
                    KIND_QUOTA_FREEZE, KIND_RECTIFICATION_CLOSE, STATES)


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
                CREATE TABLE IF NOT EXISTS permit_renewals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    renewal_no TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL REFERENCES items(id),
                    new_item_id INTEGER NOT NULL REFERENCES items(id),
                    content_hash TEXT NOT NULL,
                    result TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS renewal_conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    renewal_no TEXT NOT NULL,
                    item_id INTEGER NOT NULL REFERENCES items(id),
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
        self._migrate()

    def _migrate(self) -> None:
        """许可升级：为旧数据补列并补写历史基线，重复执行安全。"""
        columns = {row["name"] for row in
                   self.conn.execute("PRAGMA table_info(items)").fetchall()}
        with self._lock, self.conn:
            if "quota_status" not in columns:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN quota_status TEXT NOT NULL DEFAULT 'active'")
            if "renewal_of" not in columns:
                self.conn.execute("ALTER TABLE items ADD COLUMN renewal_of INTEGER")
            if "renewal_no" not in columns:
                self.conn.execute("ALTER TABLE items ADD COLUMN renewal_no TEXT")
            legacy = self.conn.execute(
                """SELECT i.* FROM items i WHERE NOT EXISTS (
                       SELECT 1 FROM records r WHERE r.item_id=i.id AND r.kind=?)""",
                (KIND_BASELINE,),
            ).fetchall()
            now = utc_now()
            for row in legacy:
                detail = (f"历史基线：许可升级前状态 status={row['status']}, "
                          f"quantity={row['quantity']}, threshold={row['threshold']}, "
                          f"version={row['version']}")
                self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (row["id"], KIND_BASELINE, detail, "closed",
                     f"BASELINE-{row['id']}", "system", now),
                )
            if legacy:
                self._append_audit_tx("migrate", ENTITY, 0, "system", {
                    "baseline_backfilled": [int(row["id"]) for row in legacy],
                })

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

    def _insert_record_tx(self, item_id: int, kind: str, detail: str, status: str,
                          external_ref: Optional[str], actor: str, now: str) -> int:
        """在当前事务内插入记录，调用方必须已持有锁和事务。"""
        cur = self.conn.execute(
            """INSERT INTO records(item_id, kind, detail, status, external_ref,
               created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
            (item_id, kind, detail, status, external_ref, actor, now),
        )
        return int(cur.lastrowid)

    def _record_by_id(self, record_id: int) -> Dict[str, Any]:
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def submit_renewal(self, item_id: int, renewal_no: str, content_hash: str,
                       expected_version: int, actor: str, inspection_detail: str,
                       rectification_note: Optional[str],
                       new_permit: Dict[str, Any]) -> Dict[str, Any]:
        """续期交接：冻结旧额度、现场检查、整改关闭、签发新许可、停用旧额度，
        全部在一个事务内，任一步失败整笔回滚，可按原续期编号重试。"""
        now = utc_now()
        with self._lock:
            with self.conn:
                existing = self.conn.execute(
                    "SELECT * FROM permit_renewals WHERE renewal_no=?", (renewal_no,)
                ).fetchone()
                if existing is None:
                    return self._execute_renewal(
                        item_id, renewal_no, content_hash, expected_version, actor,
                        inspection_detail, rectification_note, new_permit, now)
            if existing["content_hash"] == content_hash and existing["actor"] == actor:
                result = json.loads(existing["result"])
                result["idempotent"] = True
                return result
            if existing["content_hash"] == content_hash:
                item = self.get_item(item_id)
                raise ConflictError(
                    f"版本冲突：续期编号{renewal_no}已由{existing['actor']}接纳，"
                    f"许可当前版本{item['version']}，与expected_version={expected_version}"
                    f"不一致，请刷新后重试")
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO renewal_conflicts(renewal_no, item_id, actor, reason,
                       content_hash, created_at) VALUES(?,?,?,?,?,?)""",
                    (renewal_no, item_id, actor, "同一续期编号提交了不同内容",
                     content_hash, now),
                )
                conflict_id = int(cur.lastrowid)
                self._append_audit_tx("renewal_conflict", ENTITY, item_id, actor, {
                    "renewal_no": renewal_no, "conflict_id": conflict_id,
                    "reason": "同一续期编号提交了不同内容",
                })
            raise ConflictError(
                f"续期编号{renewal_no}已存在但内容不一致，冲突已留档(#{conflict_id})")

    def _execute_renewal(self, item_id: int, renewal_no: str, content_hash: str,
                         expected_version: int, actor: str, inspection_detail: str,
                         rectification_note: Optional[str],
                         new_permit: Dict[str, Any], now: str) -> Dict[str, Any]:
        item = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if item is None:
            raise NotFoundError("项目不存在")
        cur = self.conn.execute(
            """UPDATE items SET quota_status='frozen', version=version+1, updated_at=?
               WHERE id=? AND version=? AND status='approved' AND quota_status='active'""",
            (now, item_id, expected_version),
        )
        if cur.rowcount == 0:
            if item["status"] != "approved":
                raise ConflictError(f"当前状态{item['status']}不允许续期交接")
            if item["quota_status"] != "active":
                raise ConflictError("旧额度已冻结或停用，不能重复续期")
            raise ConflictError(
                f"版本冲突：许可当前版本{item['version']}，"
                f"与expected_version={expected_version}不一致，请刷新后重试")
        freeze_id = self._insert_record_tx(
            item_id, KIND_QUOTA_FREEZE,
            f"续期{renewal_no}：冻结旧额度 quantity={item['quantity']}, "
            f"threshold={item['threshold']}", "closed", None, actor, now)
        inspection_id = self._insert_record_tx(
            item_id, KIND_INSPECTION, inspection_detail, "closed", None, actor, now)
        closed_count = int(self.conn.execute(
            "UPDATE records SET status='closed' WHERE item_id=? AND status='open'",
            (item_id,),
        ).rowcount)
        close_detail = f"续期{renewal_no}：关闭未结整改{closed_count}项"
        if rectification_note:
            close_detail += f"。{rectification_note}"
        close_id = self._insert_record_tx(
            item_id, KIND_RECTIFICATION_CLOSE, close_detail, "closed", None, actor, now)
        try:
            cur = self.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at,
                   quota_status, renewal_of, renewal_no)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (new_permit["title"], new_permit["description"], new_permit["severity"],
                 new_permit["quantity"], new_permit["threshold"], "approved", 1,
                 new_permit["external_ref"], actor, now, now, "active", item_id,
                 renewal_no),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("新许可external_ref已存在，整笔续期已回滚") from exc
        new_item_id = int(cur.lastrowid)
        self.conn.execute(
            """UPDATE items SET quota_status='deactivated', version=version+1,
               updated_at=? WHERE id=?""",
            (now, item_id),
        )
        old_item = self.get_item(item_id)
        new_item = self.get_item(new_item_id)
        result = {
            "renewal_no": renewal_no,
            "item_id": item_id,
            "new_item_id": new_item_id,
            "idempotent": False,
            "closed_records": closed_count,
            "records": [self._record_by_id(rid)
                        for rid in (freeze_id, inspection_id, close_id)],
            "old_item": old_item,
            "new_item": new_item,
        }
        self.conn.execute(
            """INSERT INTO permit_renewals(renewal_no, item_id, new_item_id,
               content_hash, result, actor, created_at) VALUES(?,?,?,?,?,?,?)""",
            (renewal_no, item_id, new_item_id, content_hash,
             json.dumps(result, ensure_ascii=False, sort_keys=True), actor, now),
        )
        self._append_audit_tx("renewal", ENTITY, item_id, actor, {
            "renewal_no": renewal_no, "new_item_id": new_item_id,
            "expected_version": expected_version, "closed_records": closed_count,
            "old_quota": {"quantity": item["quantity"], "threshold": item["threshold"]},
            "new_quota": {"quantity": new_permit["quantity"],
                          "threshold": new_permit["threshold"]},
        })
        self._append_audit_tx("create", ENTITY, new_item_id, actor, {
            "renewal_no": renewal_no, "renewal_of": item_id,
            "title": new_permit["title"],
        })
        return result

    def list_renewals(self, item_id: int) -> Dict[str, Any]:
        self.get_item(item_id)
        with self._lock:
            renewals = [dict(row) for row in self.conn.execute(
                """SELECT * FROM permit_renewals WHERE item_id=? OR new_item_id=?
                   ORDER BY id""",
                (item_id, item_id),
            ).fetchall()]
            conflicts = [dict(row) for row in self.conn.execute(
                "SELECT * FROM renewal_conflicts WHERE item_id=? ORDER BY id",
                (item_id,),
            ).fetchall()]
        for renewal in renewals:
            renewal["result"] = json.loads(renewal["result"])
        return {"renewals": renewals, "conflicts": conflicts}

    def _append_audit_tx(self, action: str, entity_type: str, entity_id: int,
                         actor: str, detail: dict) -> Dict[str, Any]:
        """在当前事务内追加审计事件，调用方必须已持有锁和事务。"""
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
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._append_audit_tx(action, entity_type, entity_id, actor, detail)

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

    def close(self) -> None:
        with self._lock:
            self.conn.close()
