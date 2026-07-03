"""Lưu kết quả kiểm thử ra đĩa — không mất khi restart uvicorn."""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class PersistentResultStore:
    """
    Mỗi phiên = một file JSON trong thư mục `data/saved_results/`.
    Index nhẹ (`index.json`) để liệt kê nhanh; dữ liệu đầy đủ trong `{id}.json`.
    """

    def __init__(self, base_dir: Path, *, max_items: int = 200) -> None:
        self.base_dir = base_dir
        self.max_items = max(1, max_items)
        self.index_path = base_dir / "index.json"
        self._order: list[str] = []
        self._meta: dict[str, dict[str, Any]] = {}
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._load_index()

    def _entry_path(self, rid: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in rid)
        return self.base_dir / f"{safe}.json"

    def _load_index(self) -> None:
        if not self.index_path.is_file():
            return
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
            self._order = list(raw.get("order") or [])
            self._meta = dict(raw.get("meta") or {})
        except (OSError, json.JSONDecodeError):
            self._order = []
            self._meta = {}

    def _save_index(self) -> None:
        payload = {"order": self._order, "meta": self._meta}
        self._atomic_write_json(self.index_path, payload)

    @staticmethod
    def _atomic_write_json(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        text = json.dumps(data, ensure_ascii=False, indent=2)
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)

    def _meta_from_entry(self, rid: str, entry: dict[str, Any]) -> dict[str, Any]:
        summary = entry.get("summary") or {}
        return {
            "id": rid,
            "upload_stem": entry.get("upload_stem") or "domains",
            "created_at": entry.get("created_at") or "",
            "created_label": entry.get("created_label") or "",
            "elapsed": float(entry.get("elapsed") or 0),
            "summary": summary,
        }

    def put(self, rid: str, entry: dict[str, Any]) -> None:
        """Ghi entry đầy đủ ra đĩa và cập nhật index."""
        entry = dict(entry)
        entry["id"] = rid
        self._atomic_write_json(self._entry_path(rid), entry)
        self._cache[rid] = entry
        self._cache.move_to_end(rid)

        if rid in self._order:
            self._order.remove(rid)
        self._order.append(rid)
        self._meta[rid] = self._meta_from_entry(rid, entry)
        self._trim_to_max()
        self._save_index()

    def touch(self, rid: str) -> None:
        """Cập nhật LRU cache khi mở phiên; không đổi thứ tự theo thời gian."""
        if rid in self._cache:
            self._cache.move_to_end(rid)

    def _created_at_sort_key(self, rid: str, meta: dict[str, Any]) -> tuple[str, int]:
        created = str(meta.get("created_at") or "")
        if created:
            return (created, 0)
        try:
            path = self._entry_path(rid)
            if path.is_file():
                return (datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"), 0)
        except OSError:
            pass
        try:
            pos = self._order.index(rid)
        except ValueError:
            pos = 0
        return ("", pos)

    def list_newest_first(self) -> list[tuple[str, dict[str, Any]]]:
        items: list[tuple[str, dict[str, Any]]] = []
        for rid in self._order:
            meta = self._meta.get(rid)
            if meta:
                items.append((rid, meta))
        items.sort(key=lambda x: self._created_at_sort_key(x[0], x[1]), reverse=True)
        return items

    def _oldest_rid(self) -> Optional[str]:
        if not self._order:
            return None
        ranked = [
            (rid, self._created_at_sort_key(rid, self._meta[rid]))
            for rid in self._order
            if rid in self._meta
        ]
        if not ranked:
            return self._order[0]
        ranked.sort(key=lambda x: x[1])
        return ranked[0][0]

    def get(self, rid: str) -> Optional[dict[str, Any]]:
        if rid in self._cache:
            self._cache.move_to_end(rid)
            return self._cache[rid]
        path = self._entry_path(rid)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        self._cache[rid] = entry
        self._cache.move_to_end(rid)
        return entry

    def count(self) -> int:
        return len(self._order)

    def delete(self, rid: str) -> bool:
        """Xóa một phiên khỏi index, cache và file JSON."""
        path = self._entry_path(rid)
        had = rid in self._meta or path.is_file()
        if not had:
            return False
        if rid in self._order:
            self._order.remove(rid)
        self._meta.pop(rid, None)
        self._cache.pop(rid, None)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        self._save_index()
        return True

    def delete_all(self) -> int:
        """Xóa toàn bộ phiên đã lưu. Trả số file đã xóa."""
        rids = list(self._order)
        n = 0
        for rid in rids:
            if self.delete(rid):
                n += 1
        return n

    def _trim_to_max(self) -> None:
        while len(self._order) > self.max_items:
            oldest = self._oldest_rid()
            if oldest is None:
                break
            if oldest in self._order:
                self._order.remove(oldest)
            self._meta.pop(oldest, None)
            self._cache.pop(oldest, None)
            path = self._entry_path(oldest)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def rebuild_index_from_files(self) -> int:
        """Quét thư mục khi index trống hoặc lệch (phục hồi thủ công)."""
        found: list[tuple[str, dict[str, Any]]] = []
        for path in self.base_dir.glob("*.json"):
            if path.name == "index.json":
                continue
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rid = str(entry.get("id") or path.stem)
            entry["id"] = rid
            found.append((rid, entry))

        found.sort(key=lambda x: x[1].get("created_at") or "", reverse=False)
        self._order = [rid for rid, _ in found]
        self._meta = {rid: self._meta_from_entry(rid, entry) for rid, entry in found}
        self._save_index()
        return len(self._order)

    def ensure_loaded(self) -> None:
        if self._order:
            return
        self.rebuild_index_from_files()
