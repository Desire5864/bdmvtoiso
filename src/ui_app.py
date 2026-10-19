#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
import selectors
import threading
import time
import logging
import os
import signal
import json
import secrets
import struct
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:

    from Crypto.Hash import MD4 as _CryptoMD4

    _HAVE_CRYPTO_MD4 = True
except Exception:
    _CryptoMD4 = None
    _HAVE_CRYPTO_MD4 = False


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
OUT_DIR = ROOT / "updata"
ISO_DIR = ROOT / "iso"
CONFIG_DIR = ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"
ED2K_DB_FILE = CONFIG_DIR / "list.json"
ISO_ED2K_DB_FILE = CONFIG_DIR / "ed2k.json"
QB_WEBHOOK_LAST_FILE = CONFIG_DIR / "qb_webhook_last.json"
DEFAULT_QB_WEBHOOK_SECRET = "aiying"
CFG_QB_WEBHOOK_ENABLED = "qb_webhook_enabled"
CFG_QB_AUTO_CONVERT = "qb_auto_convert_iso"
CFG_QB_AUTO_ED2K = "qb_auto_ed2k"

ED2K_CHUNK_BYTES = 9500 * 1024


def _load_or_init_config() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:

            pass

    cfg = {
        "username": "admin",

        "password_hash": generate_password_hash("admin123"),
        "secret_key": secrets.token_hex(16),
    }
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return cfg


CONFIG_LOCK = threading.Lock()
CONFIG = _load_or_init_config()


def _get_config() -> dict:
    with CONFIG_LOCK:
        return dict(CONFIG)


def _save_config(new_cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(new_cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(new_cfg)


def _cfg_bool(cfg: dict, key: str, default: bool = False) -> bool:
    v = cfg.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return bool(default)


def _safe_name(name: str) -> str:
    name = name.strip()
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("bad name")
    if "\x00" in name:
        raise ValueError("bad name")
    return name


def _safe_next_url(nxt: str | None) -> str:

    if not nxt:
        return url_for("index")
    nxt = nxt.strip()
    if not nxt.startswith("/") or nxt.startswith("//"):
        return url_for("index")
    return nxt


def _resolved_child_under(root: Path, *relative_parts: str) -> Path:

    if not relative_parts:
        raise ValueError("bad path")
    for part in relative_parts:
        _safe_name(part)
    candidate = root.joinpath(*relative_parts).resolve()
    root_r = root.resolve()
    if not candidate.is_relative_to(root_r):
        raise ValueError("path escape")
    return candidate


def _is_bdmv_root(p: Path) -> bool:
    return (p / "BDMV" / "index.bdmv").is_file() and (p / "BDMV" / "MovieObject.bdmv").is_file()


def _disc_children(box_dir: Path) -> list[Path]:

    discs: list[Path] = []
    try:
        for p in sorted([x for x in box_dir.iterdir() if x.is_dir()], key=lambda x: x.name.lower()):
            if _is_bdmv_root(p):
                discs.append(p)
    except FileNotFoundError:
        pass
    return discs


def _job_key(box: str, disc: str | None = None) -> str:

    return box if disc is None else f"{box}::{disc}"


def _safe_iso_filename(name: str) -> str:

    name = (name or "").strip()
    if not name:
        raise ValueError("empty name")
    if "\x00" in name or "/" in name or "\\" in name:
        raise ValueError("bad name")
    if name.startswith("."):
        raise ValueError("bad name")
    if not name.lower().endswith(".iso"):
        name = name + ".iso"

    if len(name) > 240:
        raise ValueError("name too long")
    return name


def _ed2k_rewrite_filename(link: str, new_fname: str) -> str:

    try:
        parts = str(link).split("|")
        if len(parts) < 6:
            return link
        if not parts[0].startswith("ed2k://"):
            return link
        if parts[1] != "file":
            return link
        parts[2] = new_fname
        return "|".join(parts)
    except Exception:
        return link


def _find_best_iso_path(box: str, disc: str | None) -> Path | None:

    try:
        box = _safe_name(box)
        if disc is not None:
            disc = _safe_name(disc)
    except ValueError:
        return None

    try:
        default = _resolved_child_under(OUT_DIR, f"{box}.iso") if disc is None else _resolved_child_under(OUT_DIR, box, f"{disc}.iso")
        if default.exists():
            return default
    except Exception:
        pass


    best: tuple[int, Path] | None = None
    with ED2K_DB_LOCK:
        db = _load_ed2k_db()
        items = db.get("items") if isinstance(db, dict) else None
        if not isinstance(items, dict):
            return None
        for rel, item in items.items():
            if not isinstance(rel, str) or not isinstance(item, dict):
                continue
            if item.get("box") != box:
                continue
            if (item.get("disc") or None) != disc:
                continue
            try:
                p = (ROOT / rel).resolve()
                if not p.is_relative_to(OUT_DIR.resolve()):
                    continue
                if not p.exists():
                    continue
            except Exception:
                continue
            upd = int(item.get("updated_at") or 0)
            if best is None or upd > best[0]:
                best = (upd, p)
    return best[1] if best else None


@dataclass
class Job:
    key: str
    box: str
    disc: str | None
    src_dir: Path
    out_iso: Path
    status: str
    started_at: float | None = None
    ended_at: float | None = None
    last_output: str = ""
    total_bytes: int = 0
    written_bytes: int = 0
    progress: float = 0.0
    detail: str = ""
    proc_pid: int | None = None
    stop_requested: bool = False


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()

ED2K_DB_LOCK = threading.Lock()
ISO_ED2K_DB_LOCK = threading.Lock()


def _load_ed2k_db() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ED2K_DB_FILE.exists():
        return {"version": 1, "items": {}}
    try:
        data = json.loads(ED2K_DB_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": 1, "items": {}}
        if data.get("version") != 1 or not isinstance(data.get("items"), dict):
            return {"version": 1, "items": {}}
        return data
    except Exception:
        return {"version": 1, "items": {}}


def _load_iso_ed2k_db() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ISO_ED2K_DB_FILE.exists():
        return {"version": 1, "items": {}}
    try:
        data = json.loads(ISO_ED2K_DB_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": 1, "items": {}}
        if data.get("version") != 1 or not isinstance(data.get("items"), dict):
            return {"version": 1, "items": {}}
        return data
    except Exception:
        return {"version": 1, "items": {}}


def _save_iso_ed2k_db(db: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ISO_ED2K_DB_FILE.write_text(json.dumps(db, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _iso_rel_key(p: Path) -> str:

    try:
        return p.resolve().relative_to(ISO_DIR.resolve()).as_posix()
    except Exception:
        return p.name


def _safe_iso_relpath(rel: str) -> str:

    rel = (rel or "").strip().replace("\\", "/")
    if not rel or rel.startswith("/"):
        raise ValueError("bad file")
    if "\x00" in rel:
        raise ValueError("bad file")
    parts = [p for p in rel.split("/") if p]
    if not parts or ".." in parts:
        raise ValueError("bad file")
    for part in parts:
        _safe_name(part)
    if not parts[-1].lower().endswith(".iso"):
        raise ValueError("not iso")
    if len(rel) > 512:
        raise ValueError("path too long")
    return "/".join(parts)


def _resolved_iso_path(rel: str) -> Path:
    rel = _safe_iso_relpath(rel)
    return _resolved_child_under(ISO_DIR, *rel.split("/"))


def _iter_iso_files() -> list[Path]:
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    found: list[Path] = []
    try:
        for p in ISO_DIR.rglob("*.iso"):
            if p.is_file():
                found.append(p)
    except OSError:
        pass
    return sorted(found, key=lambda x: _iso_rel_key(x).lower())


def _iso_rename_target(old_rel: str, new_name: str) -> str:

    old_rel = _safe_iso_relpath(old_rel)
    new_fname = _safe_iso_filename(new_name)
    parent_parts = old_rel.split("/")[:-1]
    if parent_parts:
        return "/".join(parent_parts + [new_fname])
    return new_fname


def _get_persisted_iso_item_for_path(iso_path: Path) -> dict | None:
    rel = _iso_rel_key(iso_path)
    with ISO_ED2K_DB_LOCK:
        db = _load_iso_ed2k_db()
        item = (db.get("items") or {}).get(rel)
    if not isinstance(item, dict):
        return None
    try:
        if iso_path.exists():
            st = iso_path.stat()
            if int(item.get("size", -1)) != int(st.st_size):
                return None
            mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
            if int(item.get("mtime_ns", -1)) != int(mtime_ns):
                return None
    except OSError:
        return None
    return item


def _persist_iso_snapshot_for_path(iso_path: Path, snapshot: dict) -> None:
    rel = _iso_rel_key(iso_path)
    record = dict(snapshot)
    record["updated_at"] = int(time.time())
    with ISO_ED2K_DB_LOCK:
        db = _load_iso_ed2k_db()
        items = db.get("items")
        if not isinstance(items, dict):
            items = {}
        old = items.get(rel)
        if isinstance(old, dict):
            merged = dict(old)
            merged.update(record)
            record = merged
        items[rel] = record
        db["items"] = items
        _save_iso_ed2k_db(db)


def _prune_iso_ed2k_db_missing_files() -> None:
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    with ISO_ED2K_DB_LOCK:
        db = _load_iso_ed2k_db()
        items = db.get("items")
        if not isinstance(items, dict) or not items:
            return
        dead: list[str] = []
        for rel in list(items.keys()):
            if not isinstance(rel, str):
                dead.append(rel)
                continue
            try:
                p = (ISO_DIR / rel).resolve()
                if not p.is_relative_to(ISO_DIR.resolve()):
                    dead.append(rel)
                    continue
                if not p.exists():
                    dead.append(rel)
            except Exception:
                dead.append(rel)
        if dead:
            for k in dead:
                items.pop(k, None)
            db["items"] = items
            _save_iso_ed2k_db(db)


def _save_ed2k_db(db: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ED2K_DB_FILE.write_text(json.dumps(db, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _ed2k_rel_key(iso_path: Path) -> str:
    try:
        return iso_path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(iso_path)


def _get_persisted_item_for_path(iso_path: Path) -> dict | None:

    rel = _ed2k_rel_key(iso_path)
    with ED2K_DB_LOCK:
        db = _load_ed2k_db()
        item = (db.get("items") or {}).get(rel)
    if not isinstance(item, dict):
        return None
    try:
        if iso_path.exists():
            st = iso_path.stat()
            if int(item.get("size", -1)) != int(st.st_size):
                return None
            mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
            if int(item.get("mtime_ns", -1)) != int(mtime_ns):
                return None
    except OSError:
        return None
    return item


def _persist_job_snapshot_for_path(iso_path: Path, box: str, disc: str | None, snapshot: dict) -> None:
    rel = _ed2k_rel_key(iso_path)
    record = dict(snapshot)
    record["box"] = box
    record["disc"] = disc
    record["updated_at"] = int(time.time())
    with ED2K_DB_LOCK:
        db = _load_ed2k_db()
        items = db.get("items")
        if not isinstance(items, dict):
            items = {}
        old = items.get(rel)
        if isinstance(old, dict):
            merged = dict(old)
            merged.update(record)
            record = merged
        items[rel] = record
        db["items"] = items
        _save_ed2k_db(db)


def _prune_ed2k_db_missing_files() -> None:
    with ED2K_DB_LOCK:
        db = _load_ed2k_db()
        items = db.get("items")
        if not isinstance(items, dict) or not items:
            return
        dead: list[str] = []
        for rel in list(items.keys()):
            if not isinstance(rel, str):
                dead.append(rel)
                continue
            try:
                p = (ROOT / rel).resolve()
                if not p.is_relative_to(ROOT.resolve()):
                    dead.append(rel)
                    continue
                if not p.exists():
                    dead.append(rel)
            except Exception:
                dead.append(rel)
        if dead:
            for k in dead:
                items.pop(k, None)
            db["items"] = items
            _save_ed2k_db(db)


def _md4_digest_pure_py(data: bytes) -> bytes:


    def _lrot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    total_len = len(data)
    buf = bytearray(data)

    def _process_block(mv: memoryview, off: int) -> tuple[int, int, int, int]:
        nonlocal a, b, c, d
        x = struct.unpack_from("<16I", mv, off)
        aa, bb, cc, dd = a, b, c, d

        sa = [3, 7, 11, 19]
        for i in range(16):
            k = i
            s = sa[i % 4]
            if i % 4 == 0:
                a = _lrot((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                d = _lrot((d + _f(a, b, c) + x[k]) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                c = _lrot((c + _f(d, a, b) + x[k]) & 0xFFFFFFFF, s)
            else:
                b = _lrot((b + _f(c, d, a) + x[k]) & 0xFFFFFFFF, s)

        sb = [3, 5, 9, 13]
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            k = order[i]
            s = sb[i % 4]
            if i % 4 == 0:
                a = _lrot((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                d = _lrot((d + _g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                c = _lrot((c + _g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            else:
                b = _lrot((b + _g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)

        sc = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            s = sc[i % 4]
            if i % 4 == 0:
                a = _lrot((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                d = _lrot((d + _h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                c = _lrot((c + _h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            else:
                b = _lrot((b + _h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
        return a, b, c, d

    mv = memoryview(buf)
    off = 0
    end = len(buf) - (len(buf) % 64)
    while off < end:
        _process_block(mv, off)
        off += 64
    if off:
        rem = mv[off:].tobytes()
        mv.release()
        buf = bytearray(rem)
    else:
        mv.release()

    bit_len = total_len * 8
    buf.extend(b"\x80")
    while (len(buf) % 64) != 56:
        buf.extend(b"\x00")
    buf.extend(bit_len.to_bytes(8, "little"))
    mv = memoryview(buf)
    off = 0
    while off < len(buf):
        _process_block(mv, off)
        off += 64
    mv.release()

    return a.to_bytes(4, "little") + b.to_bytes(4, "little") + c.to_bytes(4, "little") + d.to_bytes(4, "little")


def _md4_digest(data: bytes) -> bytes:
    if _HAVE_CRYPTO_MD4 and _CryptoMD4 is not None:
        return _CryptoMD4.new(data).digest()
    return _md4_digest_pure_py(data)


def _ed2k_hash_hex_for_iso_with_progress(
    iso_path: Path,
    progress_cb: Callable[[float], None] | None = None,
) -> str:

    st = iso_path.stat()
    size = int(st.st_size)

    def _report(p: float) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb(max(0.0, min(1.0, float(p))))
        except Exception:
            pass

    piece_digests: list[bytes] = []
    if size <= 0:
        piece_digests = [_md4_digest(b"")]
        _report(1.0)
    else:
        n_pieces = (size + ED2K_CHUNK_BYTES - 1) // ED2K_CHUNK_BYTES
        extra = 1 if n_pieces > 1 else 0
        total_steps = n_pieces + extra
        done_pieces = 0
        with iso_path.open("rb") as f:
            while True:
                chunk = f.read(ED2K_CHUNK_BYTES)
                if not chunk:
                    break
                piece_digests.append(_md4_digest(chunk))
                done_pieces += 1
                _report(done_pieces / total_steps)
        if not piece_digests:
            piece_digests = [_md4_digest(b"")]
            _report(1.0)

    if len(piece_digests) == 1:
        h = piece_digests[0].hex().upper()
    else:
        h = _md4_digest(b"".join(piece_digests)).hex().upper()
    _report(1.0)
    return h


def _ed2k_hash_hex_for_iso(iso_path: Path) -> str:
    return _ed2k_hash_hex_for_iso_with_progress(iso_path, None)


def _ed2k_link_for_iso(iso_path: Path) -> str:
    st = iso_path.stat()
    h = _ed2k_hash_hex_for_iso(iso_path)


    fname = iso_path.name
    return f"ed2k://|file|{fname}|{st.st_size}|{h}|/"


ED2K_TASK_LOCK = threading.Lock()

ED2K_TASKS: dict[str, dict] = {}


def _ed2k_task_snapshot(key: str) -> dict | None:
    with ED2K_TASK_LOCK:
        t = ED2K_TASKS.get(key)
        return dict(t) if isinstance(t, dict) else None


def _ed2k_task_start_or_get(
    key: str,
    iso_path: Path,
    box: str,
    disc: str | None,
) -> dict:

    try:
        st = iso_path.stat()
    except OSError as e:
        return {"status": "error", "progress": 0.0, "ed2k": None, "error": str(e)}

    size = int(st.st_size)
    mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))


    try:
        persisted = _get_persisted_item_for_path(iso_path)
        if isinstance(persisted, dict):
            ed2k = persisted.get("ed2k")
            if isinstance(ed2k, str) and ed2k.strip():
                return {"status": "done", "progress": 1.0, "ed2k": ed2k, "error": None}
    except Exception:
        pass

    with ED2K_TASK_LOCK:
        cur = ED2K_TASKS.get(key)
        if isinstance(cur, dict):
            if cur.get("status") == "running":
                return {
                    "status": "running",
                    "progress": float(cur.get("progress") or 0.0),
                    "ed2k": None,
                    "error": None,
                }
            if cur.get("status") == "done" and int(cur.get("size", -1)) == size and int(cur.get("mtime_ns", -2)) == mtime_ns:
                return {
                    "status": "done",
                    "progress": 1.0,
                    "ed2k": str(cur.get("ed2k") or ""),
                    "error": None,
                }
        ED2K_TASKS[key] = {
            "status": "running",
            "progress": 0.0,
            "ed2k": None,
            "error": None,
            "size": size,
            "mtime_ns": mtime_ns,
        }

    def _run() -> None:
        try:

            def _cb(p: float) -> None:
                with ED2K_TASK_LOCK:
                    ex = ED2K_TASKS.get(key)
                    if isinstance(ex, dict) and ex.get("status") == "running":
                        ex["progress"] = float(p)

            h = _ed2k_hash_hex_for_iso_with_progress(iso_path, _cb)
            st2 = iso_path.stat()
            link = f"ed2k://|file|{iso_path.name}|{int(st2.st_size)}|{h}|/"

            try:
                _persist_job_snapshot_for_path(
                    iso_path,
                    box=box,
                    disc=disc,
                    snapshot={
                        "ed2k": link,
                        "size": int(st2.st_size),
                        "mtime_ns": int(getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9))),
                    },
                )
            except Exception:
                pass
            with ED2K_TASK_LOCK:
                ED2K_TASKS[key] = {
                    "status": "done",
                    "progress": 1.0,
                    "ed2k": link,
                    "error": None,
                    "size": int(st2.st_size),
                    "mtime_ns": int(getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9))),
                }
        except Exception as e:
            with ED2K_TASK_LOCK:
                ED2K_TASKS[key] = {
                    "status": "error",
                    "progress": 0.0,
                    "ed2k": None,
                    "error": str(e),
                    "size": size,
                    "mtime_ns": mtime_ns,
                }

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "running", "progress": 0.0, "ed2k": None, "error": None}


def _safe_iso_basename(fname: str) -> str:

    return _safe_iso_relpath(fname)


def _iso_task_key(fname: str) -> str:

    return f"ISO::{fname}"


def _iso_ed2k_task_start_or_get(fname: str, iso_path: Path) -> dict:


    try:
        persisted = _get_persisted_iso_item_for_path(iso_path)
        if isinstance(persisted, dict):
            ed2k = persisted.get("ed2k")
            if isinstance(ed2k, str) and ed2k.strip():
                return {"status": "done", "progress": 1.0, "ed2k": ed2k, "error": None}
    except Exception:
        pass

    key = _iso_task_key(fname)

    try:
        st = iso_path.stat()
    except OSError as e:
        return {"status": "error", "progress": 0.0, "ed2k": None, "error": str(e)}

    size = int(st.st_size)
    mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))

    with ED2K_TASK_LOCK:
        cur = ED2K_TASKS.get(key)
        if isinstance(cur, dict):
            if cur.get("status") == "running":
                return {"status": "running", "progress": float(cur.get("progress") or 0.0), "ed2k": None, "error": None}
            if cur.get("status") == "done" and int(cur.get("size", -1)) == size and int(cur.get("mtime_ns", -2)) == mtime_ns:
                return {"status": "done", "progress": 1.0, "ed2k": str(cur.get("ed2k") or ""), "error": None}
        ED2K_TASKS[key] = {"status": "running", "progress": 0.0, "ed2k": None, "error": None, "size": size, "mtime_ns": mtime_ns}

    def _run() -> None:
        try:

            def _cb(p: float) -> None:
                with ED2K_TASK_LOCK:
                    ex = ED2K_TASKS.get(key)
                    if isinstance(ex, dict) and ex.get("status") == "running":
                        ex["progress"] = float(p)

            h = _ed2k_hash_hex_for_iso_with_progress(iso_path, _cb)
            st2 = iso_path.stat()
            link = f"ed2k://|file|{iso_path.name}|{int(st2.st_size)}|{h}|/"
            try:
                _persist_iso_snapshot_for_path(
                    iso_path,
                    snapshot={
                        "ed2k": link,
                        "size": int(st2.st_size),
                        "mtime_ns": int(getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9))),
                    },
                )
            except Exception:
                pass
            with ED2K_TASK_LOCK:
                ED2K_TASKS[key] = {
                    "status": "done",
                    "progress": 1.0,
                    "ed2k": link,
                    "error": None,
                    "size": int(st2.st_size),
                    "mtime_ns": int(getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9))),
                }
        except Exception as e:
            with ED2K_TASK_LOCK:
                ED2K_TASKS[key] = {"status": "error", "progress": 0.0, "ed2k": None, "error": str(e), "size": size, "mtime_ns": mtime_ns}

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "running", "progress": 0.0, "ed2k": None, "error": None}

def _prune_stale_jobs_if_output_gone() -> None:

    with JOBS_LOCK:
        dead: list[str] = []
        for k, job in list(JOBS.items()):
            if job.status not in ("done", "error"):
                continue
            try:
                if not job.out_iso.exists():
                    dead.append(k)
            except OSError:
                dead.append(k)
        for k in dead:
            JOBS.pop(k, None)


def _unlink_if_under_outdir(iso_path: Path) -> bool:

    try:
        if not iso_path.exists():
            return False
        if iso_path.resolve().is_relative_to(OUT_DIR.resolve()):
            iso_path.unlink()
            return True
    except Exception:
        pass
    return False


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f}{u}" if u != "B" else f"{int(f)}B"
        f /= 1024
    return f"{int(n)}B"


def _dir_total_bytes(src_dir: Path) -> int:
    total = 0
    for root in [src_dir / "BDMV", src_dir / "CERTIFICATE"]:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except FileNotFoundError:
                continue
    return total


def _geniso_family_available() -> bool:

    if Path("/usr/local/bin/bdmv-genisoimage").is_file():
        return True
    for p in ("/usr/bin/genisoimage", "/bin/genisoimage"):
        if Path(p).is_file():
            return True
    return bool(shutil.which("genisoimage") or shutil.which("mkisofs"))


def _pick_local_engine() -> tuple[str, str | None]:

    if _geniso_family_available():
        return ("xorriso", None)
    if shutil.which("xorriso"):
        return ("xorriso", "提示：未找到 mkisofs/genisoimage；当前将尝试 xorriso 兜底，但可能无法严格 UDF2.50。")
    if shutil.which("hdiutil"):
        return ("hdiutil", "提示：hdiutil 无法强制 UDF 2.50，严格蓝光兼容建议安装 genisoimage/mkisofs。")
    return ("", "本机未找到 mkisofs/genisoimage/xorriso 或 hdiutil，无法转换。")


def _build_local_cmd(src_dir: Path, out_iso: Path) -> tuple[list[str], str]:
    engine, note = _pick_local_engine()
    if not engine:
        return ([], note or "无法转换")
    bdmv_to_iso = ROOT / "bdmv_to_iso.py"
    cmd = [
        sys.executable,
        str(bdmv_to_iso),
        str(src_dir),
        "--engine",
        engine,
        "-o",
        str(out_iso),
    ]
    msg = f"使用本机引擎：{engine}"
    if note:
        msg += f"\n{note}"
    return (cmd, msg)


def _run_job(job: Job) -> None:
    job.status = "running"
    job.started_at = time.time()
    try:
        if not job.src_dir.resolve().is_relative_to(DATA_DIR.resolve()):
            job.status = "error"
            job.last_output = "源目录不在 data/ 下，已拒绝执行。"
            job.ended_at = time.time()
            return
    except (OSError, ValueError):
        job.status = "error"
        job.last_output = "源目录无效，已拒绝执行。"
        job.ended_at = time.time()
        return
    try:
        if not job.out_iso.resolve().is_relative_to(OUT_DIR.resolve()):
            job.status = "error"
            job.last_output = "输出路径不在 updata/ 下，已拒绝执行。"
            job.ended_at = time.time()
            return
    except (OSError, ValueError):
        job.status = "error"
        job.last_output = "输出路径无效，已拒绝执行。"
        job.ended_at = time.time()
        return
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    job.out_iso.parent.mkdir(parents=True, exist_ok=True)
    job.total_bytes = _dir_total_bytes(job.src_dir)
    job.detail = f"总大小：{_human_size(job.total_bytes)}"
    cmd, intro = _build_local_cmd(job.src_dir, job.out_iso)
    if not cmd:
        job.status = "error"
        job.last_output = intro
        job.ended_at = time.time()
        return

    job.last_output = ""


    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=0,
        start_new_session=True,
    )
    job.proc_pid = proc.pid

    out_buf = ""
    sel = selectors.DefaultSelector()
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ)

    try:
        while True:
            if job.stop_requested:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                job.last_output = (job.last_output + "\n已请求停止任务。\n")[-4000:]

                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass

                try:
                    if _unlink_if_under_outdir(job.out_iso):
                        job.written_bytes = 0
                        job.progress = 0.0
                        job.last_output = (job.last_output + f"已删除未完成输出：{job.out_iso}\n")[-4000:]
                except Exception as e:
                    job.last_output = (job.last_output + f"删除未完成输出失败：{e}\n")[-4000:]

                break


            for key, _ in sel.select(timeout=0):
                try:
                    chunk = key.fileobj.read(4096)
                except Exception:
                    chunk = ""
                if chunk:
                    out_buf += chunk
                    job.last_output = (job.last_output + chunk)[-4000:]


            try:
                if job.out_iso.exists() and job.total_bytes > 0:
                    job.written_bytes = job.out_iso.stat().st_size
                    job.progress = max(0.0, min(0.999, job.written_bytes / job.total_bytes))
            except FileNotFoundError:
                pass

            rc = proc.poll()
            if rc is not None:
                break

            time.sleep(0.5)
    finally:
        try:
            sel.close()
        except Exception:
            pass
        try:
            if proc.stdout:
                rest = proc.stdout.read() or ""
                if rest:
                    out_buf += rest
                    job.last_output = (job.last_output + rest)[-4000:]
        except Exception:
            pass

    rc = proc.returncode if proc.returncode is not None else 1
    job.ended_at = time.time()
    job.proc_pid = None
    if rc == 0:
        job.status = "done"
        job.progress = 1.0
        try:
            if job.out_iso.exists():
                job.written_bytes = job.out_iso.stat().st_size
        except Exception:
            pass
    else:
        job.status = "cancelled" if job.stop_requested else "error"
        if job.stop_requested:

            try:
                _unlink_if_under_outdir(job.out_iso)
            except Exception:
                pass
    if out_buf:

        tail = 65536 if rc != 0 else 4000
        job.last_output = out_buf[-tail:]


    try:
        _persist_job_snapshot_for_path(
            job.out_iso,
            box=job.box,
            disc=job.disc,
            snapshot={
                "status": job.status,
                "detail": job.detail,
                "progress": float(job.progress),
                "total_bytes": int(job.total_bytes),
                "written_bytes": int(job.written_bytes),
                "ended_at": float(job.ended_at or time.time()),
                "last_output": str(job.last_output or ""),
            },
        )
    except Exception:
        pass


    if job.status == "cancelled":
        with JOBS_LOCK:
            cur = JOBS.get(job.key)
            if cur is job:
                JOBS.pop(job.key, None)


app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = _get_config().get("secret_key") or secrets.token_hex(16)

def _is_logged_in() -> bool:
    return bool(session.get("logged_in") is True)


@app.before_request
def _require_login():
    if request.path.startswith("/login"):
        return None
    if request.path.startswith("/webhook/qb"):
        return None
    # 站点图标必须匿名可取，否则登录页之前标签页没有图标
    if request.path.startswith("/static/") or request.path == "/favicon.ico":
        return None
    if not _is_logged_in():
        return redirect(url_for("login", next=request.path))
    return None


@app.get("/login")
def login():
    return render_template("login.html", error=None)


@app.get("/favicon.ico")
def favicon_ico():
    # 浏览器直接探测根路径时重定向到静态目录里的多尺寸 ico
    return redirect("/static/favicon.ico")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    cfg = _get_config()
    ok = username == str(cfg.get("username") or "") and check_password_hash(str(cfg.get("password_hash") or ""), password)
    if not ok:
        return render_template("login.html", error="账号或密码错误")

    session["logged_in"] = True
    return redirect(_safe_next_url(request.args.get("next")))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/account")
def account():
    return render_template("account.html", error=None, ok=None)


@app.post("/account")
def account_post():
    old_password = request.form.get("old_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not old_password or not new_password:
        return render_template("account.html", error="请输入旧密码和新密码", ok=None)
    if len(new_password) < 6:
        return render_template("account.html", error="新密码至少 6 位", ok=None)
    if new_password != confirm_password:
        return render_template("account.html", error="两次输入的新密码不一致", ok=None)

    cfg = _get_config()
    if not check_password_hash(str(cfg.get("password_hash") or ""), old_password):
        return render_template("account.html", error="旧密码不正确", ok=None)

    cfg["password_hash"] = generate_password_hash(new_password)
    _save_config(cfg)
    return render_template("account.html", error=None, ok="密码已更新")


@app.get("/api/settings")
def api_settings_get():
    cfg = _get_config()
    return jsonify(
        {
            "ok": True,
            CFG_QB_WEBHOOK_ENABLED: _cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False),
            CFG_QB_AUTO_CONVERT: _cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False),
            CFG_QB_AUTO_ED2K: _cfg_bool(cfg, CFG_QB_AUTO_ED2K, False),
        }
    )


@app.post("/api/settings")
def api_settings_post():
    cfg = _get_config()
    payload: dict = {}
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payload.update(data)
    if request.form:
        payload.update({k: v for k, v in request.form.items()})

    enabled = _cfg_bool(payload, CFG_QB_WEBHOOK_ENABLED, _cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False))
    auto_convert = _cfg_bool(payload, CFG_QB_AUTO_CONVERT, _cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False))
    auto_ed2k = _cfg_bool(payload, CFG_QB_AUTO_ED2K, _cfg_bool(cfg, CFG_QB_AUTO_ED2K, False))

    cfg[CFG_QB_WEBHOOK_ENABLED] = bool(enabled)
    cfg[CFG_QB_AUTO_CONVERT] = bool(auto_convert)
    cfg[CFG_QB_AUTO_ED2K] = bool(auto_ed2k)
    _save_config(cfg)
    return jsonify(
        {
            "ok": True,
            CFG_QB_WEBHOOK_ENABLED: bool(enabled),
            CFG_QB_AUTO_CONVERT: bool(auto_convert),
            CFG_QB_AUTO_ED2K: bool(auto_ed2k),
        }
    )


@app.post("/api/rename_iso")
def api_rename_iso():

    payload: dict = {}
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payload.update(data)
    if request.form:
        payload.update({k: v for k, v in request.form.items()})

    name = (payload.get("name") or "").strip()
    disc_raw = payload.get("disc")
    disc: str | None = None
    if isinstance(disc_raw, str):
        disc_raw = disc_raw.strip()
        if disc_raw:
            disc = disc_raw
    new_name = (payload.get("new_name") or payload.get("new") or "").strip()
    try:
        name = _safe_name(name)
        if disc is not None:
            disc = _safe_name(disc)
        new_fname = _safe_iso_filename(new_name)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    key = _job_key(name, disc)
    with JOBS_LOCK:
        j = JOBS.get(key)
        if j and j.status in ("running", "pending"):
            return jsonify({"ok": False, "error": "任务进行中，无法改名"}), 409

    cur = _find_best_iso_path(name, disc)
    if not cur or not cur.exists():
        return jsonify({"ok": False, "error": "当前没有可改名的输出 ISO"}), 404

    try:
        if disc is None:
            dst = _resolved_child_under(OUT_DIR, new_fname)
        else:

            dst = _resolved_child_under(OUT_DIR, name, new_fname)
    except ValueError:
        return jsonify({"ok": False, "error": "目标文件名非法"}), 400

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            return jsonify({"ok": False, "error": "目标文件已存在"}), 409
        cur.rename(dst)
    except Exception as e:
        return jsonify({"ok": False, "error": f"改名失败：{e}"}), 500


    with JOBS_LOCK:
        j2 = JOBS.get(key)
        if j2:
            j2.out_iso = dst


    try:
        old_rel = _ed2k_rel_key(cur)
        new_rel = _ed2k_rel_key(dst)
        st = dst.stat()
        size = int(st.st_size)
        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))

        with ED2K_DB_LOCK:
            db = _load_ed2k_db()
            items = db.get("items")
            if not isinstance(items, dict):
                items = {}
            rec = items.pop(old_rel, None)
            if not isinstance(rec, dict):
                rec = {}
            rec["box"] = name
            rec["disc"] = disc
            rec["updated_at"] = int(time.time())
            rec["size"] = size
            rec["mtime_ns"] = mtime_ns
            if isinstance(rec.get("ed2k"), str) and rec.get("ed2k"):
                rec["ed2k"] = _ed2k_rewrite_filename(str(rec.get("ed2k")), dst.name)
            items[new_rel] = rec
            db["items"] = items
            _save_ed2k_db(db)
    except Exception:

        pass

    out_iso_rel = str(dst)
    try:
        out_iso_rel = dst.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        pass
    return jsonify({"ok": True, "out_iso_rel": out_iso_rel})


def _qb_webhook_secret() -> str:

    return (os.environ.get("QB_WEBHOOK_SECRET") or DEFAULT_QB_WEBHOOK_SECRET).strip()


def _qb_webhook_require_auth() -> None:
    token = (request.headers.get("X-Webhook-Token") or "").strip()
    if not token:
        token = (request.args.get("token") or request.form.get("token") or "").strip()
    if not token or not hmac.compare_digest(token, _qb_webhook_secret()):
        abort(403)


def _qb_webhook_read_payload() -> dict:
    payload: dict = {}

    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payload.update(data)

    if request.form:
        payload.update({k: v for k, v in request.form.items()})

    for k, v in request.args.items():
        if k not in payload:
            payload[k] = v
    return payload


def _qb_webhook_save_last(payload: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    rec = {
        "received_at": int(time.time()),
        "remote_addr": request.headers.get("X-Forwarded-For") or request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "payload": payload,
    }
    QB_WEBHOOK_LAST_FILE.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


@app.post("/webhook/qb")
def webhook_qb():

    _qb_webhook_require_auth()
    cfg = _get_config()
    if not _cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False):
        abort(404)
    payload = _qb_webhook_read_payload()
    _qb_webhook_save_last(payload)
    name = (payload.get("name") or payload.get("torrent_name") or payload.get("content_name") or "").strip()
    save_path = (payload.get("save_path") or payload.get("content_path") or payload.get("path") or "").strip()
    queued: list[str] = []

    def _enqueue_one(box: str, disc: str | None) -> None:
        try:
            box = _safe_name(box)
            if disc is not None:
                disc = _safe_name(disc)
        except ValueError:
            return


        try:
            if disc is None:
                base_dir = _resolved_child_under(DATA_DIR, box)
                if not base_dir.is_dir() or not _is_bdmv_root(base_dir):
                    return
                out_iso = _resolved_child_under(OUT_DIR, f"{box}.iso")
                key = _job_key(box)
                src_dir = base_dir
            else:
                src_dir = _resolved_child_under(DATA_DIR, box, disc)
                if not src_dir.is_dir() or not _is_bdmv_root(src_dir):
                    return
                out_iso = _resolved_child_under(OUT_DIR, box, f"{disc}.iso")
                key = _job_key(box, disc)
        except Exception:
            return


        with JOBS_LOCK:
            ex = JOBS.get(key)
            if ex and ex.status in ("running", "pending"):
                return
            try:
                if out_iso.exists():
                    return
            except OSError:
                return
            job = Job(key=key, box=box, disc=disc, src_dir=src_dir, out_iso=out_iso, status="pending")
            JOBS[key] = job
        threading.Thread(target=_run_job, args=(job,), daemon=True).start()
        queued.append(key)


        if _cfg_bool(cfg, CFG_QB_AUTO_ED2K, False):

            def _wait_and_start_ed2k() -> None:
                deadline = time.time() + 7 * 24 * 3600
                while time.time() < deadline:
                    try:
                        with JOBS_LOCK:
                            cur = JOBS.get(key)
                        if not cur:
                            return
                        if cur.status in ("done", "error", "cancelled"):
                            break
                    except Exception:
                        pass
                    time.sleep(1.0)
                try:
                    if out_iso.exists():
                        _ed2k_task_start_or_get(key, out_iso, box=box, disc=disc)
                except Exception:
                    pass

            threading.Thread(target=_wait_and_start_ed2k, daemon=True).start()

    if _cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False):

        try:
            name2 = _safe_name(name)
        except ValueError:
            name2 = ""
        if name2:
            try:
                base_dir = _resolved_child_under(DATA_DIR, name2)
            except Exception:
                base_dir = None
            if base_dir and isinstance(base_dir, Path) and base_dir.is_dir():
                if _is_bdmv_root(base_dir):
                    _enqueue_one(name2, None)
                else:
                    discs = _disc_children(base_dir)
                    if discs:
                        for d in discs:
                            _enqueue_one(name2, d.name)

    return jsonify(
        {
            "ok": True,
            "name": name,
            "save_path": save_path,
            "payload_keys": sorted(list(payload.keys())),
            "webhook_enabled": True,
            "auto_convert_iso": _cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False),
            "auto_ed2k": _cfg_bool(cfg, CFG_QB_AUTO_ED2K, False),
            "queued_jobs": queued,
        }
    )


@app.get("/webhook/qb/last")
def webhook_qb_last():

    _qb_webhook_require_auth()
    cfg = _get_config()
    if not _cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False):
        abort(404)
    try:
        if not QB_WEBHOOK_LAST_FILE.exists():
            return jsonify({"ok": True, "last": None})
        data = json.loads(QB_WEBHOOK_LAST_FILE.read_text(encoding="utf-8"))
        return jsonify({"ok": True, "last": data})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "last": None}), 500


@app.get("/")
def index():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    _prune_stale_jobs_if_output_gone()
    _prune_ed2k_db_missing_files()
    _prune_iso_ed2k_db_missing_files()

    engine, engine_note = _pick_local_engine()
    items: list[dict] = []
    for p in sorted([x for x in DATA_DIR.iterdir() if x.is_dir()], key=lambda x: x.name.lower()):
        name = p.name
        if _is_bdmv_root(p):
            out_iso = _find_best_iso_path(name, None) or (OUT_DIR / f"{name}.iso")
            key = _job_key(name)
            with JOBS_LOCK:
                job = JOBS.get(key)
            persisted = _get_persisted_item_for_path(out_iso) if out_iso.exists() else None
            ed2k = (persisted or {}).get("ed2k") if isinstance(persisted, dict) else None
            out_iso_rel = f"updata/{name}.iso"
            try:
                out_iso_rel = out_iso.resolve().relative_to(ROOT.resolve()).as_posix()
            except (ValueError, OSError):
                pass
            out_iso_bytes: int | None = None
            try:
                if out_iso.exists():
                    out_iso_bytes = int(out_iso.stat().st_size)
            except OSError:
                pass
            items.append(
                {
                    "name": name,
                    "kind": "disc",
                    "is_bdmv": True,
                    "out_exists": out_iso.exists(),
                    "job": job,
                    "ed2k": ed2k,
                    "persisted_last_output": (persisted or {}).get("last_output") if isinstance(persisted, dict) else None,
                    "out_iso_rel": out_iso_rel,
                    "out_iso_bytes": out_iso_bytes,
                    "discs": [],
                }
            )
            continue

        discs = _disc_children(p)
        if discs:
            disc_rows: list[dict] = []
            for d in discs:
                out_iso = _find_best_iso_path(name, d.name) or (OUT_DIR / name / f"{d.name}.iso")
                key = _job_key(name, d.name)
                with JOBS_LOCK:
                    job = JOBS.get(key)
                out_iso_rel = f"updata/{name}/{d.name}.iso"
                try:
                    out_iso_rel = out_iso.resolve().relative_to(ROOT.resolve()).as_posix()
                except (ValueError, OSError):
                    pass
                out_iso_bytes: int | None = None
                try:
                    if out_iso.exists():
                        out_iso_bytes = int(out_iso.stat().st_size)
                except OSError:
                    pass
                persisted = _get_persisted_item_for_path(out_iso) if out_iso.exists() else None
                ed2k = (persisted or {}).get("ed2k") if isinstance(persisted, dict) else None
                disc_rows.append(
                    {
                        "disc": d.name,
                        "is_bdmv": True,
                        "out_exists": out_iso.exists(),
                        "job": job,
                        "out_iso_rel": out_iso_rel,
                        "out_iso_bytes": out_iso_bytes,
                        "ed2k": ed2k,
                        "persisted_last_output": (persisted or {}).get("last_output") if isinstance(persisted, dict) else None,
                    }
                )
            items.append(
                {
                    "name": name,
                    "kind": "box",
                    "is_bdmv": True,
                    "out_exists": all(x["out_exists"] for x in disc_rows) and len(disc_rows) > 0,
                    "job": None,
                    "discs": disc_rows,
                }
            )
        else:
            items.append(
                {
                    "name": name,
                    "kind": "unknown",
                    "is_bdmv": False,
                    "out_exists": False,
                    "job": None,
                    "ed2k": None,
                    "persisted_last_output": None,
                    "out_iso_rel": "",
                    "out_iso_bytes": None,
                    "discs": [],
                }
            )

    cfg = _get_config()
    iso_items: list[dict] = []
    try:
        for p in _iter_iso_files():
            rel = _iso_rel_key(p)
            sz: int | None = None
            try:
                sz = int(p.stat().st_size)
            except Exception:
                sz = None
            persisted = _get_persisted_iso_item_for_path(p)
            ed2k = (persisted or {}).get("ed2k") if isinstance(persisted, dict) else None
            iso_items.append({"file": rel, "size": sz, "ed2k": ed2k})
    except Exception:
        pass
    return render_template(
        "index.html",
        items=items,
        iso_items=iso_items,
        engine=engine,
        engine_note=engine_note,
        qb_webhook_enabled=_cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False),
        qb_auto_convert_iso=_cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False),
        qb_auto_ed2k=_cfg_bool(cfg, CFG_QB_AUTO_ED2K, False),
    )


@app.post("/convert")
def convert():
    name = request.form.get("name", "")
    disc = request.form.get("disc", "") or None
    try:
        name = _safe_name(name)
        if disc is not None:
            disc = _safe_name(disc)
    except ValueError:
        abort(400)

    try:
        base_dir = _resolved_child_under(DATA_DIR, name)
    except ValueError:
        abort(400)
    if not base_dir.is_dir():
        abort(404)


    if _is_bdmv_root(base_dir) and disc is None:
        src_dir = base_dir
        try:
            out_iso = _resolved_child_under(OUT_DIR, f"{name}.iso")
        except ValueError:
            abort(400)
        key = _job_key(name)

        with JOBS_LOCK:
            existing = JOBS.get(key)
            if existing and existing.status in ("running", "pending"):
                return redirect(url_for("index"))
            if out_iso.exists():
                JOBS[key] = Job(
                    key=key,
                    box=name,
                    disc=None,
                    src_dir=src_dir,
                    out_iso=out_iso,
                    status="error",
                    last_output="输出已存在，未覆盖。",
                )
                return redirect(url_for("index"))

            job = Job(key=key, box=name, disc=None, src_dir=src_dir, out_iso=out_iso, status="pending")
            JOBS[key] = job

        threading.Thread(target=_run_job, args=(job,), daemon=True).start()
        return redirect(url_for("index"))


    if disc is not None:
        try:
            src_dir = _resolved_child_under(DATA_DIR, name, disc)
        except ValueError:
            abort(400)
        if not src_dir.is_dir() or not _is_bdmv_root(src_dir):
            abort(404)
        try:
            out_iso = _resolved_child_under(OUT_DIR, name, f"{disc}.iso")
        except ValueError:
            abort(400)
        key = _job_key(name, disc)
        with JOBS_LOCK:
            existing = JOBS.get(key)
            if existing and existing.status in ("running", "pending"):
                return redirect(url_for("index"))
            if out_iso.exists():
                JOBS[key] = Job(
                    key=key,
                    box=name,
                    disc=disc,
                    src_dir=src_dir,
                    out_iso=out_iso,
                    status="error",
                    last_output="输出已存在，未覆盖。",
                )
                return redirect(url_for("index"))
            job = Job(key=key, box=name, disc=disc, src_dir=src_dir, out_iso=out_iso, status="pending")
            JOBS[key] = job
        threading.Thread(target=_run_job, args=(job,), daemon=True).start()
        return redirect(url_for("index"))


    discs = _disc_children(base_dir)
    if not discs:
        abort(404)
    base_r = base_dir.resolve()
    for d in discs:
        try:
            d_res = d.resolve()
            if not d_res.is_relative_to(base_r):
                continue
        except (OSError, ValueError):
            continue
        try:
            out_iso = _resolved_child_under(OUT_DIR, name, f"{d.name}.iso")
        except ValueError:
            continue
        key = _job_key(name, d.name)
        with JOBS_LOCK:
            existing = JOBS.get(key)
            if existing and existing.status in ("running", "pending"):
                continue
            if out_iso.exists():
                continue
            job = Job(key=key, box=name, disc=d.name, src_dir=d_res, out_iso=out_iso, status="pending")
            JOBS[key] = job
        threading.Thread(target=_run_job, args=(job,), daemon=True).start()
    return redirect(url_for("index"))


@app.post("/stop")
def stop():
    name = request.form.get("name", "")
    disc = request.form.get("disc", "") or None
    try:
        name = _safe_name(name)
        if disc is not None:
            disc = _safe_name(disc)
    except ValueError:
        abort(400)


    key = _job_key(name, disc)
    job: Job | None = None
    with JOBS_LOCK:
        job = JOBS.get(key)
        if not job:
            return redirect(url_for("index"))
        if job.status not in ("running", "pending"):
            return redirect(url_for("index"))
        job.stop_requested = True


    try:
        if job.proc_pid:
            try:
                os.killpg(job.proc_pid, signal.SIGTERM)
            except Exception:
                os.kill(job.proc_pid, signal.SIGTERM)
    except Exception:
        pass


    try:
        _unlink_if_under_outdir(job.out_iso)
    except Exception:
        pass

    with JOBS_LOCK:

        JOBS.pop(key, None)

    return redirect(url_for("index"))


@app.post("/clear_job")
def clear_job():
    name = request.form.get("name", "")
    disc_raw = (request.form.get("disc") or "").strip()
    disc: str | None = None
    if disc_raw:
        try:
            disc = _safe_name(disc_raw)
        except ValueError:
            abort(400)
    try:
        name = _safe_name(name)
    except ValueError:
        abort(400)
    with JOBS_LOCK:
        if disc is not None:
            JOBS.pop(_job_key(name, disc), None)
        else:
            for k in list(JOBS.keys()):
                if k == name or k.startswith(f"{name}::"):
                    JOBS.pop(k, None)
    return redirect(url_for("index"))


@app.get("/api/status")
def api_status():

    _prune_stale_jobs_if_output_gone()
    with JOBS_LOCK:
        jobs = {}
        for name, job in JOBS.items():
            out_iso_exists = False
            out_iso_bytes_disk: int | None = None
            try:
                st_o = job.out_iso.stat()
                out_iso_exists = True
                out_iso_bytes_disk = int(st_o.st_size)
            except OSError:
                pass
            jobs[name] = {
                "status": job.status,
                "progress": job.progress,
                "written_bytes": job.written_bytes,
                "total_bytes": job.total_bytes,
                "detail": job.detail,
                "last_output": job.last_output,
                "out_iso": str(job.out_iso),
                "out_iso_exists": out_iso_exists,
                "out_iso_bytes_disk": out_iso_bytes_disk,
                "proc_pid": job.proc_pid,
                "stop_requested": job.stop_requested,
                "box": job.box,
                "disc": job.disc,
            }
    return jsonify({"jobs": jobs})


def _parse_ed2k_query() -> tuple[str, str | None, Path]:

    name = request.args.get("name", "") or ""
    disc_raw = (request.args.get("disc") or "").strip()
    disc: str | None = None
    try:
        name = _safe_name(name)
        if disc_raw:
            disc = _safe_name(disc_raw)
    except ValueError:
        abort(400)


    iso_path = _find_best_iso_path(name, disc)
    if iso_path is None:
        try:
            iso_path = _resolved_child_under(OUT_DIR, f"{name}.iso") if disc is None else _resolved_child_under(OUT_DIR, name, f"{disc}.iso")
        except ValueError:
            abort(400)
    return name, disc, iso_path


@app.get("/api/ed2k")
def api_ed2k():

    name, disc, iso_path = _parse_ed2k_query()
    if not iso_path.exists():
        abort(404)
    key = _job_key(name, disc)
    snap = _ed2k_task_start_or_get(key, iso_path, box=name, disc=disc)
    return jsonify(snap)


@app.get("/api/ed2k_status")
def api_ed2k_status():

    name, disc, _iso_path = _parse_ed2k_query()
    key = _job_key(name, disc)
    t = _ed2k_task_snapshot(key)
    if not t:
        return jsonify({"status": "idle", "progress": 0.0, "ed2k": None, "error": None})
    return jsonify(
        {
            "status": str(t.get("status") or "idle"),
            "progress": float(t.get("progress") or 0.0),
            "ed2k": t.get("ed2k"),
            "error": t.get("error"),
        }
    )


@app.get("/api/iso_ed2k")
def api_iso_ed2k():

    ISO_DIR.mkdir(parents=True, exist_ok=True)
    _prune_iso_ed2k_db_missing_files()
    fname = request.args.get("file", "") or ""
    try:
        fname = _safe_iso_relpath(fname)
    except ValueError:
        abort(400)
    try:
        p = _resolved_iso_path(fname)
    except ValueError:
        abort(400)
    if not p.exists():
        abort(404)
    snap = _iso_ed2k_task_start_or_get(fname, p)
    return jsonify(snap)


@app.get("/api/iso_ed2k_status")
def api_iso_ed2k_status():
    fname = request.args.get("file", "") or ""
    try:
        fname = _safe_iso_relpath(fname)
    except ValueError:
        abort(400)
    key = _iso_task_key(fname)
    t = _ed2k_task_snapshot(key)
    if not t:
        return jsonify({"status": "idle", "progress": 0.0, "ed2k": None, "error": None})
    return jsonify(
        {
            "status": str(t.get("status") or "idle"),
            "progress": float(t.get("progress") or 0.0),
            "ed2k": t.get("ed2k"),
            "error": t.get("error"),
        }
    )


@app.post("/api/iso_rename")
def api_iso_rename():

    ISO_DIR.mkdir(parents=True, exist_ok=True)
    payload: dict = {}
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payload.update(data)
    if request.form:
        payload.update({k: v for k, v in request.form.items()})

    old_file = (payload.get("file") or "").strip()
    new_name = (payload.get("new_name") or payload.get("new") or "").strip()
    try:
        old_file = _safe_iso_relpath(old_file)
        new_rel = _iso_rename_target(old_file, new_name)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    try:
        src = _resolved_iso_path(old_file)
        dst = _resolved_iso_path(new_rel)
    except ValueError:
        return jsonify({"ok": False, "error": "bad path"}), 400
    if not src.exists():
        return jsonify({"ok": False, "error": "源文件不存在"}), 404

    if dst.exists():
        return jsonify({"ok": False, "error": "目标文件已存在"}), 409

    try:
        src.rename(dst)
    except Exception as e:
        return jsonify({"ok": False, "error": f"改名失败：{e}"}), 500


    try:
        old_rel = _iso_rel_key(src)
        new_rel = _iso_rel_key(dst)
        st = dst.stat()
        size = int(st.st_size)
        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
        with ISO_ED2K_DB_LOCK:
            db = _load_iso_ed2k_db()
            items = db.get("items")
            if not isinstance(items, dict):
                items = {}
            rec = items.pop(old_rel, None)
            if not isinstance(rec, dict):
                rec = {}
            rec["updated_at"] = int(time.time())
            rec["size"] = size
            rec["mtime_ns"] = mtime_ns
            if isinstance(rec.get("ed2k"), str) and rec.get("ed2k"):
                rec["ed2k"] = _ed2k_rewrite_filename(str(rec.get("ed2k")), dst.name)
            items[new_rel] = rec
            db["items"] = items
            _save_iso_ed2k_db(db)
    except Exception:
        pass

    return jsonify({"ok": True, "file": _iso_rel_key(dst)})


def main(host: str = "127.0.0.1", port: int = 5173, debug: bool = True) -> int:

    logging.getLogger("werkzeug").setLevel(logging.CRITICAL)


    try:
        from werkzeug.serving import WSGIRequestHandler

        _orig_log_error = WSGIRequestHandler.log_error

        def _log_error_filtered(self, format, *args):
            try:
                msg = (format % args) if args else str(format)
            except Exception:
                msg = str(format)
            if "Bad request version" in msg:
                return
            return _orig_log_error(self, format, *args)

        WSGIRequestHandler.log_error = _log_error_filtered
    except Exception:
        pass
    app.run(host=host, port=port, debug=debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
