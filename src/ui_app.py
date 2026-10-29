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
import urllib.parse
import urllib.request
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
# 合并库模式：设置环境变量 LIB_DIR 后，源盘与 ISO 库共用一个根目录，
# 由程序按内容判断（含 BDMV/ 的目录 = 待打包资源，*.iso = 镜像库）。
# 不设 LIB_DIR 时保持旧的 data/ + iso/ 双目录行为。
_LIB_ENV = (os.environ.get("LIB_DIR") or "").strip()
LIB_DIR = Path(_LIB_ENV) if _LIB_ENV else None
DATA_DIR = LIB_DIR if LIB_DIR else (ROOT / "data")
ISO_DIR = LIB_DIR if LIB_DIR else (ROOT / "iso")
OUT_DIR = ROOT / "updata"
CONFIG_DIR = ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"
ED2K_DB_FILE = CONFIG_DIR / "list.json"
ISO_ED2K_DB_FILE = CONFIG_DIR / "ed2k.json"
QB_WEBHOOK_LAST_FILE = CONFIG_DIR / "qb_webhook_last.json"
DEFAULT_QB_WEBHOOK_SECRET = "aiying"
CFG_QB_WEBHOOK_ENABLED = "qb_webhook_enabled"
CFG_QB_AUTO_CONVERT = "qb_auto_convert_iso"
CFG_QB_AUTO_ED2K = "qb_auto_ed2k"
CFG_QB_URL = "qb_url"
CFG_QB_USERNAME = "qb_username"
CFG_QB_PASSWORD = "qb_password"
DEFAULT_QB_URL = "http://192.168.3.36:8088"

ED2K_CHUNK_BYTES = 9500 * 1024

# 软删除回收站：源目录与 ISO 各自同卷，rename 是 O(1)
DATA_TRASH = DATA_DIR / ".trash"
OUT_TRASH = OUT_DIR / ".trash"
_TRASH_LAST_PRUNE = 0.0
TRASH_KEEP_DAYS = 7


def _trash_slot(root: Path) -> Path:
    """取（或建）本次删除的时间戳目录。"""
    root.mkdir(parents=True, exist_ok=True)
    slot = root / time.strftime("%Y%m%d-%H%M%S")
    slot.mkdir(parents=True, exist_ok=True)
    return slot


def _prune_trash(keep_days: int = TRASH_KEEP_DAYS) -> None:
    """清掉超过保留期的回收站目录（每小时最多跑一次）。"""
    global _TRASH_LAST_PRUNE
    now = time.time()
    if now - _TRASH_LAST_PRUNE < 3600:
        return
    _TRASH_LAST_PRUNE = now
    for root in (DATA_TRASH, OUT_TRASH):
        try:
            if not root.is_dir():
                continue
            for slot in root.iterdir():
                try:
                    if slot.is_dir() and now - slot.stat().st_mtime > keep_days * 86400:
                        shutil.rmtree(slot, ignore_errors=True)
                except OSError:
                    pass
        except OSError:
            pass


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

    # Linux 单段文件名上限是 255 **字节**（不是字符）：中文一个 3 字节，
    # 早先用 len(name) > 240 判断字符数，184 个字符 = 280 字节时会漏过，
    # 直到 os.rename 抛 ENAMETOOLONG 才失败（用户踩到过）。
    nbytes = len(name.encode("utf-8"))
    if nbytes > 255:
        raise ValueError("文件名过长：%d / 255 字节，请再缩短 %d 字节" % (nbytes, nbytes - 255))
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


ISO_EXT_PREFIX = "@data/"


def _iso_rel_key(p: Path) -> str:

    try:
        return p.resolve().relative_to(ISO_DIR.resolve()).as_posix()
    except Exception:
        pass
    # 源盘目录（原盘/）里的镜像：加前缀区分，便于回查真实路径
    if not LIB_DIR:
        try:
            return ISO_EXT_PREFIX + p.resolve().relative_to(DATA_DIR.resolve()).as_posix()
        except Exception:
            pass
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
    rel = (rel or "").strip().replace("\\", "/")
    if rel.startswith(ISO_EXT_PREFIX):
        sub = _safe_iso_relpath(rel[len(ISO_EXT_PREFIX):])
        return _resolved_child_under(DATA_DIR, *sub.split("/"))
    rel = _safe_iso_relpath(rel)
    return _resolved_child_under(ISO_DIR, *rel.split("/"))


ISO_PRUNE_DIRS = {"BDMV", "CERTIFICATE", "ANY!", "PS3_DISC.SFB"}


def _walk_isos(root: Path) -> list[Path]:
    """遍历目录找 .iso，跳过隐藏目录与 BDMV 这类无关子树。"""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ISO_PRUNE_DIRS]
        for fn in filenames:
            if fn.lower().endswith(".iso"):
                out.append(Path(dirpath) / fn)
    return out


def _iter_iso_files() -> list[Path]:
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    found: list[Path] = []
    try:
        # 扩展名大小写不敏感：qB/站点工具导出的镜像常是 `xxx.ISO`，
        # 用 rglob("*.iso") 在 Linux 上会直接把这类文件漏掉（ISO 库显示为空）
        found.extend(_walk_isos(ISO_DIR))
        # 旧模式下源盘目录里也可能直接扔着 .iso（例如 qB 下载到 原盘/），
        # 这些以前既不进 ISO 库、也不是 BDMV 资源，等于完全看不见。
        if not LIB_DIR and DATA_DIR.resolve() != ISO_DIR.resolve():
            try:
                found.extend(_walk_isos(DATA_DIR))
            except OSError:
                pass
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



# ---------------------------------------------------------------- qBittorrent 客户端
def _qb_conn() -> tuple[str, str, str]:
    """读取 qB 连接参数：配置文件优先，环境变量兜底。"""
    cfg = _get_config()
    url = str(cfg.get(CFG_QB_URL) or os.environ.get("QB_URL") or DEFAULT_QB_URL).strip().rstrip("/")
    user = str(cfg.get(CFG_QB_USERNAME) or os.environ.get("QB_USERNAME") or "").strip()
    pwd = str(cfg.get(CFG_QB_PASSWORD) or os.environ.get("QB_PASSWORD") or "")
    return url, user, pwd


def _qb_http(path: str, data: dict | None = None, cookie: str = "", timeout: int = 8):
    """最小 qB Web API 调用（不引第三方库）。返回 (正文, Set-Cookie)。"""
    url, _user, _pwd = _qb_conn()
    body = urllib.parse.urlencode(data).encode("utf-8") if data else None
    req = urllib.request.Request(url + path, data=body, method="POST" if data else "GET")
    req.add_header("Referer", url)
    req.add_header("Origin", url)
    if body:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace"), resp.headers.get("Set-Cookie", "") or ""


def _qb_login() -> str:
    url, user, pwd = _qb_conn()
    if not user:
        raise RuntimeError("未配置 qBittorrent 账号（自动化页填一下）")
    text, cookie = _qb_http("/api/v2/auth/login", {"username": user, "password": pwd})
    if text.strip() != "Ok.":
        raise RuntimeError("qBittorrent 登录失败：账号或密码不对（或被 IP 封禁）")
    return cookie.split(";")[0].strip()


def _qb_torrents(cookie: str) -> list[dict]:
    text, _ = _qb_http("/api/v2/torrents/info", cookie=cookie)
    try:
        data = json.loads(text or "[]")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _qb_match(torrents: list[dict], names: list[str]) -> list[dict]:
    """按种子名精确匹配（qB 里存的是站点给的原始种子名）。"""
    want = {n.strip() for n in names if n and n.strip()}
    return [t for t in torrents if str(t.get("name") or "").strip() in want]


# HR（Hit & Run）标记：只认 qB 种子标签，标签去掉空格/连字符/& 后比对
HR_TAG_KEYS = ("hr", "hitrun", "hitandrun")
HR_CACHE_TTL = 60.0
_HR_CACHE: dict = {"ts": 0.0, "names": set()}


def _qb_hr_names() -> set:
    """从 qB 种子标签里挑出带 HR 考核的种子名（带 60s 缓存）。"""
    now = time.time()
    if now - float(_HR_CACHE.get("ts") or 0) < HR_CACHE_TTL:
        return _HR_CACHE["names"]
    names: set = set()
    try:
        cookie = _qb_login()
        for t in _qb_torrents(cookie):
            raw = str(t.get("tags") or "")
            for tag in raw.split(","):
                k = tag.strip().lower().replace(" ", "").replace("-", "").replace("&", "")
                if k in HR_TAG_KEYS:
                    nm = str(t.get("name") or "").strip()
                    if nm:
                        names.add(nm)
                    break
    except Exception:
        pass
    _HR_CACHE["ts"] = now
    _HR_CACHE["names"] = names
    return names


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    except Exception:
        pass
    return total


def _pack_path(name: str) -> Path:
    """按资源名定位源目录（合并库模式下它可能在 lib/<分类>/<片名>）。"""
    if not LIB_DIR:
        return _resolved_child_under(DATA_DIR, name)
    for cand in _iter_pack_dirs():
        if cand.name == name:
            return cand
    raise ValueError("资源目录不存在")


def _pack_sub(name: str, disc: str) -> Path:
    """定位合集里的某个碟目录（同样兼容合并库模式）。"""
    return _resolved_child_under(_pack_path(name), disc)


def _targets_for(name: str, disc: str | None) -> dict:
    """算出「源目录 / ISO 产物」的实际路径（全部经 _safe_name 校验）。"""
    src = _pack_sub(name, disc) if disc else _pack_path(name)
    out_paths: list[Path] = []
    seen: set[str] = set()

    def _push(p: Path | None) -> None:
        """按 resolve() 后的真实路径去重，避免同一文件被列两次。"""
        if not p:
            return
        try:
            rp = p.resolve()
        except Exception:
            return
        if not rp.is_relative_to(OUT_DIR.resolve()) or not rp.is_file():
            return
        key = str(rp)
        if key in seen:
            return
        seen.add(key)
        out_paths.append(rp)

    try:
        _push(_find_best_iso_path(name, disc))
    except Exception:
        pass
    for cand in ([OUT_DIR / f"{name}.iso"] if not disc else [OUT_DIR / name / f"{disc}.iso"]):
        _push(cand)
    return {"source": src, "out": out_paths}


@app.get("/api/settings")
def api_settings_get():
    cfg = _get_config()
    return jsonify(
        {
            "ok": True,
            CFG_QB_WEBHOOK_ENABLED: _cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False),
            CFG_QB_AUTO_CONVERT: _cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False),
            CFG_QB_AUTO_ED2K: _cfg_bool(cfg, CFG_QB_AUTO_ED2K, False),
            CFG_QB_URL: str(cfg.get(CFG_QB_URL) or DEFAULT_QB_URL),
            CFG_QB_USERNAME: str(cfg.get(CFG_QB_USERNAME) or ""),
            "qb_has_password": bool(cfg.get(CFG_QB_PASSWORD)),
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
    for key in (CFG_QB_URL, CFG_QB_USERNAME):
        if key in payload:
            cfg[key] = str(payload.get(key) or "").strip()
    if "qb_password" in payload and str(payload.get("qb_password") or ""):
        cfg[CFG_QB_PASSWORD] = str(payload.get("qb_password"))
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
                base_dir = _pack_path(box)
                if not base_dir.is_dir() or not _is_bdmv_root(base_dir):
                    return
                out_iso = _resolved_child_under(OUT_DIR, f"{box}.iso")
                key = _job_key(box)
                src_dir = base_dir
            else:
                src_dir = _pack_sub(box, disc)
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
                base_dir = _pack_path(name2)
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


def _iter_pack_dirs() -> list[Path]:
    """列出待打包的资源目录（单碟或合集）。

    旧模式（未设 LIB_DIR）：DATA_DIR 下的一层子目录，语义与以前完全一致。
    合并库模式：根下第一层视为「分类目录」（原盘/、下载/…），不判为合集；
    资源在第二层 —— 本身是 BDMV 根 → 单碟，其子目录是 BDMV 根 → 合集。
    """
    def visible(x: Path) -> bool:
        return x.is_dir() and not x.name.startswith(".")

    if not LIB_DIR:
        return sorted([x for x in DATA_DIR.iterdir() if visible(x)], key=lambda x: x.name.lower())

    out: list[Path] = []
    for top in sorted([x for x in LIB_DIR.iterdir() if visible(x)], key=lambda x: x.name.lower()):
        if _is_bdmv_root(top):
            out.append(top)
            continue
        for sub in sorted([x for x in top.iterdir() if visible(x)], key=lambda x: x.name.lower()):
            if _is_bdmv_root(sub) or _disc_children(sub):
                out.append(sub)
    return out


def _src_rel(p: Path) -> str:
    """资源目录的显示路径：合并库相对库根（原盘/片名），旧模式相对 ROOT（data/片名）。"""
    base = LIB_DIR if LIB_DIR else ROOT
    try:
        return p.resolve().relative_to(base.resolve()).as_posix()
    except Exception:
        return p.name


def _scan_data_items() -> list[dict]:
    """扫描 data/ 目录并构造资源条目。

    首页渲染与 /api/resources 共用同一份扫描口径，避免两边看到的内容不一致。
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    _prune_stale_jobs_if_output_gone()
    _prune_ed2k_db_missing_files()
    _prune_iso_ed2k_db_missing_files()

    items: list[dict] = []
    hr_names = _qb_hr_names()
    _prune_trash()
    # 合并库模式由 _iter_pack_dirs 负责跳过 .trash 与纯 ISO 目录
    for p in _iter_pack_dirs():
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
                    "src_rel": _src_rel(p),
                    "hr": name in hr_names,
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
                        "hr": d.name in hr_names,
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
                    "src_rel": _src_rel(p),
                    "is_bdmv": True,
                    "hr": any(x.get("hr") for x in disc_rows),
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
                    "src_rel": _src_rel(p),
                    "is_bdmv": False,
                    "hr": False,
                    "out_exists": False,
                    "job": None,
                    "ed2k": None,
                    "persisted_last_output": None,
                    "out_iso_rel": "",
                    "out_iso_bytes": None,
                    "discs": [],
                }
            )

    return items


@app.get("/")
def index():
    items = _scan_data_items()
    engine, engine_note = _pick_local_engine()

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
        lib_mode=bool(LIB_DIR),
        engine=engine,
        engine_note=engine_note,
        qb_webhook_enabled=_cfg_bool(cfg, CFG_QB_WEBHOOK_ENABLED, False),
        qb_auto_convert_iso=_cfg_bool(cfg, CFG_QB_AUTO_CONVERT, False),
        qb_auto_ed2k=_cfg_bool(cfg, CFG_QB_AUTO_ED2K, False),
        qb_url=str(cfg.get(CFG_QB_URL) or DEFAULT_QB_URL),
        qb_username=str(cfg.get(CFG_QB_USERNAME) or ""),
        qb_has_password=bool(cfg.get(CFG_QB_PASSWORD)),
    )


@app.get("/api/resources")
def api_resources():
    """可直接打包的 BDMV 资源目录名列表。

    MoviePilot 的「BDMV自动打包ISO」插件用它与下载任务名比对后自动提交打包。
    走 JSON 接口而不是解析首页 HTML，页面改版不会再把插件带崩。
    """
    items = _scan_data_items()
    resources: list[str] = []
    detail: list[dict] = []
    for it in items:
        if not it.get("is_bdmv"):
            continue
        name = str(it.get("name") or "")
        if not name:
            continue
        if name not in resources:
            resources.append(name)
        detail.append(
            {
                "name": name,
                "kind": it.get("kind") or "",
                "out_exists": bool(it.get("out_exists")),
                "discs": [d.get("name") for d in (it.get("discs") or []) if d.get("name")],
            }
        )
    return jsonify(
        {
            "ok": True,
            "count": len(resources),
            "resources": resources,
            "items": detail,
        }
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
        base_dir = _pack_path(name)
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
            src_dir = _pack_sub(name, disc)
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


@app.post("/api/qb/test")
def api_qb_test():
    try:
        cookie = _qb_login()
        torrents = _qb_torrents(cookie)
        url, user, _ = _qb_conn()
        return jsonify({"ok": True, "url": url, "username": user, "torrents": len(torrents)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/delete")
def api_delete():
    """一键删除：qB 种子 / 源目录 / ISO 产物。dry_run=true 只返回预览清单。"""
    data = request.get_json(silent=True) if request.is_json else None
    payload = data if isinstance(data, dict) else {}
    try:
        name = _safe_name(str(payload.get("name") or ""))
        disc_raw = str(payload.get("disc") or "").strip()
        disc = _safe_name(disc_raw) if disc_raw else None
    except ValueError:
        return jsonify({"ok": False, "error": "名称不合法"}), 400

    dry_run = bool(payload.get("dry_run"))

    # targets 必须显式给出且非空。旧实现用 `payload.get("targets") or [...]`，
    # 空列表是假值 → 静默变成「三项全删」，这是危险缺省，改掉。
    raw_targets = payload.get("targets")
    if raw_targets is None:
        want = ["torrent", "source", "out"]
    elif not isinstance(raw_targets, list) or not raw_targets:
        return jsonify({"ok": False, "error": "未选择任何删除项"}), 400
    else:
        want = [t for t in ("torrent", "source", "out") if t in raw_targets]
        if not want:
            return jsonify({"ok": False, "error": "删除项不合法"}), 400

    # 只有「真的在跑」才拦。旧实现判断的是 key 是否存在，而任务完成后
    # Job 仍留在 JOBS 里（用于 /api/status），于是任何已完成的任务都被误判成
    # 「任务正在运行」，网页端删除永远失败。
    key = _job_key(name, disc)
    busy_status = ("running", "pending", "queued")
    with JOBS_LOCK:
        busy = [
            k for k, j in JOBS.items()
            if (k == key or (disc is None and k.startswith(f"{name}::")))
            and str(getattr(j, "status", "")) in busy_status
        ]
    if busy:
        return jsonify({"ok": False, "error": "任务正在运行，先停止再删除", "running": busy}), 409

    t = _targets_for(name, disc)
    src: Path = t["source"]
    outs: list[Path] = t["out"]

    # 种子名：单碟用种子名，合集用各碟目录名；都拿不到就用合集名
    seed_names = [disc] if disc else [name]
    torrent_hits: list[dict] = []
    torrent_err = ""
    if "torrent" in want:
        try:
            cookie = _qb_login()
            torrent_hits = _qb_match(_qb_torrents(cookie), seed_names)
        except Exception as exc:
            torrent_err = str(exc)

    plan = {
        "ok": True,
        "dry_run": True,
        "name": name,
        "disc": disc,
        "items": [
            {
                "key": "torrent",
                "label": "qBittorrent 种子",
                "note": "只移除种子，qB 里已下载的文件不动（文件由本服务自己删）",
                "exists": bool(torrent_hits),
                "detail": torrent_err or "%d 个种子：%s" % (
                    len(torrent_hits), "、".join(str(x.get("name")) for x in torrent_hits[:3])),
                "names": [str(x.get("name")) for x in torrent_hits],
                "size": sum(int(x.get("size") or 0) for x in torrent_hits),
            },
            {
                "key": "source",
                "label": "源目录",
                "note": "整个目录递归删除 · 不可恢复" if src.exists() else "不存在",
                "exists": src.exists(),
                "detail": str(src.relative_to(ROOT)),
                "size": _dir_size(src) if src.exists() else 0,
            },
            {
                "key": "out",
                "label": "ISO 产物",
                "note": "文件删除 · 不可恢复" if outs else "未找到",
                "exists": bool(outs),
                "detail": "、".join(str(p.relative_to(ROOT)) for p in outs),
                "size": sum(p.stat().st_size for p in outs if p.exists()),
            },
        ],
    }
    if dry_run:
        return jsonify(plan)

    done: list[str] = []
    errors: list[str] = []

    if "torrent" in want:
        if torrent_err:
            errors.append("种子：" + torrent_err)
        elif torrent_hits:
            try:
                cookie = _qb_login()
                hashes = "|".join(str(x.get("hash")) for x in torrent_hits if x.get("hash"))
                _qb_http("/api/v2/torrents/delete", {"hashes": hashes, "deleteFiles": "false"}, cookie=cookie)
                done.append("种子 %d 个" % len(torrent_hits))
            except Exception as exc:
                errors.append("种子删除失败：" + str(exc))

    # 直接删除（不进回收站）：用户明确要求删除即释放空间。
    # 安全边界：必须落在 DATA_DIR 之内、且不能是 DATA_DIR 本身。
    if "source" in want and src.exists():
        try:
            if not src.resolve().is_relative_to(DATA_DIR.resolve()) or src.resolve() == DATA_DIR.resolve():
                raise RuntimeError("路径越界，已拒绝")
            shutil.rmtree(src)
            done.append("源目录已删除")
        except Exception as exc:
            errors.append("源目录删除失败：" + str(exc))

    if "out" in want:
        moved = 0
        for p in outs:
            try:
                if p.resolve().is_relative_to(OUT_DIR.resolve()) and p.is_file():
                    p.unlink()
                    moved += 1
            except Exception as exc:
                errors.append("ISO 删除失败：" + str(exc))
        if moved:
            done.append("ISO %d 个已删除" % moved)

    # 清掉对应的 ed2k 缓存与任务记录
    try:
        if disc is None:
            db = _load_ed2k_db()
            for k in [k for k in db.keys() if k == name or k.startswith(f"{name}/")]:
                db.pop(k, None)
            _save_ed2k_db(db)
    except Exception:
        pass
    with JOBS_LOCK:
        for k in list(JOBS.keys()):
            if k == key or (disc is None and k.startswith(f"{name}::")):
                JOBS.pop(k, None)

    return jsonify({"ok": not errors, "done": done, "errors": errors})



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


@app.post("/api/iso_delete")
def api_iso_delete():
    """删除 ISO 库里的镜像文件（直接删除，不进回收站）。"""
    ISO_DIR.mkdir(parents=True, exist_ok=True)
    payload: dict = {}
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payload.update(data)
    if request.form:
        payload.update({k: v for k, v in request.form.items()})

    rel = (payload.get("file") or "").strip()
    try:
        target = _resolved_iso_path(rel)
    except ValueError:
        return jsonify({"ok": False, "error": "目标文件非法"}), 400

    if not target.is_file() or target.suffix.lower() != ".iso":
        return jsonify({"ok": False, "error": "文件不存在或不是 ISO"}), 404

    size = 0
    try:
        size = int(target.stat().st_size)
    except OSError:
        pass

    try:
        target.unlink()
    except Exception as exc:
        return jsonify({"ok": False, "error": f"删除失败：{exc}"}), 500

    # 清掉 ed2k 缓存记录
    try:
        key = _iso_rel_key(target)
        with ISO_ED2K_DB_LOCK:
            db = _load_iso_ed2k_db()
            items = db.get("items")
            if isinstance(items, dict) and key in items:
                items.pop(key, None)
                db["items"] = items
                _save_iso_ed2k_db(db)
    except Exception:
        pass

    return jsonify({"ok": True, "size": size})


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
