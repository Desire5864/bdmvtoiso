#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class BdmvToIsoError(RuntimeError):
    pass


_GENISO_WRAPPER = "/usr/local/bin/bdmv-genisoimage"


def _is_bdmv_root(dir_path: Path) -> bool:
    bdmv = dir_path / "BDMV"
    return (bdmv / "index.bdmv").is_file() and (bdmv / "MovieObject.bdmv").is_file()


def _default_volid(src_dir: Path) -> str:
    s = src_dir.name.upper()
    s = "".join(ch if ("A" <= ch <= "Z") or ("0" <= ch <= "9") or (ch == "_") else "_" for ch in s)
    s = s.strip("_") or "BLURAY"
    return s[:32]


def _geniso_family_executable() -> str | None:
    if Path(_GENISO_WRAPPER).is_file():
        return _GENISO_WRAPPER
    for p in ("/usr/bin/genisoimage", "/bin/genisoimage"):
        if Path(p).is_file():
            return p
    return shutil.which("genisoimage") or shutil.which("mkisofs")


def _mkisofs_family_supports_udfver(tool: str) -> bool:
    proc = subprocess.run([tool, "-help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return "-udfver" in out


def _run_mkisofs_family(src_dir: Path, out_iso: Path, volid: str) -> None:
    tool = _geniso_family_executable()
    xorriso = shutil.which("xorriso")

    cmd: list[str] | None = None
    if tool:
        if tool == _GENISO_WRAPPER:
            cmd = [
                tool,
                "-udf",
                "-V",
                volid,
                "-o",
                str(out_iso),
                "-graft-points",
                f"BDMV={src_dir / 'BDMV'}",
            ]
            probe = "/usr/bin/genisoimage" if Path("/usr/bin/genisoimage").is_file() else tool
        else:
            cmd = [
                tool,
                "-iso-level",
                "3",
                "-allow-limited-size",
                "-input-charset",
                "utf-8",
                "-quiet",
                "-udf",
                "-V",
                volid,
                "-o",
                str(out_iso),
                "-graft-points",
                f"BDMV={src_dir / 'BDMV'}",
            ]
            probe = tool
        if _mkisofs_family_supports_udfver(probe):
            insert_at = cmd.index("-udf") + 1
            cmd[insert_at:insert_at] = ["-udfver", "2.50"]
        if (src_dir / "CERTIFICATE").is_dir():
            cmd.append(f"CERTIFICATE={src_dir / 'CERTIFICATE'}")
    elif xorriso:
        cmd = [
            xorriso,
            "-outdev",
            str(out_iso),
            "-map",
            str(src_dir / "BDMV"),
            "/BDMV",
        ]
        if (src_dir / "CERTIFICATE").is_dir():
            cmd += ["-map", str(src_dir / "CERTIFICATE"), "/CERTIFICATE"]

    if not cmd:
        raise BdmvToIsoError("未找到 mkisofs/genisoimage（推荐）或 xorriso，无法使用外部工具生成 ISO。")

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        quoted = " ".join(shlex.quote(c) for c in cmd)
        out = proc.stdout or ""
        if len(out) > 16000:
            out = "…(工具输出过长，仅保留末尾)…\n" + out[-16000:]
        raise BdmvToIsoError(
            f"外部工具生成 ISO 失败（exit={proc.returncode}）:\n{out}\n实际命令：{quoted}"
        )


def _run_hdiutil(src_dir: Path, out_iso: Path, volid: str) -> None:
    hdiutil = shutil.which("hdiutil")
    if not hdiutil:
        raise BdmvToIsoError("未找到 macOS 的 hdiutil。")

    cmd = [
        hdiutil,
        "makehybrid",
        "-udf",
        "-udf-volume-name",
        volid,
        "-o",
        str(out_iso),
        str(src_dir),
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise BdmvToIsoError(f"hdiutil 生成 ISO 失败（exit={proc.returncode}）:\n{proc.stdout}")


@dataclass(frozen=True)
class _Entry:
    src: Path
    udf_path: str
    is_dir: bool


def _collect_entries(src_dir: Path) -> list[_Entry]:
    roots: list[Path] = [src_dir / "BDMV"]
    if (src_dir / "CERTIFICATE").is_dir():
        roots.append(src_dir / "CERTIFICATE")

    entries: list[_Entry] = []
    for root in roots:
        entries.append(_Entry(src=root, udf_path=f"/{root.name}", is_dir=True))
        for p in root.rglob("*"):
            rel = p.relative_to(src_dir)
            udf_path = "/" + "/".join(rel.parts)
            entries.append(_Entry(src=p, udf_path=udf_path, is_dir=p.is_dir()))

    entries.sort(key=lambda e: (not e.is_dir, e.udf_path))
    return entries


def _run_pycdlib(src_dir: Path, out_iso: Path, volid: str) -> None:
    try:
        import pycdlib
    except Exception as e:
        raise BdmvToIsoError(f"未安装 pycdlib（{e}）。可先 `python -m pip install -r requirements.txt`。")

    iso = pycdlib.PyCdlib()
    iso.new(udf="2.60", vol_ident=volid)

    for entry in _collect_entries(src_dir):
        if entry.is_dir:
            if entry.udf_path == f"/{entry.src.name}":
                pass
            try:
                iso.add_directory(udf_path=entry.udf_path)
            except Exception:
                continue
        else:
            with entry.src.open("rb") as fp:
                try:
                    iso.add_fp(fp, len(entry.src.stat().st_size), udf_path=entry.udf_path)
                except Exception as e:
                    raise BdmvToIsoError(f"写入失败：{entry.udf_path}（{entry.src}）: {e}")

    out_iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write(str(out_iso))
    iso.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="把 BDMV 目录打包为 Blu-ray (UDF 2.50) ISO")
    ap.add_argument("src_dir", type=Path, help="包含 BDMV/（以及可选 CERTIFICATE/）的目录")
    ap.add_argument("-o", "--out", type=Path, default=None, help="输出 ISO 路径（默认：<src_dir>.iso）")
    ap.add_argument("--volid", default=None, help="卷标（默认：从目录名生成，最多 32 字符）")
    ap.add_argument(
        "--engine",
        choices=["auto", "xorriso", "hdiutil", "pycdlib"],
        default="auto",
        help="生成引擎：auto（优先 mkisofs/genisoimage，其次 hdiutil）/ xorriso（同 auto 的 UDF 工具链）/ hdiutil / pycdlib(UDF2.60)",
    )
    args = ap.parse_args(argv)

    src_dir = args.src_dir.expanduser().resolve()
    if not src_dir.is_dir():
        raise BdmvToIsoError(f"目录不存在：{src_dir}")
    if not _is_bdmv_root(src_dir):
        raise BdmvToIsoError(f"这看起来不是 BDMV 根目录（未找到 BDMV/index.bdmv 等）：{src_dir}")

    out_iso = (args.out or src_dir.with_suffix(".iso")).expanduser().resolve()
    volid = (args.volid or _default_volid(src_dir)).upper()

    if out_iso.exists():
        raise BdmvToIsoError(f"输出已存在：{out_iso}")

    engine = args.engine
    if engine == "auto":
        if _geniso_family_executable() or shutil.which("xorriso"):
            engine = "xorriso"
        elif shutil.which("hdiutil"):
            engine = "hdiutil"
        else:
            engine = "pycdlib"

    if engine == "xorriso":
        _run_mkisofs_family(src_dir, out_iso, volid)
    elif engine == "hdiutil":
        _run_hdiutil(src_dir, out_iso, volid)
    else:
        _run_pycdlib(src_dir, out_iso, volid)

    print(f"OK: {out_iso}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BdmvToIsoError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
