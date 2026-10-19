#!/usr/bin/env python3
from __future__ import annotations

import argparse


def main() -> int:
    ap = argparse.ArgumentParser(description="bdmvtoiso 入口（默认启动 Web UI）")
    ap.add_argument(
        "cmd",
        nargs="?",
        default="ui",
        choices=["ui"],
        help="子命令（目前仅 ui）",
    )
    ap.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    ap.add_argument("--port", type=int, default=5173, help="监听端口（默认 5173）")
    ap.add_argument("--no-debug", action="store_true", help="关闭 debug")
    args = ap.parse_args()

    if args.cmd == "ui":
        from ui_app import main as ui_main

        return int(ui_main(host=args.host, port=args.port, debug=(not args.no_debug)) or 0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
