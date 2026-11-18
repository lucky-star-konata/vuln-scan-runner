#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""incident — 查看与上报漏扫应急事件。

用法:
    python incident.py --list
    python incident.py --escalate .runs/20261118-153000-nuclei \
        --reason "目标业务异常，30 分钟未恢复" --to "项目负责人"
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"
RUNS_ROOT = ROOT / ".runs"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_incident(run_dir: Path):
    path = run_dir / "incident.json"
    if not path.is_file():
        raise ValueError(f"未找到事件文件: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"事件文件解析失败: {exc}")


def list_incidents():
    if not RUNS_ROOT.is_dir():
        print("暂无运行记录（.runs 不存在）")
        return 0
    items = sorted(RUNS_ROOT.glob("*/incident.json"))
    if not items:
        print("暂无应急事件")
        return 0
    print(f"vuln-scan-runner {get_version()} · 应急事件\n")
    for path in items:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        print(f"- [{data.get('status', 'unknown')}] {path.parent.name}")
        print(f"    时间: {data.get('triggered_at', '未知')}")
        print(f"    目标: {data.get('target', '未知')}  工具: {data.get('tool', '未知')}")
        print(f"    原因: {data.get('reason', '未填写')}")
        if data.get("escalated_to"):
            print(f"    已上报: {data['escalated_to']} @ {data.get('escalated_at')}")
    return 0


def escalate(run_dir: Path, reason: str, target: str):
    incident = load_incident(run_dir)
    if incident.get("status") == "escalated":
        print(f"[!] 该事件已上报，接收人: {incident.get('escalated_to')}", file=sys.stderr)
        return 1

    incident["status"] = "escalated"
    incident["escalated_at"] = now_iso()
    incident["escalated_to"] = target
    incident["escalate_reason"] = reason
    incident.setdefault("timeline", []).append({
        "at": incident["escalated_at"],
        "event": f"上报至 {target}: {reason}",
    })

    (run_dir / "incident.json").write_text(
        json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    with open(run_dir / "incident.md", "a", encoding="utf-8") as handle:
        handle.write("\n## 上报记录\n\n")
        handle.write(f"- 时间：{incident['escalated_at']}\n")
        handle.write(f"- 上报对象：{target}\n")
        handle.write(f"- 原因：{reason}\n")
        handle.write("- 状态：escalated\n")

    print(f"[OK] 已上报: {run_dir.name} -> {target}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="查看或上报漏扫应急事件")
    parser.add_argument("--list", action="store_true", help="列出所有应急事件")
    parser.add_argument("--escalate", metavar="RUN_DIR", help="上报指定运行目录的事件")
    parser.add_argument("--reason", default="", help="上报原因")
    parser.add_argument("--to", default="", help="上报对象")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    if args.list:
        return list_incidents()

    if args.escalate:
        if not args.reason or not args.to:
            print("[!] --escalate 需要同时提供 --reason 和 --to", file=sys.stderr)
            return 2
        run_dir = Path(args.escalate)
        if not run_dir.is_absolute():
            run_dir = (Path.cwd() / run_dir).resolve()
        try:
            return escalate(run_dir, args.reason, args.to)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    print("[!] 使用 --list 或 --escalate", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
