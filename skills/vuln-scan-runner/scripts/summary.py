#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""summary — 汇总 .runs 下的扫描记录与应急事件。

用法:
    python summary.py
    python summary.py --runs .runs --out summary.md
    python summary.py --json
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

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_LABEL = {
    "critical": "严重", "high": "高危", "medium": "中危",
    "low": "低危", "info": "信息", "unknown": "未知",
}


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def count_nuclei(run_dir: Path):
    path = run_dir / "scan.txt"
    counts = {level: 0 for level in SEVERITY_ORDER}
    if not path.is_file():
        return counts, 0
    total = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = str((item.get("info") or {}).get("severity", "unknown")).lower()
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
        total += 1
    return counts, total


def summarize_result(tool: str, run_dir: Path):
    if tool == "nuclei":
        path = run_dir / "scan.txt"
        if not path.is_file():
            return {"total": 0, "counts": {}, "text": "无输出"}
        counts, total = count_nuclei(run_dir)
        parts = [f"{SEVERITY_LABEL[level]} {counts[level]}"
                 for level in SEVERITY_ORDER if counts[level]]
        return {
            "total": total,
            "counts": counts,
            "text": "、".join(parts) if parts else "无命中",
        }
    if tool == "nmap":
        path = run_dir / "scan.txt"
        if not path.is_file():
            return {"total": 0, "counts": {}, "text": "无输出"}
        ports = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and "/" in parts[0] and parts[1] == "open":
                ports += 1
        return {"total": ports, "counts": {"open_ports": ports}, "text": f"开放端口 {ports}"}
    if tool == "nikto":
        path = run_dir / "scan.txt"
        if not path.is_file():
            return {"total": 0, "counts": {}, "text": "无输出"}
        items = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("+ "):
                items += 1
        return {"total": items, "counts": {"items": items}, "text": f"条目 {items}"}
    if tool == "whatweb":
        path = run_dir / "stdout.log"
        if not path.is_file():
            return {"total": 0, "counts": {}, "text": "无输出"}
        lines = len([ln for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()])
        return {"total": lines, "counts": {"fingerprint_lines": lines}, "text": f"指纹行 {lines}"}
    return {"total": 0, "counts": {}, "text": "-"}


def load_runs(runs_root: Path):
    runs = []
    incidents = []
    for manifest_path in sorted(runs_root.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        run_dir = manifest_path.parent
        tool = manifest.get("tool", "unknown")
        item = {
            "dir": run_dir.name,
            "tool": tool,
            "target": manifest.get("target", ""),
            "status": manifest.get("status", "unknown"),
            "started_at": manifest.get("started_at", ""),
            "finished_at": manifest.get("finished_at", ""),
            "returncode": manifest.get("returncode"),
            "result": summarize_result(tool, run_dir),
        }
        runs.append(item)

        incident_path = run_dir / "incident.json"
        if incident_path.is_file():
            try:
                incident = json.loads(incident_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            incidents.append({
                "dir": run_dir.name,
                "status": incident.get("status", "unknown"),
                "triggered_at": incident.get("triggered_at", ""),
                "tool": incident.get("tool", tool),
                "target": incident.get("target", ""),
                "reason": incident.get("reason", ""),
                "escalated_to": incident.get("escalated_to", ""),
            })
    runs.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return runs, incidents


def build_markdown(runs, incidents):
    lines = [
        "# 漏扫运行汇总",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 运行总数：{len(runs)}",
        f"- 应急事件：{len(incidents)}",
        "",
        "## 运行记录",
        "",
        "| 开始时间 | 工具 | 目标 | 状态 | 结果 | 目录 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in runs:
        lines.append(
            f"| {item['started_at']} | {item['tool']} | {item['target']} "
            f"| {item['status']} | {item['result']['text']} | {item['dir']} |"
        )
    if not runs:
        lines.append("| - | - | - | 无记录 | - | - |")

    lines += ["", "## 应急事件", ""]
    if incidents:
        lines += [
            "| 时间 | 状态 | 工具 | 目标 | 原因 | 上报对象 | 目录 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for item in incidents:
            lines.append(
                f"| {item['triggered_at']} | {item['status']} | {item['tool']} "
                f"| {item['target']} | {item['reason']} | {item['escalated_to'] or '-'} | {item['dir']} |"
            )
    else:
        lines.append("无应急事件。")
    lines += ["", "> 结果计数为工具原始输出统计，是否构成漏洞需人工复核。"]
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="汇总漏扫运行记录与应急事件")
    parser.add_argument("--runs", default=str(RUNS_ROOT), help="运行记录目录，默认 .runs")
    parser.add_argument("--out", help="输出 Markdown 路径，默认 <runs>/summary.md")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    runs_root = Path(args.runs)
    if not runs_root.is_dir():
        print(f"[!] 运行目录不存在: {runs_root}", file=sys.stderr)
        return 2

    runs, incidents = load_runs(runs_root)
    if not runs:
        print(f"[!] {runs_root} 下没有 manifest.json 记录", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "runs": runs,
            "incidents": incidents,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }, ensure_ascii=False, indent=2))
        return 0

    markdown = build_markdown(runs, incidents)
    out = Path(args.out) if args.out else runs_root / "summary.md"
    out.write_text(markdown, encoding="utf-8")
    print(f"[OK] {len(runs)} runs, {len(incidents)} incidents -> {out}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
