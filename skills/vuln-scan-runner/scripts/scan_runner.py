#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_runner — 授权制漏洞扫描编排器。

只调用本机已安装的白名单工具；执行前强制校验授权范围；异常时自动进入应急响应。

零依赖，只用 Python 3 标准库。

用法:
    python scan_runner.py --scope scope.json --target https://app.example.com \
        --tool nuclei --authorized --confirm "项目名"
    python scan_runner.py --scope scope.json --target 10.10.0.8 --tool nmap \
        --profile ports --dry-run --authorized --confirm "项目名"
    python scan_runner.py --list-tools
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"
RUNS_ROOT = ROOT / ".runs"

TOOL_PROFILES = {
    "nmap": {"discovery", "ports", "service"},
    "nuclei": {"safe"},
    "nikto": {"safe"},
    "whatweb": {"safe"},
}
ERROR_PATTERNS = (
    "panic:",
    "fatal error:",
    "out of memory",
    "too many open files",
    "segmentation fault",
    "stack overflow",
)


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt


def host_of(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    elif raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            raw = raw[1:end]
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    return raw.rstrip(".").lower()


def match_rule(target: str, rule: str) -> bool:
    rule = rule.strip().rstrip(".").lower()
    try:
        network = ipaddress.ip_network(rule, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    if rule.startswith("*."):
        suffix = rule[2:]
        return target.endswith("." + suffix) and target != suffix
    return target == rule


def find_match(target: str, rules):
    for rule in rules:
        if match_rule(target, rule):
            return rule
    return None


def load_scope(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ValueError(f"无法读取 scope 文件: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"scope JSON 解析失败: 第 {exc.lineno} 行 {exc.msg}")
    if not isinstance(data, dict):
        raise ValueError("scope 根节点必须是对象")
    for field in ("engagement", "authorized_by", "targets", "allowed_tools", "window"):
        if not data.get(field):
            raise ValueError(f"scope 缺少 {field}")
    if not data["window"].get("start") or not data["window"].get("end"):
        raise ValueError("scope 缺少 window.start / window.end")
    return data


def check_authorization(scope, target, tool, confirm, authorized, at=None):
    reasons = []
    if not authorized:
        reasons.append("未提供 --authorized，视为未获得授权")
    if confirm != scope.get("engagement"):
        reasons.append("--confirm 与 scope.engagement 不一致，疑似拿错授权文件")

    window = scope["window"]
    start, end = parse_time(window["start"]), parse_time(window["end"])
    current = at or datetime.now().astimezone()
    if not (start <= current <= end):
        reasons.append(f"当前时间 {current.isoformat()} 不在授权窗口内")

    host = host_of(target)
    excluded = find_match(host, scope.get("excludes") or [])
    if excluded:
        reasons.append(f"目标 {host} 命中排除项 {excluded}")
    elif not find_match(host, scope["targets"]):
        reasons.append(f"目标 {host} 未命中任何授权目标")

    if tool not in (scope.get("allowed_tools") or []):
        reasons.append(f"工具 {tool} 不在授权工具列表内")

    return reasons


def validate_target(tool, target):
    if any(ch in target for ch in (" ", "\n", "\r", "\t")):
        raise ValueError("target 包含空白字符")
    if tool == "nmap":
        host = host_of(target)
        try:
            ipaddress.ip_network(host, strict=False)
        except ValueError:
            if not host or "." not in host:
                raise ValueError("nmap 目标需要是域名、IP 或 CIDR")
        return host
    if "://" not in target:
        raise ValueError(f"{tool} 目标需要包含 http:// 或 https://")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"{tool} 目标 URL 无效: {target}")
    return target


def build_command(tool, target, profile, rate, output_file: Path):
    if profile not in TOOL_PROFILES[tool]:
        raise ValueError(f"{tool} 不支持 profile: {profile}")
    rate = max(1, min(int(rate), 200))

    if tool == "nmap":
        host = validate_target(tool, target)
        args = ["nmap"]
        if profile == "discovery":
            args += ["-sn"]
        elif profile == "service":
            args += ["-sT", "-Pn", "-sV", "--top-ports", "100"]
        else:
            args += ["-sT", "-Pn", "--top-ports", "100"]
        args += ["--max-rate", str(rate), "-oN", str(output_file), host]
        return args
    if tool == "nuclei":
        url = validate_target(tool, target)
        return [
            "nuclei", "-u", url,
            "-severity", "low,medium,high,critical",
            "-rate-limit", str(rate), "-no-color", "-silent", "-jsonl",
            "-o", str(output_file),
        ]
    if tool == "nikto":
        url = validate_target(tool, target)
        return [
            "nikto", "-host", url, "-maxtime", "300", "-Pause", "1",
            "-nointeractive", "-output", str(output_file), "-Format", "txt",
        ]
    if tool == "whatweb":
        url = validate_target(tool, target)
        return ["whatweb", "--color=never", "--no-errors", "-a", "1", url]
    raise ValueError(f"不支持的工具: {tool}")


def display_command(cmd):
    if sys.platform == "win32":
        return subprocess.list2cmdline(cmd)
    return shlex.join(cmd)


def make_run_dir(tool):
    RUNS_ROOT.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = RUNS_ROOT / f"{stamp}-{tool}"
    suffix = 2
    while run_dir.exists():
        run_dir = RUNS_ROOT / f"{stamp}-{tool}-{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True)
    return run_dir


def write_incident(run_dir: Path, scope, manifest, reason):
    escalation = scope.get("escalation") or {}
    incident = {
        "status": "open",
        "triggered_at": now_iso(),
        "reason": reason,
        "tool": manifest["tool"],
        "target": manifest["target"],
        "command": manifest["command"],
        "run_dir": str(run_dir),
        "escalation": {
            "primary": escalation.get("primary") or "未填写",
            "secondary": escalation.get("secondary") or "未填写",
            "phone": escalation.get("phone") or "未填写",
        },
        "timeline": [
            {"at": manifest["started_at"], "event": "扫描启动"},
            {"at": now_iso(), "event": f"触发应急响应: {reason}"},
        ],
    }
    (run_dir / "incident.json").write_text(
        json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    steps = [
        "# 应急响应记录",
        "",
        f"- 状态：open",
        f"- 触发时间：{incident['triggered_at']}",
        f"- 触发原因：{reason}",
        f"- 目标：{manifest['target']}",
        f"- 工具：{manifest['tool']}",
        f"- 完整命令：`{display_command(manifest['command'])}`",
        "",
        "## 现场文件",
        "",
        "- manifest.json",
        "- stdout.log / stderr.log",
        "- 工具输出文件",
        "",
        "## 五步处置",
        "",
        "1. **立即停止**：已终止扫描进程，不再发起新请求",
        "2. **保留现场**：本目录即现场，请勿删除",
        "3. **评估影响**：确认目标业务是否异常、是否触及范围外资产",
        f"4. **通知授权方**：15 分钟内联系 {incident['escalation']['primary']}",
        f"5. **无法解决则上报**：30 分钟内升级到 {incident['escalation']['secondary']}",
        "",
        "## 上报命令",
        "",
        "```bash",
        f"python scripts/incident.py --escalate {run_dir.as_posix()} "
        f'--reason "具体原因" --to "{incident["escalation"]["secondary"]}"',
        "```",
        "",
        "## 时间线",
        "",
    ]
    for item in incident["timeline"]:
        steps.append(f"- {item['at']} {item['event']}")
    (run_dir / "incident.md").write_text("\n".join(steps) + "\n", encoding="utf-8")
    return incident


def print_incident_banner(incident, run_dir):
    print("\n" + "=" * 64, file=sys.stderr)
    print("[INCIDENT] 扫描异常，已进入应急响应流程", file=sys.stderr)
    print(f"原因: {incident['reason']}", file=sys.stderr)
    print(f"现场: {run_dir}", file=sys.stderr)
    print("五步处置:", file=sys.stderr)
    print("  1. 已自动停止扫描", file=sys.stderr)
    print("  2. 保留运行目录，不要删除", file=sys.stderr)
    print("  3. 评估目标业务影响与是否越界", file=sys.stderr)
    print(f"  4. 15 分钟内通知: {incident['escalation']['primary']}", file=sys.stderr)
    print(f"  5. 30 分钟内无法解决则上报: {incident['escalation']['secondary']}", file=sys.stderr)
    print("=" * 64 + "\n", file=sys.stderr)


def list_tools():
    print(f"vuln-scan-runner {get_version()} · 工具可用性\n")
    for tool, profiles in TOOL_PROFILES.items():
        path = shutil.which(tool)
        status = path or "未安装"
        print(f"- {tool}: {status}  (profiles: {', '.join(sorted(profiles))})")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="授权制漏洞扫描编排器")
    parser.add_argument("--scope", help="scope JSON 文件")
    parser.add_argument("--target", help="扫描目标：域名 / IP / CIDR / URL")
    parser.add_argument("--tool", choices=sorted(TOOL_PROFILES), help="扫描工具")
    parser.add_argument("--profile", default="safe", help="扫描档位，默认 safe")
    parser.add_argument("--rate", type=int, default=50, help="速率上限，默认 50，最大 200")
    parser.add_argument("--timeout", type=int, default=600, help="单次扫描超时秒数，默认 600")
    parser.add_argument("--authorized", action="store_true", help="声明已获得书面授权")
    parser.add_argument("--confirm", help="输入 scope.engagement 以确认授权文件匹配")
    parser.add_argument("--dry-run", action="store_true", help="只打印命令，不执行")
    parser.add_argument("--at", help="指定校验时间（ISO 8601），默认当前时间")
    parser.add_argument("--list-tools", action="store_true", help="列出工具可用性")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    if args.list_tools:
        list_tools()
        return 0

    if not (args.scope and args.target and args.tool):
        print("[!] 需要 --scope、--target、--tool", file=sys.stderr)
        return 2

    try:
        scope = load_scope(Path(args.scope))
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    try:
        at = parse_time(args.at) if args.at else None
    except ValueError:
        print(f"[!] --at 时间格式无效: {args.at}", file=sys.stderr)
        return 2

    reasons = check_authorization(
        scope, args.target, args.tool, args.confirm, args.authorized, at,
    )
    if reasons:
        print("[DENY] 授权校验未通过，未执行任何扫描：", file=sys.stderr)
        for reason in reasons:
            print(f"  - {reason}", file=sys.stderr)
        return 3

    try:
        if args.dry_run:
            placeholder = Path("<run_dir>/scan.txt")
            command = build_command(args.tool, args.target, args.profile, args.rate, placeholder)
        else:
            run_dir = make_run_dir(args.tool)
            command = build_command(
                args.tool, args.target, args.profile, args.rate, run_dir / "scan.txt",
            )
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    binary = shutil.which(args.tool)
    print(f"vuln-scan-runner {get_version()}")
    print(f"授权方: {scope['authorized_by']}")
    print(f"项目: {scope['engagement']}")
    print(f"目标: {args.target}")
    print(f"命令: {display_command(command)}")

    if args.dry_run:
        print(f"工具: {binary or '未安装（正式执行会失败）'}")
        print("[DRY-RUN] 未执行扫描")
        return 0

    if not binary:
        print(f"[!] 工具未安装: {args.tool}", file=sys.stderr)
        return 2

    manifest = {
        "engagement": scope["engagement"],
        "authorized_by": scope["authorized_by"],
        "target": args.target,
        "tool": args.tool,
        "profile": args.profile,
        "rate": args.rate,
        "command": command,
        "scope_file": str(Path(args.scope).resolve()),
        "started_at": now_iso(),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"[RUN] {run_dir}")
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=args.timeout,
            encoding="utf-8", errors="replace",
        )
        stdout, stderr, returncode = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        (run_dir / "stderr.log").write_text("", encoding="utf-8")
        manifest["finished_at"] = now_iso()
        incident = write_incident(run_dir, scope, manifest, f"扫描超时（{args.timeout}s）")
        print_incident_banner(incident, run_dir)
        return 4
    except KeyboardInterrupt:
        incident = write_incident(run_dir, scope, manifest, "操作员中断")
        print_incident_banner(incident, run_dir)
        return 4
    except OSError as exc:
        incident = write_incident(run_dir, scope, manifest, f"无法启动工具: {exc}")
        print_incident_banner(incident, run_dir)
        return 4

    (run_dir / "stdout.log").write_text(stdout, encoding="utf-8")
    (run_dir / "stderr.log").write_text(stderr, encoding="utf-8")
    manifest["returncode"] = returncode
    manifest["finished_at"] = now_iso()

    combined = (stdout + "\n" + stderr).lower()
    hit_pattern = next((p for p in ERROR_PATTERNS if p in combined), None)

    if returncode != 0 or hit_pattern:
        reason = f"工具退出码 {returncode}" if returncode != 0 else f"输出包含异常关键字: {hit_pattern}"
        incident = write_incident(run_dir, scope, manifest, reason)
        manifest["status"] = "incident"
        (run_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print_incident_banner(incident, run_dir)
        return 4

    manifest["status"] = "completed"
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[OK] 扫描完成，输出目录: {run_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
