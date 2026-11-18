---
name: vuln-scan-runner
description: Run authorized vulnerability scans with locally installed tools. Use when planning or executing an nmap, nuclei, or nikto scan, when you must verify authorization and scope before scanning, or when a scan errors out and needs incident response and escalation.
---

# vuln-scan-runner

在授权范围内调用本机扫描工具，执行前过授权闸门，运行异常自动进入应急响应。

## 何时使用

- 需要对某个已授权目标做端口或漏洞扫描
- 不确定目标是否在范围内，想在执行前确认
- 扫描工具报错 / 超时 / 崩溃，需要按流程停下来处置
- 需要保留每次扫描的命令、输出和时间线

## 前置条件（缺一不可）

1. 书面授权，范围覆盖目标、时间窗口和要用的工具
2. `scope.json` 已填写 `authorized_by`、`targets`、`window`、`allowed_tools`
3. 本机已安装对应工具，脚本只编排、不代装

## 授权闸门

执行必须同时满足：

- 传了 `--authorized`
- `--confirm` 与 `scope.engagement` 完全一致
- 目标命中 `targets`，且不命中 `excludes`
- 当前时间在 `window` 内
- 工具在 `allowed_tools` 内

任何一项不满足都拒绝执行，退出码 3，不发起任何网络操作。

## 标准流程

1. **填范围**：复制 `templates/scope.example.json` 为 `scope.json`，填授权方、目标、窗口、工具、上报联系人
2. **预览**：`--dry-run` 查看将要执行的完整命令
3. **执行**：确认无误后正式运行，运行目录自动落盘
4. **判读**：按工具输出人工确认，不把原始告警直接当结论
5. **收尾**：异常走应急响应；正常则归档运行目录

## 命令

```bash
python scripts/scan_runner.py --scope scope.json --target https://app.example.com \
  --tool nuclei --authorized --confirm "项目名"

python scripts/scan_runner.py --scope scope.json --target 10.10.0.8 \
  --tool nmap --profile ports --rate 50 --dry-run --authorized --confirm "项目名"

python scripts/scan_runner.py --list-tools
```

| 工具 | profile | 说明 |
| --- | --- | --- |
| `nmap` | `discovery` / `ports` | 主机发现；前 100 端口 TCP 连接扫描 |
| `nuclei` | `safe` | 默认模板，限速 |
| `nikto` | `safe` | Web 服务器检查，带暂停间隔 |

## 应急响应（五步）

运行异常时脚本自动执行第 1–2 步并生成报告：

1. **立即停止**：终止子进程，不再发起新请求
2. **保留现场**：运行目录内保留命令、stdout、stderr、时间线
3. **评估影响**：确认目标业务是否异常、是否触及范围外资产
4. **通知授权方**：15 分钟内联系 `scope.escalation.primary`
5. **无法解决则上报**：30 分钟内升级到 `secondary`，并记录上报

```bash
python scripts/incident.py --list
python scripts/incident.py --escalate .runs/<run_dir> --reason "..." --to "项目负责人"
```

详细处置说明见 [references/incident-response.md](../../references/incident-response.md)。

## 输出契约

- 每次运行必须产出一个独立目录：`manifest.json`、`stdout.log`、`stderr.log`、工具输出文件
- `manifest.json` 记录：时间、目标、工具、profile、完整命令、授权方、scope 文件
- 异常时额外产出 `incident.json` 与 `incident.md`，状态为 `open` 或 `escalated`
- 结论必须人工复核，脚本不判定漏洞真假

## 红线

- 没有书面授权不扫描；不把 `--authorized` 当作形式
- 不使用白名单之外的参数或工具，不手工改写命令绕过限速
- 不扫描排除项，不对第三方托管系统做任何探测
- 一旦影响业务或越界，先停、先报，不自行"修一下再继续"

## 坑点

- `--confirm` 是防误操作的设计，项目名不一致会被拒绝，这是预期行为
- `nuclei` 目标需要带 scheme，`nmap` 只接受主机或 IP，传错会直接报参数错误
- 工具未安装时正式执行会退出 2；`--dry-run` 会提示缺失但不执行
- 时间窗口按带时区的 ISO 8601 解析，跨时区项目必须写偏移量
