# vuln-scan-runner

[![CI](https://github.com/lucky-star-konata/vuln-scan-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/lucky-star-konata/vuln-scan-runner/actions/workflows/ci.yml)

授权制漏洞扫描编排器：只调用你本机已安装的扫描工具，执行前强制校验授权范围，运行异常自动进入应急响应流程。

> 仅限已取得书面授权的目标。详见 [DISCLAIMER.md](DISCLAIMER.md)。

## 和直接手敲命令的区别

| 风险 | 本工具的处理 |
| --- | --- |
| 忘记确认目标是否在范围内 | 每次执行前校验域名 / CIDR / 排除项 / 时间窗口 |
| 用错工具或参数过猛 | 工具白名单 + 固定参数模板，速率有上限 |
| 扫出问题不知道怎么收场 | 自动停止、保留现场、生成应急报告、给出上报路径 |
| 没有执行记录 | 每次运行落盘 manifest、stdout、stderr、工具输出 |

## 支持的工具

| 工具 | 用途 | 前提 |
| --- | --- | --- |
| `nmap` | 主机发现、端口探测、服务识别 | 本机已安装 |
| `nuclei` | 模板化漏洞扫描（JSONL 输出） | 本机已安装 |
| `nikto` | Web 服务器配置与常见问题 | 本机已安装 |
| `whatweb` | Web 技术栈与指纹识别 | 本机已安装 |

工具不随本仓库分发，脚本只负责编排。

## 快速开始

```bash
# 0. 复制授权范围模板，填成你的项目
cp skills/vuln-scan-runner/templates/scope.example.json scope.json

# 1. 预览将要执行的命令（不实际扫描）
python skills/vuln-scan-runner/scripts/scan_runner.py \
  --scope scope.json --target https://app.example.com \
  --tool nuclei --dry-run --authorized --confirm "示例漏扫"

# 2. 正式执行
python skills/vuln-scan-runner/scripts/scan_runner.py \
  --scope scope.json --target https://app.example.com \
  --tool nuclei --authorized --confirm "示例漏扫"

# 3. 汇总所有运行记录与应急事件
python skills/vuln-scan-runner/scripts/summary.py

# 4. 查看结果
#    .runs/<时间戳>-<工具>/ 下是 manifest.json、stdout.log、stderr.log、工具输出
#    .runs/summary.md 是运行汇总
```

## 授权模型

必须同时满足，否则拒绝执行：

1. `--authorized` 显式声明你已获得授权
2. `--confirm "项目名"` 与 `scope.json` 的 `engagement` 完全一致
3. 目标命中 `targets` 且不命中 `excludes`
4. 当前时间在 `window` 内
5. 工具在 `allowed_tools` 内

任一不满足直接退出，不执行任何网络操作。

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 扫描完成 |
| 2 | 参数或配置错误 |
| 3 | 授权校验未通过 |
| 4 | 运行异常，已进入应急响应流程 |

## 应急响应

工具报错、超时、崩溃或出现异常输出时：

1. 自动终止子进程
2. 保留本次运行目录作为现场
3. 生成 `incident.json` 与 `incident.md`
4. 打印五步处置流程：停止 → 保留现场 → 评估影响 → 通知授权方 → 无法解决则上报
5. 以退出码 4 结束

上报：

```bash
python skills/vuln-scan-runner/scripts/incident.py --list
python skills/vuln-scan-runner/scripts/incident.py --escalate .runs/<run_dir> \
  --reason "目标业务出现 5xx，无法自行恢复" --to "项目负责人"
```

## 目录结构

```
vuln-scan-runner/
├── VERSION
├── skills/vuln-scan-runner/
│   ├── SKILL.md
│   ├── templates/scope.example.json
│   └── scripts/
│       ├── scan_runner.py
│       ├── incident.py
│       └── summary.py
├── references/incident-response.md
└── .runs/                    # 运行记录（gitignore）
```

## License

[MIT](LICENSE)
