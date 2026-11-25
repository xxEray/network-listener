# 赛前网络基线说明

`baseline_network_profile.py` 用一台代表机提前观察赛场网络，记录 DNS 查询和公网连接，生成可复核的忽略名单和策略分析证据。它不会自动替你判断学生行为；自动忽略只覆盖已知的 Windows 系统流量，浏览器、IDE、编译器和未识别进程的 DNS 都会进入复核清单。

## 适用时机

在一台与学生机同镜像、同网络、同常用软件的代表机上运行。建议在正式发放前完成，通常观察 30 分钟。如果赛场网络或常用工具变化明显，应重新跑一次。

脚本会临时启用 Windows DNS 事件通道，结束时默认恢复原来的开关状态。需要管理员权限。

## 常用命令

```powershell
# 推荐：观察 30 分钟，并登记常用赛时工具进程
python .\baseline_network_profile.py --minutes 30 --out-dir .\network-baseline --tools "code.exe,python.exe"

# 缩短观察窗口；少于 15 分钟容易漏掉后台低频域名
python .\baseline_network_profile.py --minutes 15 --out-dir .\network-baseline --tools "code.exe,python.exe"

# 复核后，若确认工具的基础设施域名可以进入忽略名单
python .\baseline_network_profile.py --minutes 30 --out-dir .\network-baseline --tools "code.exe,python.exe" --auto-tool-ignore
```

`--tools` 使用逗号分隔进程名，例如 `code.exe,python.exe,git.exe`。`--auto-tool-ignore` 会扩大学生机过滤面，执行前先看 `review-domains.csv` 和 `review-ips.csv`。

## 输出文件

| 文件 | 用途 |
| --- | --- |
| `config-patch.json` | 可合并进 listener 配置的忽略名单，供 `provision.ps1 -NetworkProfile` 使用 |
| `baseline-report.json` | 完整观察报告，包含原始统计和 `policy_analysis` |
| `events.jsonl` | DNS 和连接快照的原始审计记录 |
| `review-domains.csv` | 未自动忽略的域名，按域名和进程去重 |
| `review-ips.csv` | 未自动忽略的公网 IP，包含端口、进程和 DNS 关联 |
| `review-processes.csv` | 未自动忽略的进程及其访问过的域名 |
| `config-patch.txt` | 便于人工查看的三组忽略名单文本 |

`--out-dir` 可以指向工作目录下的独立文件夹，例如 `network-baseline`；如果要和某次发放包放在一起，也可以指定到 `out\combined_Pro_new4_new9\baseline` 这类子目录。基线默认不会覆盖发放包里的 `policy.json`。

## `policy_analysis` 的用法

`baseline-report.json` 的 `policy_analysis` 按 `policy.json` 字段分组，目的是让人工或 AI 能依据证据修改策略，而不是只看一串域名。

| 分析字段 | 内容 |
| --- | --- |
| `allowed_domains` | 未被自动忽略的域名候选，包含进程、状态、解析 IP 和时间 |
| `ignored_domains` | 当前自动忽略的规则、命中的域名、进程和 DNS 事件数 |
| `ignored_processes` | 被标记为系统进程的观察记录，包含路径、DNS、公网 IP 和端口 |
| `ignored_ips` | 被自动忽略的公网 IP 及其 DNS、TCP 证据 |
| `process_grades` | 按 tool、system、unknown 分类进程，并保留路径、DNS 和连接证据 |
| `high_risk` | 直连 IP DNS、非标准端口、可疑 TLD 的候选证据；TLD 部分包含全量观察到的高层级域名计数 |

这些字段只提供证据。是否加入白名单、忽略名单、进程分级或可疑 TLD，应由人复核后决定；AI 可以基于这些证据提出修改建议，然后输出完整 JSON。

## 从基线结果更新 policy

1. 用发卷机或服务器上现行的 `policy.json` 作为起点。
2. 结合 `baseline-report.json` 的 `policy_analysis`、`review-*.csv` 和 `config-patch.txt` 复核。
3. 更新 `process_grades`、`high_risk` 等策略项，确认 JSON 语法正确。
4. 发放前把补丁交给 `provision.ps1 -NetworkProfile`；已部署且只想调整采集端分级时，登录 HTTPS 看板，在“策略热更新”里导入新的 `policy.json`。

看板导入只改采集端策略。学生机的 `ignored_domains`、`ignored_processes`、`ignored_ips` 和 `allowed_domains` 在发放时写入每台机器的 `config.json`；要改客户端过滤面，仍需重新发放或现场逐台修改配置。

已生成的采集端文件在 `out\combined_Pro_new4_new9\policy.json` 和 `out\combined_Pro_new4_new9\collector-server\policy.json`。更新其中一份后，导入看板即可生效；需要重新发放时，让 `provision.ps1` 重新生成这两个文件。

## 结果判断

- `stats.dns_events` 为 0 或很小时，忽略名单不完整，应延长观察时间。
- `stats.connection_snapshots` 为 0 表示没有采集到 TCP/UDP 快照，公网 IP 结论不可用。
- `warnings` 数组包含这类提示；不要忽略。
- 浏览器和赛时工具的域名默认进入复核清单，避免把学生后续可疑访问静默掉。
- 若必须加入某个未识别进程或域名，先核对路径、DNS 关联和端口，再调整策略。
