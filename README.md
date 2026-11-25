# 赛场 DNS 采集系统 · 使用说明

版本：v1.5（对应 `listener.py` / `guard.py` / `collector.py` / `provision.ps1`；全源码运行，不打包 exe）

适用场景：比赛/考试期间，在每台学生机上记录 **DNS 查询** 和 **未关联公网 TCP 连接**，把事件汇总到校内 Linux 服务器上的采集端，通过浏览器看板实时查看"谁在查什么、连哪台可疑机器"。

---

## 1. 系统组成

| 角色    | 运行的东西                                           | 作用                                                       |
| ----- | ----------------------------------------------- | -------------------------------------------------------- |
| 学生机   | `listener.py` + `guard.py`（用学生机已装的 Python 直接运行） | 读 Windows DNS 事件日志，过滤白名单后经 UDP 发给采集服务器；两个进程互相看护，被杀掉会互相拉起 |
| 采集服务器 | `collector.py`（校内 Linux 服务器的 python3）           | 接收 UDP 包、校验签名、聚合告警、保存数据、提供网页看板                           |
| 浏览器   | 看板页面                                            | 查看连接状态、告警事件、健康异常，确认告警、导出 CSV                             |

数据流：

```
学生机 listener.py ──UDP 48123/HMAC签名──▶ Linux 服务器 collector.py ──HTTPS 8443──▶ 浏览器看板
        ▲                                        │
     guard.py 看护                        logs\*.jsonl / incidents.jsonl / state.json
```

一块展示区（看板）就够了，不需要数据库、不需要联网到外网。

---

## 2. 环境准备

### 2.1 各机器需要的东西

| 机器                 | 要求                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| 发放机（Windows 10/11） | PowerShell 5.1+；可选 `openssl`（在 PATH 里）用于发放时生成自签证书；生成看板口令哈希需 .NET Framework 4.7.2+（Win10/11 自带，不满足时口令延后到采集端首次启动自动处理） |
| 学生机（Win7/10/11）    | **预装 Python ≥3.8** 并在 PATH 里（`py` / `python` / `python3` 任一可执行即可，部署脚本自动探测，优先 `pythonw.exe` 隐藏窗口）                    |
| 采集服务器（Linux）       | `python3 ≥3.8`（纯标准库，无 pip 依赖）；开放 UDP 48123、TCP 8443（HTTPS）/8080（HTTP）入站                                             |

**v1.5 不再打包任何 exe**：三个 `.py` 源码直接运行。发放前先在本机跑一遍自检：

```powershell
python listener.py --self-test --config .\config.json
python guard.py --self-test
python collector.py --self-test
.\test_compat.ps1   # 多解释器语法 + 自检 + PS 脚本解析回归
```

---

## 3. 第一步：准备名册 CSV

新建 `名册.csv`（UTF-8 编码即可，带不带 BOM 都行），四列，顺序固定：

```csv
账号,姓名,场地,备注
alice,张三,A,1号机
bob,李四,A,2号机
carol,王五,A,3号机
```

规则：

| 字段  | 要求                                                                          |
| --- | --------------------------------------------------------------------------- |
| 账号  | 必填，可见 ASCII 字符 2–64 位（字母/数字/下划线等），**不区分大小写去重**                              |
| 姓名  | 必填，1–20 个字符，不能包含 `\ / : * ? " < >                                           |
| 场地  | 可留空（默认用命令行的第一个 `-Venue`）；填了就必须落在本次 `-Venue` 场地列表内，不在列表中的行会被静默跳过（方便一份名册分多场次） |
| 备注  | 可留空，只出现在"找人清单"里                                                             |

表头也认中文别名：`账号` / `OJ账号` / `学号`，`姓名`，`场地` / `考场`，`备注`。

**校验是严格的：** 任何一行有问题都不会生成半个包，而是把错误写到名册同目录的 `roster.errors.txt`（带行号），命令以非 0 退出。修好重跑即可。

上限 1000 行。

---

## 4. 第二步：一键发放

在发放机上执行：

```powershell
.\provision.ps1 -Roster .\名册.csv -Venue A -CollectorHost netlistener.seuoj.best -Out .\out
```

如果要一次发放多个场地并共用一台采集服务器，把场地代号用逗号分开：

```powershell
.\provision.ps1 -Roster .\名册.csv -Venue A,B,C -CollectorHost netlistener.seuoj.best -Out .\out
```

输出目录会合并为 `out\combined_A_B_C\`；座位包仍按账号分发，`collector-server\` 中的名册和密钥覆盖所有选定场地。看板会在页面上用"场地"筛选。

常用参数：

| 参数                                          | 说明                                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `-Roster`                                   | 名册 CSV 路径（必填）                                                                                                    |
| `-Venue`                                    | 场地代号，可传一个或多个（如 `A` 或 `A,B,C`；必填，字母/数字/下划线/短横线，1–16 位）。单场地输出 `out\<场地>\`，多场地输出 `out\combined_场地列表\`               |
| `-CollectorHost`                            | 采集服务器的域名或 IP（必填）。**建议写域名**（服务器迁机只改 DNS）；学生机会解析一次然后缓存 300 秒                                                       |
| `-Out`                                      | 输出根目录（必填），会生成 `out\<场地>\`                                                                                        |
| `-Policy`                                   | 自定义策略 JSON（白名单域名、忽略进程、进程分级等）。不传就用内置默认策略                                                                          |
| `-NetworkProfile`                           | `baseline_network_profile.py` 生成的 `config-patch.json`。会自动合并到 `ignored_domains`、`ignored_processes`、`ignored_ips` |
| `-UiPassword`                               | 看板口令。不传则随机生成 10 位（数字+小写字母，去掉了易混字符）                                                                               |
| `-RotateKeys`                               | 重新生成所有 machine_id 和密钥（默认会复用上次 `keys-backup.json` 里的）                                                             |
| `-ListenerPy` / `-GuardPy` / `-CollectorPy` | 指定三个 .py 源码路径，默认用本目录下的                                                                                           |
| `-CollectorPort`                            | UDP 采集端口，默认 `48123`                                                                                              |
| `-WebPort`                                  | 看板 HTTPS 端口，默认 `8443`                                                                                            |

### 输出结构

```
out\A\
├─ roster.json            名册（账号/姓名/场地/机器号）
├─ secrets.json           机器号 → 密钥（采集服务器用，绝不外发）
├─ keys-backup.json       密钥备份（务必离线保存！丢了要 -RotateKeys 重发）
├─ policy.json            本场策略
├─ manifest.csv           账号、姓名、机器号、密钥指纹（核对用，不含密钥本体）
├─ 找人清单.csv            账号 → 座位包目录对照表
├─ 导入说明.txt            发给现场老师的速查
├─ seats\
│  ├─ A\
│  │  ├─ 张三_alice\          ← 拷到对应学生机（U 盘）
│  │  │  ├─ deploy.cmd       双击部署（要管理员权限）
│  │  │  ├─ uninstall.cmd    双击卸载还原
│  │  │  ├─ start.vbs / stop.vbs  手动启停
│  │  │  └─ listener.py / guard.py / config.json / 说明.txt
│  │  └─ 李四_bob\
│  └─ B\
│     └─ 王五_carol\
└─ collector-server\      ← 上传到 Linux 采集服务器
   ├─ collector.py / secrets.json / roster.json / policy.json / dashboard.json
   ├─ start-collector.sh       bash 启动脚本
   ├─ nl-collector.service     systemd 单元（开机自启 + 崩溃自动拉起）
   └─ certs\server.crt / server.key（发放机有 openssl 时生成）
```

**分发原则：`seats\<场地>\` 里每个座位文件夹只能给对应的那一台学生机；`collector-server\` 只上传到采集服务器。** `secrets.json`、`keys-backup.json` 任何时候都不要发给学生。

---

## 4.1 可选：赛前网络基线

建议在 1 台和赛场同镜像、同网络、同常用工具的代表机上前置跑 30 分钟。详细运行参数、输出文件、`policy_analysis` 字段和改策略流程见 [baseline说明.md](baseline说明.md)。

```powershell
python .\baseline_network_profile.py --minutes 30 --out-dir .\network-baseline --tools "code.exe,python.exe"
```

脚本会记录 DNS 查询和 TCP/UDP 连接，把 Windows 系统进程的已知低风险 DNS/进程/公网 IP 自动写入 `config-patch.json`；浏览器、IDE、编译器等赛时工具的域名默认放进 `review-domains.csv` 和 `review-ips.csv` 复核，避免一个"加白进程"把学生后来的可疑查询也静默掉。确认无误后用 `-NetworkProfile` 发放：

```powershell
.\provision.ps1 -Roster .\名册.csv -Venue A,B -CollectorHost netlistener.seuoj.best -Out .\out -NetworkProfile .\network-baseline\config-patch.json
```

如果需要 IDE/CDN 等工具端点自动进忽略名单，加 `--auto-tool-ignore`；这项会扩大过滤面，请先看 `review-domains.csv`。脚本会临时启用 Windows DNS 事件通道，结束后自动还原。`baseline-report.json` 的 `policy_analysis` 会把 DNS、公网 IP、进程、端口和 TLD 证据按 `policy.json` 字段分组，便于复核后直接更新进程分级和高危规则。

---

## 5. 第三步：部署采集服务器（Linux）

1. 上传整个 `collector-server\` 目录：
   
   ```bash
   scp -r collector-server user@server:/opt/nl-collector
   ```

2. 先跑自检：`cd /opt/nl-collector && python3 collector.py --self-test`，应输出 `self-test OK`。

3. 启动（二选一）：
   
   - **快速验证**：`bash start-collector.sh`（前台运行，窗口不能关）；
   
   - **正式使用**：systemd 常驻（推荐）：
     
     ```bash
     sudo cp nl-collector.service /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable --now nl-collector
     ```

4. **放行防火墙**（UDP 48123 + TCP 8443/8080），例如：
   
   ```bash
   sudo ufw allow 48123/udp && sudo ufw allow 8443/tcp
   ```

5. 看板地址：`https://服务器域名或IP:8443`
   
   - 自签名证书，浏览器会提示"不安全"——点"高级"→"继续前往"。
   - 服务器没有 openssl 且发放时没生成证书时，采集端启动自动回退明文 `http://IP:8080`（`--http-port` 可追加额外明文监听，仅限内网应急）。

6. 登录口令：
   
   - 发放时用 `-UiPassword` 指定了 → 直接用那个。
   - 没指定 → 看 `dashboard.json` 或首次启动日志打印的随机口令。
   - 忘记口令：停掉采集器，运行 `python3 collector.py --reset-password`，会生成新口令并打印。

7. 启动成功的标志（日志里会打印）：
   
   ```
   collector: UDP 采集端口已监听: 0.0.0.0:48123（N 台机器 / N 组密钥）
   collector: 看板已监听: https://0.0.0.0:8443
   ```

### 采集器常用命令

```bash
# 只接受一个场地（默认名册外/其他场地都不收；共用采集器时不要加）
python3 collector.py --dir /opt/nl-collector --venue A

# 多场地共用一个进程时，不要加 --venue；在网页筛选场地
python3 collector.py --dir /opt/nl-collector

# 改保留期（默认 7 天）
python3 collector.py --dir /opt/nl-collector --retain-days 3

# 换端口
python3 collector.py --dir /opt/nl-collector --port 48124 --web-port 8443

# 应急：同时开 8080 明文
python3 collector.py --dir /opt/nl-collector --http-port 8080
```

数据都在 `--dir` 目录下：

| 文件                                 | 内容                    |
| ---------------------------------- | --------------------- |
| `logs/YYYY-MM-DD.jsonl`            | 当天所有事件原始记录（心跳不写入）     |
| `incidents.jsonl`                  | 聚合后的告警（含确认状态），重启不丢    |
| `state.json`                       | 断点状态（已处理到哪个序号、各机最后心跳） |
| `sessions.json` / `dashboard.json` | 会话与看板口令               |

---

## 6. 第四步：部署学生机（U 盘）

1. 把该学生对应的文件夹（如 `张三_alice\`）整个拷到 U 盘，再插到对应学生机。

2. 双击 `deploy.cmd`，UAC 弹窗点"是"。**窗口提示"复制开始后即可拔掉U盘"——复制一开始就可以拔**，后续步骤全部使用已复制到本机的文件。

3. 部署做了什么（自动，无需人工）：
   
   - **第一步就把 `listener.py` / `guard.py` / `config.json` / `init.ps1` / `deploy.ps1` 复制到最终安装目录** `C:\ProgramData\Microsoft\Windows\Caches\<机器号>\`（隐藏 + 系统属性，不经临时目录）
   - 探测学生机的 Python（`py`/`python`/`python3`，优先 `pythonw.exe`）；找不到会红字报错退出
   - 开启 `Microsoft-Windows-DNS-Client/Operational` 日志通道（128MB 循环缓冲）
   - 关闭 Chrome / Edge 的"安全 DNS（DoH）"，保证查询能被系统记录（原设置会备份，卸载时还原）
   - 写入开机自启（HKLM Run 项，指向 `pythonw.exe guard.py --config ...`）
   - 启动 guard.py，从而拉起 listener.py
   - 自检 40 秒：`guard.json` 15 秒内刷新 + `state.json` 30 秒内刷新 → 写 `deploy.json`（`self_check_ok: true`）

4. 约 15–30 秒后，看板"连接状态"里该账号应变成 **在线**。

5. **不要动的东西**：安装目录（隐藏目录）、开机自启项、DNS 日志通道。学生误关的话 guard/listener 会互拉；两个都被杀才停。

6. 比赛结束 / 机器回收：双击 `uninstall.cmd`，还原 DNS 通道与浏览器设置、删掉安装目录、移除自启项。

### 学生机本地数据

`C:\ProgramData\SchoolContestDnsMonitor\<机器号>\`：

- `state.json` 处理进度（防止重复上报；含本进程 pid 供 guard 探活）
- `outbox.jsonl` 采集服务器不可达时积压的事件（恢复后自动补发）
- `guard.json` 看门狗状态（重启次数；含 guard 进程 pid 供 listener 探活）

---

## 7. 看板使用

### 顶部汇总卡片

在线 / 迟到 / 离线 / 已停止 / 密钥异常 / 从未报数 / 未确认事件 / 高危未确认。

### ① 连接状态

每个账号一行：状态、账号、姓名、场地、最近报数、来源 IP、主机名、guard、重启次数、机器数、备注。

状态含义：

| 状态       | 含义                                     |
| -------- | -------------------------------------- |
| 在线       | ≤45 秒有心跳                               |
| 迟到       | 45–90 秒有心跳（可能网络抖动，留意）                  |
| 离线       | >90 秒没有心跳                              |
| 已停止      | 收到过正常的停止上报（学生手动关了）                     |
| 密钥异常     | 收到该机器的签名校验失败包（密钥对不上，或有人拿别的包乱发）         |
| 从未报数     | 名册里有、但从没收到过包（没部署/没连上）                  |
| 备注：多机    | 同一账号在 ≥2 台机器上跑（通常一账号一机，出现要问）           |
| 备注：机器号冲突 | 同一机器号 90 秒内从 2 个不同 IP 发来（拷贝了人家安装目录/冲突） |

支持按场地筛选，以及按账号/姓名/IP/主机名搜索；勾"只看异常"过滤掉正常行。

### ② 事件（未加白名单的 DNS / 未关联的公网 TCP）

按"账号 + 目标 + 进程"聚合，一行一个组合：

| 列       | 说明                                                                                     |
| ------- | -------------------------------------------------------------------------------------- |
| 确认      | 勾选即"已处理"，默认隐藏已确认（可勾"含已确认"显示）                                                           |
| 类型      | `dns` 域名查询；`tcp` 对外连接                                                                  |
| 目标      | 域名或远端 IP                                                                               |
| 进程      | 发起查询/连接的进程名（括号里是进程号）                                                                   |
| 等级      | `interactive` 交互程序（浏览器等，重点关注）/ `system` 系统进程 / `unknown`                               |
| 高危      | `suspicious_tld` 可疑顶级域（.top/.xyz/.tk 等）/ `nonstandard_port` 非常用端口 / `direct_ip` 直接查 IP |
| 次数      | 聚合次数                                                                                   |
| 首次 / 最近 | 该组合第一次/最近一次出现的时间                                                                       |
| 原始事件    | 点开看每条原始记录（JSON），便于取证                                                                   |

可以按场地、类型、等级筛选，搜索框支持账号/目标/进程。看板每 2 秒自动刷新；筛选结果保存到浏览器，页面或浏览器刷新后会先恢复场地/类型/等级/搜索条件再继续自动刷新。右下角"导出 CSV"会导出当前筛选结果（UTF-8 BOM，Excel 直接打开不乱码，含已确认的）。

### ③ 健康异常

采集端自己发现的问题，按级别排列：

| 类型                | 含义                 | 处理                                         |
| ----------------- | ------------------ | ------------------------------------------ |
| `guard_down`      | 该机心跳说 guard.py 没在跑 | 让学生重启机器，或重跑 deploy.cmd                     |
| `key_error`       | 有签名校验失败的包          | 核对 manifest.csv 指纹；若密钥泄露用 `-RotateKeys` 重发 |
| `key_conflict`    | 同机器号多 IP           | 两台撞包/拷了安装目录，找到冲突机                          |
| `multi_machine`   | 同账号多机器             | 确认学生有没有换机器                                 |
| `agent_stopped`   | 学生主动停了             | 问清楚；必要时让学生重新 deploy                        |
| `unknown_machine` | 收到名册外的机器号          | 有人用了没发放的包                                  |

---

## 8. 现场核对流程（建议照做）

**赛前 30 分钟**

1. 采集服务器上 `systemctl start nl-collector`（或 `bash start-collector.sh`），浏览器能打开看板。
2. 学生机逐个 `deploy.cmd`；约 10 台一查：看板"在线"数应等于已部署数。
3. 看"健康异常"是否为空；有 `guard_down` / `从未报数` 当场处理。

**赛中**

4. 每 10–15 分钟扫一眼：卡片里"离线"有没有突然涨（网络/断电），"高危未确认"有没有异常增长。
5. 事件区按 `等级=interactive` + `高危` 优先看；确认过的勾掉，保持列表干净。

**赛后**

6. 导出 CSV 存档；`keys-backup.json` 离线保存。
7. 学生机 `uninstall.cmd` 还原。

---

## 9. 常见问题

| 现象              | 原因                               | 处理                                                    |
| --------------- | -------------------------------- | ----------------------------------------------------- |
| 学生机部署报"需要管理员权限" | UAC 被拒                           | 右键 `deploy.cmd` → 以管理员身份运行                            |
| deploy.cmd 一闪而过 | 被安全软件拦                           | 加白名单后重试；或看 `deploy.json` 里 `self_check_ok`            |
| 部署报"未找到 Python" | 学生机没装 Python 或不在 PATH            | 装 Python ≥3.8 勾选"Add to PATH"后重跑 deploy.cmd           |
| 看板打不开           | 防火墙没放行 / 采集器没启动                  | 放行 UDP 48123 + TCP 8443；看采集器日志有没有报错                   |
| 看板提示证书不安全       | 自签名证书                            | 浏览器"高级"→"继续前往"，属正常                                    |
| 登录提示"失败次数过多"    | 同一 IP 5 次密码错误，锁 60 秒             | 等 60 秒；或 `python3 collector.py --reset-password` 重置   |
| 账号一直"从未报数"      | 没部署 / `-CollectorHost` 写错 / 网络不通 | 学生机 ping/解析采集服务器；看 `outbox.jsonl` 是否在涨                |
| 账号"离线"但机器开着     | listener 被杀了 / 日志通道被关            | 重跑 `deploy.cmd`；guard 会自动拉起                           |
| "密钥异常"          | 包签名对不上                           | 核对 manifest 指纹；旧包重发请用 `-RotateKeys`                   |
| "机器号冲突"         | 两机用了同一个安装目录                      | 找到撞包的机器，重新发放再部署                                       |
| 事件时间与墙上时钟差 8 小时 | 浏览器时区                            | 看板已按浏览器本地时区显示；服务器时间不对就调系统时钟                           |
| 服务器重启后采集停了      | 没装 systemd 单元                    | 按 §5 装 `nl-collector.service`（`Restart=always` 会自动拉起） |

---

## 10. 数据与隐私

- 采集内容：**DNS 查询域名 + 进程名 + 对外公网 IP:端口**。不读网页内容、不截屏、不留键盘记录。
- 学生机本地只存状态和待发事件；卸载即清除。
- 采集服务器默认保留 7 天原始事件与聚合告警。
- `keys-backup.json` 是唯一能重发密钥的凭证，**离线备份**。
- 密钥只存在于 `secrets.json` / `keys-backup.json`（服务器侧）和每台学生机的 `config.json`（仅自己那一份）。`manifest.csv` 只有指纹，可用于核对但无法还原密钥。

---

## 11. 命令速查

```powershell
# 发放机（Windows）
.\provision.ps1 -Roster .\名册.csv -Venue A -CollectorHost netlistener.seuoj.best -Out .\out
.\provision.ps1 -Roster .\名册.csv -Venue A -CollectorHost netlistener.seuoj.best -Out .\out -UiPassword "abc123"
.\provision.ps1 -Roster .\名册.csv -Venue A -CollectorHost netlistener.seuoj.best -Out .\out -RotateKeys
.\provision.ps1 -Roster .\名册.csv -Venue A,B -CollectorHost netlistener.seuoj.best -Out .\out -NetworkProfile .\network-baseline\config-patch.json

# 赛前基线（学生代表机，管理员 PowerShell）
python .\baseline_network_profile.py --minutes 30 --out-dir .\network-baseline --tools "code.exe,python.exe"

# 兼容性回归（改完代码跑一遍）
.\test_compat.ps1
```

```bash
# 采集服务器（Linux）
python3 collector.py --self-test
python3 collector.py --dir /opt/nl-collector
python3 collector.py --dir /opt/nl-collector --reset-password
sudo systemctl enable --now nl-collector
```

```bat
:: 学生机（部署后，安装目录内）
pythonw listener.py --self-test
pythonw guard.py --self-test
```

---

## 12. 版本说明（v1.5 未做/已知限制）

- 学生机必须预装 Python ≥3.8（部署脚本自动探测；还原系统后 Python 消失需重装再重跑 deploy）。
- 采集端只做 Linux 服务器形态（Windows 仅用于开发自测；不做多机热备）。
- 通信只有 UDP 一条通道；极少数网络封 UDP 的环境需要改用 `--http-port` 看板方向排查，但事件上报本身暂无 TCP 回落。
- 策略热更新只改采集端：登录看板后在“策略热更新”导入 `policy.json` 即可生效；学生机过滤名单仍在发放时确定，要改客户端白名单需重新发放或现场改 `config.json`。
- HTTPS 用自签证书，浏览器有一次"不安全"警告；不做 CA/证书安装。
