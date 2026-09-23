# cf-dns-failover

基于 Cloudflare DNS 的自动化故障转移与智能线路切换服务。

本项目使用原生 Golang 开发（单文件 `./main.go`，仅依赖标准库），基于 `config.yml` 配置文件运行，支持独立为 Cloudflare API 与探测请求设置网络代理，并提供按列表顺序优先级与按最低延迟两种切换策略。

---

## 核心特性

- **原生轻量**：单文件 `./main.go`，仅使用 Go 原生标准库，无第三方外部依赖，免去模块下载困扰，直接运行。
- **双切换策略模式**：
  - **按列表顺序（priority，默认）**：配置列表中越靠前优先级越高，当前节点健康时仅更高优先级节点恢复才回切抢占。
  - **按最低延迟（latency）**：动态监测各就绪节点的实时 RTT 延迟，自动将 DNS 指向当前响应最快的健康节点。
- **独立网络代理**：支持分别针对 Cloudflare API (`cf_proxy` / `cf.proxy`) 与目标探测 (`probe_proxy`) 配置独立的 HTTP / HTTPS / SOCKS5 代理。
- **探测重试与稳健状态机**：
  - **探测失败立即重试**：单次探测遇到网络波动或异常立即就地重试（最多 `probe_retry` 次），任意一次成功即视为健康，只有重试全部失败才计入失败。
  - **统一阈值判定**：连续 `probe_count` 次探测成功判定为就绪恢复，连续 `probe_count` 次探测失败判定为离线不可用。例如设置探测次数 2、重试次数 2、循环周期 10 秒，最多需要 20 秒与 4 次探测请求确定失败。
  - **即时初始状态**：启动后各节点完成首次探测（同样支持失败就地重试）即输出「初始候选状态」，秒级感知节点全貌。
- **精准静默日志**：
  - 仅在目标候选相对当前 DNS 指向发生变更（触发切换）时打印候选状态变更日志。
  - DNS 切换成功时静默完成，切换失败时打印错误日志并自动重试 3 次。
- **容灾与重试**：
  - 初始化查询 DNS 记录：遇到鉴权错误立即报错退出，遇到网络或服务暂时性错误持续循环重试直至恢复。
  - DNS 切换重试：更新记录失败时自动重试 3 次，若仍失败则放弃本次修改，等待下次探测循环重试。
- **单循环防重叠**：单轮循环未结束前不触发新探测周期，避免堆积。

---

## 运行逻辑

1. **初始化阶段**
   - 检查 Cloudflare 中指定 `record_name` 与 `record_type` 的 DNS 记录值。
   - 若返回鉴权错误（HTTP 401/403 或 Cloudflare 认证错误码），立即退出脚本；
   - 若出现网络抖动、DNS 暂时不可达等其他错误，保持间隔循环重试，直至请求成功；
   - 成功获取记录后，确定当前 DNS 记录所指向的候选节点。

2. **首次探测（初始状态）**
   - 启动后的首次探测不遵循 `probe_count` 连续阈值，每个节点进行单次探测（若失败立即重试最多 `probe_retry` 次），全部完成即打印「初始候选状态」。
   - 根据探测结果与设定的切换模式评估最优候选；若最优候选与当前 DNS 指向不一致，立即执行候选切换。

3. **后续探测循环**
   - 每隔 `loop_time` 秒执行一次探测循环；若上一轮探测尚未结束，则跳过本次触发。
   - 并发探测配置中全部 `list.[].detect` 网址，单次探测若失败立即重试最多 `probe_retry` 次：
     - 探测成功：增加成功计数，失败计数清零；达到 `probe_count` 次判定为健康就绪；
     - 探测失败（全部重试均失败）：增加失败计数，成功计数清零；达到 `probe_count` 次判定为离线不可用。
   - 候选裁决与更新：
     - **按列表顺序（priority）**：列表中靠前的高优先级节点优先；当前活跃节点健康时，仅当更靠前的高优先级节点就绪才抢占回切；当前活跃节点不可用时，切换至最高优先级的健康节点。
     - **按最低延迟（latency）**：在所有健康就绪的节点中，选择响应延迟最低的节点。
   - 切换触发与通知：
     - 仅当目标候选与当前 DNS 指向不一致时打印「候选状态变更, 切换到候选...」；若未发生切换则不打印状态变更日志。
     - 执行 Cloudflare PATCH 更新记录，更新失败自动重试 3 次；切换成功静默无冗余日志，切换失败输出错误原因。

---

## 配置说明

配置文件为 `./config.yml`（默认路径，亦可通过 `-c` 参数指定）：

```yaml
# 每隔 n 秒循环探测一次
loop_time: 10
# 探测次数: 连续几次探测成功判定为就绪 / 连续几次失败判定为不可用
probe_count: 2
# 探测失败重试次数: 一次探测如果失败就立即重试，最多尝试 n 次
probe_retry: 2
# 单次探测超时时间，秒 (若填写 >1000 则按毫秒处理)
probe_timeout: 4
# 候选节点切换模式: priority (按列表顺序，默认) / latency (按最低延迟)
switch_mode: priority
# 探测网络代理 (支持 http://, https://, socks5://)，留空表示直连或遵循系统环境变量
probe_proxy: ""
# Cloudflare API 网络代理 (支持 http://, https://, socks5://)，留空表示直连或遵循系统环境变量
cf_proxy: "http://127.0.0.1:7890"

# Cloudflare 相关的公共配置
cf:
  # API Token，建议只授予该 Zone 的 "Zone / DNS / Edit" 权限 (也可通过环境变量 CF_API_TOKEN 传入)
  api_token: ""
  # Zone ID (也可通过环境变量 CF_ZONE_ID 传入)
  zone_id: ""
  # 需要被切换指向的 DNS 记录(完整域名)
  record_name: "xxx.xxx.cc"
  # 记录类型: A / AAAA / CNAME
  record_type: "CNAME"
  # TTL, 单位秒。1 表示 Auto。proxied 为 true 时会被 Cloudflare 忽略并强制 Auto
  ttl: 60
  # 是否开启 Cloudflare CDN 代理
  proxied: false

# 候选节点列表，按优先级从高到低排列，越靠前优先级越高
# detect: 探测地址；value: 选中时 DNS 记录指向的值 (A/AAAA 填 IP，CNAME 填域名)
list:
  - detect: "https://xx1.xxx.cc"
    value: "frp1.cc"
  - detect: "https://xx2.xxx.cc"
    value: "frp2.cc"
```

### 环境变量支持

- `CF_API_TOKEN`：Cloudflare API 访问令牌（若设置将覆盖 `config.yml` 中的 `cf.api_token`）
- `CF_ZONE_ID`：Cloudflare Zone ID（若设置将覆盖 `config.yml` 中的 `cf.zone_id`）

---

## 运行方式

无需额外构建依赖，直接使用原生 Go 运行：

```bash
# 方式 1: 直接运行
go run main.go

# 方式 2: 指定配置文件
go run main.go -c /path/to/config.yml

# 方式 3: 编译为单二进制文件
go build -o cf-failover main.go
./cf-failover -c config.yml
```
