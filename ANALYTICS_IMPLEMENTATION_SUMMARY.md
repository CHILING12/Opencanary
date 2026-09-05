# OpenCanary 多协议蜜罐事件关联与分级告警系统：实现总结

**分支：** `feature/analytics-correlation-alerting`
**提交：** `f2fd75d Add analytics correlation and alerting sidecar`

## 1. 架构与集成方式

本次实现采用独立的 **analytics sidecar（分析侧车）** 架构：读取 OpenCanary 已有 File Logger 输出的 JSONL 日志，而不修改 SSH、HTTP、FTP 等协议模块和 Twisted 守护进程启动流程。

这使现有蜜罐协议仿真和原有集成测试保持兼容，同时提供独立、可部署、可测试的安全分析能力。

新增主包：

```text
opencanary_analytics/
```

主要处理链路：

```text
JSONL 日志
  → 解析与字段归一化
  → 敏感字段脱敏 / HMAC 指纹
  → 事件 ID 去重与 SQLite 持久化
  → 五分钟窗口聚合
  → 跨协议关联与规则评分
  → 告警持久化、Webhook 通知与失败重试
  → 每日报告
```

## 2. 事件归一化与协议识别

`opencanary_analytics/normalize.py` 将 OpenCanary 的遗留事件结构统一为以下字段：

- `event_id`
- `timestamp`（UTC）
- `node_id`
- `src_ip` / `src_port`
- `dst_ip` / `dst_port`
- `protocol`
- `event_type`
- `username`
- `password_hash`
- `user_agent`
- `raw_event`（脱敏后的审计数据）

支持 ISO-8601、`Z` 时区、时区偏移、传统 OpenCanary 时间格式和 epoch 时间戳。

已覆盖 OpenCanary 的 FTP、HTTP、SSH、SMB、端口扫描、Telnet、HTTP Proxy、MySQL、MSSQL、TFTP、NTP、VNC、SNMP、RDP、SIP、Git、Redis、TCP Banner、LLMNR、MongoDB 等 logtype。

## 3. 敏感信息保护

`opencanary_analytics/redaction.py` 使用 HMAC-SHA256 生成稳定、不可逆的密码指纹，支持同一密码的关联分析，但不保存密码明文。

递归脱敏涵盖：

- `password` / `passwd` / `pass`
- `token` / `access_token`
- `api_key`
- `private_key`
- `client_secret`
- `VNC Password`
- `SECRET_STRING`
- `COMMUNITY_STRING`
- 其他 `*_password`、`*_secret` 格式字段

数据库、告警和报告都不包含密码原文。HMAC 密钥通过环境变量 `OPENCANARY_ANALYTICS_HMAC_KEY` 提供。

> 注意：OpenCanary 原始日志在被侧车读取前仍可能包含密码原文，应限制日志文件权限并配置较短的轮转和保留周期。

## 4. 存储、去重和日志采集

`opencanary_analytics/storage.py` 基于 SQLite（WAL 模式）持久化：

- 归一化事件
- 五分钟聚合记录
- 告警及通知状态
- 统计指标
- 文件 inode/offset 检查点

`opencanary_analytics/ingest.py` 实现：

- JSONL 非法记录处理
- 部分行缓存
- 按处理结果确认检查点，避免处理前推进 offset
- 重启恢复
- 文件 rename 轮转和截断检测
- 重复事件 ID 去重

## 5. 关联和可解释风险评分

事件按来源 IP 与固定 UTC 五分钟窗口关联，维护：

- 首次和最近发生时间
- 事件数量
- 唯一目标端口
- 唯一协议
- 行为标签

默认规则和分值：

| 行为 | 分值 |
| --- | ---: |
| 3 种或更多协议 | +25 |
| 端口扫描 | +30 |
| 默认账号或弱口令 | +20 |
| 敏感路径访问 | +20 |
| 高事件量 | +15 |
| 威胁情报命中 | +40 |
| 短时间爆破 | +20 |
| 白名单命中 | -30 |

风险等级：

| 分数 | 等级 |
| --- | --- |
| 0–29 | low |
| 30–59 | medium |
| 60–79 | high |
| 80+ | critical |

白名单事件会保留在数据库和报告中，但不生成告警。

## 6. 通知与报告

`opencanary_analytics/notifiers.py` 支持：

- 通用 Webhook
- Slack Incoming Webhook
- 超时与指数退避重试
- 通知冷却
- 通知失败持久化
- 已保存但未发送告警的后续重试

通知内容包括风险等级、来源 IP、协议/端口、首次和最后发生时间、事件数量、标签、评分和规则原因；不包含原始事件或凭据。

`opencanary_analytics/report.py` 生成每日 Markdown 报告，包含：

- 来源 IP Top 10
- 协议触发统计
- 用户名 Top 10
- 扫描和爆破的小时分布
- 高风险告警
- 白名单过滤数量
- 原始告警候选与去重后告警数量

## 7. 命令行与配置

`pyproject.toml` 新增命令：

```bash
opencanary-analytics
```

可用子命令：

```bash
opencanary-analytics init-db --db /var/lib/opencanary-analytics/events.sqlite3
opencanary-analytics ingest /var/tmp/opencanary.log --db /var/lib/opencanary-analytics/events.sqlite3
opencanary-analytics follow /var/tmp/opencanary.log --config analytics/analytics.example.json
opencanary-analytics report --db /var/lib/opencanary-analytics/events.sqlite3
opencanary-analytics prune --days 30 --db /var/lib/opencanary-analytics/events.sqlite3
opencanary-analytics verify /var/tmp/opencanary.log --db /var/lib/opencanary-analytics/events.sqlite3
```

新增示例：

- `analytics/analytics.example.json`
- `analytics/analytics.env.example`
- `docs/analytics.rst`

## 8. 测试与验收

新增：

```text
tests/analytics/test_analytics.py
```

覆盖项目：

- 敏感字段脱敏
- 长事件 ID 避免碰撞
- 扩展协议 logtype 分类
- 跨协议关联和评分
- 进程重启后的聚合恢复
- 部分日志行和检查点行为
- 1000 条模拟事件验收

已验证结果：

- 7 个 analytics 测试全部通过
- `python3 -m compileall -q opencanary_analytics` 通过
- `python3 -m opencanary_analytics --help` 通过
- 1000 条模拟事件：
  - 解析成功：1000 / 1000
  - 非法事件：0
  - 告警数：67
  - 相比每事件告警，告警数量下降超过 60%
  - SQLite 未发现密码明文

## 9. 发布状态

实现已提交到本地 Git 分支：

```text
feature/analytics-correlation-alerting
```

提交号：

```text
f2fd75d Add analytics correlation and alerting sidecar
```

推送到 GitHub 需要可用的 GitHub 凭据。认证后执行：

```bash
git push -u origin feature/analytics-correlation-alerting
```
