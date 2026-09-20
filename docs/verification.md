# 本地验证记录

日期：2026-09-19。宿主环境：Windows、Go 1.26.8。Action 额外在 Node 24.21.0 下实际运行，Web 生产资源也使用 Node 24 构建。Linux amd64 和 macOS arm64 服务端交叉编译通过，尚未在对应系统执行。

| 检查                                    | 结果                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `go test ./... -count=1`                | 23 个顶层测试通过，含 OIDC 条件子用例                                    |
| `go test -race ./internal/...`          | 通过                                                                     |
| `go vet ./...`                          | 通过                                                                     |
| Windows 服务端与 HTTP CLI 构建          | 通过                                                                     |
| Web TypeScript 与 Vite 生产构建         | 通过                                                                     |
| Action TypeScript、打包、进程/HTTP 测试 | 8 项通过，包含 Windows 取消处理                                          |
| Playwright 生产控制台 + 真实 Go API     | 全流程通过，包括 390px 移动端导航                                        |
| `agent-browser` 实际页面检查            | 初始化、登录和设置页面正常，无页面错误                                   |
| OpenAPI 3.1 验证及生成一致性            | 通过，无警告                                                             |
| GitHub Workflow actionlint              | 通过                                                                     |
| Docker Compose 配置校验                 | 通过                                                                     |
| Go 容器构建镜像 manifest                | 确认 `golang:1.26.8-alpine` 存在                                         |
| 缺少主密钥启动                          | 正确以退出码 1 拒绝启动                                                  |
| Go 漏洞调用分析                         | 当前代码和导入包无受影响漏洞；x/crypto 模块包含未使用的 OpenPGP 弃用通告 |

Go 测试包括加密篡改与上下文隔离、配置持久化和并发版本、敏感字段不可回显、Tag OR、动态标签与 Key 禁用、整个请求失败、并发三次防重放、版本固定、JWKS 轮换/缓存/失效、RS256 算法限制、GitHub 邮箱验证和数字 ID 绑定、改邮箱不改变绑定、CSRF、会话过期和管理令牌撤销、密码修改撤销会话、审计失败拒绝发放、通知改期/配置变化/重启/超时/去重、Resend/AgentMail 切换与凭证隔离、旧库邮件配置迁移以及实际 SQLite 快照恢复。

浏览器测试覆盖初始化、密码登录、Tag 和 Key 创建、版本更新及到期设置、规则覆盖预览与版本、引用 Tag 删除保护、敏感配置保持/替换、邮件发送商切换与独立凭证保存/清除、两页面修改冲突、管理令牌一次显示与撤销、审计导出、未启用通知提示、移动端和退出登录。

以下验证需要外部环境，**本地未声称已经执行**：

- 当前 Docker daemon 未启动，尚未实际构建/运行容器；已提供 `scripts/docker-smoke.mjs`，CI 会执行容器重启、持久化、错误主密钥及备份恢复验收。
- Linux/macOS 的实际 Runner 测试和三平台真实 OIDC 读取，需要将源码提交到 GitHub 并运行已有 CI / 手动 OIDC 工作流。
- 真实 GitHub OAuth App 登录和真实 Resend / AgentMail 投递，需要在页面配置操作者自己的凭证与 Resend 已验证域名或 AgentMail Inbox。本地覆盖了协议和故障模拟，不发送真实邮件。

截图仅使用测试生成的合成数据，不包含 Key 明文、管理令牌或真实第三方凭证。
