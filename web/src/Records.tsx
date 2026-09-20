import { useState } from "react";
import { Download, Plus, RefreshCw } from "lucide-react";
import { api, downloadJSON, formatDate, useData, type Settings } from "./api";
import {
  AsyncForm,
  CopyButton,
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  Notice,
  PageTitle,
} from "./components";

interface Audit {
  id: string;
  created_at: number;
  request_id: string;
  actor: string;
  event: string;
  decision: string;
  workspace_id: string;
  details: unknown;
}
export function AuditPage() {
  const [decision, setDecision] = useState("");
  const [event, setEvent] = useState("");
  const [repository, setRepository] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const filters = new URLSearchParams({
    decision,
    event,
    repository_id: repository,
    ...(from ? { from: new Date(from).toISOString() } : {}),
    ...(to ? { to: new Date(to).toISOString() } : {}),
  });
  const path = `/v1/admin/audit-events?${filters}&limit=100&offset=${offset}`;
  const records = useData<Audit[]>(path);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);
  return (
    <>
      <PageTitle
        title="审计日志"
        caption="追踪管理操作和 GitHub 工作流的每一次访问决策。"
      >
        <button className="secondary" onClick={records.reload}>
          <RefreshCw size={16} />
          刷新
        </button>
        <button
          className="secondary"
          disabled={exporting}
          onClick={async () => {
            setExporting(true);
            try {
              const all: Audit[] = [];
              const bound = filters.get("to") || new Date().toISOString();
              for (let offset = 0; ; offset += 1000) {
                const q = new URLSearchParams(filters);
                q.set("to", bound);
                q.set("limit", "1000");
                q.set("offset", String(offset));
                const page = await api<Audit[]>(`/v1/admin/audit-events?${q}`);
                all.push(...page);
                if (page.length < 1000) break;
              }
              downloadJSON("civault-audit.json", all);
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setExporting(false);
            }
          }}
        >
          <Download size={16} />
          {exporting ? "导出中…" : "导出 JSON"}
        </button>
      </PageTitle>
      <section className="panel">
        <div className="filters">
          <Field label="访问决策">
            <select
              value={decision}
              onChange={(e) => {
                setDecision(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">全部</option>
              <option value="allow">允许</option>
              <option value="deny">拒绝</option>
            </select>
          </Field>
          <Field label="事件">
            <input
              placeholder="runtime.resolve"
              value={event}
              onChange={(e) => {
                setEvent(e.target.value);
                setOffset(0);
              }}
            />
          </Field>
          <Field label="仓库 ID">
            <input
              value={repository}
              onChange={(e) => {
                setRepository(e.target.value);
                setOffset(0);
              }}
            />
          </Field>
          <Field label="开始时间">
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => {
                setFrom(e.target.value);
                setOffset(0);
              }}
            />
          </Field>
          <Field label="结束时间">
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => {
                setTo(e.target.value);
                setOffset(0);
              }}
            />
          </Field>
        </div>
        <ErrorBox error={error || records.error} />
        {records.loading ? (
          <Loading />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>事件</th>
                  <th>操作者</th>
                  <th>决策</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                {records.data?.map((x) => (
                  <tr key={x.id}>
                    <td className="nowrap">{formatDate(x.created_at)}</td>
                    <td>
                      <code>{x.event}</code>
                    </td>
                    <td className="small">{x.actor}</td>
                    <td>
                      <span
                        className={`badge ${x.decision === "allow" ? "success-badge" : "warning-badge"}`}
                      >
                        {x.decision === "allow" ? "允许" : "拒绝"}
                      </span>
                    </td>
                    <td>
                      <details>
                        <summary>查看</summary>
                        <p className="small">{x.request_id}</p>
                        <pre>{JSON.stringify(x.details, null, 2)}</pre>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!records.data?.length ? (
              <Empty
                text="没有符合条件的审计记录"
                description="尝试调整时间范围、事件或访问决策。管理操作与工作流访问会自动记录。"
              />
            ) : null}
          </div>
        )}
        <div className="pagination">
          <span className="muted">第 {Math.floor(offset / 100) + 1} 页</span>
          <button
            className="secondary small"
            disabled={!offset}
            onClick={() => setOffset((x) => x - 100)}
          >
            上一页
          </button>
          <button
            className="secondary small"
            disabled={(records.data?.length || 0) < 100}
            onClick={() => setOffset((x) => x + 100)}
          >
            下一页
          </button>
        </div>
      </section>
    </>
  );
}
interface Notification {
  id: string;
  path: string;
  threshold: number;
  status: string;
  attempts: number;
  created_at: number;
  sent_at: number | null;
  provider_id: string;
  last_error: string;
}
const notificationNames: Record<string, string> = {
  pending: "待发送",
  sending: "发送中",
  retry: "等待重试",
  sent: "已发送",
  cancelled: "已取消",
  failed: "发送失败",
  needs_attention: "需要处理",
};
export function NotificationsPage() {
  const [offset, setOffset] = useState(0);
  const data = useData<Notification[]>(
    `/v1/admin/notifications?limit=100&offset=${offset}`,
  );
  const settings = useData<Settings>("/v1/admin/settings");
  return (
    <>
      <PageTitle
        title="通知记录"
        caption="查看 Key 到期提醒、发送状态和重试结果。"
      >
        <button className="secondary" onClick={data.reload}>
          <RefreshCw size={16} />
          刷新
        </button>
      </PageTitle>
      {settings.data && !settings.data.resend_enabled ? (
        <Notice>
          邮件通知未启用。前往 <a href="#settings">系统设置</a> 配置 Resend；Key
          到期后仍会停止发放。
        </Notice>
      ) : null}
      <ErrorBox error={data.error} />
      <section className="panel">
        {data.loading ? (
          <Loading />
        ) : !data.data?.length ? (
          <Empty
            text="暂无到期通知"
            description="密钥达到提醒时间后，发送进度与结果会显示在这里。"
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>提醒档位</th>
                  <th>状态</th>
                  <th>尝试次数</th>
                  <th>时间 / 结果</th>
                </tr>
              </thead>
              <tbody>
                {data.data.map((n) => (
                  <tr key={n.id}>
                    <td>
                      <code>{n.path}</code>
                    </td>
                    <td>{n.threshold ? `提前 ${n.threshold} 天` : "已到期"}</td>
                    <td>
                      <span
                        className={`badge ${n.status === "sent" ? "success-badge" : n.status === "failed" || n.status === "needs_attention" ? "warning-badge" : "muted-badge"}`}
                      >
                        {notificationNames[n.status] || n.status}
                      </span>
                    </td>
                    <td>{n.attempts}</td>
                    <td>
                      {formatDate(n.sent_at || n.created_at)}
                      <small className="date-small">
                        {n.last_error || n.provider_id}
                      </small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pagination">
          <button
            className="secondary small"
            disabled={!offset}
            onClick={() => setOffset((x) => x - 100)}
          >
            上一页
          </button>
          <button
            className="secondary small"
            disabled={(data.data?.length || 0) < 100}
            onClick={() => setOffset((x) => x + 100)}
          >
            下一页
          </button>
        </div>
      </section>
    </>
  );
}
interface Token {
  id: string;
  name: string;
  created_at: number;
  expires_at: number;
  revoked: number;
}
export function TokensPage() {
  const tokens = useData<Token[]>("/v1/admin/tokens");
  const [create, setCreate] = useState(false);
  const [name, setName] = useState("");
  const [days, setDays] = useState(30);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  return (
    <>
      <PageTitle
        title="CLI 管理令牌"
        caption="让本地 CLI 通过 HTTP 管理资源。令牌不用于 GitHub CI。"
      >
        <button onClick={() => setCreate(true)}>
          <Plus size={17} />
          创建令牌
        </button>
      </PageTitle>
      <ErrorBox error={error || tokens.error} />
      <section className="panel">
        {tokens.loading ? (
          <Loading />
        ) : !tokens.data?.length ? (
          <Empty
            text="还没有管理令牌"
            description="创建一个令牌，让本地 CLI 安全连接你的 CIVault。"
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>创建时间</th>
                  <th>到期时间</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {tokens.data.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <strong>{t.name}</strong>
                    </td>
                    <td>{formatDate(t.created_at)}</td>
                    <td>{formatDate(t.expires_at)}</td>
                    <td>
                      <span
                        className={`badge ${t.revoked || t.expires_at < Date.now() / 1000 ? "muted-badge" : "success-badge"}`}
                      >
                        {t.revoked
                          ? "已撤销"
                          : t.expires_at < Date.now() / 1000
                            ? "已到期"
                            : "有效"}
                      </span>
                    </td>
                    <td>
                      <button
                        className="text-button danger-text"
                        disabled={!!t.revoked}
                        onClick={async () => {
                          if (
                            !confirm(
                              `撤销令牌 ${t.name}？使用该令牌的 CLI 将立即失去访问权限。`,
                            )
                          )
                            return;
                          try {
                            await api("/v1/admin/tokens/" + t.id, "DELETE");
                            tokens.reload();
                          } catch (e) {
                            setError((e as Error).message);
                          }
                        }}
                      >
                        撤销
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <div className="panel code-panel">
        <h3>连接本地 CLI</h3>
        <pre>{`# 设置 CIVAULT_ADMIN_TOKEN 后执行\ncivault config --server ${location.origin} --workspace ws_default\ncivault key list\ncivault key put shared/npm-token --stdin`}</pre>
      </div>
      {create ? (
        <Modal title="创建管理令牌" onClose={() => setCreate(false)}>
          <AsyncForm
            onCancel={() => setCreate(false)}
            submit={async () => {
              const r = await api<{ token: string }>(
                "/v1/admin/tokens",
                "POST",
                { name, days },
              );
              setSecret(r.token);
              setCreate(false);
              setName("");
              tokens.reload();
            }}
          >
            <Field label="名称">
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="我的笔记本"
              />
            </Field>
            <Field label="有效天数">
              <input
                type="number"
                required
                min={1}
                max={365}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              />
            </Field>
          </AsyncForm>
        </Modal>
      ) : null}
      {secret ? (
        <Modal title="令牌已创建" onClose={() => setSecret("")}>
          <Notice>此令牌只显示一次。请妥善保存，关闭后无法再次查看。</Notice>
          <pre className="token-value">{secret}</pre>
          <CopyButton text={secret} label="复制令牌" />
          <div className="form-actions">
            <button onClick={() => setSecret("")}>已保存，关闭</button>
          </div>
        </Modal>
      ) : null}
    </>
  );
}
