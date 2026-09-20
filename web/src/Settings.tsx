import { useState } from "react";
import {
  CheckCircle2,
  GitBranch as Github,
  Mail,
  Settings2,
} from "lucide-react";
import { api, useData, type Settings } from "./api";
import {
  AsyncForm,
  ErrorBox,
  Field,
  Loading,
  Notice,
  PageTitle,
} from "./components";

type SecretEdit = { mode: "keep" | "replace" | "clear"; value: string };
export function SettingsPage() {
  const settings = useData<Settings>("/v1/admin/settings");
  return (
    <>
      <PageTitle
        title="系统设置"
        caption="业务配置统一在这里管理，保存后即时生效。"
      />
      <ErrorBox error={settings.error} />
      {settings.loading ? (
        <Loading />
      ) : settings.data ? (
        <SettingsForm
          key={settings.data.revision}
          initial={settings.data}
          reload={settings.reload}
        />
      ) : null}
    </>
  );
}
function SettingsForm({
  initial,
  reload,
}: {
  initial: Settings;
  reload: () => void;
}) {
  const [s, setS] = useState(initial);
  const [gh, setGH] = useState<SecretEdit>({ mode: "keep", value: "" });
  const [resend, setResend] = useState<SecretEdit>({ mode: "keep", value: "" });
  const [days, setDays] = useState(initial.reminder_days.join(", "));
  const [test, setTest] = useState("");
  const [testError, setTestError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof Settings>(k: K, value: Settings[K]) =>
    setS((old) => ({ ...old, [k]: value }));
  return (
    <div className="settings-layout">
      <div>
        <AsyncForm
          label="保存系统设置"
          submit={async () => {
            const {
              github_id: _id,
              github_secret_configured: _gh,
              resend_key_configured: _re,
              ...body
            } = s;
            const payload = {
              ...body,
              reminder_days: days.trim()
                ? days.split(",").map((x) => Number(x.trim()))
                : [],
              ...(gh.mode === "replace"
                ? { github_secret: gh.value }
                : gh.mode === "clear"
                  ? { clear_github_secret: true }
                  : {}),
              ...(resend.mode === "replace"
                ? { resend_key: resend.value }
                : resend.mode === "clear"
                  ? { clear_resend_key: true }
                  : {}),
            };
            await api("/v1/admin/settings", "PUT", payload);
            setGH({ mode: "keep", value: "" });
            setResend({ mode: "keep", value: "" });
            reload();
          }}
        >
          <section className="panel settings-panel">
            <h2>
              <Settings2 size={19} />
              站点与 Owner
            </h2>
            <Field
              label="站点 URL"
              hint="HTTPS origin，用于 OAuth 回调和通知链接；本地允许 HTTP loopback。"
            >
              <input
                required
                type="url"
                value={s.public_url}
                onChange={(e) => set("public_url", e.target.value)}
              />
            </Field>
            <Field
              label="Owner 邮箱"
              hint="本地登录及通知收件人。更改邮箱不会更换已绑定的 GitHub ID。"
            >
              <input
                required
                type="email"
                value={s.owner_email}
                onChange={(e) => set("owner_email", e.target.value)}
              />
            </Field>
          </section>
          <section className="panel settings-panel">
            <div className="settings-heading">
              <h2>
                <Github size={19} />
                GitHub 登录
              </h2>
              <label className="check">
                <input
                  type="checkbox"
                  checked={s.github_enabled}
                  onChange={(e) => set("github_enabled", e.target.checked)}
                />
                启用
              </label>
            </div>
            <Field label="OAuth Client ID">
              <input
                value={s.github_client_id}
                onChange={(e) => set("github_client_id", e.target.value)}
                autoComplete="off"
              />
            </Field>
            <SecretField
              label="OAuth Client Secret"
              configured={initial.github_secret_configured}
              value={gh}
              setValue={setGH}
            />
            <div className="hint-box">
              <span>回调地址</span>
              <code>
                {s.public_url.replace(/\/$/, "")}/v1/auth/github/callback
              </code>
            </div>
            <p className="small muted">
              首次登录需要 GitHub 已验证邮箱与 Owner 邮箱一致。后续使用固定
              GitHub 用户 ID 验证。
            </p>
            <div className="inline">
              <span
                className={`badge ${initial.github_id ? "success-badge" : "muted-badge"}`}
              >
                {initial.github_id
                  ? `已绑定 ID ${initial.github_id}`
                  : "尚未绑定 GitHub"}
              </span>
              {initial.github_enabled ? (
                <a className="text-button" href="/v1/auth/github">
                  验证 / 绑定 GitHub
                </a>
              ) : null}
            </div>
          </section>
          <section className="panel settings-panel">
            <div className="settings-heading">
              <h2>
                <Mail size={19} />
                Resend 邮件通知
              </h2>
              <label className="check">
                <input
                  type="checkbox"
                  checked={s.resend_enabled}
                  onChange={(e) => set("resend_enabled", e.target.checked)}
                />
                启用
              </label>
            </div>
            {!initial.resend_enabled ? (
              <Notice>
                邮件通知尚未启用。配置并保存 Resend 后，服务会开始检查到期提醒。
              </Notice>
            ) : null}
            <SecretField
              label="Resend API Key"
              configured={initial.resend_key_configured}
              value={resend}
              setValue={setResend}
            />
            <Field label="发件地址" hint="必须使用 Resend 已验证的域名。">
              <input
                value={s.resend_from}
                onChange={(e) => set("resend_from", e.target.value)}
                placeholder="CIVault <alerts@example.com>"
              />
            </Field>
            <Field
              label="提前提醒天数"
              hint="默认提前 7、3、1 天各提醒一次；多个天数用逗号分隔。"
            >
              <input value={days} onChange={(e) => setDays(e.target.value)} />
            </Field>
            <label className="check">
              <input
                type="checkbox"
                checked={s.notify_on_expiry}
                onChange={(e) => set("notify_on_expiry", e.target.checked)}
              />
              到期时再次通知
            </label>
            <div className="inline test-mail">
              <button
                type="button"
                className="secondary"
                disabled={!initial.resend_enabled || busy}
                onClick={async () => {
                  setBusy(true);
                  setTest("");
                  setTestError("");
                  try {
                    await api("/v1/admin/notifications/test", "POST", {});
                    setTest("测试邮件已提交，请查看 Owner 收件箱。");
                  } catch (e) {
                    setTestError((e as Error).message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "发送中…" : "发送测试邮件"}
              </button>
              <span className="small muted">使用已保存的配置</span>
            </div>
            {test ? (
              <p className="success-text" role="status">
                {test}
              </p>
            ) : null}
            <ErrorBox error={testError} />
          </section>
          <section className="panel settings-panel">
            <h2>日志与保留策略</h2>
            <div className="form-grid">
              <Field label="运行日志级别">
                <select
                  value={s.log_level}
                  onChange={(e) => set("log_level", e.target.value)}
                >
                  {["debug", "info", "warn", "error"].map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </Field>
              <Field label="审计保留天数">
                <input
                  required
                  type="number"
                  min={1}
                  max={3650}
                  value={s.audit_retention_days}
                  onChange={(e) =>
                    set("audit_retention_days", Number(e.target.value))
                  }
                />
              </Field>
            </div>
          </section>
        </AsyncForm>
        <PasswordForm githubID={initial.github_id} reload={reload} />
      </div>
      <aside className="settings-aside">
        <div className="panel">
          <CheckCircle2 size={23} />
          <h3>加密保存配置</h3>
          <p>OAuth Secret 和 Resend API Key 由主密钥保护，保存后不再回显。</p>
          <p>
            保持不变不会重写凭证。只有明确选择“替换”或“清除”才会修改敏感字段。
          </p>
          <hr />
          <p>
            主密钥由 <code>CIVAULT_MASTER_KEY</code>{" "}
            注入，不能在页面查看或更换。
          </p>
          <small>当前配置版本 · {initial.revision}</small>
        </div>
      </aside>
    </div>
  );
}
function SecretField({
  label,
  configured,
  value,
  setValue,
}: {
  label: string;
  configured: boolean;
  value: SecretEdit;
  setValue: (v: SecretEdit) => void;
}) {
  return (
    <div className="secret-field">
      <div className="inline">
        <strong>{label}</strong>
        <span
          className={`badge ${configured ? "success-badge" : "muted-badge"}`}
        >
          {configured ? "已配置" : "未配置"}
        </span>
      </div>
      <select
        aria-label={`${label} 操作`}
        value={value.mode}
        onChange={(e) =>
          setValue({ mode: e.target.value as SecretEdit["mode"], value: "" })
        }
      >
        <option value="keep">保持不变</option>
        <option value="replace">替换为新凭证</option>
        <option value="clear">清除凭证</option>
      </select>
      {value.mode === "replace" ? (
        <input
          aria-label={`${label} 新值`}
          type="password"
          required
          autoComplete="new-password"
          value={value.value}
          onChange={(e) => setValue({ ...value, value: e.target.value })}
          placeholder="输入新凭证"
        />
      ) : null}
      {value.mode === "clear" ? (
        <p className="danger-text small">
          保存后会清除此凭证。请同时关闭对应功能。
        </p>
      ) : null}
    </div>
  );
}
function PasswordForm({
  githubID,
  reload,
}: {
  githubID: string;
  reload: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [unlink, setUnlink] = useState("");
  return (
    <section className="panel settings-panel">
      <h2>账户安全</h2>
      <AsyncForm
        label="修改密码并退出所有会话"
        submit={async () => {
          if (next !== confirm) throw new Error("两次输入的新密码不一致");
          await api("/v1/admin/password", "POST", {
            current_password: current,
            new_password: next,
          });
          setCurrent("");
          setNext("");
          setConfirm("");
          location.reload();
        }}
      >
        <Field label="当前密码">
          <input
            type="password"
            required
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </Field>
        <div className="form-grid">
          <Field label="新密码">
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </Field>
          <Field label="再次输入新密码">
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Field>
        </div>
        <p className="small muted">
          修改密码会撤销全部 Web 会话和 CLI 管理令牌。
        </p>
      </AsyncForm>
      {githubID ? (
        <AsyncForm
          label="解除 GitHub 绑定"
          submit={async () => {
            await api("/v1/admin/github-binding", "DELETE", {
              password: unlink,
            });
            setUnlink("");
            reload();
          }}
        >
          <Field label="验证本地密码以解除绑定">
            <input
              type="password"
              required
              autoComplete="current-password"
              value={unlink}
              onChange={(e) => setUnlink(e.target.value)}
            />
          </Field>
        </AsyncForm>
      ) : null}
    </section>
  );
}
