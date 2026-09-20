import { useEffect, useState } from "react";
import {
  ArrowUpRight,
  Bell,
  BookOpen,
  GitBranch as Github,
  KeyRound,
  Layers,
  LogOut,
  Plus,
  Settings2,
  ShieldCheck,
  Tag as TagIcon,
  Terminal,
  Menu,
} from "lucide-react";
import { api, setCSRF, useData, type Workspace } from "./api";
import {
  AsyncForm,
  ErrorBox,
  Field,
  Loading,
  Modal,
  Notice,
} from "./components";
import { KeysPage, TagsPage } from "./Keys";
import { PoliciesPage } from "./Policies";
import { SettingsPage } from "./Settings";
import { AuditPage, NotificationsPage, TokensPage } from "./Records";

interface Session {
  email: string;
  csrf_token: string;
}
const nav = [
  { id: "keys", label: "密钥", icon: KeyRound },
  { id: "tags", label: "标签", icon: TagIcon },
  { id: "policies", label: "授权规则", icon: ShieldCheck },
  { id: "audit", label: "审计日志", icon: BookOpen },
  { id: "notifications", label: "通知记录", icon: Bell },
  { id: "tokens", label: "CLI 令牌", icon: Terminal },
  { id: "settings", label: "系统设置", icon: Settings2 },
];

export default function App() {
  const [status, setStatus] = useState<{
    initialized: boolean;
    github_enabled: boolean;
  }>();
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    api<{ initialized: boolean; github_enabled: boolean }>("/v1/status")
      .then(async (status) => {
        if (!active) return;
        setStatus(status);
        if (status.initialized) {
          try {
            const s = await api<Session>("/v1/auth/me");
            if (active) {
              setCSRF(s.csrf_token);
              setSession(s);
            }
          } catch {
            /* An anonymous session is expected before login. */
          }
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setReady(true);
      });
    const expired = () => {
      setCSRF("");
      setSession(null);
    };
    window.addEventListener("session-expired", expired);
    return () => {
      active = false;
      window.removeEventListener("session-expired", expired);
    };
  }, []);
  if (!ready) return <Loading />;
  if (error)
    return (
      <main className="auth-page">
        <ErrorBox error={error} />
        <button onClick={() => location.reload()}>重试</button>
      </main>
    );
  if (!status?.initialized)
    return (
      <Auth
        setup
        onDone={() => {
          setStatus({ initialized: true, github_enabled: false });
          location.assign("/");
        }}
      />
    );
  if (!session)
    return (
      <Auth
        github={status.github_enabled}
        onDone={(s) => {
          if (s) {
            setCSRF(s.csrf_token);
            setSession(s);
          }
        }}
      />
    );
  return (
    <Dashboard
      session={session}
      logout={async () => {
        await api("/v1/auth/logout", "POST", {});
        setStatus(await api("/v1/status"));
        setCSRF("");
        setSession(null);
      }}
    />
  );
}
function Auth({
  setup = false,
  github = false,
  onDone,
}: {
  setup?: boolean;
  github?: boolean;
  onDone: (s?: Session) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [url, setURL] = useState(location.origin);
  return (
    <main className="auth-page">
      <div className="auth-brand">
        <ShieldCheck size={30} />
        <span>CIVault</span>
      </div>
      <div className="auth-card">
        <p className="eyebrow">YOUR CI. YOUR SECRETS.</p>
        <h1>{setup ? "初始化你的密钥空间" : "欢迎回来"}</h1>
        <p className="muted">
          {setup
            ? "创建 Owner 账户，连接你的 CI 工作流。"
            : "登录管理密钥、授权规则与工作流访问。"}
        </p>
        <AsyncForm
          label={setup ? "创建密钥空间" : "登录"}
          submit={async () => {
            if (setup) {
              await api("/v1/setup", "POST", {
                code,
                email,
                password,
                public_url: url,
              });
              setPassword("");
              setCode("");
              onDone();
            } else {
              const s = await api<Session>("/v1/auth/login", "POST", {
                email,
                password,
              });
              setPassword("");
              onDone(s);
            }
          }}
        >
          {setup ? (
            <>
              <Notice>
                在容器内读取 <code>/data/setup-token</code>{" "}
                获取一次性初始化码。完成后初始化入口将关闭。
              </Notice>
              <Field label="初始化码">
                <input
                  required
                  type="password"
                  autoComplete="off"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </Field>
              <Field
                label="站点地址"
                hint="公开访问使用 HTTPS；本地开发支持 localhost。"
              >
                <input
                  required
                  type="url"
                  value={url}
                  onChange={(e) => setURL(e.target.value)}
                />
              </Field>
            </>
          ) : null}
          <Field label="Owner 邮箱">
            <input
              required
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
          <Field
            label="密码"
            hint={setup ? "至少 12 个字符，请使用独立的长密码。" : undefined}
          >
            <input
              required
              type="password"
              minLength={setup ? 12 : undefined}
              autoComplete={setup ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
        </AsyncForm>
        {github ? (
          <a className="button github-login" href="/v1/auth/github">
            <Github size={18} />
            使用 GitHub 登录
            <ArrowUpRight size={16} />
          </a>
        ) : null}
      </div>
      <p className="auth-footer">以 OIDC 连接工作流 · 为每次读取保留审计</p>
    </main>
  );
}
function Dashboard({
  session,
  logout,
}: {
  session: Session;
  logout: () => Promise<void>;
}) {
  const spaces = useData<Workspace[]>("/v1/admin/workspaces");
  const [ws, setWS] = useState(
    () => localStorage.getItem("civault.workspace") || "ws_default",
  );
  const [page, setPage] = useState(() => location.hash.slice(1) || "keys");
  const [create, setCreate] = useState(false);
  const [name, setName] = useState("");
  const [menu, setMenu] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const h = () => {
      setPage(location.hash.slice(1) || "keys");
      setMenu(false);
    };
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  const selected = spaces.data?.some((x) => x.id === ws)
    ? ws
    : spaces.data?.[0]?.id || "ws_default";
  return (
    <div className="app-shell">
      <aside className={menu ? "sidebar open" : "sidebar"}>
        <a className="brand" href="#keys">
          <span className="brand-mark">
            <ShieldCheck size={22} />
          </span>
          <strong>CIVault</strong>
          <span className="version-pill">v1</span>
        </a>
        <div className="sidebar-label">密钥管理</div>
        <nav>
          {nav.map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              aria-current={page === item.id ? "page" : undefined}
              className={page === item.id ? "nav-link active" : "nav-link"}
            >
              <item.icon size={18} />
              {item.label}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="status-dot" />
          <span>GitHub OIDC 身份验证</span>
          <small>无 CI 长期访问凭证</small>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="导航菜单"
            onClick={() => setMenu(!menu)}
          >
            <Menu size={20} />
          </button>
          <div className="workspace-switch">
            <Layers size={17} />
            <select
              aria-label="工作区"
              value={selected}
              onChange={(e) => {
                setWS(e.target.value);
                localStorage.setItem("civault.workspace", e.target.value);
              }}
            >
              {spaces.data?.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
            <button
              className="icon-button"
              aria-label="创建工作区"
              onClick={() => setCreate(true)}
            >
              <Plus size={16} />
            </button>
          </div>
          <div className="account">
            <span className="avatar">{session.email[0]?.toUpperCase()}</span>
            <span>{session.email}</span>
            <span className="owner-label">OWNER</span>
            <button
              className="icon-button"
              aria-label="退出登录"
              onClick={() => logout().catch((e) => setError(e.message))}
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <main className="content">
          <ErrorBox error={error || spaces.error} />
          {page === "tags" ? (
            <TagsPage key={selected} ws={selected} />
          ) : page === "policies" ? (
            <PoliciesPage key={selected} ws={selected} />
          ) : page === "settings" ? (
            <SettingsPage />
          ) : page === "audit" ? (
            <AuditPage />
          ) : page === "notifications" ? (
            <NotificationsPage />
          ) : page === "tokens" ? (
            <TokensPage />
          ) : (
            <KeysPage key={selected} ws={selected} />
          )}
        </main>
        <footer className="footer">
          CIVault <span>密钥始终加密存储，访问始终经过授权。</span>
        </footer>
      </div>
      {create ? (
        <Modal title="创建工作区" onClose={() => setCreate(false)}>
          <AsyncForm
            onCancel={() => setCreate(false)}
            submit={async () => {
              const v = await api<Workspace>("/v1/admin/workspaces", "POST", {
                name,
              });
              setWS(v.id);
              spaces.reload();
              setCreate(false);
              setName("");
            }}
          >
            <Field label="工作区名称">
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如：生产环境"
              />
            </Field>
          </AsyncForm>
        </Modal>
      ) : null}
    </div>
  );
}
