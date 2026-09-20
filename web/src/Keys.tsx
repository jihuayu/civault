import { useState } from "react";
import {
  ArrowUpRight,
  Clock3,
  Code2,
  History,
  KeyRound,
  Plus,
  Search,
  ShieldCheck,
  Tag as TagIcon,
  Trash2,
} from "lucide-react";
import {
  api,
  formatDate,
  isoDate,
  localDate,
  useData,
  wsBase,
  type KeyItem,
  type Settings,
  type Tag,
  type Version,
} from "./api";
import {
  AsyncForm,
  CheckList,
  CopyButton,
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  Notice,
  PageTitle,
} from "./components";

export function KeysPage({ ws }: { ws: string }) {
  const keys = useData<KeyItem[]>(wsBase(ws) + "/keys");
  const tags = useData<Tag[]>(wsBase(ws) + "/tags");
  const settings = useData<Settings>("/v1/admin/settings");
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<KeyItem | "new" | null>(null);
  const [history, setHistory] = useState<KeyItem | null>(null);
  const [tagKey, setTagKey] = useState<KeyItem | null>(null);
  const [using, setUsing] = useState<KeyItem | null>(null);
  const [error, setError] = useState("");
  const list = keys.data || [];
  const filtered = list.filter((k) =>
    (k.path + " " + k.tags.map((t) => t.name).join(" "))
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const now = Date.now() / 1000;
  const expiring = list.filter(
    (k) => !k.disabled && k.expires_at && k.expires_at < now + 7 * 86400,
  ).length;
  async function mutate(k: KeyItem, remove = false) {
    if (
      remove &&
      !confirm(`删除 ${k.path}？历史版本将保留用于审计，工作流将无法继续读取。`)
    )
      return;
    try {
      await api(
        wsBase(ws) + "/keys/" + k.id,
        remove ? "DELETE" : "PATCH",
        remove ? undefined : { disabled: !k.disabled },
      );
      keys.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <>
      <PageTitle
        title="密钥"
        caption="集中保存 CI 凭证，按工作负载授予访问权限。"
      >
        <button onClick={() => setEditing("new")}>
          <Plus size={17} />
          创建密钥
        </button>
      </PageTitle>
      <div className="stats">
        <div className="stat">
          <div>
            <span>密钥总数</span>
            <strong>{list.length.toString().padStart(2, "0")}</strong>
          </div>
          <KeyRound />
        </div>
        <div className="stat">
          <div>
            <span>已启用</span>
            <strong>
              {list
                .filter(
                  (k) => !k.disabled && (!k.expires_at || k.expires_at > now),
                )
                .length.toString()
                .padStart(2, "0")}
            </strong>
          </div>
          <ShieldCheck />
        </div>
        <div className="stat">
          <div>
            <span>7 天内到期 / 已到期</span>
            <strong>{expiring.toString().padStart(2, "0")}</strong>
          </div>
          <Clock3 />
        </div>
      </div>
      <ErrorBox error={error || keys.error} />
      <section className="panel">
        <div className="panel-toolbar">
          <div>
            <strong>所有密钥</strong>
            <span className="count">{list.length}</span>
          </div>
          <label className="search">
            <Search size={17} />
            <input
              aria-label="搜索密钥"
              placeholder="搜索路径或标签…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
        </div>
        {keys.loading ? (
          <Loading />
        ) : !filtered.length ? (
          <Empty
            text={search ? "没有匹配的密钥" : "还没有密钥"}
            action={
              !search ? (
                <button onClick={() => setEditing("new")}>
                  <Plus size={16} />
                  创建第一个密钥
                </button>
              ) : undefined
            }
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>密钥路径</th>
                  <th>标签</th>
                  <th>版本</th>
                  <th>状态 / 有效期</th>
                  <th className="right">操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <button
                        className="text-button key-path"
                        onClick={() => setHistory(k)}
                      >
                        <span className="key-icon">
                          <KeyRound size={17} />
                        </span>
                        {k.path}
                      </button>
                      <small className="resource-id">
                        {k.id.slice(0, 18)}…
                      </small>
                    </td>
                    <td>
                      <button
                        className="tag-group"
                        onClick={() => setTagKey(k)}
                        aria-label={`管理 ${k.path} 的标签`}
                      >
                        {k.tags.length ? (
                          k.tags.map((t) => (
                            <span className="tag" key={t.id}>
                              {t.name}
                            </span>
                          ))
                        ) : (
                          <span className="muted">
                            <Plus size={12} /> 添加标签
                          </span>
                        )}
                      </button>
                    </td>
                    <td>
                      <span className="version">v{k.version}</span>
                    </td>
                    <td>
                      <span
                        className={`badge ${k.disabled || (k.expires_at && k.expires_at <= now) ? "muted-badge" : k.expires_at && k.expires_at < now + 7 * 86400 ? "warning-badge" : "success-badge"}`}
                      >
                        {k.disabled
                          ? "已禁用"
                          : k.expires_at && k.expires_at <= now
                            ? "已到期"
                            : k.expires_at && k.expires_at < now + 7 * 86400
                              ? "即将到期"
                              : "可用"}
                      </span>
                      <small className="date-small">
                        {k.expires_at ? formatDate(k.expires_at) : "无到期时间"}
                      </small>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="text-button"
                          onClick={() => setEditing(k)}
                        >
                          更新
                        </button>
                        <button
                          className="icon-button"
                          title="使用示例"
                          aria-label={`使用 ${k.path}`}
                          onClick={() => setUsing(k)}
                        >
                          <Code2 size={16} />
                        </button>
                        <button
                          className="icon-button"
                          title="版本记录"
                          aria-label={`${k.path} 版本记录`}
                          onClick={() => setHistory(k)}
                        >
                          <History size={16} />
                        </button>
                        <details className="row-menu">
                          <summary aria-label="更多操作">···</summary>
                          <div>
                            <button onClick={() => mutate(k)}>
                              {k.disabled ? "启用" : "禁用"}
                            </button>
                            <button
                              className="danger-text"
                              onClick={() => mutate(k, true)}
                            >
                              删除
                            </button>
                          </div>
                        </details>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="panel-note">
          <ShieldCheck size={14} />
          Key 值加密保存；只有命中授权规则的工作流才能读取。
        </div>
      </section>
      {editing ? (
        <KeyEditor
          key={editing === "new" ? "new" : editing.id}
          ws={ws}
          item={editing === "new" ? undefined : editing}
          close={() => setEditing(null)}
          done={() => {
            keys.reload();
            setEditing(null);
          }}
        />
      ) : null}
      {tagKey ? (
        <TagEditor
          ws={ws}
          item={tagKey}
          tags={tags.data || []}
          close={() => setTagKey(null)}
          done={() => {
            keys.reload();
            setTagKey(null);
          }}
        />
      ) : null}
      {history ? (
        <VersionHistory
          ws={ws}
          item={history}
          close={() => setHistory(null)}
          changed={keys.reload}
        />
      ) : null}
      {using ? (
        <Usage
          ws={ws}
          item={using}
          server={settings.data?.public_url || location.origin}
          close={() => setUsing(null)}
        />
      ) : null}
    </>
  );
}
function KeyEditor({
  ws,
  item,
  close,
  done,
}: {
  ws: string;
  item?: KeyItem;
  close: () => void;
  done: () => void;
}) {
  const [path, setPath] = useState(item?.path || "");
  const [value, setValue] = useState("");
  const [expiry, setExpiry] = useState(localDate(item?.expires_at || null));
  const [idem] = useState(() => crypto.randomUUID());
  return (
    <Modal title={item ? "创建新版本" : "创建密钥"} onClose={close}>
      <AsyncForm
        label={item ? "加密保存新版本" : "创建密钥"}
        onCancel={close}
        submit={async () => {
          await api(
            wsBase(ws) + "/keys",
            "POST",
            { path, value, expires_at: isoDate(expiry) },
            undefined,
            { "Idempotency-Key": idem },
          );
          setValue("");
          done();
        }}
      >
        <Field
          label="密钥路径"
          hint="例如 shared/npm-token；工作流使用此路径引用。"
        >
          <input
            required
            readOnly={!!item}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="shared/npm-token"
          />
        </Field>
        <Field
          label="密钥值"
          hint="保存后无法在控制台再次查看。支持多行 UTF-8 文本。"
        >
          <textarea
            required
            rows={5}
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="粘贴 Token 或凭证…"
          />
        </Field>
        <Field
          label="到期时间（本地时区）"
          hint="可留空；到期后停止发放此版本。"
        >
          <input
            type="datetime-local"
            value={expiry}
            onChange={(e) => setExpiry(e.target.value)}
          />
        </Field>
        {item ? (
          <Notice>保存会创建并激活新版本，旧版本的密文保持不变。</Notice>
        ) : (
          <Notice>创建后为 Key 设置标签或直接授权，工作流才可读取。</Notice>
        )}
      </AsyncForm>
    </Modal>
  );
}
function TagEditor({
  ws,
  item,
  tags,
  close,
  done,
}: {
  ws: string;
  item: KeyItem;
  tags: Tag[];
  close: () => void;
  done: () => void;
}) {
  const [selected, setSelected] = useState(item.tags.map((t) => t.id));
  return (
    <Modal title="管理 Key 标签" onClose={close}>
      <p className="mono">{item.path}</p>
      <AsyncForm
        onCancel={close}
        submit={async () => {
          await api(wsBase(ws) + "/keys/" + item.id + "/tags", "PUT", {
            tag_ids: selected,
          });
          done();
        }}
      >
        <CheckList items={tags} selected={selected} onChange={setSelected} />
        <Notice>
          标签变更会立即影响按 Tag 授权的规则。多个标签采用任意匹配。
        </Notice>
      </AsyncForm>
    </Modal>
  );
}
function VersionHistory({
  ws,
  item,
  close,
  changed,
}: {
  ws: string;
  item: KeyItem;
  close: () => void;
  changed: () => void;
}) {
  const base = wsBase(ws) + "/keys/" + item.id;
  const versions = useData<Version[]>(base + "/versions");
  const [error, setError] = useState("");
  return (
    <Modal title={`版本记录 · ${item.path}`} wide onClose={close}>
      <ErrorBox error={error || versions.error} />
      {versions.loading ? (
        <Loading />
      ) : (
        versions.data?.map((v) => (
          <div className="version-row" key={v.id}>
            <div>
              <strong>v{v.number}</strong>{" "}
              {v.active ? (
                <span className="badge success-badge">当前版本</span>
              ) : null}
              <small className="date-small">
                创建于 {formatDate(v.created_at)}
              </small>
              <code>{v.id}</code>
            </div>
            <VersionExpiry
              version={v}
              save={async (expires) => {
                await api(base + "/versions/" + v.id, "PATCH", {
                  expires_at: expires,
                });
                versions.reload();
                changed();
              }}
            />
            <button
              className="secondary small"
              disabled={!!v.active}
              onClick={async () => {
                if (!confirm(`激活 v${v.number}？后续首次读取会使用此版本。`))
                  return;
                try {
                  await api(
                    base + "/versions/" + v.id + "/activate",
                    "POST",
                    {},
                  );
                  versions.reload();
                  changed();
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              激活
            </button>
          </div>
        ))
      )}
    </Modal>
  );
}
function VersionExpiry({
  version,
  save,
}: {
  version: Version;
  save: (expiry: string | null) => Promise<void>;
}) {
  const [value, setValue] = useState(localDate(version.expires_at));
  const [error, setError] = useState("");
  return (
    <div className="version-expiry">
      <Field label="有效期">
        <input
          type="datetime-local"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
      </Field>
      <button
        className="text-button"
        onClick={() => save(isoDate(value)).catch((e) => setError(e.message))}
      >
        保存有效期
      </button>
      <ErrorBox error={error} />
    </div>
  );
}
function Usage({
  ws,
  item,
  server,
  close,
}: {
  ws: string;
  item: KeyItem;
  server: string;
  close: () => void;
}) {
  const ref = `cv://${ws}/${item.path.split("/").map(encodeURIComponent).join("/")}`;
  const example = `permissions:\n  contents: read\n  id-token: write\n\nsteps:\n  - uses: your-org/civault@<FULL_COMMIT_SHA>\n    with:\n      server: ${server}\n      workspace: ${ws}\n      export-env: true\n    env:\n      SECRET_VALUE: ${ref}\n\n  - run: ./deploy.sh`;
  return (
    <Modal title="在 GitHub Actions 中使用" wide onClose={close}>
      <div className="code-heading">
        <code>{ref}</code>
        <CopyButton text={ref} label="复制引用" />
      </div>
      <pre>{example}</pre>
      <CopyButton text={example} label="复制 Workflow 示例" />
      <Notice>
        将 Action 地址替换为你发布的仓库和完整提交 SHA。工作流需要命中该 Key
        的授权规则。
      </Notice>
    </Modal>
  );
}
export function TagsPage({ ws }: { ws: string }) {
  const tags = useData<Tag[]>(wsBase(ws) + "/tags");
  const keys = useData<KeyItem[]>(wsBase(ws) + "/keys");
  const [editing, setEditing] = useState<Tag | "new" | null>(null);
  const [error, setError] = useState("");
  return (
    <>
      <PageTitle
        title="标签"
        caption="按用途组织 Key，通过任意匹配的标签规则批量授权。"
      >
        <button onClick={() => setEditing("new")}>
          <Plus size={17} />
          创建标签
        </button>
      </PageTitle>
      <Notice>
        一条规则选择多个 Tag 时，拥有任意一个 Tag 的 Key
        都在目标范围内。标签成员变化立即生效。
      </Notice>
      <ErrorBox error={error || tags.error} />
      <div className="tag-grid">
        {tags.loading ? (
          <Loading />
        ) : (
          tags.data?.map((tag) => (
            <article className="panel tag-card" key={tag.id}>
              <div className="tag-card-top">
                <span className="tag-symbol">
                  <TagIcon size={22} />
                </span>
                <button
                  className="icon-button danger-text"
                  aria-label={`删除标签 ${tag.name}`}
                  onClick={async () => {
                    if (
                      !confirm(
                        `删除标签 ${tag.name}？正在被规则引用的标签不能删除。`,
                      )
                    )
                      return;
                    try {
                      await api(wsBase(ws) + "/tags/" + tag.id, "DELETE");
                      tags.reload();
                      keys.reload();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  <Trash2 size={16} />
                </button>
              </div>
              <h3>{tag.name}</h3>
              <p className="muted">
                {keys.data?.filter((k) => k.tags.some((t) => t.id === tag.id))
                  .length || 0}{" "}
                个 Key
              </p>
              <code className="resource-id">{tag.id}</code>
              <button className="text-button" onClick={() => setEditing(tag)}>
                重命名 <ArrowUpRight size={14} />
              </button>
            </article>
          ))
        )}
      </div>
      {!tags.loading && !tags.data?.length ? (
        <Empty
          text="还没有标签"
          action={<button onClick={() => setEditing("new")}>创建标签</button>}
        />
      ) : null}
      {editing ? (
        <TagForm
          key={editing === "new" ? "new" : editing.id}
          ws={ws}
          item={editing === "new" ? undefined : editing}
          close={() => setEditing(null)}
          done={() => {
            tags.reload();
            setEditing(null);
          }}
        />
      ) : null}
    </>
  );
}
function TagForm({
  ws,
  item,
  close,
  done,
}: {
  ws: string;
  item?: Tag;
  close: () => void;
  done: () => void;
}) {
  const [name, setName] = useState(item?.name || "");
  return (
    <Modal title={item ? "重命名标签" : "创建标签"} onClose={close}>
      <AsyncForm
        onCancel={close}
        submit={async () => {
          await api(
            wsBase(ws) + "/tags" + (item ? "/" + item.id : ""),
            item ? "PATCH" : "POST",
            { name },
          );
          done();
        }}
      >
        <Field label="标签名称">
          <input
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="例如 production、npm"
          />
        </Field>
        {item ? (
          <Notice>授权规则按稳定 ID 引用标签，重命名不会改变权限。</Notice>
        ) : null}
      </AsyncForm>
    </Modal>
  );
}
