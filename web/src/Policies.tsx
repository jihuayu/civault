import { useState } from "react";
import { Plus, ShieldCheck } from "lucide-react";
import {
  api,
  useData,
  wsBase,
  type KeyItem,
  type Policy,
  type Rule,
  type Tag,
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

export function PoliciesPage({ ws }: { ws: string }) {
  const policies = useData<Policy[]>(wsBase(ws) + "/policies");
  const keys = useData<KeyItem[]>(wsBase(ws) + "/keys");
  const tags = useData<Tag[]>(wsBase(ws) + "/tags");
  const [editing, setEditing] = useState<Policy | "new" | null>(null);
  const [history, setHistory] = useState<Policy | null>(null);
  const [error, setError] = useState("");
  return (
    <>
      <PageTitle
        title="授权规则"
        caption="定义哪些组织、仓库和工作流可以使用指定 Key。"
      >
        <button onClick={() => setEditing("new")}>
          <Plus size={17} />
          创建规则
        </button>
      </PageTitle>
      <ErrorBox error={error || policies.error} />
      <div className="policy-list">
        {policies.loading ? (
          <Loading />
        ) : (
          policies.data?.map((p) => (
            <article className="panel policy-card" key={p.id}>
              <div className="policy-icon">
                <ShieldCheck size={24} />
              </div>
              <div className="policy-main">
                <div className="inline">
                  <h3>{p.name}</h3>
                  <span className="version">v{p.version}</span>
                  <span
                    className={`badge ${p.disabled ? "muted-badge" : "success-badge"}`}
                  >
                    {p.disabled ? "已禁用" : "已启用"}
                  </span>
                </div>
                <p className="muted">
                  Owner ID <code>{p.rule.repository_owner_id}</code>
                  {p.rule.repository_id ? (
                    <>
                      {" "}
                      · 仓库 ID <code>{p.rule.repository_id}</code>
                    </>
                  ) : (
                    " · 组织范围"
                  )}
                </p>
                {p.rule.workflow_path ? (
                  <code>{p.rule.workflow_path}</code>
                ) : null}
                <div className="inline">
                  <span className="small muted">
                    {p.rule.tag_ids?.length ? "Tag 任意匹配" : "指定 Key"}
                  </span>
                  {(p.rule.tag_ids || p.rule.key_ids || []).map((id) => (
                    <span className="tag" key={id}>
                      {tags.data?.find((t) => t.id === id)?.name ||
                        keys.data?.find((k) => k.id === id)?.path ||
                        id}
                    </span>
                  ))}
                </div>
              </div>
              <div className="policy-actions">
                <button
                  className="secondary small"
                  onClick={() => setEditing(p)}
                >
                  编辑
                </button>
                <button className="text-button" onClick={() => setHistory(p)}>
                  版本
                </button>
                <button
                  className="text-button"
                  onClick={async () => {
                    try {
                      await api(wsBase(ws) + "/policies/" + p.id, "PATCH", {
                        disabled: !p.disabled,
                      });
                      policies.reload();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  {p.disabled ? "启用" : "禁用"}
                </button>
              </div>
            </article>
          ))
        )}
      </div>
      {!policies.loading && !policies.data?.length ? (
        <Empty
          text="默认拒绝所有工作流"
          action={
            <button onClick={() => setEditing("new")}>
              创建第一条授权规则
            </button>
          }
        />
      ) : null}
      {editing ? (
        <PolicyForm
          key={editing === "new" ? "new" : editing.id}
          ws={ws}
          item={editing === "new" ? undefined : editing}
          keys={keys.data || []}
          tags={tags.data || []}
          close={() => setEditing(null)}
          done={() => {
            setEditing(null);
            policies.reload();
          }}
        />
      ) : null}
      {history ? (
        <PolicyHistory ws={ws} item={history} close={() => setHistory(null)} />
      ) : null}
    </>
  );
}
const split = (value: string) =>
  value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
function PolicyForm({
  ws,
  item,
  keys,
  tags,
  close,
  done,
}: {
  ws: string;
  item?: Policy;
  keys: KeyItem[];
  tags: Tag[];
  close: () => void;
  done: () => void;
}) {
  const [name, setName] = useState(item?.name || "");
  const [rule, setRule] = useState<Rule>(
    item?.rule || {
      repository_owner_id: "",
      refs: ["refs/heads/main"],
      events: ["push", "workflow_dispatch"],
      runner_environments: ["github-hosted"],
    },
  );
  const [target, setTarget] = useState(
    item?.rule.tag_ids?.length ? "tags" : "keys",
  );
  const [ids, setIDs] = useState(
    item?.rule.tag_ids || item?.rule.key_ids || [],
  );
  const update = <K extends keyof Rule>(k: K, value: Rule[K]) =>
    setRule((r) => ({ ...r, [k]: value }));
  const covered = keys.filter((k) =>
    target === "keys"
      ? ids.includes(k.id)
      : k.tags.some((t) => ids.includes(t.id)),
  );
  const scalar: {
    key:
      | "repository_owner_id"
      | "repository_id"
      | "workflow_path"
      | "workflow_sha";
    label: string;
    placeholder: string;
  }[] = [
    {
      key: "repository_owner_id",
      label: "组织 / Owner ID",
      placeholder: "12345678",
    },
    { key: "repository_id", label: "仓库 ID（可选）", placeholder: "87654321" },
    {
      key: "workflow_path",
      label: "工作流文件（可选）",
      placeholder: ".github/workflows/publish.yml",
    },
    {
      key: "workflow_sha",
      label: "工作流提交 SHA（可选）",
      placeholder: "完整的 40 位提交 SHA",
    },
  ];
  const arrays: {
    key: "refs" | "environments" | "events" | "runner_environments";
    label: string;
    placeholder: string;
  }[] = [
    {
      key: "refs",
      label: "允许的分支 / 标签引用",
      placeholder: "refs/heads/main, refs/tags/v1.0.0",
    },
    {
      key: "environments",
      label: "GitHub Environments",
      placeholder: "production",
    },
    {
      key: "events",
      label: "事件类型",
      placeholder: "push, workflow_dispatch",
    },
    {
      key: "runner_environments",
      label: "Runner 类型",
      placeholder: "github-hosted, self-hosted",
    },
  ];
  return (
    <Modal
      title={item ? "创建规则新版本" : "创建授权规则"}
      wide
      onClose={close}
    >
      <AsyncForm
        onCancel={close}
        submit={async () => {
          const { key_ids: _k, tag_ids: _t, ...context } = rule;
          await api(wsBase(ws) + "/policies", "POST", {
            name,
            rule: {
              ...context,
              ...(target === "keys" ? { key_ids: ids } : { tag_ids: ids }),
            },
          });
          done();
        }}
      >
        <Field label="规则名称">
          <input
            required
            readOnly={!!item}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="production-publish"
          />
        </Field>
        <div className="section-label">01 · 授权目标</div>
        <div className="segmented">
          <button
            type="button"
            className={target === "keys" ? "selected" : ""}
            onClick={() => {
              setTarget("keys");
              setIDs([]);
            }}
          >
            指定 Key
          </button>
          <button
            type="button"
            className={target === "tags" ? "selected" : ""}
            onClick={() => {
              setTarget("tags");
              setIDs([]);
            }}
          >
            按 Tag · 任意匹配
          </button>
        </div>
        <CheckList
          items={
            target === "keys"
              ? keys.map((k) => ({ id: k.id, name: k.path }))
              : tags
          }
          selected={ids}
          onChange={setIDs}
        />
        <div className="coverage">
          <strong>当前覆盖 {covered.length} 个 Key</strong>
          <div>
            {covered.map((k) => (
              <span className="tag" key={k.id}>
                {k.path}
              </span>
            ))}
          </div>
        </div>
        <div className="section-label">02 · GitHub 工作负载</div>
        <div className="form-grid">
          {scalar.map((f) => (
            <Field label={f.label} key={f.key}>
              <input
                required={f.key === "repository_owner_id"}
                value={rule[f.key] || ""}
                placeholder={f.placeholder}
                onChange={(e) => update(f.key, e.target.value)}
              />
            </Field>
          ))}
        </div>
        <div className="section-label">03 · 附加限制</div>
        <div className="form-grid">
          {arrays.map((f) => (
            <ArrayField
              key={f.key}
              label={f.label}
              initial={rule[f.key] || []}
              placeholder={f.placeholder}
              update={(v) => update(f.key, v)}
            />
          ))}
        </div>
        <Notice>
          条件之间同时满足；留空的可选条件不限制。多条规则任意一条命中即可授权，窄范围规则不会覆盖已有的宽泛授权。
        </Notice>
      </AsyncForm>
    </Modal>
  );
}
function ArrayField({
  label,
  initial,
  placeholder,
  update,
}: {
  label: string;
  initial: string[];
  placeholder: string;
  update: (v: string[]) => void;
}) {
  const [text, setText] = useState(initial.join(", "));
  return (
    <Field label={label} hint="多个值用逗号分隔，精确匹配。">
      <input
        value={text}
        placeholder={placeholder}
        onChange={(e) => {
          setText(e.target.value);
          update(split(e.target.value));
        }}
      />
    </Field>
  );
}
function PolicyHistory({
  ws,
  item,
  close,
}: {
  ws: string;
  item: Policy;
  close: () => void;
}) {
  const data = useData<{ version: number; spec: Rule }[]>(
    wsBase(ws) + "/policies/" + item.id + "/versions",
  );
  return (
    <Modal title={`规则版本 · ${item.name}`} wide onClose={close}>
      <ErrorBox error={data.error} />
      {data.loading ? (
        <Loading />
      ) : (
        data.data?.map((v) => (
          <div className="policy-history" key={v.version}>
            <h3>v{v.version}</h3>
            <pre>{JSON.stringify(v.spec, null, 2)}</pre>
            <CopyButton
              text={JSON.stringify({ name: item.name, rule: v.spec }, null, 2)}
              label="复制 CLI 配置"
            />
          </div>
        ))
      )}
    </Modal>
  );
}
