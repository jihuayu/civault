import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { Check, Copy, KeyRound, X } from "lucide-react";

export function ErrorBox({ error }: { error?: string }) {
  return error ? (
    <div className="alert error" role="alert">
      {error}
    </div>
  ) : null;
}
export function Notice({ children }: { children: ReactNode }) {
  return <div className="alert notice">{children}</div>;
}
export function PageTitle({
  title,
  caption,
  children,
}: {
  title: string;
  caption: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <p className="eyebrow">WORKSPACE / CIVault</p>
        <h1>{title}</h1>
        <p className="muted">{caption}</p>
      </div>
      <div className="actions">{children}</div>
    </div>
  );
}
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}
export function Empty({ text, action }: { text: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <KeyRound size={32} />
      <h3>{text}</h3>
      <p>从创建资源开始，让 CI 按授权读取所需密钥。</p>
      {action}
    </div>
  );
}
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleID = useId();
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? "modal wide" : "modal"}
      aria-labelledby={titleID}
      onCancel={onClose}
    >
      <div className="modal-header">
        <h2 id={titleID}>{title}</h2>
        <button className="icon-button" aria-label="关闭" onClick={onClose}>
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function AsyncForm({
  submit,
  children,
  label = "保存",
  onCancel,
}: {
  submit: () => Promise<void>;
  children: ReactNode;
  label?: string;
  onCancel?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await submit();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={onSubmit}>
      <fieldset disabled={busy}>
        {children}
        <ErrorBox error={error} />
        <div className="form-actions">
          {onCancel ? (
            <button type="button" className="secondary" onClick={onCancel}>
              取消
            </button>
          ) : null}
          <button type="submit">{busy ? "处理中…" : label}</button>
        </div>
      </fieldset>
    </form>
  );
}
export function CopyButton({
  text,
  label = "复制",
}: {
  text: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  return (
    <button
      type="button"
      className="secondary small"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setError(false);
        } catch {
          setError(true);
        }
      }}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}{" "}
      {error ? "请手动复制" : copied ? "已复制" : label}
    </button>
  );
}
export function CheckList({
  items,
  selected,
  onChange,
}: {
  items: { id: string; name: string }[];
  selected: string[];
  onChange: (value: string[]) => void;
}) {
  return (
    <div className="check-list">
      {items.map((item) => (
        <label className="check" key={item.id}>
          <input
            type="checkbox"
            checked={selected.includes(item.id)}
            onChange={(e) =>
              onChange(
                e.target.checked
                  ? [...selected, item.id]
                  : selected.filter((id) => id !== item.id),
              )
            }
          />
          <span>{item.name}</span>
        </label>
      ))}
      {!items.length ? <span className="muted">暂无可选项目</span> : null}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      正在加载…
    </div>
  );
}
