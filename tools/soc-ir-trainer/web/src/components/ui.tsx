import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Icon, type IconName } from "./Icons";

/* ------------------------------------------------------------------ */
/* Score helpers                                                       */
/* ------------------------------------------------------------------ */
export function scoreTone(score: number | null | undefined): "good" | "mid" | "poor" | "none" {
  if (score === null || score === undefined) return "none";
  if (score >= 75) return "good";
  if (score >= 50) return "mid";
  return "poor";
}

export function scoreClass(score: number | null | undefined): string {
  const tone = scoreTone(score);
  return tone === "none" ? "" : tone;
}

export function ScoreRing({
  score,
  max = 100,
  grade,
  size = 132,
}: {
  score: number | null;
  max?: number;
  grade?: string | null;
  size?: number;
}) {
  const value = Math.max(0, Math.min(max, score ?? 0));
  const stroke = 9;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / max) * circumference;
  const color =
    score === null
      ? "var(--slate-600)"
      : value >= 75
        ? "var(--success)"
        : value >= 50
          ? "var(--warning)"
          : "var(--critical)";

  return (
    <div className="score-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} role="img" aria-label={`Score ${score ?? 0} out of ${max}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="var(--slate-750)"
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 700ms cubic-bezier(0.2,0.7,0.3,1)" }}
        />
      </svg>
      <div className="ring-center">
        <span className="ring-score" style={{ color }}>
          {score ?? "—"}
        </span>
        <span className="ring-label">{grade ?? `of ${max}`}</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Buttons / badges / states                                          */
/* ------------------------------------------------------------------ */
type ButtonVariant = "default" | "primary" | "ghost" | "danger";

export function Button({
  children,
  variant = "default",
  size,
  block,
  icon,
  iconRight,
  loading,
  className = "",
  ...rest
}: {
  children?: ReactNode;
  variant?: ButtonVariant;
  size?: "sm" | "lg";
  block?: boolean;
  icon?: IconName;
  iconRight?: IconName;
  loading?: boolean;
  className?: string;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const classes = [
    "btn",
    variant !== "default" ? `btn-${variant}` : "",
    size ? `btn-${size}` : "",
    block ? "btn-block" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={classes} disabled={loading || rest.disabled} {...rest}>
      {loading ? <span className="spinner" /> : icon ? <Icon name={icon} size={15} /> : null}
      {children}
      {iconRight && !loading ? <Icon name={iconRight} size={15} /> : null}
    </button>
  );
}

export function Badge({
  children,
  tone = "default",
  icon,
}: {
  children: ReactNode;
  tone?: "default" | "blue" | "green" | "amber" | "red" | "cyan" | "violet";
  icon?: IconName;
}) {
  return (
    <span className={`badge${tone !== "default" ? ` badge-${tone}` : ""}`}>
      {icon ? <Icon name={icon} size={11} /> : null}
      {children}
    </span>
  );
}

export function difficultyTone(difficulty: string): "green" | "amber" | "red" {
  const value = difficulty.toLowerCase();
  if (value === "easy") return "green";
  if (value === "hard") return "red";
  return "amber";
}

export function levelTone(level: string): "green" | "blue" | "amber" | "red" | "default" {
  const value = level.toLowerCase();
  if (value === "expert") return "green";
  if (value === "proficient") return "blue";
  if (value === "intermediate") return "amber";
  if (value === "novice" || value === "needs work") return "red";
  return "default";
}

export function EmptyState({
  icon = "compass",
  title,
  children,
  action,
}: {
  icon?: IconName;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon name={icon} size={19} />
      </div>
      <h3>{title}</h3>
      {children ? <p className="small">{children}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="empty-state" role="alert">
      <div className="empty-icon" style={{ color: "var(--red-400)" }}>
        <Icon name="alertTriangle" size={19} />
      </div>
      <h3>Something went wrong</h3>
      <p className="small">{message}</p>
      {onRetry ? (
        <Button size="sm" icon="refresh" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="empty-state" role="status" aria-live="polite">
      <span className="spinner" />
      <p className="small">{label}…</p>
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="stack" aria-busy="true" aria-label="Loading page">
      <div className="skeleton" style={{ height: 30, width: "38%" }} />
      <div className="stat-grid">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="skeleton" style={{ height: 82 }} />
        ))}
      </div>
      <div className="skeleton" style={{ height: 260 }} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Toast                                                              */
/* ------------------------------------------------------------------ */
type Toast = { id: number; kind: "error" | "success" | "info"; message: string };

const ToastContext = createContext<{ push: (message: string, kind?: Toast["kind"]) => void }>({
  push: () => undefined,
});

let toastSeed = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timers = useRef<number[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (message: string, kind: Toast["kind"] = "info") => {
      const id = ++toastSeed;
      setToasts((current) => [...current.slice(-3), { id, kind, message }]);
      const timer = window.setTimeout(() => dismiss(id), kind === "error" ? 6500 : 4200);
      timers.current.push(timer);
    },
    [dismiss],
  );

  useEffect(() => () => timers.current.forEach((timer) => window.clearTimeout(timer)), []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.kind}`} role="status">
            <Icon
              name={toast.kind === "error" ? "alertCircle" : toast.kind === "success" ? "checkCircle" : "info"}
              size={16}
            />
            <span className="grow">{toast.message}</span>
            <button onClick={() => dismiss(toast.id)} aria-label="Dismiss notification">
              <Icon name="x" size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

/* ------------------------------------------------------------------ */
/* Modal / Drawer                                                     */
/* ------------------------------------------------------------------ */
export function Modal({
  title,
  children,
  onClose,
  footer,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    ref.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <div className="modal-head">
          <h2>{title}</h2>
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-foot">{footer}</div> : null}
      </div>
    </div>
  );
}

export function Drawer({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="drawer-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <div className="drawer-head">
          <h3>{title}</h3>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            <Icon name="x" />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Formatting helpers                                                 */
/* ------------------------------------------------------------------ */
export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relativeTime(value?: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(value);
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
