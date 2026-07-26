import type { Snapshot } from "../types";
import { ErrorText } from "./ErrorText";

const STATE_META: Record<string, { label: string; className: string }> = {
  online: { label: "在线", className: "pill ok" },
  connecting: { label: "连接中", className: "pill warn" },
  sms_required: { label: "需要短信验证", className: "pill warn" },
  offline: { label: "离线", className: "pill idle" },
};

// stateMeta tolerates unknown states from a newer backend: show them raw
// instead of mislabeling as offline. `stale` marks a snapshot the panel can
// no longer refresh — a green "在线" light on a dead process is a lie.
export function stateMeta(state: string, stale = false): { label: string; className: string } {
  const meta = STATE_META[state] ?? { label: state, className: "pill idle" };
  return stale ? { ...meta, className: `${meta.className} stale` } : meta;
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("zh-CN", { hour12: false });
}

export function StatusCard({ snap, connected, onRelogin, reloginBusy, reloginError }: {
  snap: Snapshot;
  connected: boolean;
  onRelogin: () => void;
  reloginBusy: boolean;
  reloginError: string | null;
}) {
  const meta = stateMeta(snap.state, !connected);
  return (
    <section className="card">
      <h2>状态</h2>
      <div className="status-row">
        <span className={meta.className}>{meta.label}</span>
        <span className="muted">自 {formatDateTime(snap.since)}</span>
      </div>
      {snap.last_error && <ErrorText raw={snap.last_error} prefix="最近错误:" />}
      {snap.sms_pending && <p className="muted">等待短信验证码,可在弹窗或运行终端中输入。</p>}
      <div className="actions">
        <button
          onClick={onRelogin}
          disabled={reloginBusy || !connected || snap.state === "connecting" || snap.state === "sms_required"}
        >
          {reloginBusy ? "正在请求…" : "重新登录"}
        </button>
      </div>
      {reloginError && <p className="error-text">{reloginError}</p>}
    </section>
  );
}
