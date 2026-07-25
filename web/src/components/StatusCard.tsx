import type { Snapshot } from "../types";

const STATE_META: Record<string, { label: string; className: string }> = {
  online: { label: "在线", className: "pill ok" },
  connecting: { label: "连接中", className: "pill warn" },
  sms_required: { label: "需要短信验证", className: "pill warn" },
  offline: { label: "离线", className: "pill idle" },
};

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("zh-CN", { hour12: false });
}

export function StatusCard({ snap, onRelogin, reloginBusy }: {
  snap: Snapshot;
  onRelogin: () => void;
  reloginBusy: boolean;
}) {
  const meta = STATE_META[snap.state] ?? STATE_META.offline;
  return (
    <section className="card status-card">
      <div className="status-row">
        <span className={meta.className}>{meta.label}</span>
        <span className="muted">自 {formatTime(snap.since)}</span>
      </div>
      {snap.last_error && <p className="error-text">最近错误:{snap.last_error}</p>}
      <div className="actions">
        <button onClick={onRelogin} disabled={reloginBusy || snap.state === "connecting" || snap.state === "sms_required"}>
          {reloginBusy ? "正在重登…" : "重新登录"}
        </button>
        {snap.sms_pending && <span className="muted">等待输入短信验证码…</span>}
      </div>
    </section>
  );
}

export function UserCard({ snap }: { snap: Snapshot }) {
  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // clipboard API unavailable (non-secure context); ignore
    }
  };
  return (
    <section className="card">
      <h2>用户</h2>
      {snap.user ? (
        <dl className="kv">
          <dt>账号</dt>
          <dd>{snap.user.username}</dd>
          <dt>姓名</dt>
          <dd>{snap.user.display_name}</dd>
          <dt>客户端 IP</dt>
          <dd>{snap.user.client_ip}</dd>
        </dl>
      ) : (
        <p className="muted">未登录</p>
      )}
      <dl className="kv">
        <dt>device_id</dt>
        <dd className="mono">
          {snap.device_id.slice(0, 16)}…
          <button className="link" onClick={() => copy(snap.device_id)} title="复制完整 device_id">
            复制
          </button>
        </dd>
        <dt>模式</dt>
        <dd>{snap.client_type}</dd>
        <dt>SOCKS5</dt>
        <dd className="mono">{snap.proxy.socks5 ?? "已禁用"}</dd>
        <dt>HTTP</dt>
        <dd className="mono">{snap.proxy.http ?? "已禁用"}</dd>
        {snap.gateways && (
          <>
            <dt>网关</dt>
            <dd className="mono">{snap.gateways.join(", ")}</dd>
          </>
        )}
        {snap.dns && snap.dns.length > 0 && (
          <>
            <dt>隧道 DNS</dt>
            <dd className="mono">{snap.dns.join(", ")}</dd>
          </>
        )}
      </dl>
    </section>
  );
}
