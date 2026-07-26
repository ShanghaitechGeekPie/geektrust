import { useEffect, useRef, useState } from "react";
import type { Snapshot } from "../types";

function shortID(id: string): string {
  return id.length > 20 ? `${id.slice(0, 8)}…${id.slice(-8)}` : id;
}

// legacyCopy is the fallback for browsers without the async clipboard API.
function legacyCopy(text: string): boolean {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

export function UserCard({ snap }: { snap: Snapshot }) {
  const [copied, setCopied] = useState<"ok" | "fail" | null>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async () => {
    let ok: boolean;
    try {
      await navigator.clipboard.writeText(snap.device_id);
      ok = true;
    } catch {
      ok = legacyCopy(snap.device_id);
    }
    setCopied(ok ? "ok" : "fail");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setCopied(null), 1600);
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
          <dd className="mono">{snap.user.client_ip}</dd>
        </dl>
      ) : (
        <p className="muted">未登录</p>
      )}
      <dl className="kv">
        <dt>device_id</dt>
        <dd className="mono" title={snap.device_id}>
          {shortID(snap.device_id)}
          <button className="link" onClick={() => void copy()} title="复制完整 device_id">
            {copied === "ok" ? "已复制" : copied === "fail" ? "复制失败" : "复制"}
          </button>
        </dd>
        <dt>登录模式</dt>
        <dd>{snap.client_type}</dd>
        <dt>SOCKS5</dt>
        <dd className="mono">{snap.proxy.socks5 ?? "已禁用"}</dd>
        <dt>HTTP</dt>
        <dd className="mono">{snap.proxy.http ?? "已禁用"}</dd>
        {snap.gateways && snap.gateways.length > 0 && (
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
