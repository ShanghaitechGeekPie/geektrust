import { useCallback, useEffect, useRef, useState } from "react";
import { fetchTrustDevices, post, ApiError } from "../api";
import type { Snapshot, TrustDeviceList } from "../types";

function deviceLabel(name: string | undefined, os: string | undefined, osVersion: string | undefined): string {
  const fallback = [os, osVersion].filter(Boolean).join(" ").trim();
  return (name ?? "").trim() || fallback || "(未命名设备)";
}

export function TrustDevices({ snap }: { snap: Snapshot }) {
  const [list, setList] = useState<TrustDeviceList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  // Refresh results must never outlive the session they were fetched in.
  const epochRef = useRef(0);

  const refresh = useCallback(async () => {
    const epoch = ++epochRef.current;
    setError(null);
    try {
      const next = await fetchTrustDevices();
      if (epoch === epochRef.current) setList(next);
    } catch (err) {
      if (epoch !== epochRef.current) return;
      setList(null);
      setError(err instanceof ApiError ? err.message : "加载失败");
    }
  }, []);

  useEffect(() => {
    if (snap.state === "online") {
      void refresh();
    } else {
      // Leaving online invalidates every row and in-flight fetch.
      epochRef.current++;
      setList(null);
      setSelected(new Set());
      setError(null);
      setNotice(null);
    }
  }, [snap.state, refresh]);

  if (snap.client_type !== "client") {
    return (
      <section className="card">
        <h2>授信终端</h2>
        <p className="muted">
          当前为 browser 模式,服务端不允许管理授信终端。把 client_type 改为 client 后可在此绑定设备,后续登录可免短信。
        </p>
      </section>
    );
  }

  const run = async (action: () => Promise<void>, ok: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(ok);
      setSelected(new Set());
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "操作失败");
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <section className="card">
      <div className="card-head">
        <h2>授信终端</h2>
        <div className="actions">
          <button className="secondary" onClick={() => void refresh()} disabled={busy || snap.state !== "online"}>
            刷新
          </button>
          <button onClick={() => void run(() => post("/api/trust-devices/bind", {}), "已绑定当前设备")}
            disabled={busy || snap.state !== "online"}>
            绑定当前设备
          </button>
        </div>
      </div>
      {list && (
        <p className="muted">
          服务端策略:{list.trustDeviceConfig.enable ? "已启用" : "未启用"};当前设备信任状态:{list.currentTrustStatus}
        </p>
      )}
      {error && <p className="error-text">{error}</p>}
      {notice && <p className="ok-text">{notice}</p>}
      {list ? (
        <>
          <table className="devices">
            <thead>
              <tr>
                <th></th>
                <th>设备</th>
                <th>类型</th>
                <th>最近登录 IP</th>
                <th>地区</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((d) => (
                <tr key={d.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(d.id)}
                      onChange={() => toggle(d.id)}
                      disabled={d.id === list.selfId}
                    />
                  </td>
                  <td>
                    {deviceLabel(d.deviceName, d.os, d.osVersion)}
                    {d.id === list.selfId && <span className="tag">当前设备</span>}
                    {d.onlineStatus && <span className="tag ok">在线</span>}
                  </td>
                  <td>{d.deviceType ?? "-"}</td>
                  <td className="mono">{d.lastLoginIp ?? "-"}</td>
                  <td>{d.lastLoginAddress ?? "-"}</td>
                  <td>
                    <button
                      className="link danger"
                      disabled={busy || snap.state !== "online" || d.id === list.selfId}
                      onClick={() => {
                        if (window.confirm(`确定注销设备 ${deviceLabel(d.deviceName, d.os, d.osVersion)}?`)) {
                          void run(() => post("/api/trust-devices/logout", { id: d.id }), "已注销设备");
                        }
                      }}
                    >
                      注销
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="actions">
            <button
              className="secondary"
              disabled={busy || snap.state !== "online" || selected.size === 0}
              onClick={() => {
                if (window.confirm(`确定取消 ${selected.size} 台设备的授信?`)) {
                  void run(() => post("/api/trust-devices/unbind", { ids: [...selected] }), "已取消授信");
                }
              }}
            >
              取消授信({selected.size})
            </button>
          </div>
        </>
      ) : (
        !error && <p className="muted">{snap.state === "online" ? "加载中…" : "会话在线后可查看"}</p>
      )}
    </section>
  );
}
