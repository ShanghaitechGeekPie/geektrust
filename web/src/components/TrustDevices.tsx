import { useCallback, useEffect, useRef, useState } from "react";
import { fetchTrustDevices, post, errorText } from "../api";
import type { Snapshot, TrustDeviceEntry, TrustDeviceList } from "../types";

function deviceLabel(d: TrustDeviceEntry): string {
  const fallback = [d.os, d.osVersion].filter(Boolean).join(" ").trim();
  return (d.deviceName ?? "").trim() || fallback || "(未命名设备)";
}

const LIST_ERRORS: Record<number, string> = {
  503: "会话未就绪,请稍后重试",
};

export function TrustDevices({ snap, connected }: { snap: Snapshot; connected: boolean }) {
  const [list, setList] = useState<TrustDeviceList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Which mutation is in flight, so the button that was clicked is the one
  // that reports progress; null means idle.
  const [pending, setPending] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
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
      setError(errorText(err, "加载失败", LIST_ERRORS));
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

  // Only binding is refused in browser mode (server.go handleTrustBind);
  // listing, unbinding and logout work on any session, so the card stays
  // fully functional and just the bind button is disabled.
  const isClient = snap.client_type === "client";
  const busy = pending !== null;
  const canAct = connected && snap.state === "online" && !busy;

  const run = async (action: () => Promise<void>, ok: string, label: string) => {
    setPending(label);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(ok);
      setSelected(new Set());
      await refresh();
    } catch (err) {
      setError(errorText(err, "操作失败", LIST_ERRORS));
    } finally {
      setPending(null);
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

  // Current device first, then the controller's order.
  const devices = (list?.data ?? []).slice().sort((a, b) => {
    const self = list?.selfId;
    return Number(b.id === self) - Number(a.id === self);
  });
  const selfTrusted = list != null && devices.some((d) => d.id === list.selfId);

  return (
    <section className="card">
      <div className="card-head">
        <h2>授信终端</h2>
        <div className="actions">
          <button
            className="secondary"
            onClick={() => {
              setRefreshing(true);
              void refresh().finally(() => setRefreshing(false));
            }}
            disabled={!canAct || refreshing}
          >
            {refreshing ? "刷新中…" : "刷新"}
          </button>
          <button
            onClick={() => void run(() => post("/api/trust-devices/bind", {}), "已绑定当前设备", "bind")}
            disabled={!canAct || selfTrusted || !isClient}
            title={
              !isClient
                ? "browser 模式下服务端不允许绑定授信终端"
                : selfTrusted
                  ? "当前设备已在授信列表中"
                  : undefined
            }
          >
            {pending === "bind" ? "绑定中…" : "绑定当前设备"}
          </button>
        </div>
      </div>
      {list && (
        <p className="muted">
          服务端授信策略:{list.trustDeviceConfig.enable ? "已启用" : "未启用"};本机
          {selfTrusted ? "已" : "未"}在授信列表。
        </p>
      )}
      {!isClient && (
        <p className="muted small">
          当前为 browser 模式:可以查看、取消授信和注销设备,但不能绑定本机。把配置里的{" "}
          <code>client_type</code> 改为 <code>client</code> 后重新登录即可绑定,后续登录可免短信。
        </p>
      )}
      {error && <p className="error-text">{error}</p>}
      {notice && <p className="ok-text">{notice}</p>}
      {list ? (
        devices.length === 0 ? (
          <p className="muted">暂无授信终端。绑定当前设备后,后续登录可免短信验证。</p>
        ) : (
          <>
            <div className="table-wrap">
              <table className="devices">
                <thead>
                  <tr>
                    <th></th>
                    <th>设备</th>
                    <th>类型</th>
                    <th>最近登录 IP</th>
                    <th>位置</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <input
                          type="checkbox"
                          checked={selected.has(d.id)}
                          onChange={() => toggle(d.id)}
                          disabled={d.id === list.selfId}
                          aria-label={`选择 ${deviceLabel(d)}`}
                        />
                      </td>
                      <td>
                        {deviceLabel(d)}
                        {d.id === list.selfId && <span className="tag accent">当前设备</span>}
                        {d.onlineStatus && <span className="tag ok">在线</span>}
                      </td>
                      <td>{d.deviceType || "-"}</td>
                      <td className="mono">{d.lastLoginIp || "-"}</td>
                      <td>{d.lastLoginAddress || "-"}</td>
                      <td className="right">
                        <button
                          className="link danger"
                          disabled={!canAct || d.id === list.selfId}
                          title={d.id === list.selfId ? "不能注销当前设备自身的会话" : undefined}
                          onClick={() => {
                            if (window.confirm(`确定注销设备「${deviceLabel(d)}」?其会话将立即失效。`)) {
                              void run(
                                () => post("/api/trust-devices/logout", { id: d.id }),
                                "已注销设备",
                                `logout:${d.id}`,
                              );
                            }
                          }}
                        >
                          {pending === `logout:${d.id}` ? "注销中…" : "注销"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="actions">
              <button
                className="secondary"
                disabled={!canAct || selected.size === 0}
                onClick={() => {
                  if (window.confirm(`确定取消 ${selected.size} 台设备的授信?下次登录这些设备可能需要短信验证。`)) {
                    void run(
                      () => post("/api/trust-devices/unbind", { ids: [...selected] }),
                      "已取消授信",
                      "unbind",
                    );
                  }
                }}
              >
                {pending === "unbind" ? "处理中…" : `取消授信(${selected.size})`}
              </button>
            </div>
          </>
        )
      ) : (
        !error && <p className="muted">{snap.state === "online" ? "加载中…" : "会话在线后可查看"}</p>
      )}
    </section>
  );
}
