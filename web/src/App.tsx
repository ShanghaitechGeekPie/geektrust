import { useState } from "react";
import { post, ApiError, useSnapshot } from "./api";
import { StatusCard, UserCard } from "./components/StatusCard";
import { SmsDialog } from "./components/SmsDialog";
import { TrustDevices } from "./components/TrustDevices";
import { EventsList } from "./components/EventsList";

const STATE_TITLE: Record<string, string> = {
  online: "在线",
  connecting: "连接中",
  sms_required: "需要短信验证",
  offline: "离线",
};

export default function App() {
  const snap = useSnapshot();
  const [reloginBusy, setReloginBusy] = useState(false);
  const [reloginError, setReloginError] = useState<string | null>(null);

  const relogin = async () => {
    if (!window.confirm("确定重新登录?当前会话会被注销,可能需要重新短信验证。")) return;
    setReloginBusy(true);
    setReloginError(null);
    try {
      await post("/api/relogin", {});
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setReloginError("登录正在进行中");
      } else {
        setReloginError(err instanceof ApiError ? err.message : "重登失败");
      }
    } finally {
      setReloginBusy(false);
    }
  };

  if (!snap) {
    return (
      <main className="page">
        <p className="muted">正在连接面板服务…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="top">
        <h1>geekTrust 面板</h1>
        <span className={`pill ${snap.state === "online" ? "ok" : snap.state === "offline" ? "idle" : "warn"}`}>
          {STATE_TITLE[snap.state] ?? snap.state}
        </span>
      </header>
      {reloginError && <p className="error-text">重新登录失败:{reloginError}</p>}
      <div className="grid">
        <StatusCard snap={snap} onRelogin={relogin} reloginBusy={reloginBusy} />
        <UserCard snap={snap} />
      </div>
      <TrustDevices snap={snap} />
      <EventsList events={snap.events} dropped={snap.events_dropped} />
      <SmsDialog snap={snap} />
    </main>
  );
}
