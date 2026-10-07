import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { post, errorText, usePanelStore } from "./api";
import type { FriendlyError } from "./errors";
import { StatusCard } from "./components/StatusCard";
import { UserCard } from "./components/UserCard";
import { SmsDialog } from "./components/SmsDialog";
import { TrustDevices } from "./components/TrustDevices";
import { EventsList } from "./components/EventsList";
import { ProxyCards } from "./components/ProxyCards";
import { ThemeToggle } from "./components/ThemeToggle";
import { ConfirmDialog } from "./components/ConfirmDialog";
export default function App() {
  const { snap, connected } = usePanelStore();
  const [reloginBusy, setReloginBusy] = useState(false);
  const [reloginError, setReloginError] = useState<FriendlyError | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [smsOpen, setSMSOpen] = useState(false);
  const generation = snap?.generation;
  const state = snap?.state;
  const pendingGen = snap?.sms_pending ? snap.sms_gen : 0;
  const currentSession = useRef("");
  currentSession.current = `${generation}:${state}`;
  const reloginInFlight = useRef(false);
  useEffect(() => {
    setReloginError(null);
    setConfirm(false);
  }, [state, generation]);
  useEffect(() => {
    setSMSOpen(pendingGen !== 0);
  }, [pendingGen]);
  const relogin = async () => {
    if (!connected || reloginInFlight.current) return;
    const requestedSession = currentSession.current;
    reloginInFlight.current = true;
    setReloginBusy(true);
    setReloginError(null);
    try {
      await post("/api/relogin", {});
    } catch (error) {
      if (currentSession.current === requestedSession)
        setReloginError(
          errorText(error, "重新登录失败", {
            409: "已有登录正在进行，请等待完成",
          }),
        );
    } finally {
      reloginInFlight.current = false;
      setReloginBusy(false);
    }
  };
  return (
    <>
      <header className="app-bar">
        <div className="app-bar-inner">
          <div className="brand">
            <span className="brand-mark">
              <ShieldCheck className="size-5" />
            </span>
            <span>geekTrust</span>
          </div>
          <span className="workspace">
            / <span>本地控制台</span>
          </span>
          <div className="ml-auto flex items-center gap-3">
            <span
              className={`service-badge ${connected ? "service-online" : "service-offline"}`}
            >
              <span className="size-1.5 rounded-full bg-current" />
              {connected ? "服务在线" : "服务离线"}
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="page">
        <div className="page-heading">
          <div>
            <h1>连接概览</h1>
            <p>查看本机会话与代理。</p>
          </div>
        </div>
        {!snap ? (
          <Card className="p-6">
            <h2 className="text-lg font-medium">
              {connected ? "正在加载状态…" : "正在连接面板服务…"}
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">
              请确认 geektrust run 正在运行。连接失败时会自动重试。
            </p>
          </Card>
        ) : (
          <>
            {!connected && (
              <div className="connection-warning" role="status">
                与面板服务的连接已断开，正在重连。以下为最后已知状态。
              </div>
            )}
            <div className="overview-grid">
              <StatusCard
                snap={snap}
                connected={connected}
                onRelogin={() => setConfirm(true)}
                onSMS={() => setSMSOpen(true)}
                reloginBusy={reloginBusy}
                reloginError={reloginError}
              />
              <UserCard snap={snap} />
            </div>
            <ProxyCards snap={snap} connected={connected} />
            <TrustDevices snap={snap} connected={connected} />
            <EventsList events={snap.events} dropped={snap.events_dropped} />
            {!!pendingGen && (
              <SmsDialog
                key={pendingGen}
                snap={snap}
                connected={connected}
                open={smsOpen && !!pendingGen}
                onOpenChange={setSMSOpen}
              />
            )}
          </>
        )}
      </main>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="重新登录？"
        description="当前会话将失效，并重新完整登录。你可能需要再次输入短信验证码。"
        action="重新登录"
        onConfirm={() => void relogin()}
        disabled={
          !connected ||
          reloginBusy ||
          state === "connecting" ||
          state === "sms_required"
        }
      />
    </>
  );
}
