import { RefreshCw, LoaderCircle, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { friendlyError, type FriendlyError } from "../errors";
import type { Snapshot } from "../types";
import { ErrorText } from "./ErrorText";
export function StatusCard({
  snap,
  connected,
  onRelogin,
  onSMS,
  reloginBusy,
  reloginError,
}: {
  snap: Snapshot;
  connected: boolean;
  onRelogin: () => void;
  onSMS: () => void;
  reloginBusy: boolean;
  reloginError: FriendlyError | null;
}) {
  const states = {
    online: ["已连接", "校园资源可通过本地代理访问。"],
    offline: ["会话已断开", "重新登录以恢复校园资源访问。"],
    connecting: ["正在连接", "正在建立会话，请稍候。"],
    sms_required: ["完成验证后连接", "请输入短信验证码，继续本次登录。"],
  };
  const [title, description] = states[snap.state] ?? [
    "状态未知",
    "等待面板更新连接状态。",
  ];
  const working = reloginBusy || snap.state === "connecting";
  return (
    <Card className="status-card">
      <div>
        <h2 className="status-title">{title}</h2>
        <p className="mt-3 text-sm text-muted-foreground">{description}</p>
      </div>
      {snap.last_error && (
        <ErrorText error={friendlyError(snap.last_error, "连接失败")} />
      )}
      {reloginError && <ErrorText error={reloginError} />}
      <div className="mt-auto flex justify-end pt-5">
        {snap.sms_pending ? (
          <Button onClick={onSMS} disabled={!connected}>
            <KeyRound />
            输入验证码
          </Button>
        ) : (
          <Button
            variant="outline"
            onClick={onRelogin}
            disabled={!connected || working || snap.state === "sms_required"}
          >
            {working ? (
              <LoaderCircle className="animate-spin" />
            ) : (
              <RefreshCw />
            )}
            {working ? "连接中…" : "重新登录"}
          </Button>
        )}
      </div>
    </Card>
  );
}
