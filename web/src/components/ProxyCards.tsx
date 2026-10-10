import { SquareTerminal } from "lucide-react";
import { Card } from "@/components/ui/card";
import type { Snapshot } from "../types";
import { CopyButton } from "./CopyButton";
export function ProxyCards({
  snap,
  connected,
}: {
  snap: Snapshot;
  connected: boolean;
}) {
  return (
    <div className="proxy-grid">
      {(["socks5", "http"] as const).map((type) => {
        const address = snap.proxy[type];
        const available = !!address && connected && snap.state === "online";
        return (
          <Card className="proxy-card" key={type}>
            <div className="flex items-center gap-2 text-sm font-medium">
              <SquareTerminal className="size-4 text-muted-foreground" />
              <h2>{type === "socks5" ? "SOCKS5" : "HTTP"} 代理</h2>
              <span
                className={`ml-auto text-xs font-normal ${available ? "text-success" : "text-muted-foreground"}`}
              >
                {!address
                  ? "已禁用"
                  : available
                    ? "可用"
                    : !connected
                      ? "状态未知"
                      : "等待连接"}
              </span>
            </div>
            <div className="flex min-w-0 items-center justify-between gap-2">
              <code className="break-all text-sm">{address || "未启用"}</code>
              {address && <CopyButton value={address} />}
            </div>
            <p className="text-xs text-muted-foreground">
              {type === "socks5"
                ? "用于支持 SOCKS5 的应用"
                : "用于 HTTP 代理设置"}
            </p>
          </Card>
        );
      })}
    </div>
  );
}
