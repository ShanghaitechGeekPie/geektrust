import { ChevronRight } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Snapshot } from "../types";
import { CopyButton } from "./CopyButton";
export function UserCard({ snap }: { snap: Snapshot }) {
  const name = snap.user?.display_name || snap.user?.username || "未登录";
  return (
    <Card className="account-card">
      <div className="flex min-w-0 items-center gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-medium" title={name}>
            {name}
          </h2>
          <p
            className="truncate text-xs text-muted-foreground"
            title={snap.controller_host}
          >
            {snap.controller_host || "控制器未配置"}
          </p>
        </div>
      </div>
      <dl className="account-fields">
        <dt>账号</dt>
        <dd>{snap.user?.username || "—"}</dd>
        <dt>客户端 IP</dt>
        <dd>{snap.user?.client_ip || "—"}</dd>
      </dl>
      <Dialog>
        <DialogTrigger asChild>
          <Button variant="ghost" size="sm" className="mt-auto self-end">
            查看详情
            <ChevronRight />
          </Button>
        </DialogTrigger>
        <DialogContent aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>连接与设备详情</DialogTitle>
          </DialogHeader>
          <dl className="detail-fields">
            <dt>控制器</dt>
            <dd>{snap.controller_host || "—"}</dd>
            <dt>设备 ID</dt>
            <dd className="flex flex-wrap items-center gap-1">
              <code className="break-all">{snap.device_id}</code>
              <CopyButton value={snap.device_id} label="复制设备 ID" />
            </dd>
            <dt>登录模式</dt>
            <dd>{snap.client_type}</dd>
            <dt>状态更新时间</dt>
            <dd>
              {Number.isNaN(Date.parse(snap.since))
                ? snap.since
                : new Date(snap.since).toLocaleString("zh-CN")}
            </dd>
            <dt>网关</dt>
            <dd className="font-mono">{snap.gateways?.join(", ") || "—"}</dd>
            <dt>隧道 DNS</dt>
            <dd className="font-mono">{snap.dns?.join(", ") || "—"}</dd>
          </dl>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
