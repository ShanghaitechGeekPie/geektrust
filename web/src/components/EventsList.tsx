import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { friendlyError } from "../errors";
import type { HistoryEvent } from "../types";
function ActivityRows({ events }: { events: HistoryEvent[] }) {
  return (
    <ul className="activity-list">
      {events.map((event, index) => {
        const date = new Date(event.ts);
        const color = ["login_success", "restore_success"].includes(event.kind)
          ? "bg-success"
          : event.kind === "login_failed"
            ? "bg-destructive"
            : event.kind === "interaction_required"
              ? "bg-warning"
              : "bg-muted-foreground";
        const text =
          event.kind === "login_failed"
            ? friendlyError(event.message, "登录失败").summary
            : event.kind === "interaction_required"
              ? "登录需要验证，请重新登录"
              : event.message;
        return (
          <li key={`${event.ts}-${index}`}>
            <time dateTime={event.ts} title={event.ts}>
              {Number.isNaN(date.getTime())
                ? event.ts
                : date.toLocaleTimeString("zh-CN", { hour12: false })}
            </time>
            <span
              aria-hidden="true"
              className={`size-1.5 shrink-0 rounded-full ${color}`}
            />
            <span
              className="min-w-0 break-words"
              title={text === event.message ? undefined : event.message}
            >
              {text}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
export function EventsList({
  events,
  dropped,
}: {
  events: HistoryEvent[];
  dropped: number;
}) {
  const [open, setOpen] = useState(false);
  const newest = [...events].reverse();
  return (
    <Card className="activity-card">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-base font-medium">最近活动</h2>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            最近 {Math.min(10, events.length)} 条
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setOpen(true)}
            disabled={!events.length}
          >
            查看全部
          </Button>
        </div>
      </div>
      {events.length ? (
        <ActivityRows events={newest.slice(0, 10)} />
      ) : (
        <p className="text-sm text-muted-foreground">暂无活动记录</p>
      )}
      {dropped > 0 && (
        <p className="text-xs text-muted-foreground">
          另有 {dropped} 条事件未能记录。
        </p>
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="activity-dialog">
          <DialogHeader>
            <DialogTitle>活动记录</DialogTitle>
            <DialogDescription>共 {events.length} 条</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto overscroll-contain pr-2">
            <ActivityRows events={newest} />
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" className="w-full">
                关闭
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
