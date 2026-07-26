import { friendlyError } from "../errors";
import type { HistoryEvent } from "../types";

const KIND_LABEL: Record<string, string> = {
  login_start: "开始登录",
  login_success: "登录成功",
  restore_success: "恢复会话",
  login_failed: "登录失败",
  invalidated: "会话失效",
};

function formatTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function EventsList({ events, dropped }: { events: HistoryEvent[]; dropped: number }) {
  return (
    <section className="card">
      <h2>事件</h2>
      {dropped > 0 && <p className="muted">有 {dropped} 条早期事件因缓冲上限被丢弃。</p>}
      {events.length === 0 ? (
        <p className="muted">暂无事件</p>
      ) : (
        <ul className="events">
          {[...events].reverse().map((ev, i) => {
            // Only login_failed carries a wrapped Go error chain; every other
            // kind is already a plain sentence that must not be rewritten.
            const text =
              ev.kind === "login_failed" ? friendlyError(ev.message).summary : ev.message;
            return (
              <li key={`${ev.ts}-${events.length - i}`}>
                <span className="mono muted ev-time">{formatTime(ev.ts)}</span>
                <span className={`tag kind-${ev.kind}`}>{KIND_LABEL[ev.kind] ?? ev.kind}</span>
                <span className="ev-msg" title={text === ev.message ? undefined : ev.message}>
                  {text}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
