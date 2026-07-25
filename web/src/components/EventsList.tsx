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
  return Number.isNaN(d.getTime())
    ? ts
    : d.toLocaleTimeString("zh-CN", { hour12: false });
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
          {[...events].reverse().map((ev, i) => (
            <li key={`${ev.ts}-${i}`}>
              <span className="mono muted">{formatTime(ev.ts)}</span>
              <span className={`tag kind-${ev.kind}`}>{KIND_LABEL[ev.kind] ?? ev.kind}</span>
              <span>{ev.message}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
