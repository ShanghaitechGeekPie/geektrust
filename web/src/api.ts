import { useSyncExternalStore } from "react";
import type { Snapshot, TrustDeviceList } from "./types";
import { friendlyError, type FriendlyError } from "./errors";

// ---------------------------------------------------------------------------
// Live store. The SSE stream feeds full snapshots; a one-shot /api/status
// fetch seeds the first paint and is discarded once stream data exists, so a
// slow fetch can never overwrite fresher data. `connected` mirrors the SSE
// link so the UI can flag stale data instead of presenting a dead process as
// "online".

export interface PanelStore {
  snap: Snapshot | null;
  connected: boolean;
}

let store: PanelStore = { snap: null, connected: false };
const listeners = new Set<() => void>();
let sawStream = false;
let stream: EventSource | undefined;
let streamEpoch = 0;

function publish(next: PanelStore) {
  store = next;
  listeners.forEach((l) => l());
}

function connect() {
  const es = new EventSource("/api/events");
  stream = es;
  es.onopen = () => {
    if (!store.connected) publish({ ...store, connected: true });
  };
  es.onmessage = (e) => {
    let snap: Snapshot;
    try {
      snap = JSON.parse(e.data) as Snapshot;
    } catch {
      return; // tolerate a malformed frame; the next broadcast resyncs
    }
    sawStream = true;
    publish({ snap, connected: true });
  };
  es.onerror = () => {
    // EventSource retries the connection itself.
    if (store.connected) publish({ ...store, connected: false });
  };
}

async function seed(epoch: number) {
  try {
    const resp = await fetch("/api/status");
    if (!resp.ok) return;
    const snap = (await resp.json()) as Snapshot;
    if (epoch === streamEpoch && !sawStream) publish({ ...store, snap });
  } catch {
    // the SSE loop owns retries
  }
}



function subscribePanel(cb: () => void) {
  listeners.add(cb);
  if (listeners.size === 1) {
    sawStream = false;
    connect();
    void seed(++streamEpoch);
  }
  return () => {
    listeners.delete(cb);
    if (listeners.size === 0) {
      streamEpoch++;
      stream?.close();
      stream = undefined;
      store = { ...store, connected: false };
    }
  };
}

export function usePanelStore(): PanelStore {
  return useSyncExternalStore(subscribePanel, () => store);
}

// ---------------------------------------------------------------------------
// Request helpers.

export class ApiError extends Error {
  /** HTTP status; 0 means the panel server was unreachable. */
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// The panel server's own rejections are English protocol strings; these
// statuses get Chinese text unless the call site supplies something better.
const PANEL_STATUS_TEXT: Record<number, string> = {
  400: "请求无效，请刷新页面后重试",
  403: "面板拒绝了该请求，请通过配置中 web.listen 的地址访问面板",
  404: "面板服务不支持该操作，请刷新页面后重试",
  405: "面板服务不支持该操作，请刷新页面后重试",
};

// errorText renders an unknown error for the UI: call-site overrides first,
// then panel status defaults (the server speaks English, the panel speaks
// Chinese), then the server text reduced by friendlyError, then the fallback.
// The raw server text is kept as `detail` wherever it adds diagnostic value.
export function errorText(err: unknown, fallback: string, overrides?: Record<number, string>): FriendlyError {
  if (err instanceof ApiError) {
    const specific = overrides?.[err.status];
    if (specific) return { summary: specific };
    const panel = PANEL_STATUS_TEXT[err.status];
    if (panel) return { summary: panel, detail: err.message || undefined };
    if (err.message) return friendlyError(err.message, fallback);
  }
  return { summary: fallback };
}

async function doFetch(path: string, init?: RequestInit): Promise<Response> {
  let resp: Response;
  try {
    resp = await fetch(path, init);
  } catch {
    throw new ApiError(0, "无法连接面板服务");
  }
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data.error) message = data.error;
    } catch {
      // keep the generic message
    }
    throw new ApiError(resp.status, message);
  }
  return resp;
}

export async function post(path: string, body: unknown): Promise<void> {
  await doFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const resp = await doFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await resp.json()) as T;
}

export async function fetchTrustDevices(): Promise<TrustDeviceList> {
  const resp = await doFetch("/api/trust-devices");
  return (await resp.json()) as TrustDeviceList;
}
