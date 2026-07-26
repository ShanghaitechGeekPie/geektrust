import { useSyncExternalStore } from "react";
import type { Snapshot, TrustDeviceList } from "./types";

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
let reconnectTimer: number | undefined;

function publish(next: PanelStore) {
  store = next;
  listeners.forEach((l) => l());
}

function connect() {
  reconnectTimer = undefined;
  const es = new EventSource("/api/events");
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
    // Rebuild the stream ourselves: EventSource stops retrying once closed,
    // and the UI needs an explicit "disconnected" signal either way.
    es.close();
    if (store.connected) publish({ ...store, connected: false });
    if (reconnectTimer === undefined) {
      reconnectTimer = window.setTimeout(connect, 2000);
    }
  };
}

async function seed() {
  try {
    const resp = await fetch("/api/status");
    if (!resp.ok) return;
    const snap = (await resp.json()) as Snapshot;
    if (!sawStream) publish({ ...store, snap });
  } catch {
    // the SSE loop owns retries
  }
}

connect();
void seed();

export function usePanelStore(): PanelStore {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => store,
  );
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

// errorText renders an unknown error for the UI: status-specific overrides
// first (the server speaks English, the panel speaks Chinese), then the
// server-provided text, then the generic fallback.
export function errorText(err: unknown, fallback: string, overrides?: Record<number, string>): string {
  if (err instanceof ApiError) {
    const specific = overrides?.[err.status];
    if (specific) return specific;
    return err.message || fallback;
  }
  return fallback;
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

export async function fetchTrustDevices(): Promise<TrustDeviceList> {
  const resp = await doFetch("/api/trust-devices");
  return (await resp.json()) as TrustDeviceList;
}
