import { useSyncExternalStore } from "react";
import type { Snapshot, TrustDeviceList } from "./types";

// Live snapshot store fed by the SSE stream. The server sends a full
// snapshot on connect and on every change, so a reconnect (EventSource
// retries automatically) always resynchronizes.
let current: Snapshot | null = null;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((l) => l());
}

function connect() {
  const es = new EventSource("/api/events");
  es.onmessage = (e) => {
    current = JSON.parse(e.data) as Snapshot;
    emit();
  };
  es.onerror = () => {
    es.close();
    // EventSource only retries while open; rebuild the stream manually.
    setTimeout(connect, 2000);
  };
}
connect();

export function useSnapshot(): Snapshot | null {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current,
  );
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function parseError(resp: Response): Promise<never> {
  let message = `HTTP ${resp.status}`;
  try {
    const data = (await resp.json()) as { error?: string };
    if (data.error) message = data.error;
  } catch {
    // keep the generic message
  }
  throw new ApiError(resp.status, message);
}

export async function post(path: string, body: unknown): Promise<void> {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) await parseError(resp);
}

export async function fetchTrustDevices(): Promise<TrustDeviceList> {
  const resp = await fetch("/api/trust-devices");
  if (!resp.ok) await parseError(resp);
  return (await resp.json()) as TrustDeviceList;
}
