import { act, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import type { Snapshot } from "./types";
class Stream {
  static instances: Stream[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  close = vi.fn();
  constructor() {
    Stream.instances.push(this);
  }
}
const snapshot: Snapshot = {
  generation: 1,
  state: "online",
  since: "2026-10-06T00:00:00Z",
  last_error: null,
  user: null,
  device_id: "fixture",
  client_type: "client",
  controller_host: "vpn.example.edu.cn",
  gateways: [],
  dns: [],
  proxy: { socks5: null, http: null },
  sms_pending: false,
  sms_gen: 0,
  events_dropped: 0,
  events: [],
};
beforeEach(() => {
  vi.resetModules();
  Stream.instances = [];
  vi.stubGlobal("EventSource", Stream);
  vi.stubGlobal(
    "fetch",
    vi.fn(() => new Promise<Response>(() => {})),
  );
});
it("waits for a current snapshot before declaring a reconnected panel live", async () => {
  const { usePanelStore } = await import("./api");
  function Probe() {
    const state = usePanelStore();
    return (
      <span>
        {state.connected ? "live" : "stale"}:{state.snap?.generation ?? 0}
      </span>
    );
  }
  render(<Probe />);
  const stream = Stream.instances[0];
  act(() => stream.onmessage?.({ data: JSON.stringify(snapshot) }));
  expect(screen.getByText("live:1")).toBeTruthy();
  act(() => stream.onerror?.());
  expect(screen.getByText("stale:1")).toBeTruthy();
  act(() => stream.onopen?.());
  expect(screen.getByText("stale:1")).toBeTruthy();
  act(() =>
    stream.onmessage?.({
      data: JSON.stringify({ ...snapshot, generation: 2 }),
    }),
  );
  expect(screen.getByText("live:2")).toBeTruthy();
});
