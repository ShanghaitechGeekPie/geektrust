import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { SmsDialog } from "./SmsDialog";
import { TrustDevices } from "./TrustDevices";
import { EventsList } from "./EventsList";
import type { Snapshot, TrustDeviceList } from "../types";
const api = vi.hoisted(() => ({
  fetchTrustDevices: vi.fn(),
  post: vi.fn(),
  postJSON: vi.fn(),
}));
vi.mock("../api", async (original) => ({
  ...(await original<typeof import("../api")>()),
  ...api,
}));
const snapshot: Snapshot = {
  generation: 1,
  state: "online",
  since: "2026-10-06T00:00:00Z",
  last_error: null,
  user: { username: "user", display_name: "用户", client_ip: "192.0.2.1" },
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
const devices: TrustDeviceList = {
  data: [
    { id: "self", deviceName: "本机" },
    { id: "other", deviceName: "其他设备" },
  ],
  selfId: "self",
  currentTrustStatus: 1,
  trustDeviceConfig: { enable: true },
};
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
beforeEach(() => {
  api.fetchTrustDevices.mockReset();
  api.post.mockReset();
  api.postJSON.mockReset();
});
it("discards a device response after the session changes", async () => {
  const old = deferred<TrustDeviceList>();
  const next = deferred<TrustDeviceList>();
  api.fetchTrustDevices
    .mockReturnValueOnce(old.promise)
    .mockReturnValueOnce(next.promise);
  const { rerender } = render(<TrustDevices snap={snapshot} connected />);
  rerender(<TrustDevices snap={{ ...snapshot, generation: 2 }} connected />);
  await act(async () => old.resolve(devices));
  expect(screen.queryByText("其他设备")).toBeNull();
  await act(async () =>
    next.resolve({ ...devices, data: [{ id: "new", deviceName: "新设备" }] }),
  );
  expect(screen.getAllByText("新设备").length).toBeGreaterThan(0);
});
it("closes an old confirmation and blocks its action when the session changes", async () => {
  api.fetchTrustDevices.mockResolvedValue(devices);
  const { rerender } = render(<TrustDevices snap={snapshot} connected />);
  await waitFor(() =>
    expect(
      screen.getAllByRole("button", { name: "注销 其他设备" }).length,
    ).toBeGreaterThan(0),
  );
  fireEvent.click(screen.getAllByRole("button", { name: "注销 其他设备" })[0]);
  expect(screen.getByRole("alertdialog")).toBeTruthy();
  rerender(<TrustDevices snap={{ ...snapshot, generation: 2 }} connected />);
  expect(screen.queryByRole("alertdialog")).toBeNull();
  expect(api.post).not.toHaveBeenCalled();
});
it("requires confirmation for self logout and posts the correct device", async () => {
  api.fetchTrustDevices.mockResolvedValue(devices);
  api.post.mockResolvedValue(undefined);
  render(<TrustDevices snap={snapshot} connected />);
  await waitFor(() =>
    expect(
      screen.getAllByRole("button", { name: "注销 本机" }).length,
    ).toBeGreaterThan(0),
  );
  fireEvent.click(screen.getAllByRole("button", { name: "注销 本机" })[0]);
  expect(api.post).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "注销" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith("/api/trust-devices/logout", {
      id: "self",
    }),
  );
});
it("keeps mutations disabled after the panel disconnects", async () => {
  api.fetchTrustDevices.mockResolvedValue(devices);
  const { rerender } = render(<TrustDevices snap={snapshot} connected />);
  await waitFor(() =>
    expect(
      screen.getAllByRole("button", { name: "注销 其他设备" }).length,
    ).toBeGreaterThan(0),
  );
  rerender(<TrustDevices snap={snapshot} connected={false} />);
  expect(
    (
      screen.getAllByRole("button", {
        name: "注销 其他设备",
      })[0] as HTMLButtonElement
    ).disabled,
  ).toBe(true);
});
it("shows 10 recent events and all retained events in the dialog", () => {
  const events = Array.from({ length: 40 }, (_, i) => ({
    ts: `2026-10-06T00:${String(i).padStart(2, "0")}:00Z`,
    kind: "login_start",
    message: `事件${i}`,
  }));
  render(<EventsList events={events} dropped={0} />);
  expect(document.querySelector(".activity-list")?.children.length).toBe(10);
  fireEvent.click(screen.getByRole("button", { name: "查看全部" }));
  expect(
    document.querySelector('[role="dialog"] .activity-list')?.children.length,
  ).toBe(40);
});
it("prevents duplicate SMS resends while the request is pending", async () => {
  vi.useFakeTimers();
  const response = deferred<{ restarting?: boolean }>();
  api.postJSON.mockReturnValue(response.promise);
  render(
    <SmsDialog
      snap={{ ...snapshot, sms_pending: true, sms_gen: 7 }}
      connected
      open
      onOpenChange={() => {}}
    />,
  );
  act(() => vi.advanceTimersByTime(60000));
  const button = screen.getByRole("button", { name: "重新发送" });
  fireEvent.click(button);
  fireEvent.click(button);
  expect(api.postJSON).toHaveBeenCalledTimes(1);
  await act(async () => response.resolve({}));
  vi.useRealTimers();
});
it("keeps an old SMS result out of a new verification generation", async () => {
  const old = deferred<void>();
  api.post.mockReturnValue(old.promise);
  const { rerender } = render(
    <SmsDialog
      key={7}
      snap={{ ...snapshot, sms_pending: true, sms_gen: 7 }}
      connected
      open
      onOpenChange={() => {}}
    />,
  );
  fireEvent.change(screen.getByLabelText("6 位短信验证码"), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证并连接" }));
  expect(api.post).toHaveBeenCalledWith("/api/sms", { code: "123456", gen: 7 });
  rerender(
    <SmsDialog
      key={8}
      snap={{ ...snapshot, sms_pending: true, sms_gen: 8 }}
      connected
      open
      onOpenChange={() => {}}
    />,
  );
  await act(async () => old.reject(new Error("old failure")));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(
    (screen.getByLabelText("6 位短信验证码") as HTMLInputElement).value,
  ).toBe("");
});

it("allows browser-mode device management while refusing a new local binding", async () => {
  api.fetchTrustDevices.mockResolvedValue({
    ...devices,
    data: [{ id: "other", deviceName: "其他设备" }],
  });
  render(
    <TrustDevices snap={{ ...snapshot, client_type: "browser" }} connected />,
  );
  await waitFor(() =>
    expect(
      screen.getAllByRole("button", { name: "注销 其他设备" }).length,
    ).toBeGreaterThan(0),
  );
  expect(
    (screen.getByRole("button", { name: "绑定本机" }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  expect(
    (
      screen.getAllByRole("button", {
        name: "注销 其他设备",
      })[0] as HTMLButtonElement
    ).disabled,
  ).toBe(false);
});

it("explains a background authentication challenge without showing an internal error", () => {
  render(<EventsList events={[{ ts: "2026-10-06T00:00:00Z", kind: "interaction_required", message: "authentication interaction required" }]} dropped={0} />);
  expect(screen.getByText("登录需要验证，请重新登录")).toBeTruthy();
  expect(screen.queryByText("authentication interaction required")).toBeNull();
});
