import { useCallback, useEffect, useRef, useState } from "react";
import { Laptop, Smartphone, RefreshCw, LoaderCircle } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { fetchTrustDevices, post, errorText } from "../api";
import type { FriendlyError } from "../errors";
import type { Snapshot, TrustDeviceEntry, TrustDeviceList } from "../types";
import { ErrorText } from "./ErrorText";
import { ConfirmDialog } from "./ConfirmDialog";
function deviceLabel(device: TrustDeviceEntry) {
  return (
    device.deviceName?.trim() ||
    [device.os, device.osVersion].filter(Boolean).join(" ") ||
    "未命名设备"
  );
}
const ERRORS = {
  503: "会话未就绪，请稍后重试",
  409: "当前登录模式不能绑定设备",
};
type Confirmation =
  | { session: string; kind: "logout"; device: TrustDeviceEntry }
  | { session: string; kind: "unbind"; ids: string[] };
export function TrustDevices({
  snap,
  connected,
}: {
  snap: Snapshot;
  connected: boolean;
}) {
  const [loaded, setLoaded] = useState<{
    session: string;
    list: TrustDeviceList;
  } | null>(null);
  const [error, setError] = useState<FriendlyError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pending, setPending] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const epoch = useRef(0);
  const mutation = useRef<string | null>(null);
  const sessionKey = `${snap.generation ?? 0}:${snap.state}:${snap.since}:${snap.user?.username ?? ""}`;
  const sessionRef = useRef(sessionKey);
  if (sessionRef.current !== sessionKey) {
    sessionRef.current = sessionKey;
    epoch.current++;
    mutation.current = null;
  }
  const list = loaded?.session === sessionKey ? loaded.list : null;
  const refresh = useCallback(async () => {
    const request = ++epoch.current;
    const session = sessionRef.current;
    setRefreshing(true);
    setError(null);
    try {
      const next = await fetchTrustDevices();
      if (request !== epoch.current) return;
      setLoaded({ session, list: next });
      const ids = new Set((next.data ?? []).map((device) => device.id));
      setSelected(
        (previous) => new Set([...previous].filter((id) => ids.has(id))),
      );
    } catch (error) {
      if (request !== epoch.current) return;
      setLoaded(null);
      setError(errorText(error, "加载设备失败", ERRORS));
    } finally {
      if (request === epoch.current) setRefreshing(false);
    }
  }, []);
  useEffect(() => {
    epoch.current++;
    setLoaded(null);
    setSelected(new Set());
    setError(null);
    setNotice(null);
    setPending(null);
    setRefreshing(false);
    setConfirmation(null);
    if (snap.state === "online") void refresh();
    return () => {
      epoch.current++;
    };
  }, [sessionKey, snap.state, refresh]);
  const devices = [...(list?.data ?? [])].sort(
    (a, b) => Number(b.id === list?.selfId) - Number(a.id === list?.selfId),
  );
  const selfTrusted = devices.some((device) => device.id === list?.selfId);
  const eligible = devices.filter((device) => device.id !== list?.selfId);
  const selectedIDs = eligible
    .filter((device) => selected.has(device.id))
    .map((device) => device.id);
  const canRefresh =
    connected && snap.state === "online" && pending === null && !refreshing;
  const canAct = canRefresh && list !== null;
  const run = async (
    action: () => Promise<void>,
    success: string,
    label: string,
  ) => {
    if (!canAct || mutation.current === sessionKey) return;
    const session = sessionKey;
    mutation.current = session;
    setPending(label);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (session !== sessionRef.current) return;
      setNotice(success);
      setSelected(new Set());
      await refresh();
    } catch (error) {
      if (session === sessionRef.current)
        setError(errorText(error, "设备操作失败", ERRORS));
    } finally {
      if (session === sessionRef.current) {
        mutation.current = null;
        setPending(null);
      }
    }
  };
  const toggle = (id: string) =>
    setSelected((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const renderDevice = (device: TrustDeviceEntry) => {
    const Icon = /ios|android|phone/i.test(`${device.os} ${device.deviceType}`)
      ? Smartphone
      : Laptop;
    return (
      <div className="flex min-w-0 items-center gap-3">
        <span className="device-icon">
          <Icon className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{deviceLabel(device)}</span>
            {device.id === list?.selfId && (
              <span className="text-xs text-success">本机</span>
            )}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {[device.os, device.osVersion, device.deviceType]
              .filter(Boolean)
              .join(" · ") || "设备信息未提供"}
          </p>
        </div>
      </div>
    );
  };
  const logoutButton = (device: TrustDeviceEntry) => (
    <Button
      variant="ghost"
      size="sm"
      disabled={!canAct}
      onClick={() =>
        setConfirmation({ session: sessionKey, kind: "logout", device })
      }
      aria-label={`注销 ${deviceLabel(device)}`}
    >
      {pending === `logout:${device.id}` ? "注销中…" : "注销"}
    </Button>
  );
  const confirmTitle =
    confirmation?.kind === "unbind"
      ? `取消 ${confirmation.ids.length} 台设备的授信？`
      : confirmation?.device.id === list?.selfId
        ? "注销本机？"
        : "注销设备？";
  const confirmDescription =
    confirmation?.kind === "unbind"
      ? "这些设备下次登录可能需要短信验证。"
      : confirmation?.device.id === list?.selfId
        ? "本机会话将立即失效，代理连接会断开。重新登录后可以恢复连接。"
        : `设备「${confirmation ? deviceLabel(confirmation.device) : ""}」的会话将立即失效。`;
  return (
    <Card className="devices-card">
      <div className="devices-heading">
        <div className="flex items-baseline gap-2">
          <h2 className="text-base font-medium">授信设备</h2>
          <span className="text-xs text-muted-foreground">
            {list ? `${devices.length} 台` : ""}
          </span>
        </div>
        <div className="flex gap-2">
          <Button
            variant="ghost"
            size="icon"
            aria-label="刷新设备"
            disabled={!canRefresh}
            onClick={() => void refresh()}
          >
            {refreshing ? (
              <LoaderCircle className="animate-spin" />
            ) : (
              <RefreshCw />
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!canAct || selfTrusted || snap.client_type !== "client"}
            title={
              snap.client_type !== "client"
                ? "browser 模式不能绑定本机"
                : selfTrusted
                  ? "本机已授信"
                  : undefined
            }
            onClick={() =>
              void run(
                () => post("/api/trust-devices/bind", {}),
                "已绑定本机",
                "bind",
              )
            }
          >
            {pending === "bind"
              ? "绑定中…"
              : selfTrusted
                ? "本机已授信"
                : "绑定本机"}
          </Button>
        </div>
      </div>
      {(error || notice || snap.client_type !== "client") && (
        <div className="px-6 pb-4">
          {error && <ErrorText error={error} />}
          {notice && (
            <p className="text-sm text-success" role="status">
              {notice}
            </p>
          )}
          {snap.client_type !== "client" && (
            <p className="mt-2 text-xs text-muted-foreground">
              browser 模式可以管理已有设备；绑定本机需要 client 登录模式。
            </p>
          )}
        </div>
      )}
      {list && devices.length ? (
        <>
          <div className="hidden md:block">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10 pl-4">
                    <Checkbox
                      aria-label="选择全部其他设备"
                      disabled={!canAct || !eligible.length}
                      checked={
                        selectedIDs.length === eligible.length &&
                        eligible.length > 0
                          ? true
                          : selectedIDs.length
                            ? "indeterminate"
                            : false
                      }
                      onCheckedChange={(value) =>
                        setSelected(
                          value === true
                            ? new Set(eligible.map((device) => device.id))
                            : new Set(),
                        )
                      }
                    />
                  </TableHead>
                  <TableHead>设备</TableHead>
                  <TableHead>最近登录 IP</TableHead>
                  <TableHead>位置</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead className="pr-4 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((device) => (
                  <TableRow key={device.id}>
                    <TableCell className="pl-4">
                      <Checkbox
                        aria-label={`选择 ${deviceLabel(device)}`}
                        checked={selected.has(device.id)}
                        disabled={!canAct || device.id === list.selfId}
                        onCheckedChange={() => toggle(device.id)}
                      />
                    </TableCell>
                    <TableCell>{renderDevice(device)}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {device.lastLoginIp || "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {device.lastLoginAddress || "—"}
                    </TableCell>
                    <TableCell
                      className={`text-xs ${device.onlineStatus ? "text-success" : "text-muted-foreground"}`}
                    >
                      {device.onlineStatus === undefined
                        ? "未知"
                        : device.onlineStatus
                          ? "在线"
                          : "离线"}
                    </TableCell>
                    <TableCell className="pr-4 text-right">
                      {logoutButton(device)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <ul className="md:hidden">
            {devices.map((device) => (
              <li className="mobile-device" key={device.id}>
                <Checkbox
                  aria-label={`选择 ${deviceLabel(device)}`}
                  checked={selected.has(device.id)}
                  disabled={!canAct || device.id === list.selfId}
                  onCheckedChange={() => toggle(device.id)}
                />
                <div className="min-w-0 flex-1">{renderDevice(device)}</div>
                {logoutButton(device)}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="px-6 pb-6 text-sm text-muted-foreground">
          {refreshing
            ? "正在加载设备…"
            : snap.state !== "online"
              ? "连接后可查看授信设备。"
              : error
                ? "设备列表暂不可用。"
                : "暂无授信设备。"}
        </p>
      )}
      <div className="devices-footer">
        <span className="text-xs text-muted-foreground">
          {list
            ? `授信策略${list.trustDeviceConfig.enable ? "已启用" : "未启用"}`
            : ""}
        </span>
        <Button
          variant="ghost"
          size="sm"
          disabled={!canAct || selectedIDs.length === 0}
          onClick={() =>
            setConfirmation({
              session: sessionKey,
              kind: "unbind",
              ids: selectedIDs,
            })
          }
        >
          {pending === "unbind"
            ? "处理中…"
            : `取消授信（${selectedIDs.length}）`}
        </Button>
      </div>
      <ConfirmDialog
        open={confirmation !== null}
        onOpenChange={(value) => {
          if (!value) setConfirmation(null);
        }}
        title={confirmTitle}
        description={confirmDescription}
        action={confirmation?.kind === "unbind" ? "取消授信" : "注销"}
        destructive
        disabled={!canAct || confirmation?.session !== sessionKey}
        onConfirm={() => {
          if (!confirmation || confirmation.session !== sessionKey) return;
          if (confirmation.kind === "unbind")
            void run(
              () =>
                post("/api/trust-devices/unbind", { ids: confirmation.ids }),
              "已取消授信",
              "unbind",
            );
          else
            void run(
              () =>
                post("/api/trust-devices/logout", {
                  id: confirmation.device.id,
                }),
              "已注销设备",
              `logout:${confirmation.device.id}`,
            );
        }}
      />
    </Card>
  );
}
