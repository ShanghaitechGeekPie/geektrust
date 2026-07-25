export type PanelState = "offline" | "connecting" | "sms_required" | "online";

export interface UserInfo {
  username: string;
  display_name: string;
  client_ip: string;
}

export interface ProxyInfo {
  socks5: string | null;
  http: string | null;
}

export interface HistoryEvent {
  ts: string;
  kind: string;
  message: string;
}

// Snapshot mirrors GET /api/status and the SSE payload (docs/WEBUI.md §6.3).
export interface Snapshot {
  state: PanelState;
  since: string;
  last_error: string | null;
  user: UserInfo | null;
  device_id: string;
  client_type: string;
  gateways: string[] | null;
  dns: string[] | null;
  proxy: ProxyInfo;
  sms_pending: boolean;
  sms_gen: number;
  events_dropped: number;
  events: HistoryEvent[];
}

// TrustDeviceEntry/List mirror the controller wire format (§7.4).
export interface TrustDeviceEntry {
  id: string;
  deviceName?: string;
  deviceType?: string;
  os?: string;
  osVersion?: string;
  lastLoginIp?: string;
  lastLoginAddress?: string;
  networkZoneList?: string[];
  onlineStatus?: boolean;
}

export interface TrustDeviceList {
  data: TrustDeviceEntry[];
  selfId: string;
  currentTrustStatus: number;
  trustDeviceConfig: { enable: boolean };
}
