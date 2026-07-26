// Failure text reaching the panel is a Go error chain, not a user message:
// `check sms code: sdpc checkSms: code 75500403: 验证码错误` or
// `cas chain: Get "https://…": dial tcp: i/o timeout`. Rendering that raw
// makes the panel look broken, so every failure is reduced to one actionable
// Chinese line while the original stays one click away for debugging.

// Control-plane codes documented in docs/TECHNICAL.md §11.1 plus the two
// found only in code (75500000 trust_device.go, 75500401 sdpc/client.go).
// Undocumented codes are deliberately absent: the fallback below prefers the
// controller's own Chinese message over a guess.
const CODE_TEXT: Record<string, string> = {
  "10000000": "该账号已登录,无需重复上线",
  "10000001": "请求参数无效,请检查配置后重试",
  "10000004": "服务端未找到会话,请重新登录",
  "10000008": "接口签名校验失败,请检查系统时间与 device_id",
  "75500000": "当前为纯 web 模式,服务端不允许绑定授信终端",
  "75500001": "认证已超时,请重新登录",
  "75500002": "会话已失效,请重新登录",
  "75500006": "当前账号已在线,无需重复上线",
  "75500304": "登录票据已失效,请重新登录",
  "75500401": "验证码仍在有效期内,请直接输入上一条短信中的验证码",
  "75599999": "控制器要求的前置步骤未完成,请重新登录",
};

// Transport failures, most specific first: a DNS or TLS error also mentions
// the host, so ordering decides which explanation wins.
const NET_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  [/no such host|dns/i, "无法解析控制器域名,请检查 DNS 或网络连接"],
  [/connection refused/i, "控制器拒绝连接,请检查地址与端口"],
  [/x509|certificate|tls handshake/i, "TLS 证书校验失败,请检查系统时间与证书信任"],
  [/no route to host|network is unreachable/i, "网络不可达,请检查本机网络"],
  [/i\/o timeout|context deadline exceeded|timed? ?out/i, "连接控制器超时,请检查网络"],
  [/connection reset|broken pipe|unexpected eof|\beof\b/i, "与控制器的连接被中断,请重试"],
  [/context canceled/i, "操作已取消"],
];

const CJK = /[\u4e00-\u9fff]/;

export interface FriendlyError {
  /** One actionable line for the user. */
  summary: string;
  /** The original text, set only when it says more than the summary. */
  detail?: string;
}

// lastChineseSegment picks the controller's own message out of a wrapped
// chain. Go wraps with ASCII prefixes (`cas chain: `), so the last colon-
// separated part containing Chinese is the server's actual complaint.
function lastChineseSegment(text: string): string | null {
  const parts = text.split(": ");
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i].trim();
    if (part && CJK.test(part)) return part;
  }
  return null;
}

export function friendlyError(raw: string): FriendlyError {
  const text = raw.trim();
  if (!text) return { summary: "未知错误" };

  const code = text.match(/\bcode (\d{6,8})\b/);
  const mapped = code && CODE_TEXT[code[1]];
  if (mapped) return { summary: mapped, detail: text };

  for (const [pattern, message] of NET_RULES) {
    if (pattern.test(text)) return { summary: message, detail: text };
  }

  const tail = lastChineseSegment(text);
  if (tail && tail !== text) return { summary: tail, detail: text };
  return { summary: text };
}
