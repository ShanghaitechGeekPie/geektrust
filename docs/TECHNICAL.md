# geekTrust 技术规格文档(aTrust SDP 2.0 连接协议)

> 本文档客观、完整地描述与上海科技大学 aTrust VPN(Sangfor aTrust SDP 2.0,`https://vpn.shanghaitech.edu.cn/`)建立连接、并通过其代理网关转发 TCP 流量所需的全部协议细节。
> 文中所有请求/响应结构、字段、状态码均经过线上实测验证,并与本仓库 `src/` 下的 Python 参考实现一一对应。
> 配套设计与实施计划见 [`PLAN.md`](./PLAN.md)。`ANALYSIS.md`、`HANDOFF.md`、`PROTOCOL.md` 为早期调研笔记(归档,仅供内部参考)。

---

## 目录

1. [总体架构](#1-总体架构)
2. [术语与常量](#2-术语与常量)
3. [控制面:认证与会话建立](#3-控制面认证与会话建立)
4. [资源配置拉取](#4-资源配置拉取)
5. [隧道建立](#5-隧道建立)
6. [每连接认证](#6-每连接认证)
7. [数据面](#7-数据面)
8. [用户态 TCP 端点](#8-用户态-tcp-端点)
9. [代理入口(SOCKS5/HTTP)](#9-代理入口socks5http)
10. [密码学与签名参考](#10-密码学与签名参考)
11. [状态码与错误码总表](#11-状态码与错误码总表)
12. [运行与鲁棒性要点](#12-运行与鲁棒性要点)
13. [参考实现索引(Python)](#13-参考实现索引python)

---

## 1. 总体架构

```
┌────────────┐  SOCKS5/HTTP   ┌──────────────────────┐  TLS(自定义二进制帧)  ┌──────────────────┐
│  应用程序    │ ◄────────────► │  geekTrust           │ ◄════════════════════► │  aTrust 代理网关    │
│ (curl/浏览器)│   本地代理入口   │  (本项目,用户态实现)   │   TCP-over-tunnel    │  <gateway>:441    │
└────────────┘                │                      │                       └────────┬─────────┘
                              │  ┌────────────────┐  │  HTTPS/JSON(控制面)           │
                              │  │ 登录/配置模块    │──┼──────────────────────────────► │
                              │  └────────────────┘  │                                ▼
                              └──────────────────────┘                       ┌──────────────────┐
                                                                            │  SDPC 控制器        │
                                                                            │ vpn.shanghaitech.edu.cn │
                                                                            └──────────────────┘
```

设计要点:

- **不创建系统虚拟网卡、不修改路由表、不需要 root**。所有流量从本地 SOCKS5/HTTP 代理入口进入,
  按 aTrust 的「每连接认证」模型,将每条 TCP 连接映射为隧道内一个独立的 conntrack,
  以用户态 TCP 端点的方式在隧道内重建,再封装为 IPv4 包经数据帧转发。
- **模块解耦**:代理入口(SOCKS5/HTTP inbound)与隧道传输(aTrust outbound)之间通过一个抽象的
  「TCP 连接工厂」接口隔离;登录/配置模块独立产出「会话凭据」,隧道模块只消费会话凭据,二者不互相依赖。
- 控制面(登录、配置)走标准 HTTPS/JSON;数据面走网关 441 端口上的 TLS,承载自定义二进制帧(版本号 `0x05`)。

---

## 2. 术语与常量

### 2.1 端点与网络

| 名称 | 值 | 说明 |
|---|---|---|
| 控制器基址 | `https://vpn.shanghaitech.edu.cn` | 控制面 HTTPS/JSON |
| IDS 基址 | `https://ids.shanghaitech.edu.cn` | 统一身份认证(CAS) |
| 代理网关(外网) | `119.78.254.241:441`、`59.78.171.241:441` | 数据面 TLS,二者等价可切换 |
| 代理网关(内网) | `10.13.90.147:441` | 仅校园网内可达 |
| 代理网关(IPv6) | `[2001:da8:801d:d5a:9020:100:d:5a93]:441` | IPv6 接入 |
| 目标资源:电子资源 | `10.15.45.163:443` / `library.shanghaitech.edu.cn` | appId `681165d0-1c77-11ed-8650-cd35a51aa42a` |
| 目标资源:Egate | `10.15.44.192:443` / `egate.shanghaitech.edu.cn` | appId `c2fe8720-1c77-11ed-8650-cd35a51aa42a` |
| nodeGroup | `2eb64590-0f24-11ed-8ff1-d9356cf2043a` | 上述资源所属网关组 |

### 2.2 标识与凭据

| 名称 | 说明 |
|---|---|
| `device_id` | 设备标识,32 位大写十六进制。规范值取 `MD5("atrust-headless-client-v1").upper()` = `84B5B45FE73EC0036C3E97717308447F`。**必须持久化、永不变更**,服务器据此记忆「受信设备」,避免重复短信验证。(参考脚本 `atrust_socks5.py` 中的兜底默认值 `83D23A2C…` 仅为占位,实际应使用持久化的固定值。) |
| `sid` | 会话 ID,形如 `<unitid>_<uuid>`(如 `9e700fcd-…_63c16989-…`),由 `sessionIdExchange` 通过 Set-Cookie 确立。隧道认证与每连接认证均使用它。 |
| `sidTicket` | 一次性票据,来自 `checkcode`/`ticketExchange`,用于换取 `sid`。 |
| `csrfToken` | 来自 `authConfig.data.security.csrfToken`,作为 `x-csrf-token` 头。 |
| `connectToken` | 每连接认证成功后网关下发的连接令牌(32 位十六进制字符串),数据帧据此定位 conntrack。 |
| `guid` | 来自 `authConfig.data.guid`,账号级标识。 |

### 2.3 公共请求约定(控制面)

所有 `/passport/v1/*` 与 `/controller/v1/*` 请求:

- **Query 参数**(缺失或大小写错误会返回 400/422):
  - `clientType`:浏览器路径用 `SDPBrowserClient`(桌面路径用 `SDPClient`)。
  - `platform`:**大小写敏感,必须为 `Mac`**。`Macintosh` 会报 `10000001 invalid_param in query`;`mac`(全小写)会报 422。
  - `lang`:`zh-CN`。
- **请求头**:
  - `x-csrf-token: <csrfToken>`(必带)。
  - `Content-Type: application/json;charset=utf-8`。
  - 桌面路径的受信请求另需 `X-Request-Sig`(见 §10.3);**浏览器路径无需此头**。

---

## 3. 控制面:认证与会话建立

完整登录序列(线上实测通过):

```
GET  /passport/v1/public/authConfig            → csrfToken / challenge / devicePubKeyMod / rsaCert
IDS passkey 登录 → CASTGC
→ GET /passport/v1/public/casLogin → 302 → IDS → 302 → /passport/v1/auth/cas?ticket=ST
→ 302 → /portal/shortcut.html?...&data={"ticket":"<casTicket>"}
→ POST /controller/v1/public/reportEnv          (前置,缺失则 authCheck 报 75599999)
→ GET  /passport/v1/auth/authCheck              (受信设备直接通过;新设备 nextService=auth/sms)
→ POST /passport/v1/auth/sms?action=sendsms     (仅新设备)
→ POST /passport/v1/auth/sms?action=checkcode   (仅新设备) → sidTicket
→ POST /passport/v1/public/sessionIdExchange    → 建立 sid 会话
→ GET  /passport/v1/user/onlineInfo             → isOnline:true
```

> 本节描述**浏览器路径**(`clientType=SDPBrowserClient`)。`authConfig` 是第一步,提供后续所需的
> `csrfToken`(作为 `x-csrf-token` 头)及 `challenge`/`devicePubKeyMod`/`rsaCert`。
> 注:参考脚本 `tmp/clean_login.py` 走**桌面路径**(`clientType=SDPClient` 并计算 signKey),二者均可用;
> geekTrust 采用浏览器路径以规避接口签名。`tmp/clean_login.py`、`tmp/vpn_sms5.py` 在 authCheck/sendsms 处停止,
> 未调用 ticketExchange/sessionIdExchange/onlineInfo——§3.7/§3.8 依据线上实测,而非这两个脚本。

### 3.1 IDS 统一身份认证(passkey 免密)

通过 `third_party/shanghaitech-ids-passkey`(WebAuthn passkey)完成 IDS 登录,无需用户名密码:

1. `IDSClient(keystore).login()`:使用 keystore 中的 passkey 私钥对 IDS 挑战签名,获得 IDS 会话 cookie(含 `CASTGC`)。
2. 登录成功后 `keystore.dump()` 持久化(`sign_count` 会递增,必须回写)。

> passkey 的**绑定**需浏览器交互(见该库 `bind` 命令);geekTrust 的 Go 实现只需复用已绑定的 keystore 完成登录(见 PLAN.md §4.3)。

### 3.2 authConfig — 获取公共配置

```
GET /passport/v1/public/authConfig?clientType=SDPBrowserClient&platform=Mac&lang=zh-CN
```

响应 `data` 关键字段:

| 字段 | 说明 |
|---|---|
| `security.csrfToken` | 后续请求的 `x-csrf-token`。 |
| `guid` | 账号级 GUID。 |
| `antiReplayRand` | 防重放随机数(十六进制串)。 |
| `pubKey` / `pubKeyExp` | 控制器 RSA 公钥(用于密码加密等)。 |
| `antiMITMAttackData.devicePubKeyMod` | 设备公钥模数(512 个十六进制字符,即 2048 比特 RSA 模数,大写)。 |
| `antiMITMAttackData.devicePubKeyExp` | 设备公钥指数(`10001`,即 65537)。 |
| `antiMITMAttackData.challenge` | 挑战值(base64,128 随机字节),由服务器下发。 |
| `antiMITMAttackData.encryptedChallenge` | 挑战的加密值(大写十六进制)。authConfig 会一并下发;客户端亦可按 §10.2 自行计算(二者等价)。 |
| `antiMITMAttackData.rsaCert` | 服务器 TLS 证书(base64 DER),其 RSA 模数即 `devicePubKeyMod`。 |
| `antiMITMAttackData.sm2encCert` | SM2 加密证书(base64 DER)。 |
| `antiMITMAttackData.mitmSig` | 控制器签名(64 位小写十六进制)。 |
| `antiMITMAttackData.antiMITMRequest` | 布尔;本网关为 `false`(无需额外 antiMITMRequest 往返)。 |

### 3.3 CAS 跳转 — 获取 casTicket

```
GET /passport/v1/public/casLogin?sfDomain=Shanghaitech.edu.cn        (302 → IDS)
GET <IDS Location>  (携带 IDS 会话/CASTGC)                            (302 → /passport/v1/auth/cas?ticket=ST-…)
GET /passport/v1/auth/cas?ticket=ST-…                                (302 → /portal/shortcut.html?…)
```

最终重定向到 `/portal/shortcut.html?...&data=<urlencoded JSON>`,其中 `data` 反序列化后:

```json
{"ticket": "<casTicket>", "env": {"need": true, "timing": "pre-login"}}
```

`data.ticket` 即 `casTicket`,用于下一步 `reportEnv`。

### 3.4 reportEnv — 环境上报(关键前置)

```
POST /controller/v1/public/reportEnv?clientType=SDPBrowserClient&platform=Mac&lang=zh-CN
Content-Type: application/json;charset=utf-8
x-csrf-token: <csrfToken>
```

请求体:

```json
{
  "ticket": "<casTicket>",
  "timing": "pre-login",
  "env": {
    "endpoint": {
      "device_id": "<DEVICE_ID>",
      "device": { "type": "browser" }
    }
  },
  "antiMITMAttackData": {
    "enable": 0,
    "devicePubKeyMod": "<authConfig 下发的 devicePubKeyMod>",
    "devicePubKeyExp": "10001",
    "rsaCert": "<authConfig 下发的 rsaCert>"
  }
}
```

- 缺失此步,`authCheck` 返回 `75599999`(操作异常/设备未注册)。
- `antiMITMAttackData` 亦可传空对象 `{}`(最小化),实测同样可通过;但建议按上式填写完整。
- 成功响应:`{"code":0,"data":{},"message":"OK"}`。
- **注意**:已登录态再次调用会返回 `{"code":10000000,"message":"user has been logged in"}`(本步骤应在建立会话**之前**调用)。

### 3.5 authCheck — 认证检查

```
GET /passport/v1/auth/authCheck?clientType=SDPBrowserClient&platform=Mac&lang=zh-CN
x-csrf-token: <csrfToken>
```

- **受信设备**(该 `device_id` 已完成过首次验证):`{"code":0, ...}`,`data.nextService` 不为 `auth/sms`,可直接进入会话换取。
- **新设备**:`{"code":0, "data":{"nextService":"auth/sms","nextServiceList":[{"authType":"auth/sms",...}]}}`,需走短信二次验证(§3.6)。

### 3.6 短信二次验证(仅新设备首次)

```
POST /passport/v1/auth/sms?action=sendsms&clientType=…&platform=Mac&lang=zh-CN      (触发短信,请求体 {})
POST /passport/v1/auth/sms?action=checkcode&clientType=…&platform=Mac&lang=zh-CN
Content-Type: application/json;charset=utf-8
{"code": "<6位验证码>"}
```

- 验证码发送到账号绑定手机,**60 秒有效且只能使用一次**(重复使用旧码会失败)。
- `checkcode` 成功响应:

```json
{
  "code": 0,
  "message": "短信认证成功",
  "data": {
    "sidTicket": "<unitid>_<uuid>",
    "onlineInfo": { "isOnline": true, "username": "...", "displayName": "...", "userId": "...", "clientIp": "..." }
  }
}
```

### 3.7 会话换取

`sidTicket` 有两个来源:**新设备**经 §3.6 `checkcode` 返回;**已登录态**经 `ticketExchange` 换取。二者都用 `sessionIdExchange` 建立会话。

```
POST /passport/v1/public/ticketExchange?clientType=…&platform=Mac&lang=zh-CN        (已登录态) → data.sidTicket
POST /passport/v1/public/sessionIdExchange?clientType=…&platform=Mac&lang=zh-CN
{"sidTicket": "<sidTicket>"}
```

- `sessionIdExchange` 成功响应 `{"code":0,...}`,并通过 Set-Cookie 确立会话 cookie:
  `sid`、`sid.sig`、`sid-legacy`、`sid-legacy.sig`、`straceid`、`straceid.sig`、`lang` 等。
- `sid` 即后续隧道/每连接认证所用会话标识。

### 3.8 onlineInfo — 在线状态

```
GET /passport/v1/user/onlineInfo?clientType=…&platform=Mac&lang=zh-CN
x-csrf-token: <csrfToken>
```

响应:`{"code":0,"data":{"isOnline":true,"username":"...","displayName":"...",...}}`。
会话失效时返回 `75500002`(会话无效/未登录)。

---

## 4. 资源配置拉取

### 4.1 clientResource(浏览器路径,无需签名)

```
POST /controller/v1/user/clientResource?clientType=SDPBrowserClient&platform=Mac&lang=zh-CN
Content-Type: application/json;charset=UTF-8
x-csrf-token: <csrfToken>
```

请求体(浏览器简单 body):

```json
{
  "resourceType": {
    "sdpPolicy": {},
    "appList": {},
    "favoriteAppList": {},
    "featureCenter": {},
    "uemSpace": { "params": { "action": "login" } }
  }
}
```

- **使用 `clientType=SDPBrowserClient` + 上述简单 body 时,无需 `X-Request-Sig`,实测返回 `code:0`。**
- 若使用 `clientType=SDPClient` 且 body 含 `sdpPolicy.clientSelfProtection.refreshSeed`、`uemPolicy.params.version` 等字段,
  则会触发接口签名校验(缺失/错误返回 `10000008 interface sig verify failed`),需按 §10.3 计算 `X-Request-Sig`。
  **geekTrust 采用浏览器路径,规避签名。**

响应 `data` 关键子项:`appList`、`favoriteAppList`、`featureCenter`、`sdpPolicy`(含 `clientOption`/`accessSecurity`/`loginSecurity`/`accountSecurity`)、`uemSpace`。

### 4.2 appList 结构与域名→内网 IP 映射

`data.appList.data.appInfo[]` 为资源分组,每组 `apps[]` 为具体应用:

```json
{
  "id": "681165d0-1c77-11ed-8650-cd35a51aa42a",
  "name": "电子资源",
  "accessModel": "L3VPN",
  "subModel": "L3VPN",
  "accessAddress": "https://library.shanghaitech.edu.cn/qbsjk/list.htm",
  "nodeGroupId": "2eb64590-0f24-11ed-8ff1-d9356cf2043a",
  "addressList": [
    { "protocol": "tcp", "port": "443", "host": "10.15.45.163" },
    { "protocol": "tcp", "port": "443", "host": "library.shanghaitech.edu.cn" }
  ]
}
```

**域名→内网 IP 映射规则**(参考实现 `build_domain_map`):对同一应用 `addressList` 中的条目,
`host` 若含 `@` 先取 `@` 之后部分;随后,`host` 为纯数字点分者记为内网 IP,为域名者记为域名;
将该应用的域名映射到其第一个内网 IP。例如 `library.shanghaitech.edu.cn → 10.15.45.163`。
含通配符/范围(`*`、`-`、`/`)的 `host` 不参与映射。

### 4.3 网关线路

网关接入地址来自 `nodeGroup.addresses`(或 spaConfig 的 `proxyAddresses`),均为 `441/TCP-TLS`:
`119.78.254.241:441`、`59.78.171.241:441`、`10.13.90.147:441`(内网)、`[2001:da8:801d:d5a:9020:100:d:5a93]:441`。
实现应对多条线路做 TCP 探测择优,失败时切换(见 §12)。

---

## 5. 隧道建立

### 5.1 TLS 接入

- TCP 连接到 `<gateway>:441`,在其上建立 TLS(实测 TLS 1.2,cipher 如 `ECDHE-RSA-AES128-GCM-SHA256`)。
- 本网关 `udpSpa.enable=0`(UDP 敲门关闭),且**接受不带 SPA 扩展的纯 TLS 连接**(SPA 见 §10.4,当前非必需)。

### 5.2 帧格式总览(版本字节 `0x05`)

通用请求帧:`05 <cmd:1B> <BE16 len> <payload>`。响应方向 cmd 通常置 `0x80` 位(如 `0x13`→`0x93`)。
例外:隧道认证阶段的方法接受响应为 `05 D0`,VIP 分配响应为 `05 00 …`(均不遵循置 0x80 位规则,见 §5.3)。

| cmd | 方向 | 含义 |
|---|---|---|
| `0x01` | C→S | 隧道认证方法协商(见 §5.3) |
| `0x04` | C→S | 虚拟 IP 请求 |
| `0x13` | C→S | 每连接认证请求(见 §6) |
| `0x93` | S→C | 每连接认证响应 |
| `0x14` | C→S | 上行数据帧(见 §7) |
| `0x94` | S→C | 下行数据帧 |
| `0x15` | C→S | 心跳请求 `05 15 00 00` |
| `0x95` | S→C | 心跳响应 `05 95 00 00` |
| `0x16` | C→S | 二次 VIP 请求(双栈补发,单栈 IPv4 可不用) |
| `0x96` | S→C | 二次 VIP 响应 |

### 5.3 隧道认证(一次性写入三段)

客户端连接后一次写入:

```
[1] 05 01 D0                                          # 认证方法协商(方法 0xD0)
[2] 53 00 <BE16 len> {"sid":"<sid>"}                  # S 帧(0x53),JSON 注意键为小写 "sid"
[3] 05 04 00 01 00 00 00 00 00 00                     # cmd=4 VIP 请求:05 04 + 00(保留) + 01(vipType) + 6 字节 0
```

服务器顺序响应:

```
[1] 05 D0                                             # 方法接受
[2] 53 00 <BE16 len> {"code":0,"data":{"deviceID":"<tunnelDeviceID>"},"message":"OK"}
[3] 05 00 <flag:1B> <addrType:1B> <addr>              # VIP 分配帧
```

- VIP 帧 `addrType`:`1`→IPv4(addr 6 字节,前 4 字节为 IPv4 地址,后 2 字节为掩码/前缀);`4`→IPv6(18 字节);`5`→双栈(22 字节)。
- 虚拟 IP(VIP)= addr 前 4 字节(如 `10.19.240.43`)。**VIP 仅用作数据包的源地址(SNAT 标记),不创建网卡。**
- `data.deviceID` 为隧道内设备标识(如 `596A7DAA`/`B4B7B8BA`),与登录 `device_id` 不同。
- JSON 键必须小写 `"sid"`(大写 `"Sid"` 会报 `no 'sid' field`)。

### 5.4 心跳

- 客户端周期发送 `05 15 00 00`,服务器回 `05 95 00 00`。
- 参考实现每 20 秒发送一次心跳(只发不收);**隧道死亡由读循环的连接断开/读失败检测触发**(`reader` 循环读出错即判定死亡并关闭所有连接)。
- 「连续 N 次心跳无响应判死」是一种可选的更主动的保活策略,建议在 Go 实现中采用(见 §12)。

---

## 6. 每连接认证

每条需要转发的 TCP 连接,先做一次每连接认证以获取 `connectToken`。

### 6.1 请求帧

```
05 13 <BE16 len> <authRequestIP JSON>
```

### 6.2 authRequestIP JSON(字段顺序与结构,实测可用)

字段须按以下顺序序列化(Go `encoding/json` 结构体序;参考实现用 `OrderedDict` 保证顺序):

```json
{
  "sid": "<sid>",
  "appId": "681165d0-1c77-11ed-8650-cd35a51aa42a",
  "url": "tcp:10.15.45.163:443",
  "deviceId": "<DEVICE_ID>",
  "connectionId": "<MD5(DEVICE_ID).upper()>-<UnixMicro>",
  "env": {
    "application": {
      "runtime": {
        "process": {
          "name": "aTrustXtunnel",
          "digital_signature": "TrustAppClosed",
          "platform": "macOS",
          "fingerprint": "<SHA256(process path).upper()>",
          "description": "TrustAppClosed",
          "path": "/Applications/aTrust.app/Contents/Resources/bin/aTrustXtunnel",
          "version": "TrustAppClosed",
          "security_env": "normal"
        },
        "process_trusted": "TRUSTED"
      }
    }
  },
  "conntrackHash": 1,
  "lang": "zh-CN",
  "ip": {
    "atype": 2048,
    "protocol": 6,
    "destAddr": "10.15.45.163",
    "destPort": 443,
    "srcAddr": "<VIP>",
    "srcPort": <本地分配源端口>
  },
  "procHash": "<SHA256(process path).upper()>",
  "xRequestSig": ""
}
```

字段约定:

| 字段 | 类型 | 说明 |
|---|---|---|
| `sid` | string | 会话 sid。 |
| `appId` | string | 目标应用 ID(来自 appList;电子资源为 `681165d0-…`)。 |
| `url` | string | `<proto>:<dstIP>:<dstPort>`,proto 用 `tcp`/`udp`。 |
| `deviceId` | string | **键名全小写 `deviceId`**(非 `deviceID`);值为登录 `device_id`。 |
| `connectionId` | string | `MD5(device_id).upper() + "-" + 微秒时间戳`。 |
| `env` | object | 完整 trustapp 环境结构,`process_trusted` 须为 `"TRUSTED"`。 |
| `conntrackHash` | uint64 | 自增连接标识(从 1 开始),响应会原样回显。 |
| `lang` | string | `zh-CN`。 |
| `ip.atype` | int | `2048`(0x0800,IPv4)或 `34525`(0x86DD,IPv6)。 |
| `ip.protocol` | int | `6`(TCP)/`17`(UDP)。 |
| `ip.destAddr`/`destPort` | string/int | 目标地址/端口。 |
| `ip.srcAddr`/`srcPort` | string/int | 源地址=VIP,源端口=本地分配。 |
| `procHash` | string | `SHA256(process path).upper()`,与 `env...fingerprint` 一致。 |
| `xRequestSig` | string | **本网关不校验,可置空字符串**(置空/随机均返回 `code:0`)。如需计算见 §10.3。 |

> **不要包含** `appToken`、`rcAppliedInfo` 字段(早期资料中的 C++ 模型字段;Go 隧道实现的 authRequestIP 不含二者,加入会导致结构不符)。

### 6.3 响应帧

```
05 93 <status:1B> <BE16 len> <authResponseIP JSON>
```

> `status` 为 1 字节状态位(实测观察值为 `0x82`;参考实现仅读走该字节、不校验其值)。

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "connectToken": "871b233c7055e4d030974840b91acdd2",
    "conntrackHash": 1,
    "vipType": "public",
    "vip6Type": ""
  }
}
```

- `code:0` 表示成功,`data.connectToken` 用于后续数据帧。
- `conntrackHash` 与请求一致(据此在并发下匹配请求/响应)。
- 失败时 `code` 非 0(如 `10000001 invalid arguments`,通常因 authRequestIP 结构不符)。

---

## 7. 数据面

### 7.1 上行数据帧(0x14)

```
05 14 <tokenLen:1B> <connectToken ASCII 字节> 00 00 <pktCount:1B> [ <BE16 pktLen> <完整 IPv4 包> ]×N
```

- `connectToken` 以其 **ASCII 字符串字节**发送(32 字节,tokenLen=32)。
- 每个 IPv4 包前缀 2 字节大端长度。
- 一次可携带多个包(`pktCount`),参考实现每次发 1 个。

### 7.2 下行数据帧(0x94)— 两种布局

`05 94` 之后,网关使用两种布局之一(用首 2 字节启发式区分):

- **len-mode**:`05 94 <BE16 len(≤4096)> <载荷>`,其中**载荷是一个或多个 IPv4 包按各自 IP 头 total-length 字段拼接而成**。
- **token-mode**:`05 94 <tokenLen=32> <token 32B> 00 00 <count:1B> [ <BE16 plen> <IPv4 包> ]×N`。
  此时首 2 字节为 `0x20 XX`(tokenLen=32 → 高字节 0x20),其值 `0x20XX ≥ 8192 > 4096`,据此与 len-mode 区分。

**关键:必须按 IP 头 total-length(`ip[2:4]`)逐个拆分帧内拼接的多个 IPv4 包**(参考实现 `_split_ip_packets`)。
若把整段载荷当成单个 IP 包、用帧长计算 TCP 载荷,会把后续 IP 包误当作前一个包的载荷,导致 TCP 流损坏
(表现为 TLS 记录在合并段边界处错位)。

### 7.3 IPv4 包结构

标准 IPv4 头(20 字节,IHL=5)+ TCP 段。参考实现构造:

- IP 头:`version/IHL=0x45`、total length、`id=0x1234`、`flags/frag=0x4000`(DF)、`TTL=64`、`protocol=6`、头校验和、`src=VIP`、`dst=目标IP`。
- TCP 段:源/目的端口、seq/ack、data offset=5、flags、window=65535、TCP 校验和(含伪首部)。
- 上行包源地址为 VIP(网关据此匹配 conntrack);单包过大(>1500B)由网关侧处理分片。

### 7.4 下行分发

参考实现 reader 线程读取 0x94 帧 → 拆分出 IPv4 包 → 按 TCP 目的端口(=本连接的本地源端口)路由到对应 `TCPConn`。

---

## 8. 用户态 TCP 端点

数据面承载的是完整 IPv4/TCP 包,因此需在用户态实现一个最小 TCP 端点(参考实现 `TCPConn`):

### 8.1 连接建立(三次握手)

1. 选取初始序号 ISN(随机),`my_seq = ISN`。
2. 发送 SYN(`flags=0x02`),`my_seq += 1`。
3. 等待 SYN-ACK:收到带 SYN 标志的段(`flags & 0x02` 且当前 `peer_seq == 0`)时,`peer_seq = seg.seq + 1`。
4. 发送 ACK(`flags=0x10`)。握手完成。
5. 超时(参考 8 秒)未收到 SYN-ACK 判定失败。

### 8.2 数据发送

- 应用字节流按 MSS(参考 1400)分段,逐段发 PSH+ACK(`flags=0x18`),每段 `my_seq += len(chunk)`。

### 8.3 数据接收与 TCP 重组

收到对端 TCP 段后按序号重组(参考实现 `on_ip_packet`):

- `seq == peer_seq`:有序,追加载荷,`peer_seq += len`;随后循环取出乱序缓存 `_ooo` 中与新 `peer_seq` 衔接的段。
- `seq > peer_seq`:未来段,暂存 `_ooo[seq]`。
- `seq < peer_seq`:重传/重叠段;`overlap = peer_seq - seq`,仅追加重叠之后的新数据 `payload[overlap:]`(完全重复则跳过)。
- 每次收到带载荷的段回复 ACK(`flags=0x10`)。
- FIN(`flags&0x01`):更新 `peer_seq`,回 ACK,标记关闭。
- RST(`flags&0x04`):标记关闭。

### 8.4 关闭

发送 FIN+ACK(`flags=0x11`),`my_seq += 1`,标记关闭并注销 conntrack。

---

## 9. 代理入口(SOCKS5/HTTP)

参考实现 `atrust_socks5.py` 提供 SOCKS5 入口(HTTP CONNECT 入口同构,见 PLAN.md):

### 9.1 SOCKS5 握手

1. 客户端发 `0x05 <nmethods> <methods>`;服务器回 `0x05 0x00`(无认证)。
2. 客户端发请求 `0x05 <cmd> 0x00 <atyp> <dst.addr> <dst.port>`:
   - `cmd=0x01`(CONNECT;不支持的命令回 `0x05 0x07 …`)。
   - `atyp`:`0x01`=IPv4(4 字节)、`0x03`=域名(1 字节长度+域名)、`0x04`=IPv6(16 字节);**不支持的 atyp 回 `0x05 0x08 …`**。
3. 域名先经 §4.2 的域名→内网 IP 映射解析;映射未命中时**回退到公网 DNS**(`gethostbyname`);仍无法解析则回 `0x05 0x04 …`(host unreachable)。
4. 通过隧道建立 TCP 连接(§6+§8,失败重试,见 §12),成功后回 `0x05 0x00 0x00 0x01 0.0.0.0:0`。
5. 双向中继:客户端↔隧道 TCP 端点,逐块(参考 4096 字节)转发,任一方向结束即关闭。

### 9.2 解耦

- SOCKS5/HTTP 入口仅依赖一个「`open_tcp(dst_ip, dst_port) -> 双向字节流`」抽象接口,不感知 aTrust 隧道细节。
- 隧道模块只消费「会话凭据(sid/device_id/网关)」,不感知入口协议。
- 登录/配置模块独立产出会话凭据并持久化,供隧道模块加载复用。

---

## 10. 密码学与签名参考

> 本节为完整协议参考。geekTrust 的浏览器路径**不需要**计算 signKey/X-Request-Sig 即可工作;
> 列出这些算法是为兼容桌面路径及完整性。

### 10.1 signKey 推导

```
CONST  = "3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq"
pubkey = devicePubKeyMod + devicePubKeyExp            # 字符串拼接,如 "B9D641…292F" + "10001"
h1     = SHA256(pubkey + CONST)
signKey = UPPER_HEX( h1 XOR SHA256( UPPER_HEX(h1) + challenge_b64 ) )
```

- `challenge` 取 `authConfig.antiMITMAttackData.challenge`(base64 原文,不解码)。
- `devicePubKeyMod`/`devicePubKeyExp` 取 `authConfig.antiMITMAttackData` 下发值。
- 实现见 `src/atrust_crypto.py:sign_key`(已用真实日志 3/3 验证)。

### 10.2 encryptedChallenge

```
CONST2 = "OrHWuJz7gku5awmVb5w1sKTmfeCWHmzokBxmn0sn0faIcv1G10PdrbbRGKBrrZ3m"
k      = SHA256(devicePubKeyMod + devicePubKeyExp + CONST2)
key,iv = k[0:16], k[16:32]
encryptedChallenge = UPPER_HEX( AES-CBC-128-PKCS7( challenge_b64 字符串, key, iv ) )
```

实现见 `src/atrust_crypto.py:encrypted_challenge`(与实测值一致)。

### 10.3 X-Request-Sig(桌面路径接口签名)

```
X-Request-Sig = LOWER_HEX( HMAC-SHA256( hex_decode(signKey), pathWithQuery + body ) )
```

- `pathWithQuery` = 路径 + `?` + 查询串(如 `/controller/v1/user/clientResource?platform=Mac&clientType=SDPClient`)。
- `body` = 实际发送的紧凑 JSON 字节。
- HMAC 密钥为 `signKey` 的十六进制解码字节(32 字节);输出为 64 位**小写**十六进制(服务器大小写不敏感比对)。
- 仅 `clientType=SDPClient` + 特定 body 字段的受信请求需要;浏览器路径无需。
- 注:本仓库 Python 参考实现走浏览器路径,未实现此签名;上式为桌面路径参考。

### 10.4 SPA(单包授权,本网关当前非必需)

- 本网关 `udpSpa.enable=0`(UDP 敲门关闭),且网关接受不带 SPA 扩展的 TLS 连接。
- 如启用:TLS ClientHello 自定义扩展 `0xFF04`:
  - V1:`TOTP + 0x0000 + "TSPA"`;
  - V2:`TOTP + BE16(len+4) + 0x00 + hashType + BE16(len) + payload + "TSPA"`(hashType=1:`SHA256(seed+SALT)`;2:明文)。
- TOTP:RFC 6238,6 位,HMAC-SHA1,**步长 28800 秒(8 小时)**,secret = base32(spa_seed)。
- UDP 敲门(关闭):`[type:1][TLV: tag(1B)+len(2B)+val]`,Tag1=时间戳(`Unix-2006054656`,10 字节)、Tag2=nonce(16B,前 8B 与 deviceHash 异或)、Tag5=deviceHash,SM4 加密。

---

## 11. 状态码与错误码总表

### 11.1 控制面(HTTP `code`)

| code | 含义 | 处置建议 |
|---|---|---|
| `0` | 成功 | — |
| `10000000` | user has been logged in(已登录态重复 pre-login reportEnv) | reportEnv 应在建立会话前调用 |
| `10000001` | invalid_param / invalid arguments(参数非法,如 platform 大小写错、authRequestIP 结构不符) | 检查参数/结构 |
| `10000004` | ERR_PERMISSION_DENIED: session not found(会话不存在) | 会话失效,需重登 |
| `10000008` | interface sig verify failed(接口签名错误) | 桌面路径签名缺失/错误;改用浏览器路径或修正签名 |
| `75500001` | 当前认证已超时,请返回首页重新登录 | 重新走登录流程 |
| `75500002` | 会话无效/用户未登录 | 重登 |
| `75500006` | 当前账号已在线,无需重复上线 | 复用在线会话或先下线 |
| `75500304` | 当前票据已失效 | 重新获取票据 |
| `75599999` | 操作异常(authCheck 前置未完成/设备未注册) | 确保先 reportEnv |

### 11.2 隧道/数据面

> 注意:以下为**隧道层**错误码,与 §11.1 控制面 HTTP `code` 是**不同命名空间**(数值相同但含义无关)。
> 例如隧道层 `10000004` 触发换线,与控制面 `10000004`(session not found)无关。

| code / 现象 | 含义 | 处置建议 |
|---|---|---|
| 隧道认证 `code:0` + deviceID + VIP | 成功 | — |
| 每连接认证 `code:0` + connectToken | 成功 | — |
| 每连接认证 `10000001 invalid arguments` | authRequestIP 结构不符 | 按 §6.2 校正字段(尤其 deviceId 小写、完整 env、去掉 appToken/rcAppliedInfo) |
| 无 SYN-ACK(握手超时) | 网关瞬时拒绝(快速连接 churn 触发限速/conntrack 污染) | 退避重试(§12) |
| `1001`/`1002`/`1003`/`1005`/`1006` | 隧道:选线/拨号/封装/IO 超时/VIP 解析 | 换线/重连 |
| `10000002`~`10000004`、`99700001` | 触发线路切换 | 切换网关线路 |

---

## 12. 运行与鲁棒性要点

### 12.1 设备信任与免短信

- `device_id` 持久化且永不变更。首次登录某 `device_id` 需一次短信验证;此后该 `device_id` 成为「受信设备」,
  `authCheck` 直接通过(`code:0` 且无 `nextService=auth/sms`),**不再需要短信**。
- IDS 侧用 passkey 免密。因此用户仅需「绑定一次 passkey + 首次登录输入一次短信」,之后全程自动。
- 会话凭据(cookies、sid、device_id、网关线路)加密持久化(0600 权限),重启直接复用;失效才重登。

### 12.2 网关限速与连接重试

- 网关对**快速连接 churn**(短时间内大量建立/关闭连接)会瞬时拒绝(表现为无 SYN-ACK)。
- 每连接认证/握手失败时应**退避重试**(参考:最多 4 次,间隔 1.5 秒),避免雪崩。
- 避免无谓地频繁建立隧道;复用已建立的隧道承载多条连接。

### 12.3 保活与重连

- 隧道心跳:参考实现 20 秒一次、只发不收,判死由读循环失败检测(见 §5.4);Go 实现建议改用「连续多次丢失判死」的主动保活。
- 断线后指数退避重连(如 1s→30s 封顶);连续失败用持久化凭据静默重登;
  仅当服务器再次强制新设备验证时才提示用户(尽量避免)。
- 会话在线刷新:周期调用 `onlineInfo` 检测会话有效性,失效触发重登。
- 网络变化监听(可选):网络切换后主动重建隧道。

### 12.4 线路选择与切换

- 从网关线路列表(§4.3)TCP 探测择优;失败切换下一条;隧道错误码 `10000002~4`/`99700001` 触发换线。

---

## 13. 参考实现索引(Python)

| 文件 | 职责 | 对应章节 |
|---|---|---|
| `src/atrust_crypto.py` | signKey / encryptedChallenge / RSA 加密 | §10.1 §10.2 |
| `src/atrust_l3.py` | L3 隧道(TLS 接入、隧道认证、心跳、帧收发)+ 用户态 TCP 端点(握手/重组/中继) | §5 §6 §7 §8 |
| `src/atrust_socks5.py` | clientResource 拉取、域名映射、SOCKS5 入口、双向中继 | §4 §9 |
| `third_party/shanghaitech-ids-passkey/` | IDS passkey 免密登录(keystore) | §3.1 |

### 13.1 关键函数与协议对应

- `atrust_l3.L3Tunnel._tunnel_auth` — §5.3 隧道认证三段写入与 VIP 解析。
- `atrust_l3.L3Tunnel.request_auth` — §6 每连接认证(按 `conntrackHash` 匹配 0x93 响应)。
- `atrust_l3.L3Tunnel.send_data` — §7.1 上行 0x14 数据帧。
- `atrust_l3.L3Tunnel._read_data_resp` / `_split_ip_packets` — §7.2 下行 0x94 两种布局 + IP 包拆分。
- `atrust_l3.TCPConn._do_per_conn_auth` — §6.2 authRequestIP 构造。
- `atrust_l3.TCPConn.on_ip_packet` — §8.3 TCP 重组。
- `atrust_socks5.fetch_client_resource` — §4.1 浏览器路径免签 clientResource。
- `atrust_socks5.build_domain_map` — §4.2 域名→内网 IP 映射。
- `atrust_socks5.handle_socks5` — §9 SOCKS5 握手与中继。

### 13.2 实测验证结果

```
SOCKS5 监听 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 -k https://library.shanghaitech.edu.cn/
  → HTTP 200,<title>上海科技大学图书馆</title>
curl --socks5-hostname 127.0.0.1:1080 -k https://library.shanghaitech.edu.cn/qbsjk/list.htm
  → HTTP 200,<title>全部数据库</title>
```
