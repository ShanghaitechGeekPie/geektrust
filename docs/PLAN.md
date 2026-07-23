# geekTrust 设计与实施计划

> **项目名称:geekTrust** —— 面向上海科技大学 aTrust VPN(Sangfor aTrust SDP 2.0,`https://vpn.shanghaitech.edu.cn/`)的独立、纯粹的 VPN 客户端。
> 目标:完成「登录 → 隧道建立 → 流量代理」全过程,通过本地 SOCKS5/HTTP 代理把 VPN 环境暴露给其他程序,并**长期稳定保活**。
> 协议的全部细节(请求/响应结构、字段、状态码)见 [`TECHNICAL.md`](./TECHNICAL.md);本计划聚焦工程设计与实施。

---

## 1. 设计目标

1. **纯粹**:不创建系统虚拟网卡、不改路由表、不需要 root;流量统一从本地 SOCKS5/HTTP 代理进出。
2. **解耦**:代理入口(inbound)与隧道传输(outbound)解耦;登录/配置与隧道解耦;各模块通过接口协作。
3. **鲁棒**:在网络波动、网关限速、会话/隧道断开等情况下自动恢复,适合长时间运行。
4. **省心**:用户「绑定一次 passkey + 首次登录输入一次短信」后,后续**全自动**,无需任何手动操作(尤其避免重复接收手机验证码)。
5. **语言:Go**(与官方隧道实现同语言,便于对照;uTLS 可注入自定义 TLS 扩展)。

---

## 2. 总体架构

```
                 ┌─────────────────────────────── geekTrust ───────────────────────────────┐
                 │                                                                          │
  应用程序  ─────►│  inbound 层        Dialer 接口        outbound 层                        │──────► aTrust 网关
 (curl/浏览器)    │  ┌────────────┐   ┌──────────────┐   ┌──────────────────────────────┐    │  TLS(0x05 帧)
  SOCKS5/HTTP    │  │ SOCKS5 服务 │   │              │   │ tunnel: TLS 接入/认证/心跳/重连 │    │
                 │  │ HTTP 代理   │──►│net.Conn/UDP  │──►│ l3:每流认证 + gVisor IPv4    │    │
                 │  └────────────┘   │ Dialer       │   │ frame:0x05 帧编解码          │    │
                 │                    └──────────────┘   └──────────────────────────────┘    │
                 │        ▲                                          ▲                       │
                 │        │                                          │ 会话凭据               │
                 │  ┌─────┴──────────────────────────────────────────┴─────────┐            │
                 │  │  session/credential: 会话凭据存储 + 自动刷新/静默重登        │            │
                 │  └─────▲────────────────────────────────────────────────────┘            │
                 │        │                                                                  │
                 │  ┌─────┴──────────────┐    ┌──────────────────────┐                      │
                 │  │ sdpc: 控制器 API     │◄───│ idsauth: IDS passkey  │                      │
                 │  │ authConfig/reportEnv│    │ keystore 免密登录(Go) │                      │
                 │  │ authCheck/sms/会话  │    └──────────────────────┘                      │
                 │  │ clientResource      │                                                  │
                 │  └────────────────────┘    ┌──────────────────────┐                      │
                 │                            │ config: 配置/状态持久化 │                      │
                 │                            └──────────────────────┘                      │
                 └──────────────────────────────────────────────────────────────────────────┘
```

### 2.1 关键解耦接口

- **`Dialer`(inbound ↔ outbound)**:

  ```go
  type Dialer interface {
      // 建立到 ip:port 的隧道 TCP 或 connected UDP 流。appID 来自 Resolver;
      // domain 仅用于后缀通配符授权,其他情况为空。
      Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
      DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
  }
  ```

  inbound(SOCKS5/HTTP)只依赖 `Dialer` 和 `Resolver`,不需要了解 aTrust 帧格式
  或 gVisor 实现。单测可注入 mock,传输实现也能独立替换。
- **`CredentialProvider`(登录 ↔ 隧道)**:

  ```go
  type CredentialProvider interface {
      // 返回当前有效会话凭据(sid、device_id、csrfToken、cookies、网关线路);失效则自动重登
      Credential(ctx context.Context) (*Credential, error)
  }
  ```

  隧道模块只消费 `Credential`,不感知登录流程;登录模块负责产出与刷新凭据。
- **`Resolver`(目标解析与授权选择)**:从 clientResource 读取精确域名、IP/CIDR/范围和后缀通配符规则。
  域名先查精确映射,再尝试公网/系统 DNS;没有可用 IPv4 时,通过 l3 的内部 UDP
  接口查询上游下发的 split-horizon DNS。解析结果再匹配 IP 规则,最后才用后缀通配符。
  `Resolve` 和 `ResolveUDP` 分别按 TCP/UDP protocol 选择 IP、`appId` 以及可选
  `domain`。解析失败时,inbound 按入口协议返回错误或丢弃数据报。

---

## 3. 目录结构

```
geektrust/
  cmd/geektrust/main.go            # CLI 入口(-config config.toml)
  internal/
    idsauth/                       # IDS passkey 免密登录(Go 移植,仅登录,不含绑定)
      keystore.go                  #   keystore 读取(zlib 压缩 JSON,兼容 Python 库格式)
      webauthn.go                  #   WebAuthn assertion 签名(ES256/EdDSA/RS256)
      client.go                    #   IDS 登录流程(execution → startAssertion → login)
    sdpc/                          # 控制器 API(TECHNICAL.md §3 §4)
      authconfig.go                #   authConfig
      login.go                     #   casLogin/CAS 跳转、reportEnv、authCheck、sms、sessionIdExchange
      resource.go                  #   clientResource(浏览器路径免签)、appList 解析、域名映射
      client.go                    #   公共参数/头、错误码处理
    session/                       # 会话凭据存储 + 自动刷新/静默重登(CredentialProvider 实现)
      store.go                     #   凭据加密持久化(0600)
      provider.go                  #   有效性检测(onlineInfo)、失效重登
    frame/                         # 0x05 帧编解码(TECHNICAL.md §5.2 §7)
      codec.go                     #   请求/响应帧、数据帧两种布局、IP 包拆分
    tunnel/                        # 隧道(TLS 接入、隧道认证、心跳、重连、线路切换)
      tunnel.go                    #   L3Tunnel:连接/认证/VIP/心跳/reader 循环
      line.go                      #   线路探测择优 + 失败切换
      reconnect.go                 #   指数退避重连
    l3/                            # 每流认证 + gVisor IPv4(TCP/UDP Dialer 实现)
      auth.go                      #   authRequestIP 构造、per-conn auth(0x13/0x93)
      gvisor.go                    #   IPv4 link endpoint、TCP/UDP net.Conn 封装
    inbound/                       # 代理入口(仅依赖 Dialer/Resolver)
      socks5.go                    #   RFC 1928 CONNECT + UDP ASSOCIATE
      http.go                      #   HTTP CONNECT + RFC 9298 CONNECT-UDP
      udp.go                       #   connected UDP flow 表、重建与回收
      server.go                    #   监听/并发/优雅退出
    resolver/                      # 域名→隧道内 IP(Resolver 实现)
    config/                        # 配置加载/状态路径
  config.example.toml
docs/
  TECHNICAL.md                     # 协议技术规格(权威)
  PLAN.md                          # 本文档
  ANALYSIS.md / HANDOFF.md / PROTOCOL.md   # 早期调研笔记(归档,仅供内部参考)
```

---

## 4. 登录与短信策略

### 4.1 首次设置

1. **绑定 passkey**:引导用户使用 Python 库 `third_party/shanghaitech-ids-passkey` 的 `bind` 命令
   (需浏览器交互),生成 `keystore` 文件。geekTrust 的 Go 实现**不实现绑定**(绑定涉及浏览器自动化,
   Python 库已完备),仅消费已绑定的 keystore。
2. **首次短信验证**:新 `device_id` 首次登录时,服务器要求短信二次验证,无法绕过。

### 4.2 自动恢复与再次验证

- **IDS 免密**:Go 移植的 `idsauth` 用 keystore 中的 passkey 私钥完成 WebAuthn assertion 登录,无需密码。
- **稳定设备标识**:`device_id` 持久化且不应更改。更换它会被服务器视为新设备,再次触发短信。
- **会话持久化与静默重登**:会话凭据(cookies/sid/device_id/网关线路)加密持久化,重启直接复用;
  会话失效时先尝试 passkey 静默重登。
- **授信终端(client 模式)**:`client_type = "client"` 时 reportEnv 以 `clientType=SDPClient` 上报,
  会话成为「客户端模式」;短信验证成功后会话建立时自动调用 `POST /passport/v1/security/trustDevice`
  绑定授信终端。之后同一 `device_id` 的完整登录 `authCheck` 不再要求短信(已实测:
  删除状态文件重新登录仍免短信)。browser 模式为纯 web 会话,服务器拒绝绑定(75500000)。

browser 模式下服务端是否再次要求短信并不完全由 `device_id` 决定;保持会话存活和复用
持久化状态可以减少短信次数,但不能保证首次验证后永久免短信。

### 4.3 Go 移植 ids-passkey 登录(仅登录)

参照 Python 库 `client.py` 的流程(TECHNICAL.md §3.1):

1. **读取 keystore**(`keystore.go`):兼容 Python 库格式(zlib 压缩的 JSON),字段含
   `username`、`credential_id`、`alg`、`private_key_pem`、`sign_count`、`user_id`、`anon_biometrics_id`、
   `base_url`、`device_name`、`rp_id`、`created_at`。**回写时必须保留全部字段(含未识别字段)**,
   否则 Python 库 `from_dict` 会因缺字段而失败。
2. **取 execution**(`client.go`):`GET <ids>/authserver/login?...` 页面,提取 `execution` 隐藏字段值。
3. **发起 assertion**(`webauthn.go`):`POST startAssertion {userId: base64(username), id: anon_biometrics_id}` →
   响应路径 `result.request.publicKeyCredentialRequestOptions`(含 challenge),同级有 `result.request.requestId`;
   用 passkey 私钥对 `authenticatorData + clientDataHash` 签名(WebAuthn assertion),`sign_count += 1`。
4. **登录**:`POST login` 表单,字段 `_eventId=submit`、`username=base64(username)`、`cllt=fidoLogin`、
   `dllt=generalLogin`、`lt=""`、`execution`,以及
   `responseJson={"requestId": <步骤3的 requestId>, "credential": <assertion>, "sessionToken": null}`
   (**注意 responseJson 是包装对象,不是裸 assertion**)→ 获得 IDS 会话 cookie(含 `CASTGC`)。
5. **回写 keystore**:`sign_count` 递增后持久化(保留全部字段)。

> 签名算法(`alg`)由 keystore 指定:`-7`=ES256(P-256,`crypto/ecdsa`)、`-8`=EdDSA(`crypto/ed25519`)、
> `-257`=RS256(`crypto/rsa` PKCS#1 v1.5)。WebAuthn 断言格式参照 Python 库 `_webauthn.py:create_authentication_response`。

---

## 5. 隧道与数据面(对照 TECHNICAL.md §5–§8)

### 5.1 隧道(`tunnel/`)

- **线路选择**(`line.go`):从网关线路列表(TECHNICAL.md §4.3)并发完成 TLS 握手后按延迟择优;
  仅 TCP 可连接但无法完成网关 TLS 的地址不参与选择,失败时切换下一条。
- **TLS 接入**:TCP 到 `<gateway>:441` → TLS(本网关接受不带 SPA 扩展的连接;SPA 见 TECHNICAL.md §10.4,当前非必需;
  如需,用 uTLS 注入 0xFF04 扩展)。
- **隧道认证**(`tunnel.go`):写入 `05 01 D0` + `53 00 <len> {"sid":...}` + `05 04 00 01 00×6`;
  读 `05 D0` + S 帧 `{code:0,data:{deviceID}}` + VIP 帧 → 得 VIP。
- **心跳**:周期发 `05 15 00 00`(参考 20s);Go 实现采用「连续多次丢失判死」的主动保活(TECHNICAL.md §5.4),触发重连。
- **reader 循环**:解析 0x93(认证响应,按 conntrackHash 匹配)、0x94(数据帧)、0x95(心跳)等;
  数据帧按 TECHNICAL.md §7.2 两种布局解析,**按 IP 头 total-length 拆分拼接的多个 IP 包**(`frame/codec.go`)。
- **重连**(`reconnect.go`):指数退避(1s→30s 封顶);连续失败用持久化凭据静默重登;
  错误码 `10000002~4`/`99700001` 触发换线。

### 5.2 每连接认证与用户态 IPv4 栈(`l3/`)

- **authRequestIP**(`auth.go`):严格按 TECHNICAL.md §6.2 构造(字段顺序、`deviceId` 小写、完整 `env`、
  `procHash`=SHA256(path) 的**大写十六进制**,与 `env…fingerprint` 一致、**不含** `appToken`/`rcAppliedInfo`);
  `xRequestSig` 可置空。TCP/UDP 分别使用 `ip.protocol=6/17`;后缀通配符兜底时在 `ip` 后加入可选 `domain`。
- **用户态 IPv4 栈**(`gvisor.go`):
  - 每条活隧道复用一个 gVisor IPv4/TCP/UDP stack,自定义 link endpoint 的 MTU 为 1400;
  - TCP 由 gVisor 负责握手、重传、拥塞/流量控制、SACK、乱序重组和 FIN/RST/TIME_WAIT;
  - UDP 使用 connected endpoint 保留数据报边界,payload 上限 1372 字节以避免 IP 分片;
  - link endpoint 按 protocol/源端口取得 connectToken,把完整 IPv4 包封入 0x14 帧;
    同一 token 的连续包合并进一个多包帧,减少 TLS 与串行 socket write 开销。
- **Dialer 实现**:`l3` 接收已解析的 IP、端口、`appId` 和可选域名:
  原子保留源端口/下行路由 → per-conn auth 取 connectToken → 建立固定
  VIP:srcPort 的 gVisor TCP 或 UDP endpoint → 返回 `net.Conn`。

---

## 6. 鲁棒性设计(长时间运行)

### 6.1 网关限速与连接重试

- 网关对**快速连接 churn** 会瞬时拒绝(无 SYN-ACK)。握手超时最多退避重试 4 次;
  每连接认证 `10000008 auth in progress` 用较短退避重试;明确的 TCP RST/connection refused
  和持久认证拒绝立即返回,避免把目标服务故障放大成重试风暴。
- **复用隧道**:一条隧道承载多条连接,避免频繁建立隧道;conntrack 按源端口复用管理。
- 入口 EOF 先做 TCP 半关闭;完整关闭后由 gVisor 完成 FIN_WAIT_2/TIME_WAIT。下行路由保留
  130 秒(两个默认 60 秒状态周期加余量),避免过早注销造成 FIN/ACK 丢弃和端口复用冲突。

### 6.2 保活与自愈

| 层级     | 机制                                                           |
| -------- | -------------------------------------------------------------- |
| 隧道     | 心跳(20s,连续多次丢失判死,见 TECHNICAL.md §5.4)+ 指数退避重连 |
| 线路     | TLS 握手探测择优 + 网关自代理回环保护 + 错误码触发换线          |
| 会话     | 周期`onlineInfo` 检测 + 失效后 passkey 重登;服务端要求时提示短信 |
| 凭据     | 加密持久化,重启复用                                            |
| 网络变化 | 可选监听系统网络事件,主动重建隧道                              |
| 入口连接 | 每连接独立 goroutine,单连接失败不影响整体;优雅退出             |

### 6.3 并发与资源

- 每条入站连接使用双向复制 goroutine,通过共享隧道和共享 gVisor stack 多路复用;
  源端口同时索引下行连接和每连接 connectToken。
- 写隧道加锁串行化帧发送;读由单一 reader 线程分发到 gVisor link endpoint。
- 提供并发上限、半关闭超时、TIME_WAIT 路由回收和隧道销毁清理,防止资源泄漏。

---

## 7. 代理入口(`inbound/`,仅依赖 Dialer/Resolver)

- **SOCKS5**(`socks5.go`):`127.0.0.1:1080`,支持 RFC 1928 CONNECT 和
  UDP ASSOCIATE。UDP 关联绑定到 TCP 控制连接,校验客户端源 IP/端口,
  `FRAG != 0` 的数据报静默丢弃。
- **HTTP**(`http.go`):`127.0.0.1:8080`,支持 HTTP/1.1 CONNECT,以及
  RFC 9298 `connect-udp` Upgrade + RFC 9297 DATAGRAM Capsule。
- **无认证**(只应监听回环地址);Resolver 按 TCP/UDP 协议分别选择 IP、
  `appId` 和可选域名。
- inbound 仅依赖 TCP/UDP Dialer 与 Resolver 接口,不感知 aTrust 帧格式,
  可使用 mock 独立测试。

---

## 8. 配置(`config/`)

`config.example.toml`(示意):

```toml
# 登录
keystore = "./ids-passkey.keystore"     # passkey 凭据（由 bind 生成）
device_id = "<init 生成的 32 位大写十六进制值>"  # 每个安装独立且持久化
client_type = "client"                  # 支持授信终端绑定

# 控制器
base_url = "https://vpn.shanghaitech.edu.cn"
platform = "Mac"                        # 大小写敏感

# 网关(可多条,自动择优/切换)，默认直接从上游获取，如果填写则使用自定义的Gateway，从上游获取的时候如果给的是域名，可以指定dns服务器来解析
gateways = ["119.78.254.241:441", "59.78.171.241:441"]

# 代理入口
[inbound.socks5]
listen = "127.0.0.1:1080"
[inbound.http]
listen = "127.0.0.1:8080"

# 状态持久化
state_file = "./state.enc"              # 加密会话凭据(0600)
```

---

## 9. 里程碑

| 里程碑                | 内容                                                                                                | 验收                                             |
| --------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **M1 登录(Go)** | `idsauth` passkey 登录 + `sdpc` 控制面(authConfig/CAS/reportEnv/authCheck/sms/会话)+ 凭据持久化 | 命令行登录成功并产出 sid;服务端要求时完成短信验证 |
| **M2 隧道**     | `frame` 编解码 + `tunnel`(TLS/认证/VIP/心跳/重连/换线)                                          | 隧道认证得 VIP,心跳稳定,断线自动重连             |
| **M3 数据面**   | `l3` 每流认证 + gVisor IPv4/TCP/UDP + `Dialer`                                                   | 经隧道完成 TCP TLS 握手及 UDP DNS 查询           |
| **M4 代理入口** | SOCKS5 CONNECT/UDP ASSOCIATE + HTTP CONNECT/CONNECT-UDP + Resolver                                | TCP 页面返回 200,两种 UDP 入口查询校内 DNS 成功  |
| **M5 鲁棒固化** | 保活/静默重登/线路切换/并发/优雅退出 + 配置样例 + README                                            | 长时间运行稳定,网络波动自愈                      |

---

## 10. 可行性说明

- 全链路已用 Python 参考实现(`src/atrust_l3.py`、`src/atrust_socks5.py`)**线上实测打通**:
  SOCKS5 代理访问 `https://library.shanghaitech.edu.cn/` 返回 HTTP 200(`<title>上海科技大学图书馆</title>`),
  以及 `/qbsjk/list.htm`(`全部数据库`)。
- 协议全部细节(请求/响应结构、字段、状态码、帧格式、TCP 重组、IP 包拆分)已固化为 [`TECHNICAL.md`](./TECHNICAL.md),
  Go 实现按该规格逐模块对照实现即可,无未决协议风险。
- 固定 `device_id` 和复用持久化会话可减少短信验证;服务端在后续完整登录中仍可能再次要求短信。

## 11. 参考

你可以参考以下项目来实现我们的project，但注意这些只能作为参考，实现时还是尽可能尊重项目文档，只是在如果遇到坑之类的时候可以参考成熟的项目来避坑，在README中需要对这些项目进行鸣谢，你可以在.agent文件夹中clone这些项目，但注意.agent文件夹应当被git忽略。

- [github.com/Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect/)
- [github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)
