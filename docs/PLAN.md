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
                 │  │ HTTP CONNECT│──►│  net.Conn    │──►│ l3: 每连接认证 + 用户态 TCP    │    │
                 │  └────────────┘   │  Dialer      │   │ frame: 0x05 帧编解码          │    │
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
      // 建立到 ip:port 的隧道 TCP 连接。appID 来自 Resolver;
      // domain 仅用于后缀通配符授权,其他情况为空。
      Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
  }
  ```

  inbound(SOCKS5/HTTP)只依赖 `Dialer`,不需要了解 aTrust 帧格式或用户态 TCP。
  单测可注入 mock Dialer,传输实现也能独立替换。
- **`CredentialProvider`(登录 ↔ 隧道)**:

  ```go
  type CredentialProvider interface {
      // 返回当前有效会话凭据(sid、device_id、csrfToken、cookies、网关线路);失效则自动重登
      Credential(ctx context.Context) (*Credential, error)
  }
  ```

  隧道模块只消费 `Credential`,不感知登录流程;登录模块负责产出与刷新凭据。
- **`Resolver`(目标解析与授权选择)**:从 clientResource 读取精确域名、IP/CIDR/范围和后缀通配符规则。
  域名先查精确映射,再用公网 DNS 得到 IPv4 并查 IP 规则;IP 规则未命中时才用后缀通配符。
  Resolver 返回 IP、`appId` 以及可选 `domain`。解析失败时,inbound 可直接返回 SOCKS5
  host-unreachable;其他失败按拨号错误处理。解析职责仍留在 inbound 层。

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
    l3/                            # 每连接认证 + 用户态 TCP(Dialer 实现)
      auth.go                      #   authRequestIP 构造、per-conn auth(0x13/0x93)
      tcpconn.go                   #   用户态 TCP 端点:握手/seq-ack/重组/中继
      netstack.go                  #   IPv4/TCP 包构造与校验和
    inbound/                       # 代理入口(仅依赖 Dialer)
      socks5.go                    #   SOCKS5(CONNECT;UDP ASSOCIATE 暂不实现)
      http.go                      #   HTTP CONNECT
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

服务端是否再次要求短信并不完全由 `device_id` 决定。实测中,会话彻底失效后走完整登录流程时,
服务端可能再次返回 `nextService=auth/sms`。此时 CLI 会提示输入验证码。保持会话存活和复用
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

- **线路选择**(`line.go`):从网关线路列表(TECHNICAL.md §4.3)TCP 探测择优;失败切换下一条。
- **TLS 接入**:TCP 到 `<gateway>:441` → TLS(本网关接受不带 SPA 扩展的连接;SPA 见 TECHNICAL.md §10.4,当前非必需;
  如需,用 uTLS 注入 0xFF04 扩展)。
- **隧道认证**(`tunnel.go`):写入 `05 01 D0` + `53 00 <len> {"sid":...}` + `05 04 00 01 00×6`;
  读 `05 D0` + S 帧 `{code:0,data:{deviceID}}` + VIP 帧 → 得 VIP。
- **心跳**:周期发 `05 15 00 00`(参考 20s);Go 实现采用「连续多次丢失判死」的主动保活(TECHNICAL.md §5.4),触发重连。
- **reader 循环**:解析 0x93(认证响应,按 conntrackHash 匹配)、0x94(数据帧)、0x95(心跳)等;
  数据帧按 TECHNICAL.md §7.2 两种布局解析,**按 IP 头 total-length 拆分拼接的多个 IP 包**(`frame/codec.go`)。
- **重连**(`reconnect.go`):指数退避(1s→30s 封顶);连续失败用持久化凭据静默重登;
  错误码 `10000002~4`/`99700001` 触发换线。

### 5.2 每连接认证与用户态 TCP(`l3/`)

- **authRequestIP**(`auth.go`):严格按 TECHNICAL.md §6.2 构造(字段顺序、`deviceId` 小写、完整 `env`、
  `procHash`=SHA256(path) 的**大写十六进制**,与 `env…fingerprint` 一致、**不含** `appToken`/`rcAppliedInfo`);
  `xRequestSig` 可置空。后缀通配符兜底时在 `ip` 后加入可选 `domain`。
- **用户态 TCP 端点**(`tcpconn.go` + `netstack.go`):
  - 三次握手(SYN/SYN-ACK/ACK),seq/ack 跟踪;
  - 发送按 MSS(1400)分段 PSH+ACK;
  - 接收 TCP 重组:有序追加、乱序缓存、重传/重叠去重(TECHNICAL.md §8.3);
  - FIN/RST 处理;
  - 实现 `net.Conn` 接口,供 inbound 直接读写。`SetReadDeadline/SetDeadline` 映射到读缓冲 + 定时器
    (读超时返回 timeout 错误);`SetWriteDeadline` 约束发送入队超时(写本身经隧道锁串行发出);
    `LocalAddr`=VIP:srcPort,`RemoteAddr`=dstIP:dstPort。
- **Dialer 实现**:`l3` 接收已解析的 IP、端口、`appId` 和可选域名:
  分配源端口 → per-conn auth 取 connectToken(失败退避重试,见 §6.1)→ 建立 TCPConn → 返回 `net.Conn`。

---

## 6. 鲁棒性设计(长时间运行)

### 6.1 网关限速与连接重试

- 网关对**快速连接 churn** 会瞬时拒绝(无 SYN-ACK)。`Dial` 失败时**退避重试**(参考:最多 4 次,间隔 1.5s)。
- **复用隧道**:一条隧道承载多条连接,避免频繁建立隧道;conntrack 按源端口复用管理。
- 连接关闭时发送 FIN 并注销 conntrack,避免网关侧 conntrack 堆积。

### 6.2 保活与自愈

| 层级     | 机制                                                           |
| -------- | -------------------------------------------------------------- |
| 隧道     | 心跳(20s,连续多次丢失判死,见 TECHNICAL.md §5.4)+ 指数退避重连 |
| 线路     | 多线路探测择优 + 错误码触发换线                                |
| 会话     | 周期`onlineInfo` 检测 + 失效后 passkey 重登;服务端要求时提示短信 |
| 凭据     | 加密持久化,重启复用                                            |
| 网络变化 | 可选监听系统网络事件,主动重建隧道                              |
| 入口连接 | 每连接独立 goroutine,单连接失败不影响整体;优雅退出             |

### 6.3 并发与资源

- 每条入站连接一个 goroutine,通过共享隧道的多路复用(按源端口/conntrackHash 分发)转发。
- 写隧道加锁串行化帧发送;读由单一 reader 线程分发到各 TCPConn。
- 提供并发上限与空闲回收,防止资源泄漏。

---

## 7. 代理入口(`inbound/`,仅依赖 Dialer)

- **SOCKS5**(`socks5.go`):`127.0.0.1:1080`,支持 CONNECT(TECHNICAL.md §9.1)。UDP ASSOCIATE 暂不实现
  (TECHNICAL.md 仅给出 `ip.protocol=17` 的 UDP 每连接认证字段,UDP 数据帧/中继规格待补充后再议)。
- **HTTP CONNECT**(`http.go`):`127.0.0.1:8080`。
- **无认证**(可配置开启);Resolver 为目标选择 IP、`appId` 和可选域名。
- inbound 通过 `Dialer` 接口建立连接,与隧道完全解耦,可独立单测(mock Dialer)。

---

## 8. 配置(`config/`)

`config.example.toml`(示意):

```toml
# 登录
keystore = "./ids-passkey.keystore"     # passkey 凭据(由 Python 库 bind 生成)
device_id = "84B5B45FE73EC0036C3E97717308447F"   # 持久化设备标识(勿改)

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
| **M3 数据面**   | `l3` 每连接认证 + 用户态 TCP(重组)+ `Dialer`                                                    | 经隧道建立 TCP 连接到 library:443,完成 TLS 握手  |
| **M4 代理入口** | `inbound` SOCKS5/HTTP(依赖 Dialer)+ Resolver                                                      | `curl --socks5-hostname` 访问 library 返回 200 |
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
