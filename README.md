# geekTrust

面向上海科技大学 aTrust VPN(Sangfor aTrust SDP 2.0,`https://vpn.shanghaitech.edu.cn/`)的独立纯用户态客户端。

不创建虚拟网卡、不改路由表、不需要 root:登录与隧道完全在用户态完成,VPN 内的 TCP 流量通过本地
SOCKS5 / HTTP CONNECT 代理暴露给其他程序。协议规格见 [`docs/TECHNICAL.md`](docs/TECHNICAL.md),
工程设计见 [`docs/PLAN.md`](docs/PLAN.md)。

## 工作原理

```
应用程序 ──SOCKS5/HTTP──► geekTrust ──TLS(0x05 自定义帧)──► aTrust 网关 :441
```

- **登录**:IDS passkey(WebAuthn)免密登录 → CAS 跳转 → reportEnv → authCheck →
  会话换取。
- **隧道**:网关 441 端口 TLS 之上承载版本 `0x05` 的二进制帧;一次隧道认证取得
  虚拟 IP(VIP,仅用作数据包的源地址标记)。
- **数据面**:每条 TCP/UDP 流先做一次「每连接认证」取得 connectToken,再交给
  gVisor 用户态 IPv4 栈处理。TCP 具备重传、拥塞控制、乱序重组、半关闭和
  TIME_WAIT;UDP 保留数据报边界。完整 IPv4 包经隧道数据帧转发,入口不感知
  aTrust 帧格式。
- **保活**:心跳 20s,连续无响应判死,随后指数退避重连(1s→30s);多线路先完成
  TLS 握手再按延迟择优,避免把透明代理回环误判为可用网关;隧道层错误码触发换线;
  会话失效时 passkey 静默重登。

## 安装

需要 Go 1.24+。

```sh
go build -o geektrust ./cmd/geektrust
```

## 一次性准备:绑定 passkey

geekTrust 只消费已绑定的 passkey 凭据(keystore)。绑定流程需要浏览器交互,由
[shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey) 完成:

```sh
pip install "git+https://github.com/vvbbnn00/shanghaitech-ids-passkey.git"
shanghaitech-ids-passkey bind --keystore ids-passkey.keystore
```

> keystore 含 passkey 私钥,勿泄露、勿提交到版本库。

## 配置

复制 `config.example.toml` 为 `config.toml`,按需修改:

```toml
keystore = "./ids-passkey.keystore"   # passkey 凭据
device_id = "84B5B45FE73EC0036C3E97717308447F"  # 持久化设备标识,请设置一个自己的唯一标识
base_url = "https://vpn.shanghaitech.edu.cn"
platform = "Mac"                      # 大小写敏感
client_type = "browser"               # browser:纯 web 会话;client:客户端模式(可绑定授信终端)
gateways = []                         # 留空 = 从上游自动获取网关线路
dns = []                              # 可选:覆盖上游下发的隧道内 DNS
state_file = "./state.enc"            # 加密的会话凭据

[inbound.socks5]
enabled = true
listen = "127.0.0.1:1080"    # 代理无认证,务必只监听回环地址
[inbound.http]
enabled = true
listen = "127.0.0.1:8080"    # 同上:改成 0.0.0.0 会把你的 VPN 会话暴露给局域网
```

## 使用

```sh
# 登录(新 device_id 首次登录需输入一次短信验证码)
./geektrust -config config.toml login

# 启动代理(默认命令;会话自动恢复,失效时静默重登)
./geektrust -config config.toml run

# 经隧道拨号自检(443 端口会完成 TLS 握手并打印证书主题)
./geektrust -config config.toml dial library.shanghaitech.edu.cn

# 授信终端管理(需要 client_type = "client")
./geektrust -config config.toml trust-device list       # 查询授信终端
./geektrust -config config.toml trust-device bind       # 手动绑定本机
./geektrust -config config.toml trust-device unbind <id>
./geektrust -config config.toml trust-device logout <id>
```

经代理访问:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://library.shanghaitech.edu.cn/
curl -x http://127.0.0.1:8080 https://library.shanghaitech.edu.cn/qbsjk/list.htm
```

UDP 有两种标准入口:

- SOCKS5 按 RFC 1928 使用 `UDP ASSOCIATE`(`CMD=0x03`),客户端把 RFC 1928
  UDP 数据报发往服务器返回的临时 UDP 端口。
- HTTP/1.1 按 RFC 9298 使用
  `GET /.well-known/masque/udp/{target_host}/{target_port}/` 和
  `Upgrade: connect-udp`;UDP 载荷按 RFC 9297 DATAGRAM Capsule 传输,
  Context ID 为 0。当前 HTTP listener 不提供 HTTP/2 或 HTTP/3。

两种入口都保持 TCP 控制连接/HTTP 升级连接的生命周期,并为每个 UDP 目标独立
执行解析和 `protocol=17` 每连接认证。

## 短信验证

新 device_id 首次登录必定触发短信二次验证,无法绕过。要**长期免短信**,把
`client_type` 设为 `"client"`:登录时 reportEnv 会以 `clientType=SDPClient`
上报,会话成为「客户端模式」;短信验证成功后会话建立时 geekTrust 自动调用
`POST /passport/v1/security/trustDevice` 把本机绑定为授信终端。之后同一
`device_id` 的完整登录 `authCheck` 不再要求短信,直接走 `ticketExchange`
(已实测:绑定后删除状态文件重新登录仍免短信,资源策略完整拉取)。

`client_type = "browser"`(默认)时为纯 web 会话,无法绑定授信终端
(服务器返回 75500000);此时免短信只能依赖会话持续存活与静默恢复。

无论哪种模式,`device_id` 都必须持久化且不应更改;更换 `device_id` 会被视为
新设备,需要重新短信验证并重新绑定。会话凭据加密保存(`state.enc` +
自动生成的 `state.enc.key`,均 0600 权限),重启直接复用。

## 路由与解析

路由策略来自 clientResource 下发的完整应用表。规则包含精确域名、
`*.cn`/`*.com` 等后缀通配符,以及精确 IP、CIDR 和 IP 区间。端口范围
也参与匹配:

- `library.shanghaitech.edu.cn:443` 这类精确域名走专属应用和内网地址;
- 其他域名先由 DNS 解析,再按目标 IP 选择应用;没有 IP 规则时才尝试
  后缀通配符;
- IP 规则相同时优先更具体的规则。校园内外网的兜底应用覆盖大部分地址
  和端口,但网关自身 IP、`198.18.0.0/15` 等地址仍会被网关拒绝。

DNS 先直连 `223.5.5.5`、`119.29.29.29` 和系统解析器,并过滤 Clash 等
代理产生的 `198.18.0.0/15` fake-ip。公网/系统 DNS 没有可用 IPv4 时,
再通过 VPN 内的 UDP 流查询上游下发的校内 DNS,用于解析 split-horizon
内网域名。`dns` 配置项可覆盖上游 DNS。后缀通配符兜底会把域名交给
网关再次解析,CDN 地址不一致时可能被拒绝。

代理入口会拒绝把当前 VPN 网关的 `host:port` 再送回隧道。这可中断 Clash TUN
等透明代理把 geekTrust 的内层网关连接重新导向 geekTrust SOCKS5 所形成的回环。

## 限制

- 代理数据面仅支持 IPv4 目标。网关接入线路本身可以是 IPv6,但线上隧道认证
  分配的是 `addrType=1` IPv4 VIP;因此 IPv6 字面量和仅有 AAAA 的目标无法转发。
- 隧道 MTU 为 1400;UDP payload 上限为 1372 字节。SOCKS5/CONNECT-UDP 会按
  RFC 要求静默丢弃需要 IP 分片的超大数据报。
- 控制面走浏览器路径(clientType=SDPBrowserClient),不计算接口签名。

## 鸣谢

本项目的实现参考了以下开源项目(协议逆向与工程经验),特此感谢:

- [shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey) —
  IDS passkey 登录的 Python 实现;geekTrust 的 `internal/idsauth` 是其登录流程的
  Go 移植(keystore 格式双向兼容),passkey 绑定仍由该项目完成。
- [zju-connect](https://github.com/Mythologyli/zju-connect) — 浙江大学 aTrust
  客户端(Go),其隧道帧处理与线路择优实现是重要的对照参考。
- [metacubex/gvisor](https://github.com/metacubex/gvisor) — gVisor 用户态网络栈的
  Go module 发行版,负责完整 TCP 状态机、重传、拥塞控制和窗口管理。
- [Xray-core](https://github.com/XTLS/Xray-core) — 代理协议实现的一般性参考。

## 许可与声明

本项目仅供学习与合法使用,请遵守学校相关政策与法律法规。
