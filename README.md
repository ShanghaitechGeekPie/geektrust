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
- **数据面**:每条 TCP 连接先做一次「每连接认证」取得 connectToken,再交给 gVisor
  用户态 TCP/IP 栈处理重传、拥塞控制、流量控制、乱序重组、半关闭和 TIME_WAIT,
  封装为 IPv4 包经数据帧转发。入口只看到标准 `net.Conn`,不区分 HTTP、TLS、
  SSH、IMAP 等上层协议。
- **保活**:心跳 20s,连续无响应判死,随后指数退避重连(1s→30s);多线路探测择优,
  隧道层错误码触发换线;会话失效时 passkey 静默重登。

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
device_id = "84B5B45FE73EC0036C3E97717308447F"  # 持久化设备标识,勿改
base_url = "https://vpn.shanghaitech.edu.cn"
platform = "Mac"                      # 大小写敏感
gateways = []                         # 留空 = 从上游自动获取网关线路
dns = []                              # 可选:回退解析用的 DNS 服务器
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
```

经代理访问:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://library.shanghaitech.edu.cn/
curl -x http://127.0.0.1:8080 https://library.shanghaitech.edu.cn/qbsjk/list.htm
```

## 短信验证

新 device_id 首次登录必定触发短信二次验证,无法绕过。之后是否需要短信由服务端
决定:`device_id` 持久化且不应更改,会话凭据加密保存(`state.enc` + 自动生成的
`state.enc.key`,均 0600 权限),重启直接复用,会话失效时 passkey 静默重登。
只要会话能持续或静默恢复,就不会再要求短信。

注意:实测发现当会话彻底失效、需要走完整登录流程时,服务端可能再次要求短信
(设备信任并未稳定地记住 device_id)。因此「免短信」依赖保持会话存活,
而不是设备绑定本身。更换 `device_id` 或删除状态文件后重新登录,也可能
再次要求短信。

## 路由与解析

路由策略来自 clientResource 下发的完整应用表。规则包含精确域名、
`*.cn`/`*.com` 等后缀通配符,以及精确 IP、CIDR 和 IP 区间。端口范围
也参与匹配:

- `library.shanghaitech.edu.cn:443` 这类精确域名走专属应用和内网地址;
- 其他域名先由 DNS 解析,再按目标 IP 选择应用;没有 IP 规则时才尝试
  后缀通配符;
- IP 规则相同时优先更具体的规则。校园内外网的兜底应用覆盖大部分地址
  和端口,但网关自身 IP、`198.18.0.0/15` 等地址仍会被网关拒绝。

DNS 默认直连 `223.5.5.5` 和 `119.29.29.29`,并过滤 fake-ip 假地址;
系统 DNS 是最后一层兜底。可用 `dns` 配置项覆盖。后缀通配符兜底会把
域名交给网关再次解析,CDN 地址不一致时可能被拒绝。

## 限制

- 仅 TCP over IPv4。网关接入线路本身可以是 IPv6,但线上隧道认证分配的是
  `addrType=1` IPv4 VIP;因此 IPv6 字面量和仅有 AAAA 的目标无法转发。域名有
  IPv4 地址时正常使用。SOCKS5 UDP ASSOCIATE 也暂不支持(UDP 数据帧格式未定)。
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
