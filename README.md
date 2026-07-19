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
  会话换取。受信设备免短信(见下文「短信」一节)。
- **隧道**:网关 441 端口 TLS 之上承载版本 `0x05` 的二进制帧;一次隧道认证取得
  虚拟 IP(VIP,仅用作数据包的源地址标记)。
- **数据面**:每条 TCP 连接先做一次「每连接认证」取得 connectToken,随后在隧道内
  以用户态 TCP 端点(三次握手、seq/ack、重组)重建,封装为 IPv4 包经数据帧转发。
- **保活**:心跳 20s + 连续无响应判死 → 指数退避重连(1s→30s);多线路探测择优,
  隧道层错误码触发换线;会话失效时 passkey 静默重登。

## 安装

需要 Go 1.24+。

```sh
go build -o geektrust ./cmd/geektrust
```

## 一次性准备:绑定 passkey

geekTrust 只消费已绑定的 passkey 凭据(keystore),绑定流程需要浏览器交互,由
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
listen = "127.0.0.1:1080"
[inbound.http]
enabled = true
listen = "127.0.0.1:8080"
```

## 使用

```sh
# 首次登录(新 device_id 需输入一次短信验证码)
./geektrust -config config.toml login

# 启动代理(默认命令;会话自动恢复/静默重登)
./geektrust -config config.toml run

# 经隧道拨号自检(443 端口会完成 TLS 握手)
./geektrust -config config.toml dial library.shanghaitech.edu.cn
```

经代理访问 VPN 内资源:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://library.shanghaitech.edu.cn/
curl -x http://127.0.0.1:8080 https://library.shanghaitech.edu.cn/qbsjk/list.htm
```

## 短信验证

短信二次验证仅在「新 device_id 首次登录」时触发,无法绕过首次验证。
`device_id` 持久化且不应更改;会话凭据加密保存(`state.enc` + 自动生成的
`state.enc.key`,均 0600 权限),重启直接复用、失效自动静默重登,因此
**一台机器只需输入一次短信**。若更换 `device_id` 或删除状态文件,会再次要求短信。

## 限制

- 仅 TCP over IPv4。SOCKS5 UDP ASSOCIATE 与 IPv6 目标暂不支持(协议规格中
  UDP 数据帧格式未定;隧道 VIP 为 IPv4)。
- 域名解析优先使用 clientResource 下发的应用地址表(域名 → 隧道内网 IP),
  未命中时回退公网 DNS。
- 浏览器路径(clientType=SDPBrowserClient),不计算接口签名。

## 鸣谢

本项目的实现参考了以下开源项目(协议逆向与工程经验),特此感谢:

- [shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey) —
  IDS passkey 登录的 Python 实现;geekTrust 的 `internal/idsauth` 是其登录流程的
  Go 移植(keystore 格式双向兼容),passkey 绑定仍由该项目完成。
- [zju-connect](https://github.com/Mythologyli/zju-connect) — 浙江大学 aTrust
  客户端(Go),其隧道帧处理与线路择优实现是重要的对照参考。
- [Xray-core](https://github.com/XTLS/Xray-core) — 代理协议实现的一般性参考。

## 许可与声明

本项目仅供学习与合法使用,请遵守学校相关政策与法律法规。
