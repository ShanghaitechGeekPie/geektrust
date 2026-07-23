# geekTrust

geekTrust 是上海科技大学 aTrust VPN 的独立纯用户态客户端。它不创建虚拟网卡、不修改系统路由，也不需要 root。VPN 内的 TCP 和 UDP 流量通过本地 SOCKS5、HTTP CONNECT 代理提供给其他程序。

协议细节见 [`docs/TECHNICAL.md`](docs/TECHNICAL.md)，工程设计见 [`docs/PLAN.md`](docs/PLAN.md)。

## 工作原理

```text
应用程序 -> SOCKS5 / HTTP -> geekTrust -> TLS 隧道 -> aTrust 网关
```

- 使用 IDS passkey 完成免密码登录。
- client 模式会在首次短信验证后尝试绑定授信终端。绑定成功后，会话失效时可静默重登，通常不再要求短信。
- 每条 TCP 或 UDP 流先完成网关认证，再交给 gVisor 用户态 IPv4 栈处理。
- 自动恢复会话、选择可用网关并维护隧道心跳。

## 快速开始

需要 Go 1.24+ 和 [uv](https://docs.astral.sh/uv/)。

```sh
go build -o geektrust ./cmd/geektrust
```

### 新用户：完成初始化和 passkey 绑定

macOS 可通过 Homebrew 安装 uv：

```sh
brew install uv
```

然后运行：

```sh
./geektrust -config config.toml init --bind-passkey
```

`--bind-passkey` 通过 `uvx --from git+... --with selenium` 在隔离环境中运行
`shanghaitech-ids-passkey`，不会把 passkey 工具或其 Python 依赖安装到全局环境。

该命令会：

1. 使用系统安全随机源生成独立的 128 位 `device_id`。
2. 通过 uvx 打开浏览器并生成 keystore。
3. 写入默认使用 `client_type = "client"` 的配置。
4. 启用本地 SOCKS5 和 HTTP 代理。

初始化默认拒绝覆盖已有配置。只有明确需要重建配置时才使用 `--force`。

### 已有 keystore

如果已经完成 passkey 绑定，可直接复用：

```sh
./geektrust -config config.toml init \
  --keystore /path/to/ids-passkey.keystore
```

`device_id` 默认仍由 init 随机生成。也可以提供自己生成的 32 位大写十六进制值：

```sh
./geektrust -config config.toml init \
  --keystore /path/to/ids-passkey.keystore \
  --device-id 0123456789ABCDEF0123456789ABCDEF
```

不要复用文档中的示例值。每个安装应使用不同的 `device_id`，首次登录后也不要修改它。

### 首次登录

```sh
./geektrust -config config.toml login
```

新设备首次登录可能需要短信验证。验证成功后，client 模式会尝试把当前设备绑定为授信终端。绑定成功后，即使会话失效，程序也可以使用 passkey 静默重登；同一 `device_id` 通常不会再次触发短信。若自动绑定失败，可在登录后运行 `trust-device bind`。

启动代理：

```sh
./geektrust -config config.toml run
```

## 配置

推荐使用 `geektrust init` 生成配置，而不是复制固定模板。生成结果大致如下：

```toml
keystore = "./ids-passkey.keystore"
device_id = "<init 生成的 32 位大写十六进制值>"
base_url = "https://vpn.shanghaitech.edu.cn"
platform = "Mac"
client_type = "client"
state_file = "./state.enc"
gateways = []
dns = []
log_level = "info"

[inbound.socks5]
enabled = true
listen = "127.0.0.1:1080"

[inbound.http]
enabled = true
listen = "127.0.0.1:8080"
```

关键配置：

- `device_id`：设备的稳定身份。init 会安全随机生成。修改后会被服务器视为新设备，需要重新验证和绑定。
- `client_type`：推荐使用 `client`。首次短信验证后会尝试绑定授信终端；绑定成功后，后续登录通常不再要求短信。
- `keystore`：passkey 私钥文件。不要泄露或提交到版本库。
- `state_file`：加密会话状态。密钥保存在同目录的 `<state_file>.key`，两个文件权限均为 0600。
- `gateways`：留空时使用服务端下发的线路。
- `dns`：通常留空。只有需要覆盖服务端下发的隧道 DNS 时才设置。

SOCKS5 和 HTTP 代理没有身份认证，只应监听 `127.0.0.1`。不要把监听地址改为 `0.0.0.0`，否则同一网络中的其他设备可能使用你的 VPN 会话。

### browser 兼容模式

只有在目标控制器不支持 client 模式时，才把 `client_type` 改为 `browser`。browser 模式不能绑定授信终端，因此会话彻底失效后可能再次要求短信。默认初始化流程不使用该模式。

## 常用命令

```sh
# 登录或恢复会话
./geektrust -config config.toml login

# 强制执行完整登录，不恢复已有会话
./geektrust -config config.toml login --fresh

# 启动本地代理
./geektrust -config config.toml run

# 经隧道连接目标；443 端口会执行 TLS 握手
./geektrust -config config.toml dial library.shanghaitech.edu.cn

# 查看授信终端
./geektrust -config config.toml trust-device list

# 手动绑定当前设备
./geektrust -config config.toml trust-device bind

# 取消授信或注销指定终端
./geektrust -config config.toml trust-device unbind <id>
./geektrust -config config.toml trust-device logout <id>
```

经代理访问：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://library.shanghaitech.edu.cn/
curl -x http://127.0.0.1:8080 https://library.shanghaitech.edu.cn/qbsjk/list.htm
```

## UDP 支持

SOCKS5 入口按 RFC 1928 支持 `UDP ASSOCIATE`。HTTP/1.1 入口按 RFC 9298 支持 CONNECT-UDP，UDP 载荷使用 RFC 9297 DATAGRAM Capsule，Context ID 为 0。当前 HTTP listener 不提供 HTTP/2 或 HTTP/3。

两种入口都使用控制连接管理 UDP relay 的生命周期，并为每个目标执行独立的网关认证。

## 路由与解析

路由策略来自服务端下发的完整应用表，支持精确域名、域名后缀、精确 IP、CIDR、IP 区间和端口范围。精确规则优先于范围更大的规则。

普通域名先使用公共和系统 DNS。没有可用 IPv4 结果时，程序通过 VPN 内的 UDP 流查询服务端下发的校内 DNS，以解析 split-horizon 内网域名。`dns` 配置可覆盖这些隧道 DNS。

程序会拒绝把当前 VPN 网关再次送回隧道，避免 Clash TUN 等透明代理形成回环。

## 限制

- 代理数据面只支持 IPv4 目标。网关接入线路可以使用 IPv6。
- 隧道 MTU 为 1400，UDP payload 上限为 1372 字节。需要 IP 分片的超大数据报会按相应代理协议的要求丢弃。

## 鸣谢

- [shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey)：IDS passkey 登录和浏览器绑定流程。geekTrust 的 `internal/idsauth` 与其 keystore 格式兼容。
- [zju-connect](https://github.com/Mythologyli/zju-connect)：aTrust 隧道帧处理和线路选择参考。
- [metacubex/gvisor](https://github.com/metacubex/gvisor)：用户态 TCP/IP 栈。
- [Xray-core](https://github.com/XTLS/Xray-core)：代理协议实现参考。

## 许可与声明

本项目仅供学习与合法使用。请遵守学校相关政策和法律法规。
