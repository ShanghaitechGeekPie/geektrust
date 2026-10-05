# geekTrust

geekTrust 是 aTrust VPN 的纯用户态客户端。它不创建虚拟网卡、不修改系统路由，也不需要 root，而是通过本地 SOCKS5 和 HTTP 代理把 VPN 内的 TCP、UDP 流量提供给其他程序。

协议细节见 [`docs/TECHNICAL.md`](docs/TECHNICAL.md)，工程设计见 [`docs/PLAN.md`](docs/PLAN.md)。

## 工作原理

```text
应用程序 -> SOCKS5 / HTTP -> geekTrust -> TCP 流式通道 / UDP L3 隧道 -> aTrust 网关
```

- 使用 IDS passkey 免密码登录。
- client 模式在首次短信验证后会尝试绑定授信终端。绑定成功后，会话失效时可静默重登，通常不再要求短信。
- TCP 优先使用网关原生流式通道；显式开启兼容选项后，流式命令不支持或提前关闭时可回退到 L3 隧道。
- UDP 和 TCP 回退流量由 gVisor 用户态 IPv4 栈处理。
- 会话自动恢复；有多条网关线路时错峰竞速，直接使用最先完成 TLS 握手的连接。

## 快速开始

从源码构建需要 Go 1.24+：

```sh
go build -o geektrust ./cmd/geektrust
```

这样构建的二进制可以正常使用，但 Web 面板只显示构建提示页。需要完整面板时，安装 Node 20+ 后执行：

```sh
make build
```

### 新用户：初始化并绑定 passkey

`--bind-passkey` 需要 [uv](https://docs.astral.sh/uv/)。geekTrust 会优先使用与自身同目录的 `uvx`（文件名带 `_with-uv` 的发布包已附带），找不到时再从 `PATH` 中查找。macOS 可用 Homebrew 安装：

```sh
brew install uv
```

然后运行：

```sh
./geektrust -config config.toml init --bind-passkey
```

该命令会：

1. 用系统安全随机源生成 128 位 `device_id`。
2. keystore 不存在时，通过 `uvx` 在隔离环境中运行 [shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey)，打开浏览器完成绑定并生成 keystore。不会向全局环境安装任何 Python 包。
3. 写入 `client_type = "client"` 的配置，启用本地 SOCKS5、HTTP 代理和 Web 面板。

配置文件已存在时，init 会拒绝覆盖。确实需要重建时再加 `--force`。

### 已有 keystore

已经完成 passkey 绑定的话，直接指定 keystore：

```sh
./geektrust -config config.toml init \
  --keystore /path/to/ids-passkey.keystore
```

`device_id` 默认由 init 随机生成。也可以用 `--device-id` 指定自己生成的 32 位大写十六进制值：

```sh
./geektrust -config config.toml init \
  --keystore /path/to/ids-passkey.keystore \
  --device-id 0123456789ABCDEF0123456789ABCDEF
```

不要照抄示例值。每个安装都应使用不同的 `device_id`，首次登录后也不要再修改。

### 首次登录与启动

```sh
./geektrust -config config.toml login
```

新设备首次登录可能需要短信验证。验证成功后，client 模式会尝试把当前设备绑定为授信终端；绑定成功后，同一 `device_id` 通常不会再触发短信。自动绑定失败时，可以手动运行 `trust-device bind`。

启动代理：

```sh
./geektrust -config config.toml run
```

`run` 启动后可打开 Web 面板 <http://127.0.0.1:8081>，在其中完成短信验证、查看连接状态和管理授信终端。

## 配置

推荐用 `geektrust init` 生成配置。生成结果如下（另含一行注释）：

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

[web]
enabled = true
listen = "127.0.0.1:8081"
```

手工编写配置可参考 [`config.example.toml`](config.example.toml)。

主要配置项：

- `device_id`：设备的稳定身份。修改后服务器会把它视为新设备，需要重新验证和绑定。
- `client_type`：推荐 `client`。手写配置省略该项时默认为 `browser`。
- `keystore`：passkey 私钥文件。不要泄露，也不要提交到版本库。
- `state_file`：加密的会话状态。密钥保存在同目录的 `<state_file>.key`，两个文件都只允许当前用户读写。
- `gateways`：留空时使用服务端下发的线路。
- `dns`：通常留空，仅在需要覆盖服务端下发的隧道 DNS 时设置。

SOCKS5 和 HTTP 代理没有身份认证，只应监听 `127.0.0.1`。如果改成 `0.0.0.0`，同一网络中的其他设备也能使用你的 VPN 会话。

### 部署兼容选项

所有控制器默认采用严格模式，不再根据学校域名启用兼容行为。
在配置文件中添加 `[compatibility]`，只开启目标部署需要的选项：

```toml
[compatibility]
fallback_app_id = ""
fallback_gateways = []
gateway_server_name = ""
missing_gateway_group_fallback = false
tcp_to_l3_fallback = false
```

应用 ID 和网关地址仅用于缺失数据时的兜底；已有资源规则和非空网关组优先。
TCP→L3 回退不覆盖认证拒绝、连接不允许、不可达或取消。
TLS 域名覆盖仍验证证书；选项拼写错误会拒绝加载配置。
修改后重新启动客户端；关闭选项后，缓存会话不会恢复旧的兜底网关。
旧的顶层 `app_id` 已移除，请明确填写 `compatibility.fallback_app_id`。
上海科大的可选值和进程元数据覆盖示例见 [config.example.toml](config.example.toml)。

### browser 兼容模式

只有在控制器不支持 client 模式时，才把 `client_type` 设为 `browser`。browser 模式不能绑定授信终端，会话彻底失效后可能再次要求短信。

## Web 面板

`run` 期间默认启用本地面板，只监听回环地址，没有身份认证：

```toml
[web]
enabled = true
listen = "127.0.0.1:8081"
```

功能：

- 实时连接状态（在线、连接中、需要短信验证、离线）和最近事件。
- 短信验证：需要短信时自动弹出输入框，网页和终端都可以输入，以先提交的为准；支持重新发送。
- 当前用户信息（账号、姓名、客户端 IP）、网关和隧道 DNS。
- 授信终端：查看列表、取消授信、注销设备；绑定当前设备仅限 client 模式。
- 重新登录。

说明：

- `listen` 必须是回环地址，且不能使用 80 端口，否则配置加载失败。需要远程访问时用 SSH 转发：`ssh -L 8081:127.0.0.1:8081 user@host`。
- 面板启动失败（如端口被占用或与代理端口冲突）只会记录警告并跳过面板，不影响 VPN 和代理。
- `enabled = false` 时不启动面板，短信只能在终端输入。

## 常用命令

```sh
# 查看版本号
./geektrust version

# 登录或恢复会话
./geektrust -config config.toml login

# 跳过已保存的会话，强制完整登录
./geektrust -config config.toml login --fresh

# 启动本地代理（不带命令时默认执行 run）
./geektrust -config config.toml run

# 经隧道连接目标，端口默认 443；443 端口会额外完成 TLS 握手
./geektrust -config config.toml dial library.shanghaitech.edu.cn

# 查看授信终端
./geektrust -config config.toml trust-device list

# 手动绑定当前设备（仅 client 模式）
./geektrust -config config.toml trust-device bind

# 取消授信（可一次指定多个 ID）或注销指定终端
./geektrust -config config.toml trust-device unbind <id> [<id>...]
./geektrust -config config.toml trust-device logout <id>
```

经代理访问：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://library.shanghaitech.edu.cn/
curl -x http://127.0.0.1:8080 https://library.shanghaitech.edu.cn/qbsjk/list.htm
```

## UDP 支持

- SOCKS5 入口支持 RFC 1928 `UDP ASSOCIATE`。
- HTTP 入口支持 HTTP/1.1 上的 RFC 9298 CONNECT-UDP（RFC 9297 DATAGRAM Capsule，Context ID 为 0），不支持 HTTP/2 和 HTTP/3。

两种入口的 UDP 关联都随对应的 TCP 控制连接结束。

## 路由与解析

路由规则来自服务端下发的应用表，支持精确域名、域名后缀、精确 IP、CIDR、IP 区间和端口范围；范围越小的规则优先级越高。

域名先用公共 DNS 和系统 DNS 解析。没有可用 IPv4 结果时，再通过 VPN 查询服务端下发的校内 DNS，以解析只在校内可见的域名。`dns` 配置可覆盖这些隧道 DNS。

DNS 查询先用 UDP，失败或回复被截断时改用 TCP；持续失败的服务器会暂时跳过并改用备用服务器，恢复后自动重新使用。具体超时和冷却规则见 [`docs/TECHNICAL.md`](docs/TECHNICAL.md) §12.5。

程序会拒绝把当前 VPN 网关地址再送回隧道，避免与 Clash TUN 等透明代理形成回环。

## 限制

- 代理只支持 IPv4 目标。连接网关的线路可以使用 IPv6。
- 隧道 MTU 为 1400，UDP 载荷上限为 1372 字节，超出的数据报会被丢弃。

## 发布构建

GitHub Actions 在 pull request 和手动触发时构建并测试发布包；推送 `v*` 标签时，验证通过后创建 GitHub Release。支持的平台：

- Linux：amd64、arm64
- macOS：amd64、arm64
- Windows：amd64、arm64

在本地生成发布包：

```sh
bash scripts/package-release.sh v0.1.0 dist
# 附带 uv/uvx 的版本（需要 curl）
bash scripts/package-release-uv.sh v0.1.0 dist
```

输出目录必须为空。每个压缩包包含内置完整 Web 面板的二进制、`config.example.toml` 和 README，输出目录中另生成 `SHA256SUMS`。GitHub Release 只发布不含 uv 的包。

版本号使用 `vMAJOR.MINOR.PATCH` 格式（如 `v0.1.0`），预发布版本可用 `v0.1.0-rc.1`。版本号会写入压缩包名和二进制，可用 `geektrust version` 或 `geektrust --version` 查看。

在要发布的提交上创建并推送标签：

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## 鸣谢

- [shanghaitech-ids-passkey](https://github.com/vvbbnn00/shanghaitech-ids-passkey)：IDS passkey 登录和浏览器绑定流程。`internal/idsauth` 与其 keystore 格式兼容。
- [zju-connect](https://github.com/Mythologyli/zju-connect)：aTrust 隧道帧处理和线路选择参考。
- [metacubex/gvisor](https://github.com/metacubex/gvisor)：用户态 TCP/IP 栈。
- [Xray-core](https://github.com/XTLS/Xray-core)：代理协议实现参考。

## 声明

本项目仅供学习和合法使用。请遵守学校相关政策和法律法规。

## 支持的学校

- 上海科技大学
- 华东师范大学：需要根据学校的情况进行配置，Passkey 可通过 [ecnu-sso-passkey](https://github.com/nanakusa-electronics/ecnu-sso-passkey) 获取。
