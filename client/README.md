# client

`client` 封装认证、会话、资源解析和 TCP/UDP 连接，供其他 Go 项目直接引用。
它不启动代理监听器，也不创建 TUN 或修改系统路由、DNS。

```go
import "github.com/ShanghaitechGeekPie/geektrust/client"

c, err := client.New(client.Options{
    ControllerURL: controllerURL,
    DeviceID:      deviceID,
    Authenticator: &client.PasskeyAuthenticator{Store: credentials},
    SessionStore:  sessions,
})
if err != nil { return err }
defer c.Close()

if _, err := c.Connect(ctx); err != nil { return err }
conn, err := c.DialContext(ctx, "tcp", address)
if err != nil { return err }
defer conn.Close()
```

- `ControllerURL` 必须是 HTTPS origin（不带路径、查询参数）。`DeviceID` 是持久保存的 32 位大写十六进制标识，可用 `NewDeviceID` 生成。
- `ClientMode` 默认为 false，即 browser 模式；设为 true 后，首次短信验证成功时会尝试绑定授信终端。
- `BlobStore` 收到的是凭据或会话的明文字节，调用方负责保密、原子写入和持久化。同一 passkey 使用同一认证器串行更新计数器；保存失败不会提交断言。
- 认证遵循调用方的 context，允许等待短信输入；网络连接和解析设有超时。连接建立后，用 `SetDeadline` 控制读写。`Close` 会取消操作并关闭自有连接。
- TCP 优先遵循服务端 L3 偏好，否则先尝试流式 TCP；仅显式设置 `Compatibility.TCPToL3Fallback` 后，网关明确不支持流式命令或在建立阶段提前关闭时才可退回 L3，明确的目标拒绝和取消不会触发回退。
- 所有控制器均默认严格模式，不按域名推断兼容行为。`Options.Compatibility` 使用公开的 `deployment.Compatibility`，与 TOML `[compatibility]` 字段一一对应；可分别配置应用 ID、缺失网关地址、TLS 域名、缺失网关组和 TCP→L3 回退。网关列表只筛选已分配线路，不覆盖非空的网关组。删除或关闭选项后，新客户端立即采用严格行为，缓存会话不会恢复旧的兜底地址。
- `LoginDomain` 显式选择 CAS 域；默认从控制器发现。`ControllerLogin` 可替换整个控制器登录流程，通过共享 HTTP CookieJar 建立会话，SDK 随后检查在线状态和资源。`ChallengeHandler` 接收带到期时间的短信验证请求；未提供交互处理器返回 `auth.ErrRequired`，未知认证方式返回 `auth.ErrUnsupported`。
- 默认 TLS 验证 CA。`GatewayTrustStore` 是显式启用的私有证书 TOFU 兜底，正常 CA 验证通过时不强制检查已有 pin；调用方负责持久保存 pin。
- UDP 保留数据报边界，payload 上限为 1372 字节。`ExchangePacket` 仅支持未分片 IPv4 ICMP Echo；实际可用性取决于控制器授权和网关支持。IPv6 目标未实现。

`Info.Implemented` 仅表示库已经实现的协议能力；`Resources` 表示控制器下发的授权范围，
`OpenTransport` 返回已建立线路和实际分配的 IPv4 地址。它们均不保证任意目标可达。
`Compatibility.ProcessIdentity` 可以覆盖流式 TCP 和 L3 的进程名、平台和路径，并统一重新计算指纹。
未配置时保留各自已实现的协议元数据；这些值与宿主操作系统无关，不代表平台连接验证结果。
