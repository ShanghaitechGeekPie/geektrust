# client

`client` 提供可嵌入的 aTrust 会话、连接、解析和状态接口。CLI、Web 和 SDK 共用一个内部运行核心。SDK 不创建 TUN、代理监听器或文件目录，不修改系统路由、DNS 或 ACL。

```go
import (
    "github.com/ShanghaitechGeekPie/geektrust/auth"
    "github.com/ShanghaitechGeekPie/geektrust/client"
)

identity, err := auth.NewPasskey(credentials)
if err != nil { return err }
c, err := client.New(client.Options{
    ControllerURL: controllerURL,
    DeviceID: deviceID,
    Auth: client.AuthOptions{Identity: identity, OnChallenge: prompt},
    SessionStore: sessions,
})
if err != nil { return err }
defer c.Close()
if _, err := c.Connect(ctx); err != nil { return err }
conn, err := c.DialContext(ctx, "tcp", address)
if err != nil { return err }
defer conn.Close()
```

`credentials` 实现 `auth.CredentialStore`；`sessions` 实现按 `client.SessionScope` 分开的 `Load`、`Save`、`Delete`。Save 必须原子且持久。SDK 会再次核对缓存归属，拒绝将旧 Cookie 发给另一控制器或身份。设备 ID 由宿主持久保存。

`New` 只检查和复制设置。`Connect`、`Authenticate` 可以发起短信交互；后台、数据连接和解析遇到短信要求时返回 `auth.ErrInteractionRequired`。挑战区分本地 `Deadline` 和服务端 `ServerExpiresAt`，提供限生命周期的 `Resend`。不提供完整控制器登录替换钩子。

部署默认为 `deployment.Auto`。上科大的已验证 TLS 身份和缺字段补充由内部适配提供；未知控制器采用 `Generic`。`Fallbacks=nil` 使用部署默认，`&deployment.Fallbacks{}` 关闭全部兜底。TLS 设置放在 `Network.GatewayTLS`，正常 CA 验证成功时不强制检查 pin；未知 CA 的兜底需要原子的 `CheckOrEnroll`，并继续验证证书身份和有效期。

SDK 默认仅使用控制器 DNS；额外来源由 `DNS.FallbackLookup` 明确提供。CLI 的 `auto` 顺序在命令转换层保留。`Network.AllowedGateways=nil` 不额外限制，显式空列表拒绝全部线路。`CheckTarget` 收到地址、协议、端口和代；`DNSQueryTarget` 区分基础 DNS 查询，只能收紧访问权限。

`Status` 返回安全快照；`Subscribe(ctx)` 为每个订阅者提供独立有界队列，慢订阅者不会阻塞连接。`ImplementedCapabilities()` 表示 SDK 实现范围，不代表资源授权或目标连通。`ExchangeICMPEcho` 仅支持未分片 IPv4 Echo，UDP 保留数据报边界，payload 上限为 1372 字节。IPv6 目标未实现。

`Close` 取消并关闭自有对象，`Shutdown(ctx)` 等待自有任务，支持超时。宿主提供的 transport、身份和存储对象由宿主管理。旧会话的连接不跨代重放数据，宿主负责重连。
