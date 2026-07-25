# geekTrust Web 面板设计文档

本文档是 Web 面板特性的实施守则。实现必须与本文件一致；任何偏离都需要先修改本文件。

## 1. 目标与非目标

### 1.1 目标

- 在 `geektrust run` 期间提供本地 Web 面板，实时查看 VPN 连接状态。
- 短信验证可在浏览器中完成（终端 stdin 输入保留，双通道先到先赢）。
- 查看当前登录用户信息（username、displayName、clientIP）。
- 查看并管理授信终端（列表、绑定当前设备、取消授信、注销设备）。
- 面板为可开关配置项，`enabled` 默认 `true`。

### 1.2 非目标

- 不为 `login`、`trust-device`、`dial` 等一次性命令提供面板；面板生命周期等于 `run` 进程。
- 不自动打开浏览器。
- 不支持非回环监听，不引入认证/token 机制。远程访问由用户自行 SSH 端口转发。
- 不修改登录协议、隧道、代理数据面的任何行为。
- 不做多页面路由、用户偏好持久化、主题切换。
- 不提交前端构建产物到 git；不要求纯 Go 构建者安装 Node。

## 2. 配置

### 2.1 配置结构

```toml
[web]
enabled = true
listen  = "127.0.0.1:8081"
```

Go 结构（`internal/config/config.go`）：

```go
type Config struct {
    // ...existing fields...
    Web WebConfig `toml:"web"`
}

type WebConfig struct {
    // Enabled 使用指针以区分"未设置"(默认 true)与显式 false。
    // 这是配置中唯一的指针布尔,不得扩散此模式。
    Enabled *bool  `toml:"enabled"`
    Listen  string `toml:"listen"`
}

const DefaultWebListen = "127.0.0.1:8081"

// WebEnabled 是读取面板开关的唯一入口。
func (c *Config) WebEnabled() bool {
    return c.Web.Enabled == nil || *c.Web.Enabled
}
```

### 2.2 默认值与校验

`applyDefaults`：

- `Web.Listen == ""` 时填 `DefaultWebListen`。

`validate`：

- `WebEnabled()` 为 true 且 `Web.Listen` 非回环地址时报错：
  `web.listen must be a loopback address, got %q`。
- 回环判定：`net.SplitHostPort` 取 host；`net.ParseIP(host).IsLoopback()` 为真，或 host 为 `localhost`。`0.0.0.0`、`::`、空 host、任意非回环 IP/域名一律拒绝。
- 端口必须为十进制数字且在 1-65535 范围内；`0`、空端口、服务名一律拒绝（`127.0.0.1:0` 会绑定临时端口，使日志地址与 Host 校验失效）。**另拒绝端口 80**：浏览器会把 `http://host:80` 规范化为缺省端口 authority，Host/Origin 不再含 `:80`，严格相等校验将全部 403。
- **规范化**：validate 将 `Web.Listen` 重写为规范形式（IP 字面量经 `net.ParseIP(...).String()` 规范化，如 `[0:0:0:0:0:0:0:1]` → `[::1]`；`localhost` 保留；端口去前导零），后续日志地址、Host 校验、Origin 校验统一使用该规范值（浏览器序列化 authority 的形式）。
- `enabled=false` 时不校验 listen 语义（仍由 applyDefaults 填充，但不使用）。

### 2.3 init 模板

`internal/config/init.go` 的 `renderInitialConfig` 追加：

```toml
[web]
enabled = true
listen = "127.0.0.1:8081"
```

关键约束：`PrepareInitialConfig` 目前手工构造 `Config` 后直接调用 `cfg.validate()`（不经过 `applyDefaults`）。本特性要求在 `PrepareInitialConfig` 中、validate 之前调用 `cfg.applyDefaults()`，否则空 `Web.Listen` 会被新校验拒绝或渲染出空地址。init 测试须断言返回的 Config 与渲染出的 TOML 都包含 `[web]` 默认值。

## 3. 架构

```text
浏览器 (127.0.0.1:8081)
  │  GET /api/status · GET /api/events (SSE) · POST /api/*
  ▼
internal/webui.Server
  │  Hub(状态快照+事件广播)  Broker(短信双通道)
  ▼
session.Provider ── 异步 FIFO 事件分发 ──► webui.Hub (Observer)
  │  SMSHandler = webui.Broker(网页通道 + 共享 stdin 读取器)
  ▼
sdpc.Client (SendSMS / CheckSMSCode / trustDevice 系列)
```

### 3.1 启动顺序（cmdRun 重排，严格按序）

1. 若 `!cfg.WebEnabled()`：保持现状——`session.NewProvider(cfg, logger, smsPrompt)`，后续步骤与现行 `cmdRun` 完全一致，不创建任何 web 组件。
2. 若启用：先检查 `cfg.Web.Listen` 与任何**已启用**的 inbound 监听地址（`inbound.socks5`/`inbound.http`）是否相同；相同则 `logger.Warn`（面板与代理端口冲突）并退化为第 1 步的现状路径——绝不允许面板抢占端口导致 inbound 绑定失败。无冲突时同步执行 `net.Listen("tcp", cfg.Web.Listen)`。
   - 失败：`logger.Warn`，`webActive=false`，退化为第 1 步的现状路径。
   - 成功：`webActive=true`。
3. webActive 时，严格按序装配：
   - `hub := webui.NewHub(cfg)`（持有静态配置字段）。
   - `broker := webui.NewBroker(hub.SetSMSPending)` —— pending 回调为**必填构造参数**，禁止后注入，杜绝 nil 调用与未定义窗口。`Hub.SetSMSPending` 在 Hub 锁内更新状态、解锁后广播。
   - `provider := session.NewProvider(cfg, logger, nil)`；`provider.SetSMSHandler(broker)`；`provider.AddObserver(hub)`。
   - `server := webui.NewServer(hub, broker, provider, cfg)`；goroutine 运行 `server.Serve(listener)`。
   - `logger.Info("web panel", "url", "http://"+cfg.Web.Listen)`。
   - `defer`：以**新的** `context.WithTimeout(context.Background(), 5*time.Second)` 执行 `server.Shutdown`（不用 run 的 ctx，此时它可能已取消）。
4. `provider.Credential(ctx)` —— 如需短信，此时面板已可访问。
5. `CheckLoop`、`tunnel.Manager`、`inbound` 与现状一致。

致命登录失败（keystore 缺失等）维持现状：进程报错退出，面板随之关闭。短信等待属于阻塞等待输入而非失败，进程不退出，面板保持可用。

### 3.2 面板故障策略

Web 服务是附属品：任何时刻 web 服务出错只记日志，绝不影响 VPN 会话与代理数据面。Provider 不依赖 webui 包的任何返回值（SMSHandler 的 Prompt 返回值除外）。

## 4. 事件模型（session 包新增）

### 4.1 类型

```go
// internal/session/events.go
package session

type EventKind string

const (
    EventLoginStart   EventKind = "login_start"
    EventLoginSuccess EventKind = "login_success"
    EventRestoreOK    EventKind = "restore_success"
    EventLoginFailed  EventKind = "login_failed"
    EventInvalidated  EventKind = "invalidated"
)

// SessionInfo 是面向观察者的脱敏会话快照。绝不包含 SID、Cookie、CSRF。
type SessionInfo struct {
    Username    string
    DisplayName string
    ClientIP    string
    DeviceID    string
    ClientType  string
    Gateways    []string // 生效值(clientResource/配置/默认)
    DNS         []string // 生效值
}

// Event 是可 JSON 序列化的历史记录单元;不得携带函数、凭据或原始错误对象。
type Event struct {
    Kind    EventKind
    Time    time.Time
    Message string       // 已脱敏(见 §4.4)
    Session *SessionInfo // 仅 LoginSuccess/RestoreOK 携带
    // Dropped 是 dispatcher 在本事件之前累计丢弃的事件数,
    // 由 dispatcher 出队时填写;Hub 据以生成快照的 events_dropped。
    Dropped uint64
}

// Observer 接收会话生命周期事件。实现必须快速返回。
type Observer interface{ OnSessionEvent(Event) }
```

注意：`OnlineInfo` 类型属于 `sdpc` 包，session 包不复用它定义事件负载；`SessionInfo` 是唯一对外快照类型。

### 4.2 异步 FIFO 分发（强制）

同步回调存在两个已确认缺陷：Observer 回调内调用 `Credential` 会等待自身（acquire 未返回，`refreshCall.done` 未关闭）；解锁后 flush 会让后发事件超车（如 `login_start` 越过 `invalidated`）。因此：

- `Provider` 内含一个 dispatcher：`sync.Mutex` + 条件变量（或带缓冲 channel）+ 单一 drainer goroutine。
- `emit(ev)`：在调用点就地加盖 `time.Now()`，**入队即返回**（可发生在持 `p.mu` 区间内，但入队操作本身不得调用任何 Observer）。
- drainer goroutine 是唯一调用 Observer 的线程，严格 FIFO，不持 `p.mu`；**锁纪律（强制）**：出队与 `Dropped` 盖章在 dispatcher 锁内完成，调用任何 `OnSessionEvent` 之前必须先释放 dispatcher 锁——持队列锁回调可与 `p.mu` 形成 AB-BA 死锁。
- 队列上限 256；满时丢弃最旧事件并累加 `dropped`。
- drainer 在首次 `AddObserver` 时启动；无 Observer 时 emit 为 no-op，不启动 goroutine。`AddObserver` 仅在装配期（首次 `Credential` 之前）调用，之后只读。

### 4.3 事件触发点与发布顺序（强制）

原则：**先发布 Provider 内部状态，再入队事件**，杜绝"Hub 显示 online 但 `ActiveSDPC()` 仍为 nil"的窗口。

- `login()`/`restore()` 不直接发成功事件；签名改为返回成功负载：
  - `login(ctx) (*Credential, *SessionInfo, error)`
  - `restore(ctx) (*Credential, *SessionInfo, error)`（无可恢复会话时三者皆 nil）
  - `acquire(ctx) (*Credential, *SessionInfo, restored bool, err error)`
  - `SessionInfo` 由统一构造函数组装：`newSessionInfo(info *sdpc.OnlineInfo, cred *Credential, clientType string)`——Username/DisplayName/ClientIP 取自 `info`，DeviceID/Gateways/DNS 取自 `cred`（生效值），ClientType 取自配置。login/restore 在拿到 `finishLogin` 的 cred 与 `OnlineInfo` 后调用它。
- `Credential` 在 acquire 返回后、持 `p.mu` 完成 `p.cur`/`p.refreshing` 写回，**随后**（锁内入队，§4.2 保证入队不回调）按序入队：
  - 成功：`login_success`（restored=false）或 `restore_success`（restored=true），携带 `SessionInfo`。
  - 失败：`login_failed`，Message 为脱敏错误文本。
- 事件表：

| 事件 | 触发位置 | Session | Message |
|---|---|---|---|
| `login_start` | `acquire` 判定需要完整登录处（restore 不适用/失败回退；每次 acquire 至多一次） | nil | `开始完整登录` |
| `login_success` | `Credential` 成功写回后 | 填充 | `会话已建立: <DisplayName>` |
| `restore_success` | `Credential` 成功写回后（restore 路径） | 填充 | `已恢复会话: <DisplayName>` |
| `login_failed` | `Credential` 失败写回后 | nil | 脱敏后的错误文本 |
| `invalidated` | `Invalidate()`、`InvalidateIfCurrent` 命中当前凭据时、`TryForceRelogin` 清会话时（均在清状态之后） | nil | `会话已失效` |

短信相关状态不经由事件表达（见 §5，由 Broker 的 pending 状态表达）。

### 4.4 错误脱敏（凭据红线的一部分）

`login_failed` 的 Message 与 API 错误响应在进入 Hub/HTTP 层之前必须经过 `sanitizeErrorText`：

- 将 URL 查询参数中敏感键的值替换为 `***`：`ticket`、`sid`、`code`、`password`（已确认 `CasTicket` 链路错误可能包含 `.../auth/cas?ticket=ST-...`）。
- 截断至 300 字符。
- 上游 `APIError` 的展示字段名为 `Message`（不是 `Msg`），其文本由控制器生成，可透传。

## 5. 短信 Broker（webui 包）

### 5.1 接口（session 包新增）

```go
// SMSHandler 是需要短信交互能力的处理器;resend 在 Prompt 返回前一直有效。
type SMSHandler interface {
    Prompt(ctx context.Context, resend func(context.Context) error) (string, error)
}

// SetSMSHandler 替换简单的 SMSPrompter;webui 装配期调用。
func (p *Provider) SetSMSHandler(h SMSHandler)
```

`smsFlow` 改为：若 handler 非 nil，调用 `handler.Prompt(ctx, resendFn)`；否则走现有 `p.prompt(ctx)`。`resendFn` 捕获当前 `sc` 调用 `sc.SendSMS` 并**原样返回错误**（保留 `*sdpc.APIError` 类型）；webui handler 用 `errors.As` + `CodeSMSStillValid`(75500401) 映射 429，其余错误 500，Message 经 §4.4 脱敏后展示。

### 5.2 Broker 结构

```go
type Broker struct {
    mu      sync.Mutex
    gen     uint64
    pending *smsPending  // 仅 Prompt 执行期间非 nil
    stdin   *stdinReader // 懒启动,进程级唯一
    onPendingChange func(pending bool, gen uint64) // 必填构造参数(Hub.SetSMSPending)
}

type smsPending struct {
    gen      uint64
    result   chan string // cap 1;仅 claim 成功者写入
    resolved bool        // mu 保护;已被某通道 claim
    done     bool        // mu 保护;Prompt 已退出
    resend   func(context.Context) error
    // opMu 是每代独立的操作锁:只序列化 resend 与 Prompt 退出,
    // 不阻塞 claim;网络 I/O 期间持有 opMu 而不持有 Broker 的 mu。
    opMu     sync.Mutex
}
```

`NewBroker(onPendingChange func(pending bool, gen uint64))`：回调为必填参数且不可为 nil。布防时回调 `(true, 当前 gen)`，拆除时回调 `(false, 0)`；Hub 在同一锁内存入这两个值并据此发布 `sms_pending` 与 `sms_gen`（快照代与 Broker 代必然一致，不得另设计数器）。

### 5.3 单一 stdin 读取器（修复已确认的孤儿 Scanner 缺陷）

现有 `smsPrompt` 每次调用新建 goroutine + `bufio.Scanner(os.Stdin)`；ctx 取消后该 goroutine 残留并可能吞掉下一次输入的验证码。Broker 改为：

- 进程级**唯一** `stdinReader` goroutine：循环 `bufio.Scanner(os.Stdin)` 读行，每行交给 `broker.claimTerminal(code)`（免代校验，规则见 §5.4）。
- 首次 `Prompt` 时懒启动（懒启动加锁防并发重复启动）；进程生命周期内不退出（run 进程级单例，可接受）。
- `Prompt` 布防时向 stderr 打印"Enter the 6-digit code: "提示（保留终端 UX）；终端输入经同一 claim 通道，与网页提交完全对等。

### 5.4 布防、claim 与退出协议（强制，全部在同一 mu 下裁决）

`Prompt(ctx, resend)`：

1. `mu.Lock`：`gen++`（**跳过 0**：回绕到 0 时再自增一次，0 永远表示"无 pending"）；创建本地 `result := make(chan string, 1)` 并以它安装 `pending{gen, result, resolved:false, done:false, resend}`；`mu.Unlock`。此后步骤统一引用该本地 `result`，不经过 `b.pending`。
2. 调用 `onPendingChange(true, gen)` —— **先完成布防，Hub 才对网页可见 `sms_pending=true` 与正确的 `sms_gen`**，不存在"快照显示 pending 但 POST 无投递目标"的窗口。
3. `select` 等待并记录胜出分支：`case code := <-result`（记 `gotCode=true` 并保存 code）或 `<-ctx.Done()`（记 `gotCode=false`）。
4. **统一退出裁决（关键，`mu.Lock` 一次定胜负）**：`mu.Lock` 并绑定当前代指针 `p := b.pending`（`b.pending` 只能被本 Prompt 的退出路径清除，此处必非 nil）；
   - 若 `p.resolved`（claim 已仲裁成功）：若 `!gotCode` 则执行 `code = <-result`（claim 在置 `resolved=true` 后才写通道且写入无需任何锁，该接收至多等待这一次通道写入，必然成功）；置 `p.done=true`、`b.pending=nil`，`mu.Unlock`；调 `onPendingChange(false, 0)`；`p.opMu.Lock(); p.opMu.Unlock()`（等待该代在飞 resend）；返回该 code。`gotCode=true` 时**复用第 3 步已保存的 code，不得再次接收**（result 仅一个缓冲值，重复接收会死锁）。
   - 否则（真正取消）：置 `p.done=true`、`b.pending=nil`（**必须在本次持锁内完成**，此后到达的 claim 一律 409），`mu.Unlock`；调 `onPendingChange(false, 0)`；`p.opMu.Lock(); p.opMu.Unlock()`；返回 ctx 错误。

由此：每个缓冲值只被消费一次；claim 与取消在同一 mu 下裁决，不存在"202 已投递但 Prompt 未取码"的窗口；退出全程使用持锁期绑定的代指针 `p`，不引用已清空的 `b.pending`；Prompt 返回后 `smsFlow` 的 `CheckSMSCode` 绝不与在飞的 `SendSMS` 并发。

`claim(code, gen, source)`（网页 POST 与 stdin 行共用入口，两条规则）：

1. `mu.Lock`；满足任一条件即 `mu.Unlock` 返回 `ErrNoPending`（HTTP 映射 409）：`pending==nil`、`pending.done`、`pending.resolved`；**仅当 source 为网页时**追加判定 `gen != pending.gen`。终端通道（`claimTerminal`）免代校验：同一 mu 下直接命中当前 pending（终端用户看到的是当前提示，无跨代窗口）。
2. 否则在同一持锁区间内绑定 `p := b.pending`、置 `p.resolved=true`，`mu.Unlock`，随后 `p.result <- code`（写入的是持锁期绑定的代通道；cap 1 且不可能有其他写入者，永不阻塞——即使 Prompt 随后清空了 `b.pending` 也不受影响）。
3. 只有 claim 成功者得到 202；后到者、跨代提交一律 409。验证码格式（6 位数字）在 HTTP 层与 stdin 行处理处各自校验。

**代（gen）进入 HTTP 契约**：快照包含 `sms_gen`（仅 pending 时非 0，值来自 Broker 回调）；`POST /api/sms` 与 `POST /api/sms/resend` 请求体必须携带当前代，gen 缺失/不匹配返回 409（防止旧 Prompt 时代的延迟提交/重发误投新 Prompt）。stdin 通道不做 gen 校验。

`Resend(ctx, gen)`（双重校验 + opMu 序列化，不在 Broker mu 下做网络 I/O）：
1. `mu.Lock`：校验 `pending!=nil && !done && !resolved && gen==pending.gen`，取出 pending 指针；失败 → `mu.Unlock`，409。
2. `mu.Unlock`；`p.opMu.Lock()`。
3. **重校验**：`mu.Lock` 再次确认同一 pending 仍满足 `!done && !resolved && gen 相等`；失败 → 两个锁都释放，409（防止 claim/退出后越权执行）。
4. `mu.Unlock`；以 handler 传入的 `ctx`（`/api/sms/resend` 用 `r.Context()`）调用 resend 闭包（持 opMu，耗时秒级）；`p.opMu.Unlock()`。

**resend 与 claim 的仲裁规则（唯一）**：claim 只经 Broker mu，**允许**在 resend 网络 I/O 进行中完成（用户已持有短信，提交当前代验证码不受重发影响）；opMu 保证的是 resend 与 **Prompt 退出**互斥——Prompt 返回（继而 `smsFlow` 调 `CheckSMSCode`）绝不代表仍有在飞的 `SendSMS`。已确认并发安全前提：Prompt 挂起期间 `sc` 无其他使用者，`SendSMS` 不修改 `sdpc.Client` 可变字段（csrf 只读）；若未来 `SendSMS` 行为改变需重审此约束。

`EventInvalidated` 事件**不**清除 pending：进行中的登录不被 `Invalidate` 取消（forceLogin 只影响下一次 acquire），SMS 窗口随 Prompt 返回自然结束。

### 5.5 webActive=false

不创建 Broker；`cmdRun` 直接使用原 `smsPrompt`（行为与现状完全一致）。

## 6. Hub 与状态快照（webui 包）

### 6.1 状态推导（取代状态机转移图）

Hub 维护三个事实，状态由规则推导，不存在未覆盖的转移：

- `acquiring bool`：`login_start` 置 true；`login_success`/`restore_success`/`login_failed` 置 false。
- `sessionActive bool`：`login_success`/`restore_success` 置 true；`invalidated`/`login_failed` 置 false。
- `smsPending bool` 与 `smsGen uint64`：Broker 的 `onPendingChange`（即 `Hub.SetSMSPending(bool, uint64)`）设置，唯一来源；布防 `(true, N)`，拆除 `(false, 0)`。

推导规则（优先级从高到低）：

```text
smsPending        → sms_required
acquiring         → connecting
sessionActive     → online
否则              → offline
```

任意事件序列（含 `offline` 下收到 `restore_success`、SMS 中收到 `login_failed`、online 下收到 `invalidated`）都有确定结果。

### 6.2 事件消费与字段保留规则（同一锁区语义）

`Hub.OnSessionEvent(ev)` 与 `Hub.SetSMSPending(bool, uint64)` 必须：在 Hub 锁内完成全部状态更新，解锁后再广播快照。其中：

- `login_success`/`restore_success`：锁内**深拷贝** `ev.Session`（含 Gateways/DNS 切片复制）为当前会话快照字段；`acquiring=false`、`sessionActive=true`、**`last_error=nil`**（成功必须清除旧失败，覆盖 `login_failed` → `restore_success` 序列）。
- `invalidated`/`login_failed`：锁内清空会话快照字段（user/gateways/dns 归 null）；`sessionActive=false`；`login_failed` 另置 `acquiring=false` 与 `last_error`（已脱敏）。
- `login_start`：`acquiring=true`、`last_error=nil`。
- `events_dropped`：取最近一次事件的 `Event.Dropped` 原值展示。
- **历史事件 DTO**：Hub 把每个 `Event` 映射为 `HistoryEvent{ts, kind, message}`（RFC3339 时间、小写 kind、脱敏 message）存入环形缓冲；`Session`/`Dropped` 是 observer 内部字段，**不进入**事件列表 JSON。快照事件数组只含这三个小写字段。

| 字段 | 规则 |
|---|---|
| `device_id`、`client_type`、`proxy` | 静态配置，始终存在 |
| `user`、`gateways`、`dns` | 仅 `sessionActive` 时存在（来自最近一次 `SessionInfo` 的深拷贝）；否则 null |
| `since` | 最近一次**状态值**变化的时间 |
| `last_error` | `login_failed` 设置；`login_start` 清空 |
| `events` | 内存环形缓冲最近 50 条，进程生命周期内保留（跨重登不清空） |
| `events_dropped` | dispatcher 累计丢弃数，随事件 envelope 更新 |

### 6.3 快照结构（`GET /api/status` 与 SSE 共用）

```json
{
  "state": "online",
  "since": "2026-07-25T10:00:00+08:00",
  "last_error": null,
  "user": { "username": "2022533000", "display_name": "陆天成", "client_ip": "10.19.244.163" },
  "device_id": "A882F6E166A3808A3FB4A40B6CB82052",
  "client_type": "client",
  "gateways": ["119.78.254.241:441"],
  "dns": ["10.15.44.11"],
  "proxy": { "socks5": "127.0.0.1:1080", "http": "127.0.0.1:8080" },
  "sms_pending": false,
  "sms_gen": 0,
  "events_dropped": 0,
  "events": [
    { "ts": "2026-07-25T10:00:01+08:00", "kind": "login_success", "message": "会话已建立: 陆天成" }
  ]
}
```

- `user`/`gateways`/`dns` 在无活动会话时为 `null`。
- `proxy` 中未启用的入口为 `null`。
- `sms_gen` 仅 `sms_pending=true` 时为当前代（非 0 整数），否则为 0。
- **凭据红线**：快照与任何 API 响应绝不包含 SID、Cookie、CSRF token、keystore 内容、短信验证码；事件 Message 必经 §4.4 脱敏。

### 6.4 SSE

`GET /api/events`：

- 响应头：`Content-Type: text/event-stream; charset=utf-8`、`Cache-Control: no-cache`、`Connection: keep-alive`；每帧写出后立即 `Flush`。
- 连接建立立即发送一份完整快照（`data: <json>\n\n`）。
- 之后每次状态变更或新事件时重发完整快照（快照小，不做增量 diff）。
- 每客户端缓冲 chan cap 8；写满即断开该客户端（慢客户端不得阻塞 Hub）。
- 每 25 秒发送 `: keepalive\n\n` 注释帧。
- 前端 `EventSource` 断线自动重连，重连即得最新快照。

## 7. HTTP API

除 `GET /api/events`（SSE，`text/event-stream`）外，所有端点请求/响应均为 JSON（`Content-Type: application/json; charset=utf-8`）。端点前缀 `/api`。

### 7.1 Provider 新增支撑方法

```go
// ActiveSDPC 仅在有活动凭据时返回控制器客户端;否则 nil。
// (Invalidate 清空 cur 但保留旧 sc,直接读 SDPCClient 可能拿到过期客户端。)
func (p *Provider) ActiveSDPC() *sdpc.Client

// InvalidateIfCurrent 仅当 expected 仍是当前凭据时才失效化:
// 比较、清空、置 forceLogin、入队 invalidated 在同一 p.mu 临界区。
// CredentialProvider 接口中的 Invalidate() 由本方法替代(干净切换,
// 接口消费者与测试 fake 一并迁移)。具体类型 Provider 上既有的导出方法
// Invalidate() 保留且语义不变,供现有直接调用方与测试使用。
// 内部拆两个持锁前提的私有助手,避免 TryForceRelogin 重入 p.mu:
//   clearSessionLocked(): 清 cur + 入队 invalidated(不碰 forceLogin),
//     供 TryForceRelogin 使用——其强制语义只经 refreshCall.force 表达,
//     不得残留全局 forceLogin(否则后续某次 acquire 会意外跳过 restore)。
//   invalidateLocked(): clearSessionLocked() + 置 forceLogin,
//     供 Invalidate/InvalidateIfCurrent 使用。
func (p *Provider) InvalidateIfCurrent(expected *Credential) bool

// TryForceRelogin 原子预留一次强制重登:
// 同一把 p.mu 下检查无进行中 acquire;若 cur 非空则清空 cur 并入队
// invalidated 事件;安装一个 force=true 的 refreshCall 占用刷新槽。
// ok=false:有进行中 acquire(调用方映射 409)。
// ok=true:调用方独占该预留,必须以后台 goroutine 精确调用一次返回的
// run(context.Background());它执行强制登录(跳过 restore)并向所有
// 后来汇入的 Credential 等待者发布结果。此后的 relogin 请求一律 409。
func (p *Provider) TryForceRelogin() (run func(context.Context), ok bool)
```

webui 的 trust-device/relogin handler 依赖一个窄接口（`ActiveSDPC`、`TryForceRelogin`），便于用假实现做确定性测试。

### 7.2 端点

| 方法 | 路径 | 请求体 | 成功响应 | 说明 |
|---|---|---|---|---|
| GET | `/api/status` | — | 200 快照（§6.3） | 页面加载时拉取一次 |
| GET | `/api/events` | — | SSE 流 | 见 §6.4 |
| POST | `/api/sms` | `{"code":"123456","gen":3}` | 202 `{}` | code 必须 6 位数字，否则 400；gen 缺失/不匹配或 claim 失败 409。202 仅表示已投递，验证结果经状态推送反映 |
| POST | `/api/sms/resend` | `{"gen":3}` | 202 `{}` | 无有效 pending 或 gen 不匹配 409；`75500401` 映射 429 + 服务端消息 |
| POST | `/api/relogin` | `{}` | 202 `{}` | 见 §7.3 |
| GET | `/api/trust-devices` | — | 200（§7.4） | `ActiveSDPC()` 为 nil 时 503 |
| POST | `/api/trust-devices/bind` | `{}` | 200 `{}` | `client_type != client` 时 409；无活动会话 503 |
| POST | `/api/trust-devices/unbind` | `{"ids":["..."]}` | 200 `{}` | ids 为空 400；无活动会话 503 |
| POST | `/api/trust-devices/logout` | `{"id":"..."}` | 200 `{}` | id 为空 400；无活动会话 503 |

### 7.3 relogin 语义（原子预留，无 TOCTOU）

- handler 调用 `provider.TryForceRelogin()`：
  - `ok=false`（有进行中的 acquire，含 SMS 挂起的初始登录或另一 relogin 预留）→ **409** `{"error":"login already in progress"}`。
  - `ok=true` → 后台 goroutine 精确调用一次 `run(context.Background())`，202 立即返回；状态变化经 SSE 推送。
- 判定、清会话（含 invalidated 事件）、占用刷新槽在同一把 `p.mu` 下完成：不存在"检查后新 acquire 插入"的窗口，也不存在"202 但只汇入旧 acquire"或"强制标志被消费后再次发生非强制登录"的路径。acquire 内部以预留的 `force` 标记跳过 restore，不再依赖可被提前消费的全局 forceLogin 标志（该标志仅保留给 `Invalidate()` 的既有语义）。

### 7.4 授信终端响应（透传真实 wire 格式）

`GET /api/trust-devices` 直接序列化 `sdpc.TrustDeviceList`，JSON 字段以其真实 tag 为准：

```json
{
  "data": [
    { "id": "...", "deviceName": "MacBook", "deviceType": "mac",
      "os": "macOS", "osVersion": "15.5", "onlineStatus": true,
      "lastLoginIp": "192.0.2.2", "lastLoginAddress": "LAN",
      "networkZoneList": ["默认网络区域"] }
  ],
  "selfId": "...",
  "currentTrustStatus": 1,
  "trustDeviceConfig": { "enable": true }
}
```

前端 `types.ts` 与测试都以这一份契约为准。

### 7.5 错误响应

统一结构 `{"error":"..."}`，文本经 §4.4 脱敏：

- 400：请求体/参数非法。
- 409：状态冲突（无 pending 短信、gen 不匹配、browser 模式绑定、relogin 进行中）。
- 429：服务端短信限流（`75500401`）。
- 503：无活动会话。
- 500：控制器/内部错误。

## 8. 安全模型

1. **仅回环**：配置校验强制（§2.2），不提供绕过开关。
2. **Host 校验**：中间件要求 `Host` 头等于规范化后的 `Web.Listen`（§2.2，含端口），否则 403。防御 DNS rebinding。
3. **点击劫持防护**：所有响应（页面与 API）带 `Content-Security-Policy: frame-ancestors 'none'` 与 `X-Frame-Options: DENY`。缺失该头时，恶意网页可 iframe 面板并以同源身份诱导点击（Origin/Host 检查均失效）。
4. **跨站提交防护**：不发出任何 CORS 头；POST 若带 `Origin` 头，其 host 必须等于规范化后的 `Web.Listen`，否则 403；POST 要求 `Content-Type: application/json`。
5. **无凭据输出**：见 §6.3 红线与 §4.4 脱敏；Broker 日志只记"已提交"，不记验证码内容。
6. **无 Cookie/本地存储**：面板不设置 Cookie，不写 localStorage。
7. **前端依赖白名单**：dependencies 仅 react、react-dom；devDependencies 仅 vite、@vitejs/plugin-react、typescript、@types/react、@types/react-dom、@types/node（类型包为 tsc 构建所必需，随 package-lock.json 锁定）。不引入 UI 组件库/路由/状态库。

## 9. 前端（web/，React + TypeScript + Vite）

### 9.1 工程结构

```text
web/
  package.json  package-lock.json  tsconfig.json  vite.config.ts  index.html
  src/
    main.tsx  App.tsx  api.ts  types.ts  styles.css
    components/
      StatusCard.tsx   状态灯 + since + last_error
      UserCard.tsx     用户信息 + device_id(复制按钮) + client_type + 代理入口
      SmsDialog.tsx    弹窗:6 位输入、60s 倒计时、重新发送、错误内联
      TrustDevices.tsx 表格 + 绑定/取消授信/注销;browser 模式显示禁用说明
      EventsList.tsx   最近事件流(新→旧)
```

- `package-lock.json` 提交到 git（`npm ci` 可重现构建）。
- 数据层 `api.ts`：fetch + `EventSource`；单例 store（`useSyncExternalStore`），不引入状态库。
- 无路由，单页。UI 文案中文。样式手写 CSS（约 200 行），深浅色按 `prefers-color-scheme`。
- 短信弹窗：`state === "sms_required"` 时自动弹出、输入框自动聚焦；提交时携带当前 `sms_gen`；提交后进入"验证中"等待状态推送；60 秒倒计时仅作提示（客户端计时）。

### 9.2 构建与 dev 代理

`vite.config.ts`：

- `build.outDir = '../internal/webui/dist'`，`build.emptyOutDir = true`。
- dev 代理必须兼容 §8 的 Host/Origin 校验（字符串简写会保留 5173 的 Host 与 Origin，导致全部请求 403）：

```ts
server: {
  proxy: {
    '/api': {
      target: 'http://127.0.0.1:8081',
      changeOrigin: true, // Host 改写为 target → 通过 Host 校验
      configure: (proxy) => {
        proxy.on('proxyReq', (proxyReq) => { proxyReq.removeHeader('origin') })
      },
    },
  },
}
```

`Makefile`（仓库根，真实可执行，tab 缩进）：

```make
.PHONY: web build
web:
	npm --prefix web ci
	npm --prefix web run build

build: web
	go build -o geektrust ./cmd/geektrust
```

`.gitkeep` 保全（关键）：Vite `emptyOutDir=true` 会删除被跟踪的 `dist/.gitkeep`；只靠 Makefile 的 touch 步骤无法约束直接执行 `npm run build` 的门槛，删除一旦被提交，干净检出的 `go build` 会因 embed 无匹配文件而失败。因此由 `web/package.json` 的 `postbuild` 脚本负责重建（npm 在 build 后自动执行，跨平台 Node 实现，不依赖 shell）：

```json
"scripts": {
  "build": "tsc && vite build",
  "postbuild": "node -e \"require('node:fs').closeSync(require('node:fs').openSync('../internal/webui/dist/.gitkeep','a'))\""
}
```

前端开发：`go run ./cmd/geektrust run`（终端 1）+ `npm --prefix web run dev`（终端 2，Vite 5173 端口）。不做进程编排。

`internal/webui/dist` embed 规则：`//go:embed all:dist`（`all:` 前缀包含 `.gitkeep` 点文件，已核实可编译）；git 中只跟踪 `dist/.gitkeep`。`Server` 启动时检测 `index.html` 缺失则页面路由返回占位页（200，说明"前端未构建，运行 make web"），API 不受影响。`.gitignore` 增加 `web/node_modules/` 与 `internal/webui/dist/*`（`!internal/webui/dist/.gitkeep`）。

### 9.3 页面布局

单栏卡片流，最大宽度 960px 居中：顶栏（标题 + 大状态灯：绿 online / 黄 connecting、sms_required / 灰 offline）→ `StatusCard` + `UserCard`（并排，窄屏堆叠）→ `TrustDevices`（或 browser 模式说明卡）→ 操作区（`重新登录`，二次确认；409 时提示"登录正在进行中"）→ `EventsList`。`SmsDialog` 全局弹窗，优先级最高。

## 10. 测试计划

均使用合成数据，不触网。

| 包 | 测试 |
|---|---|
| `internal/config` | `[web]` 缺省→enabled true + 默认 listen；显式 false；非回环拒绝（`0.0.0.0`、公网 IP、域名）；`localhost`/`::1` 接受；端口非法拒绝（`0`、空、服务名、`80`）；规范化（`[0:0:0:0:0:0:0:1]:8081`→`[::1]:8081`、前导零去除）；`PrepareInitialConfig` 返回值与渲染 TOML 均含 `[web]` 默认 |
| `internal/session` | 事件发射：login 成功/失败各一例；成功 Observer 回调内断言 `ActiveSDPC()!=nil`（验证先发布后入队；不断言 TryForceRelogin，此时它按契约应返回 ok=true 且会清状态，破坏性操作不放回调里）；FIFO 顺序（invalidated 先于 login_start 入队则先送达）；Observer 回调内调用 `Credential` 不死锁（带超时）；脱敏覆盖 ticket/sid/code/password；`TryForceRelogin`：acquire 进行中 ok=false，成功后 ok=true 且 cur 被清、invalidated 已入队，预留未消费期间第二次调用 ok=false，run 执行后确实发生跳过 restore 的新登录；`InvalidateIfCurrent`：过期 expected 为 no-op（刚提交的重登结果不被抹掉），当前 expected 才清状态并入队；队列溢出后 `Event.Dropped` 递增且随事件可见 |
| `internal/webui` Broker | 网页胜出后**终端通道再赢一次**（回归：孤儿 Scanner 吞码）；终端通道胜出；近同时双通道提交只有一个 claim 成功——网页胜则该 POST 202 且终端行被忽略（ErrNoPending）；终端胜则网页 POST 409；gen 不匹配的跨代提交 409；布防后快照 `sms_gen` 等于 Broker 当前代、拆除后归 0；gen 回绕跳过 0（MaxUint64 用例）；取消持锁后到达的 claim 一律 409；ctx 取消与 claim 竞态：claim 在先则 Prompt 仍返回该码；无 pending 时提交/resend 409；resend 重校验必须真正命中第二道检查——先发起 Resend 并使其停在首次校验之后（持有该代 opMu），完成 claim，释放后断言返回 409 且 resend 闭包未被调用；resend 进行中 Prompt 不返回的鉴别性用例——resend 通过重校验后阻塞其闭包（占住该代 opMu），随后 claim 成功，断言 Prompt 在闭包释放前不返回、释放后返回该 code |
| `internal/webui` HTTP | status 快照字段与凭据红线（响应体不含 `sid`/`csrf`/ticket）；快照事件对象**精确**只含 `ts`/`kind`/`message`；Host 不符 403；跨源 Origin POST 403；非 JSON POST 403；全部响应含 `frame-ancestors` 与 `X-Frame-Options`；`/api/events` 为 `text/event-stream` 且首帧完整快照；sms 提交 202/400/409；resend 202/409 之外必须验证类型化错误映射——假 resend 闭包返回 `*sdpc.APIError{Code:75500401}` 时 429、返回其他错误时 500（§5.1/§7.2 跨包契约）；relogin：无 acquire 202 且状态转 connecting，acquire 进行中 409，且 202 后确实发生新登录；trust-devices 503（无会话）/409（browser 绑定）/200（假 sdpc 服务器）；Hub 消费：配置覆盖值与 clientResource 值各断言一次快照 gateways/dns；`login_failed`→`restore_success` 后 `last_error` 为 null |
| `cmd/geektrust` | web listen 与启用的 inbound 监听冲突时 `webActive=false` 走降级路径（辅助函数单测），无冲突时正常装配 |
| 构建 | 仅含 `.gitkeep` 的 dist 下 `go build ./cmd/geektrust` 成功（`go test ./...` 隐含覆盖 embed）；commit 4 必须通过 `npm --prefix web ci && npm --prefix web run build`（含 tsc） |

前端不设单元测试（无既有 JS 测试设施）；以 `npm run build`（tsc + vite）与手动冒烟验证。

## 11. 文档

- `README.md`：快速开始加面板地址一行；新增"Web 面板"小节（功能、配置、SSH 转发示例 `ssh -L 8081:127.0.0.1:8081 user@host`、Node 20+ 构建要求）。
- `docs/PLAN.md`：§8 配置节追加 `[web]`；组件清单加 `internal/webui` 一段。
- `docs/TECHNICAL.md`：不涉及协议变更，不加内容。

## 12. 提交计划

每个提交独立可编译、可通过 `go test ./...`：

1. `feat: add web panel configuration` — config（含 `PrepareInitialConfig` 走 applyDefaults）+ init 模板 + 测试。
2. `feat: add session events and SMS handler hooks` — `SessionInfo`/`Event`/dispatcher/`SetSMSHandler`/`ActiveSDPC`/`InvalidateIfCurrent`（`CredentialProvider` 接口迁移：消费者与 fake 一并从 `Invalidate` 切到 `InvalidateIfCurrent`；CheckLoop 与隧道拒绝路径改用条件失效化）/`TryForceRelogin` + 脱敏 + 测试。
3. `feat: add webui server and REST API` — internal/webui（Hub/Broker/Server/占位 dist）+ cmdRun 接线 + 测试。
4. `feat: add React web panel frontend` — web/ 源码（含 package-lock.json）+ Makefile + .gitignore；必须通过 `npm --prefix web ci && npm --prefix web run build`。
5. `docs: document web panel` — README + PLAN + 本文件（docs/WEBUI.md）。

提交前必须：本地审查 → reviewer 子代理审查 → 修复 → 复审通过 → 冻结后提交（沿用本次会话既定流程）。

## 13. 验收标准

- `geektrust run`（web 默认开）日志打印面板地址；浏览器打开可见状态卡片。
- 新设备首次 `run`：面板自动弹出短信输入；网页提交验证码后登录成功；之后再次需要短信时终端输入同样可用（无吞码）。
- `enabled=false`：无任何监听，行为与现状完全一致。
- 非回环 listen：配置加载直接报错。
- 面板可查看用户信息、授信终端列表，并完成绑定/取消授信/注销/重新登录；relogin 在登录进行中返回 409，成功后确实触发新登录。
- 响应携带 `frame-ancestors 'none'` 与 `X-Frame-Options: DENY`；`/api/events` 为 `text/event-stream`；错误文本不含 ticket/sid。
- `go build ./cmd/geektrust`（无 Node、无 dist 产物）成功；访问面板得占位提示页。
- `go vet ./...`、`go test -race ./...`、`git diff --check` 全部通过。
