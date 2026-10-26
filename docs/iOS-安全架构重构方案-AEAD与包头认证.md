# iOS 安全架构重构方案：AEAD、包头认证与会话路由

日期：2026-10-26  
适用范围：iOS BLE/TCP 共用 Noise XX 会话、私密消息、ACK、握手状态和重放防护。

## 1. 目标与非目标

### 1.1 目标

本方案解决以下核心问题：

1. AEAD 解密失败不能消耗接收 nonce；
2. 私密包的端到端相关包头必须被认证；
3. sender 必须路由到唯一 Noise 会话，禁止对所有会话盲试解密；
4. ACK 必须由目标 Noise 会话认证，不能由裸消息 ID 改变送达状态；
5. Noise 建立和身份绑定完成之前，会话不能暴露给业务层；
6. 认证失败、nonce 耗尽和协议异常必须以安全失败方式关闭会话；
7. BLE 与 TCP 继续共用同一套传输会话和 nonce 状态。

### 1.2 非目标

本次重构不改变：

- Noise XX 的握手模式；
- X25519、Ed25519、ChaCha20-Poly1305、SHA-256 的密码算法；
- BLE 和 TCP 的底层发现、连接、分片实现；
- 公共广播消息的签名协议，但公共广播仍需使用严格包格式校验。

## 2. 当前架构问题

当前调用链大致为：

```text
ChatEngine
  -> SessionManager.encrypt/decrypt
    -> NoiseXX.encrypt/decrypt
      -> CipherState.encrypt/decrypt
```

同时，`ChatEngine` 先构造 `CQPacket` 外层包头，再把私密明文交给 Noise 加密。Noise 调用使用空 associated data：

```text
AEAD(plaintext, AD = empty)
```

因此 `sender`、`msgId`、`flags` 等外层字段不在认证范围内。

当前 iOS `CipherState.decrypt` 还会在 `ChaChaPoly.open` 前递增 `n`：

```swift
let nonce = noiseNonce(n)
n += 1
return try ChaChaPoly.open(...)
```

认证失败时，状态已经改变，导致攻击者可以发送伪造密文使会话永久失步。

另外，`ChatEngine.handlePrivate` 在找不到 sender 对应会话时，会遍历全部会话并逐个尝试解密。这会放大 CPU 消耗，也会让错误包影响多个会话。

## 3. 目标架构

重构后建议采用以下分层：

```text
TransportEnvelopeRouter
        |
        v
AuthenticatedPacketCodec
        |
        v
SessionManager
  - PendingHandshakeStore
  - AuthenticatedSessionStore
  - RemoteTempIdIndex
        |
        v
NoiseTransportSession
  - SerializedCipherState
  - nonce commit-after-auth
  - failure budget
  - nonce exhaustion handling
```

业务层不再直接调用 `NoiseXX.encrypt(plaintext)`，而是调用带有包头上下文的会话 API：

```swift
try session.encryptPacket(
    header: packetHeader,
    plaintext: privatePlaintext
)
```

接收流程也必须先通过 sender 索引会话，再使用同一个规范化包头作为 AD：

```swift
let session = sessionManager.session(forRemoteTempId: packet.sender)
let plaintext = try session.decryptPacket(header: packet.header, payload: packet.payload)
```

禁止保留“遍历全部会话尝试解密”作为 fallback。

## 4. 第一层：可提交的 SerializedCipherState

### 4.1 状态定义

```swift
enum TransportState {
    case active
    case closing
    case closed
    case nonceExhausted
}

final class SerializedCipherState {
    private let key: SymmetricKey
    private var receiveNonce: UInt64 = 0
    private var sendNonce: UInt64 = 0
    private var state: TransportState = .active
    private let lock = NSLock()
}
```

所有 `encrypt` 和 `decrypt` 都必须在同一把锁或同一个 actor 中串行执行。不能只保护 `n += 1`，而要保护“读取 nonce、执行 AEAD、提交 nonce、处理状态”这一整个事务。

### 4.2 接收路径：认证成功后提交 nonce

建议语义：

```swift
func decrypt(ciphertext: Data, ad: Data) throws -> Data {
    lock.lock()
    defer { lock.unlock() }

    guard state == .active else { throw NoiseError.invalidState }
    guard ciphertext.count >= 16 else { throw NoiseError.decryptFailed }
    guard receiveNonce < UInt64.max else {
        state = .nonceExhausted
        throw NoiseError.nonceExhausted
    }

    let candidate = receiveNonce
    let nonce = noiseNonce(candidate)

    do {
        let plaintext = try open(ciphertext, nonce: nonce, ad: ad)
        receiveNonce = candidate + 1
        return plaintext
    } catch {
        // 关键：认证失败不改变 receiveNonce
        throw NoiseError.decryptFailed
    }
}
```

必须满足：

- 短密文不改变 nonce；
- AEAD tag 错误不改变 nonce；
- AD 错误不改变 nonce；
- 成功解密且即将溢出时安全关闭；
- 不允许调用方在认证前观察或修改 nonce。

### 4.3 发送路径：加密成功后提交 nonce

发送端也采用 commit-after-success：

```swift
let candidate = sendNonce
let sealed = try seal(plaintext, nonce: noiseNonce(candidate), ad: ad)
sendNonce = candidate + 1
return sealed
```

这样即使平台加密 API 异常，也不会无故消耗发送 nonce。

### 4.4 失败预算

不递增 nonce 解决了状态失步，但认证失败仍会消耗 CPU。因此每个会话需要维护失败预算：

```text
per session:
  authFailureCount
  failureWindowStart
  lastFailureTime
```

建议初始策略：

- 单个会话在 10 秒内连续 8 次 AEAD 失败：暂时丢弃该来源包；
- 连续 32 次失败：关闭当前 Noise 会话并要求重新握手；
- 不在错误日志中输出完整密文、密钥、nonce 或详细内部状态；
- 失败预算按 remoteTempId 和底层连接双重限速。

失败限速不能通过递增 nonce 实现。

## 5. 第二层：AuthenticatedPacketHeader

### 5.1 包头分类

必须明确字段的认证语义：

| 字段 | 语义 | 是否进入端到端 AD |
|---|---|---|
| `version` | 协议版本 | 是 |
| `type` | 包类型 | 是 |
| `flags` | 私密包处理语义 | 是 |
| `sender` | 当前发送方临时 ID | 是 |
| `msgId` | 端到端消息 ID | 是 |
| `ttl` | 中继跳数 | 默认否，属于 hop-by-hop |
| `payload_len` | 当前封装长度 | 不单独进入 AD，但必须严格匹配 |

如果业务决定 TTL 也属于端到端语义，则将 TTL 加入 AD；否则中继节点可以递减 TTL，但不能把 TTL 当作端到端认证字段。

### 5.2 规范化 AD

不要直接对 Swift 结构体内存布局做认证。增加显式规范化编码：

```swift
struct AuthenticatedPacketHeader {
    let version: UInt8
    let type: UInt8
    let flags: UInt8
    let sender: Data   // 16 bytes
    let msgId: Data    // 16 bytes

    func associatedData() throws -> Data {
        guard sender.count == 16, msgId.count == 16 else {
            throw PacketError.invalidHeader
        }
        return Data("CQchat packet AD v1".utf8)
            + Data([version, type, flags])
            + sender
            + msgId
    }
}
```

`payload_len` 由解码器检查，但不需要重复加入 AD，因为 AEAD 本身已经认证 payload 长度和内容；如果协议希望防止不同封装层重解释，也可以将长度加入 AD，但两端必须完全一致。

### 5.3 API 重构

废弃或限制以下 API：

```swift
try noise.encrypt(plaintext)
try noise.decrypt(ciphertext)
```

替换为：

```swift
try noise.encrypt(plaintext: plaintext, associatedData: header.associatedData())
try noise.decrypt(ciphertext: ciphertext, associatedData: header.associatedData())
```

更推荐由 `NoiseTransportSession` 封装，业务层不能自行传入空 AD：

```swift
try session.encryptPacket(header: header, plaintext: plaintext)
try session.decryptPacket(header: header, ciphertext: ciphertext)
```

## 6. 第三层：SessionManager 改为双索引和分阶段状态

### 6.1 会话状态

```swift
enum SessionAvailability {
    case handshaking
    case noiseEstablished
    case identityAuthenticated
    case usable
    case closing
    case closed
}
```

只有 `usable` 状态可以被私聊发送逻辑获取。

### 6.2 双索引

维护两个明确索引：

```text
pendingByTempId: [Data: PendingSession]
activeByTempId:  [Data: Session]
activeByFingerprint: [Data: Session]
```

接收私密包时只允许：

```swift
activeByTempId[packet.sender]
```

然后验证：

```text
packet.sender == session.remoteTempId
```

禁止遍历 `allSessions()` 试解密。

### 6.3 认证晋升

握手完成后不要直接写入 active 会话：

```text
HANDSHAKING
  -> NOISE_ESTABLISHED
  -> 收到并验证 Hello
  -> IDENTITY_AUTHENTICATED
  -> 写入 activeByTempId / activeByFingerprint
  -> USABLE
```

`SessionManager.complete()` 应拆为：

```swift
finishNoiseHandshake(tempId:) throws
authenticateIdentity(tempId:, hello:) throws
promoteToUsable(tempId:) throws
```

其中 `authenticateIdentity` 必须验证：

1. Hello 的 X25519 公钥等于 Noise `remoteStatic`；
2. Ed25519 binding signature 正确；
3. fingerprint 等于 Hello 中的 Ed25519 公钥计算结果；
4. 不存在同 fingerprint 的冲突活动会话，或按明确策略关闭旧会话。

## 7. 第四层：ACK 改为加密控制消息

### 7.1 推荐设计

不再使用“裸 ACK 修改业务状态”。可以继续保留外层 `ACK` 类型以方便路由，但 ACK payload 必须是对应 Noise 会话加密后的控制明文：

```text
ACK outer packet:
  version
  type = ACK
  flags = 0
  sender = receiver temp id
  msg_id = fresh random packet id
  ttl = hop-by-hop
  payload = NoiseEncrypt(
      content_type = ACK_V1
      acked_msg_id[16]
      direction = 1 byte
      session_generation[8]
  , AD = authenticated outer header)
```

接收端处理顺序：

1. 使用 `sender` 查找唯一会话；
2. 用完整外层 AD 解密；
3. 验证明文 content type；
4. 验证 `acked_msg_id` 存在于该会话/目标的 awaiting 表；
5. 验证方向和 session generation；
6. 通过后才标记 delivered；
7. 对 ACK packet 自身做去重，重复 ACK 只做幂等处理，不重复触发业务副作用。

### 7.2 awaitingAck 结构

不要使用全局裸字典：

```swift
[Data: AwaitingAck]
```

改为：

```swift
struct AwaitingAckKey: Hashable {
    let fingerprint: Data
    let msgId: Data
    let generation: UInt64
}
```

ACK 只能删除完整 key 匹配的等待项。

## 8. 包解码和重放边界

### 8.1 严格包长度

`CQPacket.decode` 必须要求：

```text
data.count == headerSize + payload_len
```

不能接受尾随字节。

同时严格检查：

- `version` 白名单；
- `type` 白名单；
- flags 保留位必须为 0；
- sender/msgId 长度固定为 16；
- payload 长度不超过类型上限；
- TTL 范围有效。

### 8.2 去重时机

建议按消息类型处理：

- HANDSHAKE：使用 tempId、step 和握手状态限速，不依赖全局 msgId 去重；
- PRIVATE/ACK：先完成 sender 路由和 Noise 认证，再登记需要保护的业务 msgId；
- BROADCAST：先完成签名验证，再登记 msgId；
- FRAGMENT：分片缓存必须有总容量、单消息容量、来源配额和过期时间。

## 9. 握手失败处理

所有握手步骤必须使用失败即 abort 的结构：

```swift
case 2:
    guard let noise = sessions.handshake(forTemp: temp) else { return }
    do {
        _ = try noise.initiatorRead2(body)
        let body3 = try noise.initiatorWrite3(payload: encodeHello())
        route(body3)
    } catch {
        sessions.abortHandshake(forTemp: temp)
        securityLimiter.recordFailure(for: temp)
    }
```

禁止：

- 忽略 `try?` 的错误后继续推进状态机；
- 在失败的 Noise 对象上继续调用后续步骤；
- 让密码学异常穿出 BLE delegate、TCP read loop 或主线程任务。

同一个 temp ID 已存在活动握手时，`beginHandshake` 不应无条件覆盖。应返回已有状态、拒绝新握手或经过连接上下文验证后替换。

## 10. Nonce 和会话代次

每次成功建立 Noise transport 时分配 `generation`：

```text
fingerprint + generation -> active session
```

重握手、断线重连或会话关闭后，旧 generation 的：

- ACK；
- retry；
- queued media；
- delayed packet

全部不得作用于新会话。

nonce 处理规则：

1. 一个 `CipherState` 只绑定一个方向和一个 generation；
2. BLE/TCP 共享同一个 CipherState，不分别维护 nonce；
3. 认证失败不改变 nonce；
4. nonce 到 `UInt64.max` 前安全关闭并重新握手；
5. 会话关闭后禁止复用旧 CipherState。

## 11. 媒体队列修复

当前排队媒体没有可靠保存目标 fingerprint。重构时将目标信息放入不可变队列项：

```swift
struct PendingMedia {
    let messageId: Data
    let destinationFingerprint: Data
    let sessionGeneration: UInt64
    let kind: ChatMessage.Kind
    let body: Data
    let thumbnail: Data?
}
```

flush 时只处理：

```text
destinationFingerprint == requested fingerprint
sessionGeneration == current generation
```

发送失败时不能从其他目标队列中删除，也不能使用另一个 fingerprint 的 Noise 会话加密。

## 12. 迁移策略

### 阶段 A：内部 API 和状态隔离

- 新增 `AuthenticatedPacketHeader`；
- 新增 `SerializedCipherState`；
- 为 SessionManager 增加 pending/active 双索引；
- 保持旧协议仅用于单元测试，不让业务继续调用空 AD API。

### 阶段 B：协议版本升级

包头认证改变了 AEAD 输入，建议将协议版本升级到 `v2` 或为 PRIVATE/ACK 增加明确的 transport version。

安全默认：

- 新版本只接受新 AD 格式；
- 不要在同一会话中自动降级为空 AD；
- 旧版本连接应重新握手，不复用旧 CipherState；
- BLE 和 TCP 两条路径都必须使用相同 AD 编码。

### 阶段 C：灰度验证

上线前同时运行：

- Android 与 iOS 交叉互通向量；
- v2 正常文本/图片/语音/ACK；
- BLE 分片和 TCP 完整包；
- 旧版本包明确拒绝并记录兼容性事件。

## 13. 必须新增的安全测试

### 13.1 nonce 提交测试

1. 构造错误 tag，解密失败；
2. 紧接着发送正确密文；
3. 正确密文必须仍然成功解密。

并发测试：

- 多线程/Task 同时调用 decrypt；
- 每个合法密文只成功一次；
- nonce 不跳号、不重复、不倒退。

### 13.2 包头认证测试

逐字段修改并确认失败：

- version；
- type；
- flags；
- sender；
- msgId；
- AD domain/version。

TTL 测试必须明确：TTL 若不属于 AD，改变 TTL 不能导致 AEAD 失败；若属于 AD，改变后必须失败。

### 13.3 会话路由测试

- 未知 sender 不触发全会话解密；
- sender 指向错误会话时拒绝；
- 同一 ciphertext 不能在另一个会话中成功；
- 失败包不能消耗其他会话 nonce；
- sender 与 `remoteTempId` 不匹配时不处理业务。

### 13.4 ACK 测试

- 裸 ACK 不能改变 delivered；
- 错误 fingerprint 的 ACK 被拒绝；
- 错误 generation 的 ACK 被拒绝；
- 已处理 ACK 重放只产生幂等结果；
- 修改 ACK 外层 header 或内部 msgId 后认证失败。

### 13.5 状态机测试

- Hello 验证前不可发送普通私聊；
- step 2 失败后不能生成 step 3；
- 同一 temp ID 不能覆盖活动握手；
- 失败握手不能进入 active session；
- nonce 耗尽后旧会话不能继续发送或接收。

## 14. 验收标准

重构完成后必须满足：

- 任何 AEAD 认证失败都不会改变接收 nonce；
- 任一包头认证字段改变都会导致解密失败；
- 私密包只会尝试一个按 sender 路由得到的会话；
- ACK 不经过 Noise 认证就不能改变消息状态；
- 未完成身份绑定的会话不会暴露给普通私聊业务；
- BLE/TCP 使用同一会话、同一方向 nonce、同一 AD 编码；
- nonce 溢出、认证失败风暴和握手异常都有安全终止路径；
- Android/iOS 共享向量和攻击回归测试全部通过。

## 15. 推荐实施顺序

1. 先修复 iOS `CipherState.decrypt` 的 commit-after-auth nonce 语义；
2. 抽取 `AuthenticatedPacketHeader` 和非空 AD API；
3. 改造 `SessionManager` 的 sender 路由，删除全会话盲试解密；
4. 引入 pending/noiseEstablished/identityAuthenticated/usable 状态；
5. 将 ACK 改为 Noise 加密控制消息；
6. 增加失败预算、nonce exhaustion 和握手 abort；
7. 修复去重、媒体队列、严格包长度和随机源错误；
8. 最后升级协议版本并进行 Android/iOS 互通回归。

这套顺序可以先消除最危险的 nonce 失步和元数据篡改，再逐步替换会话生命周期，不需要一次性重写 BLE/TCP 传输层。
