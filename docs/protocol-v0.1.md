# CQchat Protocol v0.1

可执行规范。字节序、长度、未知字段、版本协商、错误与重试以本文为准。
机器可读向量：[`../shared/test-vectors/v0.1.json`](../shared/test-vectors/v0.1.json)。
实现入口：`ios/`、`android/`；共享参考编码：`shared/reference/`。

**版本号：** 传输信封 `version = 0x02`（加入 `destination`/`next_hop` 的包头版本）。旧 `0x01` 包头不得按新格式解析。
**端序：** 除 Noise AEAD nonce 计数（小端）外，多字节整数一律 **大端**。
**字符串：** UTF-8，无 BOM。
**未知 `type` / 未知 `flags` bit：** 丢弃该包，不崩溃；不得当作成功。

---

## 1. 分层

| 层 | 职责 | 可见信息 |
|---|---|---|
| 载体（BLE / TCP） | 搬字节 | 密文信封 |
| 传输信封 | 转发、去重、分片、TTL、定向路由 | `version/type/flags/sender/msg_id/destination/next_hop/ttl/payload_len` |
| 加密载荷 | 会话明文 | 仅会话双方 |

路由/中继节点 **不得** 依赖昵称、长期公钥、聊天正文或媒体类型做转发决策。

蓝牙与 Wi‑Fi **共用同一信封**；不得为局域网另定义明文语义。

---

## 2. 常量

| 名称 | 值 |
|---|---|
| `VERSION` | `0x02` |
| `HEADER_SIZE` | `70` |
| `BLE_MTU_PAYLOAD` | `512`（再按协商 MTU−3 收紧） |
| `MAX_ENVELOPE` | `65535 + 70`（受 `payload_len` u16 限制） |
| `TTL_DEFAULT` | `7` |
| `MSG_EXPIRY_SECS` | `600`（时间有效期，与 TTL 独立） |
| `MAX_RETRIES` | `5`（同一路径） |
| `TEMP_ID_ROTATE_SECS` | `180` |
| `DEDUP_TTL_SECS` | `300` |
| `DEDUP_MAX_ENTRIES` | `4096`（LRU） |
| `TCP_PORT` | `37251` |
| `MDNS_TYPE` | `_cqchat._tcp` |
| `MEDIA_BLE_MAX` | `102400` |
| `IMAGE_MAX_EDGE` | `1280` |
| `IMAGE_JPEG_QUALITY` | `0.7` |
| `VOICE_SR` | `16000` |
| `VOICE_CHANNELS` | `1` |
| `VOICE_FRAME_MS` | `20` |
| `VOICE_MAX_SECS` | `60` |

### BLE UUID

- Service: `c1c10001-c1c1-4000-8000-00000000c1c1`
- Inbox: `c1c10002-c1c1-4000-8000-00000000c1c1`

广播 Service Data：**仅** `VERSION (1) || temp_id (16)`。禁止长期公钥、昵称、指纹。

### mDNS

TXT 仅 `v=1`。服务名/TXT **不放**身份。

---

## 3. 三种密钥（禁止混用）

| 概念 | 算法 | 用途 |
|---|---|---|
| 长期身份 | Ed25519 | 二维码核对、公频签名、稳定身份 |
| 会话协商 | X25519 | Noise 静态 DH |
| 会话消息 | Noise 派生 | ChaCha20-Poly1305 实际加解密 |

```
identity_seed = CSPRNG(32)   // Keychain / Keystore，永不上传
x25519_seed   = HKDF-SHA256(ikm=identity_seed, salt=32×0x00, info="cqchat-v1-x25519",  L=32)
ed25519_seed  = HKDF-SHA256(ikm=identity_seed, salt=32×0x00, info="cqchat-v1-ed25519", L=32)
fingerprint   = SHA256(ed25519_public)[0..16)   // 二维码身份；与 X25519 公钥区分
```

QR：`cqchat:v1:` + fingerprint 的 32 位小写 hex。
扫码 = 建立可识别的长期身份关系；未扫 = 临时匿名设备。

昵称不参与认证。为防止将一个 Ed25519 身份错误绑定到另一把 Noise 静态密钥，Hello 还必须携带身份绑定签名：

```
binding_message = UTF8("CQchat identity binding v1") || u8(1) || x25519_public:32 || ed25519_public:32
binding_signature = Ed25519.Sign(ed25519_private, binding_message)
```

接收方必须同时验证：Hello 中的 `x25519_public` 等于当前 Noise 会话解出的远端静态公钥，且 `binding_signature` 能由 Hello 中的 `ed25519_public` 验证通过；否则不得将临时会话 rebind 到该 Ed25519 fingerprint。

### Noise

`Noise_XX_25519_ChaChaPoly_SHA256`

- 静态密钥 = 上表 X25519
- AEAD nonce：12 字节 = `4×0x00 || uint64_le(n)`，每方向独立，从 0 递增；**禁止**用系统时间作 nonce
- 握手 step1 无密钥时仍须 `MixHash(payload)`（可为空）
- 蓝牙与热点共用同一对 CipherState；换通道 **不** 重新握手
- 会话状态损坏：安全失败并重新 XX；禁止复用未知状态
- v0.1 只用 XX；不上 IK/XX 以外模式，不上 Double Ratchet

前向安全：指 **活会话** 级。离线排队、久断线、多设备密钥生命周期 **不** 等同宣传为同等前向保密。

---

## 4. 传输信封

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 1 | `version` |
| 1 | 1 | `type` |
| 2 | 1 | `flags` |
| 3 | 16 | `sender` = 当前 temp_id |
| 19 | 16 | `msg_id` = CSPRNG(16)，≥128 bit 随机；禁止时间戳/指纹拼接 |
| 35 | 16 | `destination` = 目标节点 temp_id；全零表示广播 |
| 51 | 16 | `next_hop` = 当前期望下一跳 temp_id；全零表示由邻居自主接收 |
| 67 | 1 | `ttl` |
| 68 | 2 | `payload_len` u16 BE |
| 70 | N | `payload` |

### 定向转发语义

- `destination` 和 `next_hop` 都使用 16 字节临时节点 ID；全零地址是广播哨兵值。
- 节点收到非全零 `next_hop` 且不等于自己的 `temp_id` 时，必须丢弃，不得交给业务层或继续转发。
- `destination` 等于本机 `temp_id` 时，节点可以交付业务，但不得继续转发该包。
- 当前基础实现没有完整路由表；由于 `destination`/`next_hop` 已被端到端 AD 认证，中继节点不得改写它们。需要逐跳改写下一跳时，必须新增独立的逐跳外层信封。
- `sender` 保持为原始发送节点，不在中继时改写；`msg_id` 在全路径保持不变。
- 私密包的 AEAD AD 为 `UTF8("CQchat packet AD v2") || version || type || flags || sender || msg_id || destination || next_hop`。其中 `destination`、`next_hop` 和其他字段按上述固定顺序编码；`payload_len` 不纳入 AD（由密文长度校验），`ttl` 也不纳入 AD，因为 TTL 允许中继逐跳递减。任何 AD 字段被篡改都会导致 AEAD 验证失败。

### flags

| bit | 名 | 含义 |
|---|---|---|
| 0 | `NEEDS_ACK` | 需要送达确认 |
| 1 | `PRIORITY_LOW` | 低优先级（媒体）；拥塞时可降转发概率 |
| 2–7 | 保留 | 置 0；未知 bit → 丢弃 |

### type

| 值 | 名 |
|---|---|
| `0x01` | DISCOVER |
| `0x02` | BROADCAST |
| `0x03` | HANDSHAKE |
| `0x04` | PRIVATE |
| `0x05` | ACK |
| `0x06` | SYNC（v0.1 可空） |
| `0x07` | MEDIA_META（元数据仍应进加密载荷；中继不可依赖） |
| `0x08` | FRAGMENT |

### 去重

- 键：`msg_id`
- TTL：`DEDUP_TTL_SECS`；容量：`DEDUP_MAX_ENTRIES` LRU
- 重复：丢弃（ACK 对同一 `ack_msg_id` 可幂等处理）
- 成功解密的 Noise 计数器/消息亦拒绝重放

### TTL / 过期 / 重试（三者独立）

- **TTL**：空间跳数；每跳减 1；0 不转发
- **过期**：`created_at + MSG_EXPIRY_SECS`；超时 → `failed`
- **重试**：同路径 ≤ `MAX_RETRIES`；换载体（BLE↔TCP）可用同一 `msg_id`，不另占握手

拥塞：降低 `PRIORITY_LOW` 转发概率；不得只靠「TTL=7」做全部控制。

---

## 5. 消息状态机

```
created → queued → sent → delivered
                 ↘ failed
         relayed（仅中继节点本地观测，不展示给发送方为已送达）
```

| 状态 | 含义 | UI |
|---|---|---|
| `created` | 本地已构造 | 可不展示 |
| `queued` | 等待载体/热点/权限 | 「等待中」 |
| `sent` | 已写入附近链路（BLE 或 TCP） | 「已交给附近」 |
| `relayed` | 被他机转发 | 发送方 **不** 据此显示送达 |
| `delivered` | 收到针对该 `msg_id` 的 ACK | 「已送达」 |
| `failed` | 过期或重试耗尽 | 「失败」 |

**禁止** 因写入本地队列就显示「已发送」或绿色勾。v0.1 不做已读回执。

---

## 6. 载荷

### BROADCAST `0x02`

```
nickname_len:u8 | nickname | text_len:u16 BE | text | ed25519_pk:32 | sig:64
```

签名消息 = `msg_id || nickname || text`。UI 必须标「公开消息」。

### HANDSHAKE `0x03`

```
pattern:u8=1 | step:u8∈{1,2,3} | body
```

完成后只有在 Hello 的 Ed25519-X25519 绑定签名验证通过后，才可绑定对方 `fingerprint`（Ed25519）。Hello 可在 handshake payload 或随后 PRIVATE 中交换昵称。

### 会话身份状态

实现必须区分以下两个状态：

1. `HANDSHAKE_COMPLETE`：Noise XX 已完成，且远端静态 X25519 公钥已确定；会话只能保存在临时表中，只允许处理一个经过 AEAD 保护的 Hello，不能发送或交付普通私聊、不能更新已识别联系人、不能触发私聊通知。
2. `IDENTITY_AUTHENTICATED`：接收方验证 Hello 的 `x25519_public` 等于 Noise 远端静态公钥，验证 Ed25519 绑定签名，并由该公钥计算出 fingerprint 后，原子地将会话从临时表移动到身份表。只有身份表中的会话可以用于普通私聊。

状态只能单向切换 `HANDSHAKE_COMPLETE → IDENTITY_AUTHENTICATED`。指纹冲突、重复 Hello 携带不同身份、签名失败或 X25519 不匹配都必须拒绝，不得覆盖已有身份会话；临时会话超时后应连同 Noise 状态一起销毁。`IDENTITY_AUTHENTICATED` 表示密码学身份绑定已验证，不等同于用户通过 QR 完成人工信任确认。

### PRIVATE `0x04`

Noise `EncryptWithAd(ad="", plaintext)` → ciphertext\|\|tag。

明文：`content_type:u8 | body`

| content_type | 含义 |
|---|---|
| `0x01` | UTF-8 文本 |
| `0x02` | 图片媒体容器 |
| `0x03` | 语音 CQOP |
| `0x10` | Hello：`nickname_len:u8 \|\| nickname \|\| ed25519_pk:32 \|\| x25519_pk:32 \|\| binding_sig:64` |

媒体容器（在加密体内）：

```
thumb_len:u32 BE | thumb | data_len:u32 BE | data
```

缩略图、文件名、大小、正文均视为敏感；**全部进密文**。中继只见信封。

### ACK `0x05`

`ack_msg_id:16`。收到后停止对该 id 的重传。

### FRAGMENT `0x08`

对完整信封 `raw` 切片；各片共用同一 `msg_id`：

```
index:u16 BE | total:u16 BE | data
```

须容忍乱序、重复、丢失。未完成对象有内存上限；超时/`DEDUP_TTL` 后丢弃。分片不再二次分片。
v0.1 **不要求** 媒体断点续传（列为后续）；丢失则整消息失败并可同 `msg_id` 重发。

### CQOP 语音

```
"CQOP" | sample_rate:u32 BE | channels:u8 | frame_count:u16 BE
  × (pkt_len:u16 BE | opus_packet)
```

参数见常量表。生产构建须真实 Opus；stub 不得跨端互通。

### TCP 帧

`len:u32 BE | body`（body = 完整信封，可已是 FRAGMENT）。

---

## 7. 通道策略

1. 文字 / 握手 / ACK：BLE 优先；已有 TCP 亦可。
2. 媒体：`size ≤ MEDIA_BLE_MAX` 可 BLE 分片；更大必须 TCP；无热点 → `queued`，UI「等待热点」，禁止假装已发出。
3. TCP 失败：同 `msg_id`、同密文退回 BLE（若尺寸允许）。
4. 禁止双通道无协调并发重复发送；一发一等 ACK 或超时再换通道。

---

## 8. 错误码（应用层日志 / 调试；不全部上线）

| 码 | 含义 |
|---|---|
| `E_VERSION` | 版本不支持 |
| `E_DECODE` | 信封/载荷解析失败 |
| `E_DEDUP` | 重复 msg_id |
| `E_TTL` | TTL 耗尽 |
| `E_EXPIRED` | 消息过期 |
| `E_NOISE` | 握手/解密失败 |
| `E_REPLAY` | nonce/计数器重放 |
| `E_NO_PATH` | 无可用载体 |
| `E_QUOTA` | 分片/存储上限 |
| `E_REJECT_UNVERIFIED_MEDIA` | 未验证对端大文件被拒 |

---

## 9. 版本协商

对方 `version >` 本端：丢弃并可选 DISCOVER 指示本端版本。
对方 `version <` 且不兼容：丢弃。当前实现仅接受 `0x02` 包头；`0x01` 包头不得按新格式解析。

---

## 10. v0.1 明确不做

长期后台 Mesh 中继承诺、跨多跳大文件、杀进程后必达、Double Ratchet、多设备同步、已读、群组加密、断点续传（规范预留至后续版本）。
