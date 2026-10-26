# CQchat Protocol v1

两端共用。字段顺序、端序、长度、类型码必须一致。本文件是唯一权威；改协议先改这里，再改 iOS / Android。

## 常量

| 名称 | 值 |
|---|---|
| `VERSION` | `0x01` |
| `BLE_MTU_PAYLOAD` | `512`（分片阈值；写特征时按协商 MTU−3 再收紧） |
| `TTL_DEFAULT` | `7` |
| `TEMP_ID_ROTATE_SECS` | `180` |
| `DEDUP_TTL_SECS` | `300` |
| `TCP_PORT` | `37251` |
| `MDNS_TYPE` | `_cqchat._tcp` |
| `MEDIA_BLE_MAX` | `102400`（100 KiB） |
| `IMAGE_MAX_EDGE` | `1280` |
| `IMAGE_JPEG_QUALITY` | `0.7` |

### BLE UUID（128-bit）

- Service: `c1c10001-c1c1-4000-8000-00000000c1c1`
- Inbox (write / write-without-response / notify): `c1c10002-c1c1-4000-8000-00000000c1c1`

广播：只在 Service Data 放 `VERSION (1) || temp_id (16)`。禁止长期公钥、昵称。

### Noise

`Noise_XX_25519_ChaChaPoly_SHA256`

- 静态身份：X25519（Keychain / Keystore）
- 公频签名：Ed25519（同一 32 字节 `identity_seed` 经 HKDF 派生，见下）
- 传输 nonce：Noise 标准（12 字节 = 4 零 + 8 字节小端计数），每方向独立递增
- 蓝牙与热点共用同一对 CipherState；失败用同一 `msg_id` 换通道重发，不重新握手

### 身份派生

```
identity_seed = CSPRNG(32)          // 首次启动生成，永不上传
x25519_seed   = HKDF-SHA256(ikm=identity_seed, salt="", info="cqchat-v1-x25519",  L=32)
ed25519_seed  = HKDF-SHA256(ikm=identity_seed, salt="", info="cqchat-v1-ed25519", L=32)
fingerprint   = SHA256(x25519_public)[0..16)   // 16 字节；二维码为 32 字符小写 hex
```

昵称仅本地展示与公频明文，不参与认证。

## 包头（所有类型）

大端。总长 = 29 + `payload_len`。

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `type` | 见类型表 |
| 2 | 1 | `flags` | bit0=`NEEDS_ACK`；其余 0 |
| 3 | 16 | `sender` | 当前临时标识（轮换中的 temp_id） |
| 19 | 16 | `msg_id` | 随机 16 字节；去重与分片拼回键 |
| 35 | 1 | `ttl` | 起始 7，每跳减 1；0 丢弃 |
| 36 | 2 | `payload_len` | 大端 u16 |
| 38 | N | `payload` | |

包头固定 **38** 字节（含 `payload_len`）。总长 = 38 + `payload_len`。

接收：`msg_id` 在约 5 分钟 LRU 内重复则丢弃（ACK 类型除外：对同一 `ack_msg_id` 可幂等）。`ttl==0` 不转发。

## 类型

| 值 | 名称 | 载荷 |
|---|---|---|
| `0x01` | `DISCOVER` | 空（发现只靠广播 Service Data；此类型可选，用于主动探测） |
| `0x02` | `BROADCAST` | 公频明文 + Ed25519 |
| `0x03` | `HANDSHAKE` | Noise XX 握手字节 |
| `0x04` | `PRIVATE` | Noise 传输密文 |
| `0x05` | `ACK` | 确认 |
| `0x06` | `SYNC` | 第一期可空实现 |
| `0x07` | `MEDIA_META` | 媒体说明（通常再包进 PRIVATE 明文） |
| `0x08` | `FRAGMENT` | 分片 |

## 载荷细节

### BROADCAST `0x02`

```
nickname_len: u8
nickname:     bytes (UTF-8)
text_len:     u16 BE
text:         bytes (UTF-8)
ed25519_pk:   32 bytes
sig:          64 bytes
```

签名消息 = `msg_id || nickname || text`（原始字节拼接，无长度前缀以外的额外分隔）。

### HANDSHAKE `0x03`

```
pattern: u8 = 1   // Noise XX
step:    u8       // 1, 2, 3
body:    bytes    // 该步 Noise 消息原文
```

Noise 消息按标准 XX 处理；step1 无密钥时仍须 `MixHash(payload)`（即使 payload 为空）。  
握手完成后双方从静态公钥算 `fingerprint`，会话绑定该指纹。昵称在加密通道内用 PRIVATE / handshake payload 的 `Hello` 交换。

### PRIVATE `0x04`

`payload` = Noise `EncryptWithAd(ad="", plaintext)` 输出（密文 \|\| tag）。

明文：

```
content_type: u8
body:         bytes
```

| content_type | 含义 |
|---|---|
| `0x01` | UTF-8 文本 |
| `0x02` | 图片（见媒体容器） |
| `0x03` | 语音 Opus（见媒体容器） |
| `0x10` | Hello：`nickname_len:u8 \|\| nickname` |
| `0x11` | 回执请求已由包头 `NEEDS_ACK` 表达；此值保留 |

### ACK `0x05`

```
ack_msg_id: 16 bytes
```

包头自己的 `msg_id` 仍须唯一。收到后停止对该 `ack_msg_id` 的重传。

### FRAGMENT `0x08`

当完整包（含包头）> 可用 MTU 时：

1. 序列化完整原始包 `raw`（原始 `type` 不是 FRAGMENT）
2. 按 `chunk_size` 切开；每个分片：

```
index: u16 BE   // 从 0
total: u16 BE
data:  bytes
```

3. 外层包：`type=FRAGMENT`，**同一** `msg_id`、`sender`、`ttl`（首片的 ttl；转发时统一递减）

收齐后按 `index` 拼接 `data`，得到 `raw`，再解析。分片本身不再二次分片。

## 媒体容器

图片 / 语音在 PRIVATE 明文 `body` 中：

```
thumb_len: u32 BE
thumb:     JPEG bytes（可 0）
data_len:  u32 BE
data:      bytes
```

- 图片 `data`：JPEG，长边 ≤ 1280，质量 ≈ 0.7；`thumb` 为更小预览 JPEG（边长约 160）
- 语音 `data`：CQchat Opus 封装（见下）；`thumb_len=0`

### Opus 封装 `CQOP`

```
magic:       "CQOP" (4)
sample_rate: u32 BE (=16000)
channels:    u8 (=1)
frame_count: u16 BE
repeat frame_count times:
  pkt_len: u16 BE
  pkt:     Opus packet bytes
```

## 通道策略

1. 文字 / 握手 / ACK / 小包：蓝牙优先；若已有 TCP 也可直送。
2. 媒体：压完后 `size = thumb_len + data_len + 8`：
   - `size ≤ 100KiB`：可蓝牙分片；有热点则优先 TCP。
   - `size > 100KiB`：必须 TCP；无热点则 **排队**，UI 显示「等待网络/热点」，**不得**标为已发送。
3. TCP 失败：用**同一** `msg_id` 与**同一**密文改走蓝牙（若尺寸允许）；不重新 Noise 握手。
4. 热点：mDNS 查 `_cqchat._tcp`，TCP 帧为：

```
len: u32 BE
body: 完整 CQ 包（可已是 FRAGMENT 或普通包）
```

mDNS TXT 只放 `v=1`，不放身份。

## 验证状态

- 本地保存已扫过的 `fingerprint` 集合
- UI：在集合内 →「已验证」；否则「未验证」
- 二维码内容：`cqchat:v1:` + fingerprint 的 32 位 hex（小写）

## 通知

仅本地通知。进程被杀或设备离开范围不弹。附近人发现通知须冷却（建议 ≥ 10 分钟 / 同一 fingerprint 或 temp_id）。

## 明确不做（第一期）

实时通话、Nostr、推送服务器、好友系统、朋友圈、Double Ratchet。
