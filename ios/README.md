# CQchat iOS

Swift / SwiftUI · CoreBluetooth · Keychain

协议权威说明见仓库根目录 [`docs/protocol-v0.1.md`](../docs/protocol-v0.1.md)。与 Android 必须字节级一致。

## 打开工程

1. 用 Xcode 16+ 打开 `CQchat.xcodeproj`
2. 选真机（蓝牙 / 热点需真机）
3. Signing Team 选自己的开发者账号
4. 运行

## 能力（第一期最小版）

- 首次启动生成 `identity_seed`，派生 X25519 + Ed25519，写入 Keychain
- 同时作 BLE central + peripheral；广播 Service Data 仅 `version || temp_id`（约 3 分钟轮换）
- 公频：Ed25519 签名广播
- 私聊：Noise XX，蓝牙与 TCP 共用会话密钥
- 热点：`_cqchat._tcp` + TCP 帧；失败同一 `msg_id` 退回蓝牙
- 图片压缩（长边 1280 / q≈0.7）+ 缩略图；过大且无热点则「等待」
- 二维码：`cqchat:v1:` + 指纹 hex；扫过显示「已验证」
- 仅本地通知；附近人发现有冷却

## Opus

语音容器为 `CQOP`（见 PROTOCOL）。生产构建请链接 libopus（`ios/Vendor` 可自行加入）。未链接时编码器为开发 stub，**跨端语音需真实 Opus**。

## 协议自检

`CQchat/Resources/v0.1.json` 与 `shared/test-vectors/v0.1.json` 相同，包头编码必须对得上。
