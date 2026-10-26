# CQchat Android

Kotlin · BLE · Keystore · 前台服务

协议权威说明见 [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)。与 iOS 必须字节级一致。

## 打开工程

1. Android Studio 打开 `android/`
2. 真机调试（蓝牙扫描通常需要定位权限）
3. 首次运行会申请蓝牙 / 定位 / 通知 / 相机等权限
4. 后台靠 `MeshForegroundService` 保活扫描与广播

## 协议自检

```bash
./gradlew :app:testDebugUnitTest
```

覆盖：包头向量、分片拼回、HKDF 身份派生、Noise XX 握手与双向加解密。

## 能力（第一期最小版）

与仓库 README / PROTOCOL 对齐：无账号、临时标识轮换、公频 Ed25519、私聊 Noise XX、TCP 与 BLE 共用会话、二维码验证、图片压缩与排队、仅本地通知。
