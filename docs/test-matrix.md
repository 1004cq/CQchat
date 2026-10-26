# CQchat 测试矩阵（v0.1）

## 自动化（每次改协议必跑）

| 项 | 位置 | 通过标准 |
|---|---|---|
| 信封编解码向量 | `shared/test-vectors/v0.1.json` | 与参考实现逐字节一致 |
| HKDF / fingerprint | 同上 + Android unit / 参考脚本 | Ed25519 指纹一致 |
| 分片乱序拼回 | Android `PacketCodecTest` + 参考 | 乱序/重复仍还原 |
| Noise XX 握手 + 双向传输 | Android unit；Swift 真机/单测 | 互通密文可解 |
| 重放 msg_id | 单测 | 第二次丢弃 |

```bash
python3 shared/reference/cqpacket.py
# Android
cd android && ./gradlew :app:testDebugUnitTest
```

## 真机互操作（发版前）

设备：≥1 iPhone + ≥1 Android；关蜂窝与 Wi‑Fi 上网（局域网热点测试时按场景开）。

| 场景 | 期望 |
|---|---|
| iOS↔iOS / Android↔Android / 跨端 公频文字 | 可见且验签通过；UI 标公开 |
| 私聊 Noise 文字 | 可解密；未 ACK 不显示已送达 |
| 扫码后 | 「已验证」；未扫「未验证」 |
| 同热点发图 | TCP 优先；失败同 msg_id 退 BLE（若 ≤100KiB） |
| 无热点大图 | `queued` /「等待热点」，不假装已发出 |
| 重复投递 | 接收方不出现双份气泡 |

## 系统状态

| 状态 | iOS | Android |
|---|---|---|
| 前台附近模式 | 发现+收发 | 发现+收发 |
| 切到后台短时 | 不保证；记录是否仍收 | 前台服务下尽量维持 |
| 锁屏 | 扫描降频/合并；不承诺 | 视厂商与电池优化 |
| 杀进程 | 不收、不弹推送 | 不收（无 FCM） |
| 拒蓝牙/定位权限 | 说明+引导；不静默失败 | 同左；`neverForLocation` 需测发现率 |
| 低电量 | 暂停媒体；文字/ACK 优先 | 同左 |

## 指标（记录，不作虚高承诺）

- 发现中位时间
- 单跳送达率、重复包比例
- 排队→delivered P95
- 重连成功率
- BLE/Wi‑Fi 电量抽样
- 测试向量一致率 = 100%

## 后续（非 v0.1 门槛）

多跳 RF（3/5/10 台）、断点续传、fuzz、流量分析评估。
