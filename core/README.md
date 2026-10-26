# Shared core（规划）

目标：协议编解码、加密、分片、去重、重试与消息状态机放在 **一份可测试核心**，Swift / Kotlin 只做系统适配（BLE、生命周期、权限、通知、TCP）。

## 当前

- 规范：`docs/protocol-v0.1.md`
- 参考实现与向量：`shared/reference/`、`shared/test-vectors/`
- 两端仍各有一份协议实现；以向量锁定字节一致性

## 下一步（不阻塞 v0.1 真机）

优先 Rust + UniFFI（或稳定 C ABI）迁入：

```text
core/
  protocol/
  crypto/
  routing/
  storage/
  test-vectors/   # 可与 shared/ 合并
```

原生层：`ios/*/BluetoothAdapter`、`android/*/bluetooth` 只搬运已封好的信封。
