# GoVPN 5.7：Rust 重写 vs Go 实现性能对比

> **Note:** 本文已合并进 Rust 代码树的三语性能文档：
> [`rust/docs/en/performance.md`](../rust/docs/en/performance.md) ·
> [`rust/docs/zh/performance.md`](../rust/docs/zh/performance.md) ·
> [`rust/docs/ru/performance.md`](../rust/docs/ru/performance.md)。本文保留为原始对比记录。

> 日期：2026-11-25
> 对象：`rust/`（Rust 重写，release） vs `src/cypherpunks.ru/govpn`（Go 5.7 优化版）
> 关联：`docs/performance-optimization.md`（Go 侧优化记录）、`docs/rust-rewrite-design.md`（Rust 设计）

---

## 1. 结论摘要

同一台机器、同一时段、对齐后的基准输入下（中位数，5 次）：

| 类别 | 结果 |
|---|---|
| classic 789B 发送 / 接收 | Rust **快 1.50× / 1.48×** |
| noise MTU 发送 | Rust **快 1.60×** |
| encless / CnW / AONT | Rust **快 1.34×–1.87×** |
| 每包分配 | classic/noise：两边均 **0**；encless 编码 Rust **2** vs Go **5**，解码 **1 vs 1**；AONT **1 vs 3** |

关键发现与修复：

1. **Poly1305 是此前 classic 落后的真正原因**。RustCrypto `poly1305` 0.8 的 AVX2 后端在本机
   Zen3 上存在约 **845 ns/包的固定开销**，且 16B–1500B 全区间都比同 crate 的软件后端慢
   **2.5×–4.5×**（798B：AVX2 1,523 ns vs soft 591 ns）。通过 `rust/.cargo/config.toml`
   固定软件后端后，classic 路径从落后 7%–11% 变为领先 48%–50%。
2. Rust 传输层新增 `encode_into`/`decode_into` 并接入 peer 收发路径，classic/noise 达到
   **0 alloc/packet**，与 Go 优化版一致。
3. AVX2 Salsa20 改为**所有完整 64B 块 + 最后不足 64B 的块都走 SIMD**，去掉标量尾部；
   同时去掉 scratch/output 的冗余清零。classic 编码由此前的 2,575 ns 降到 1,308 ns。

---

## 2. 测试环境与方法

- CPU：AMD Ryzen 5 PRO 5675U（Zen3，AVX2），12 线程
- Go：1.22.2 linux/amd64，`GO111MODULE=off GOPATH=$(pwd)`
- Rust：edition 2021，`cargo build --release`，运行时 AVX2 分派
- 基准：两边均取 **5 次运行的中位数**；Go 用 `-count 5 -benchmem`，Rust 用
  `crypto_bench` / `proto_bench`（内置计数分配器，输出 ns/op、allocs/op、B/op）
- 输入严格对齐 Go 基准（`common.go`：`MTUDefault = 1515`）：

| 场景 | 载荷 |
|---|---|
| classic 789B | 789 B（`peer_test.go testPt`） |
| noise MTU | 1490 B = `MTUDefault-25` |
| encless 128B | 128 B |
| encless MTU | 1506 B = `MTUDefault-9` |
| CnW | 16 B（AONT 头） |
| AONT | 128 B |

> Go 的 classic/noise 基准跑在 `Peer.EthProcess` / `PktProcess` 上（持久 `outT`，0 alloc）；
> Rust 对比表使用同等语义的 **in-place codec**（`encode_into`/`decode_into`，复用缓冲区，
> 0 alloc）。Rust 的 `encode`/`decode` 便捷包装数字列在 §3.2。

复测命令：

```bash
# Go
cd /mnt/app/govpn-5.7
GO111MODULE=off GOPATH=$(pwd) go test -run XXX -bench . -benchmem -count 5 \
  cypherpunks.ru/govpn cypherpunks.ru/govpn/cnw cypherpunks.ru/govpn/aont

# Rust（rust/.cargo/config.toml 会自动固定 Poly1305 软件后端）
cd rust
cargo build --release --examples
for i in 1 2 3 4 5; do ./target/release/examples/crypto_bench; done
for i in 1 2 3 4 5; do ./target/release/examples/proto_bench; done
```

---

## 3. 结果

### 3.1 主对比（Go/Rust > 1 表示 Rust 更快）

| 场景 | Go ns/op | Go allocs | Rust ns/op | Rust allocs | Go/Rust |
|---|---:|---:|---:|---:|---:|
| classic 789B 编码 | 1,967 | 0 | 1,308 | 0 | **1.50×** |
| classic 789B 解码 | 1,979 | 0 | 1,338 | 0 | **1.48×** |
| noise MTU 编码 (1490B) | 3,320 | 0 | 2,070 | 0 | **1.60×** |
| noise MTU 解码 (1490B) | —（Go 无此基准） | — | 2,122 | 0 | — |
| encless 128B 编码 | 13,128 | 5 | 7,023 | 2 | **1.87×** |
| encless 128B 解码 | 10,970 | 1 | 7,040 | 1 | **1.56×** |
| encless MTU 编码 (1506B) | 17,240 | 5 | 9,820 | 2 | **1.76×** |
| encless MTU 解码 (1506B) | 15,257 | 1 | 10,209 | 1 | **1.49×** |
| CnW chaff 16B | 10,410 | 1 | 6,025 | 1 | **1.73×** |
| CnW winnow 16B | 9,845 | 1 | 6,122 | 1 | **1.61×** |
| AONT 128B 编码 | 1,355 | 3 | 910 | 1 | **1.49×** |
| AONT 128B 解码 | 1,312 | 3 | 982 | 1 | **1.34×** |

单核载荷吞吐换算：

| 场景 | Go | Rust |
|---|---:|---:|
| classic 789B 编码 | 401 MB/s | 603 MB/s |
| classic 789B 解码 | 399 MB/s | 590 MB/s |
| noise MTU 编码 | 449 MB/s | 720 MB/s |
| noise MTU 解码 | — | 702 MB/s |
| encless MTU 编码 | 87.4 MB/s | 153.4 MB/s |
| encless MTU 解码 | 98.7 MB/s | 147.5 MB/s |

### 3.2 Rust 便捷 API（每次分配）参考

| 场景 | ns/op | allocs/op | B/op |
|---|---:|---:|---:|
| encode 789 plain | 1,322 | 2 | 1,668 |
| decode 789 plain | 1,424 | 2 | 1,643 |
| encode MTU noise | 2,064 | 2 | 3,070 |
| decode MTU noise | 2,165 | 2 | 3,045 |

与 in-place 路径相差约 1%–6%；生产 peer 路径已改用 in-place，仅 UDP 批处理交接需要
移交所有权（当前 1 alloc/包，见 §5）。

### 3.3 组件计时（classic 789B 分解）

| 组件 | Rust 耗时 | 说明 |
|---|---:|---|
| XTEA 加密/解密 8B | 76.0 / 73.9 ns | 64 轮 + 预计算轮表；与 Go 的 ~87–176 ns 同档或更快 |
| Salsa20 XOR 854B | 574.7 ns | AVX2，全块 + 尾部均 SIMD |
| Salsa20 XOR 1500B | 793.5 ns | 同上 |
| Poly1305 tag 798B（soft） | 590.7 ns | 固定软件后端后 |
| Poly1305 tag 798B（AVX2 旧路径） | 1,523 ns | 已弃用 |
| Poly1305 tag 16B（soft / AVX2） | 24.8 / 845.1 ns | AVX2 固定开销约 845 ns |

76 + 575 + 591 ≈ 1,242 ns，加上约 60 ns 的拷贝/框架处理，与实测 1,308 ns 吻合。

---

## 4. 分析

### 4.1 Rust 领先项

- **CnW（1.61×–1.73×）**：`chaff_into`/`winnow_into` 每 8 字节批量调用 `keystream8_512`，
  用 AVX2 同时算 8 条独立 Salsa20 流（每条 8 个 block），把 Go 版逐字节生成 keystream 的
  成本一次性并行完成；Poly1305 仍使用“一次乘法出两个候选 tag”的常量时间专用公式。
- **encless（1.49×–1.87×）**：收益来自 CnW SIMD 化 + AONT Salsa20 全块 AVX2；编码分配
  5→2，解码 1→1。MTU 解码吞吐 98.7→147.5 MB/s。
- **AONT（1.34×–1.49×）**：AVX2 Salsa20 + 单次分配，Go 为 3 次分配。
- **noise MTU（1.60×）**：1499B 帧几乎全部落在 AVX2 全块路径，且传输层去掉了中间拷贝。

### 4.2 classic 789B：从落后到领先

之前的结论“剩余差距来自 XTEA/Poly1305 后端差异”被组件计时证实，但具体原因不是指令集
本身，而是 **RustCrypto poly1305 0.8 的 AVX2 后端在该 Zen3 机器上异常慢**：

| 消息长度 | AVX2 后端 | 软件后端 |
|---:|---:|---:|
| 16 B | 845 ns | 25 ns |
| 64 B | 1,211 ns | 60 ns |
| 256 B | 1,310 ns | 198 ns |
| 798 B | 1,523 ns | 591 ns |
| 1,500 B | 1,813 ns | 1,099 ns |

AVX2 路径有约 845 ns 的固定开销，并在所有尺寸上都慢于软件后端（该后端本身是常量时间的）。
`rust/.cargo/config.toml` 通过 `--cfg poly1305_force_soft` 固定软件后端；Go 向量测试确认
字节级结果不变。此前 classic 编码中 Poly1305 约占 1.5 µs，是 2.1 µs 总耗时的主要部分。

其余两项修复：

- **Salsa20 尾部**：此前只对 512B 整数倍用 AVX2，789B 包有 342B 走标量。现改为所有完整
  64B 块用 AVX2，并对最后不足 64B 的块再做一次 AVX2 核心调用、只异或所需字节，彻底去掉
  标量尾部。
- **清零与拷贝**：编码/解码只清零 64B Salsa scratch，frame/output 区域直接写入；去掉整块
  `resize(..., 0)` 的冗余 memset。

结果：classic 编码 2,575 → 1,308 ns（约 2×），解码 2,233 → 1,338 ns。

### 4.3 本轮同时落地的改动

- `rust/.cargo/config.toml`：固定 Poly1305 软件后端（含 `--check-cfg` 声明）。
- `govpn-proto`：新增 `Session/Encoder/Decoder::encode_into`、`decode_into`；便捷
  `encode`/`decode` 委托给它们，Go 向量测试逐字节保持通过；新增 dirty-buffer 复用的
  in-place 等价性测试。
- `govpn-net`：UDP/TCP 收发复用 `payload`/`scratch`/`wire` 缓冲区，去掉接收侧 `to_vec()`。
- `govpn-crypto`：AVX2 Salsa20 全块 + 尾部 SIMD；CnW 批处理保持不变。

---

## 5. 遗留项与备注

- `.cargo/config.toml` 的 `build.rustflags` 会被环境变量 `RUSTFLAGS` 覆盖；若复测时手动
  设置了 `RUSTFLAGS`，需自行加上 `--cfg poly1305_force_soft`，否则会回到慢速 AVX2 路径。
- Poly1305 软件后端约 12 ns/16B 块；若追求极致，可进一步实现多包/4 路 SIMD Poly1305，
  预计还能再省 200–300 ns/包，但需新增常量时间实现与差分测试，当前未做。
- 共享环境单次波动可达 ±20%，本文均为同批次 5 次中位数；Go 旧文档（早些时候）的数字比
  本次快约 10%–15%，不能与本次直接混用。
- Go 没有 noise MTU 解码基准，故该项只报 Rust。
- 生产服务端 UDP 发送经共享 `sendmmsg` batcher 移交所有权，当前 1 alloc/包；如需与 Go 的
  0 alloc 完全对齐，可加 buffer pool 回收（预计收益 <100 ns/包）。
- io_uring / `recvmmsg`/`sendmmsg` 的端到端 pps 未纳入本表：本环境无 `CAP_NET_ADMIN`，
  无法创建 TAP；相关单元测试（loopback mmsg、socketpair io_uring）已覆盖正确性。