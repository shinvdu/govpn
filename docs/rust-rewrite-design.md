# GoVPN → Rust 重写技术设计

> 目标版本：GoVPN 5.7（GPLv3+）
> 文档状态：Draft v0.1（2026-11-25）
> 适用范围：Linux 数据面重写；FreeBSD 作为第二阶段
> 评审重点：协议兼容边界、encless 性能方案、数据面架构、"待确认决策"

---

## 0. 结论先行

1. **GoVPN 是什么**：一个 Go 写的自研协议 VPN 守护进程（PAKE 握手 + Salsa20/Poly1305 传输 + 可选 encless 无加密模式），代码约 3.7k 行，GOPATH 时代工程，依赖 6 个 submodule。
2. **当前性能的真正瓶颈**，按影响排序：
   - **encless 模式是算法级瓶颈**：每包 256 次 Chaff Poly1305 + 512 次 Winnow Poly1305 调用，单核解码 75.6 µs/包（20 MB/s payload）。用"1 字节 Poly1305 专用公式 + SIMD 批量化"可提升 **10–20 倍**（Go 标量版已实现 5.44×，见 §0.5），这是全项目最大的单项收益。
   - **经典模式的瓶颈不在密码算法，而在每包固定开销**：每包 1 次堆分配、整块缓冲区清零（CPU profile 占 11.5%）、176 ns XTEA、每包 goroutine + channel、全局 RWMutex、字符串键 map 查找、每包 2–4 次 syscall（大部分已在 §0.5 修复）。单核加密吞吐虽达 ~3 Gbps，端到端会被上述开销拉低。
   - **UDP 服务端"一包一 goroutine"**（`cmd/govpn-server/udp.go`）是 pps 扩展性的头号结构性问题，缓冲区池又被绑定为"每 peer 2 个缓冲区"，天然限制并发（已修复，见 §0.5）。
3. **Rust 的收益主要来自架构，而不是"Rust 比 Go 快"**：零分配热路径、批处理 I/O（recvmmsg/sendmmsg/io_uring）、SO_REUSEPORT 分片、位图重放窗口、定时器轮、以及 encless 的 SIMD 专用实现。经典模式单核预计 **1.5–2.5×**，端到端 pps 预计 **2–4×**；encless 预计 **10–20×**。
4. **建议的落地路径**：先保证与 GoVPN 5.7 的**字节级互通**（wire-compatible），用 Go 版本作为 oracle 做差分测试；分 6 个里程碑，约 20–30 人周。
5. **MTU 兼容坑**：noise 模式有效载荷上限是 `MTU-25`，encless 是 `MTU-9`；原实现只校验 `MTU-1`，超限帧会被截断/丢弃。已在 Go 侧按模式校验并显式拒绝（§0.5）；Rust 需保持同样行为并覆盖边界测试。

---

## 0.5 Go 侧已落地优化（2026-11-25 复测）

Rust 重写暂缓。下列问题已在当前 Go 代码中修复，作为 Rust 版的行为基线与性能对照。完整的方法、推导、验证与复现步骤见 **[`docs/performance-optimization.md`](performance-optimization.md)**。

### 已实施

| 类别 | 改动 | 验证 |
|---|---|---|
| cnw | 1 字节 Poly1305 专用公式（`tags1`，一次 130-bit 乘法得两个 tag）+ 每包只算一次 HSalsa20；`ChaffInto`/`WinnowInto` | `cnw_opt_test.go`：5,000 随机 key 与 `poly1305.Sum` 一致；Chaff/Winnow 输出与旧实现逐字节一致 |
| encless | 用 `ChaffInto`/`WinnowInto`、`aont.DecodeParts` 去掉中间切片、append 与拷贝 | 现有往返/握手测试 + 新增 `TestDecodeParts` |
| peer 热路径 | 去掉每包 `append` 分配（persistent `outT`）；只清零 32B keystream 头；只按模式清零 padding；重放窗口由 2×map 改为 257-bit 位图 | 新增 `TestNonceWindow`、`TestMaxPayload`、`TestEthProcessRejectsOversized`；Enc/Dec 0 alloc |
| MTU 语义 | `maxPayload()`：plain `MTU-1`、noise `MTU-25`、encless `MTU-9`；超限明确拒绝并记录，不再静默截断 | 边界测试覆盖 1490/1491、1506/1507 |
| UDP 服务端 | 固定 `GOMAXPROCS` 个 reader 内联处理数据包（移除每包 goroutine、移除每 peer 2 缓冲区限制）；`netip.AddrPort` 键；每 reader 256 槽流缓存 + generation 失效；握手分流到 4 个 worker（同地址同 worker，队列有界） | 本机 UDP 真实回归：handshake → 5 包 `FramesIn=5`、`FramesUnauth=0` |
| 身份缓存 | 改为切片顺序扫描，避免 map 遍历；握手路径已移出数据面 | 现有握手测试 + 真实回归 |
| TAP | 读取错误不再 panic 整个进程；退避重试，同一错误只记录一次，peer 状态保持有效 | 回归中 `not pollable` 场景下服务保持可用且数据面鉴权成功 |
| TCP | `netip` 键、`terminate()` 非阻塞终止、会话结束停止 peer goroutine | 本机 TCP 真实回归：`FramesIn=5`、`FramesUnauth=0` |
| 健壮性 | 队列/握手状态有界；线程终止不再依赖无缓冲 channel 发送 | 交叉回归 |

### 复测数据（同机，`-count=3` 中位数）

| 场景 | 优化前 | 优化后 | 提升 |
|---|---:|---:|---:|
| 经典 789B 加密 | 2,805 ns | 1,827 ns | 1.54× |
| 经典 789B 解密 | 2,068 ns | 1,827 ns | 1.13× |
| 经典 noise MTU 加密 | 4,217 ns / 359 MB/s | 3,040 ns / 490 MB/s | 1.39× |
| encless 128B 编码 | 32,817 ns | 11,232 ns | 2.92× |
| encless 128B 解码 | 54,688 ns | 9,964 ns | 5.49× |
| encless MTU 编码 | 42,288 ns / 35.8 MB/s | 15,326 ns / 98.3 MB/s | 2.76× |
| encless MTU 解码 | 75,593 ns / 20.0 MB/s | 13,889 ns / 108.8 MB/s | 5.44× |
| cnw Chaff（16B） | 41,097 ns | 9,235 ns | 4.45× |
| cnw Winnow（16B） | 58,928 ns | 8,769 ns | 6.72× |
| 每包分配（经典 / encless 解码） | 1 / 5 | 0 / 1 | — |

CPU profile 变化：`SliceZero` 从 11.5% 降到 ~1.4%（只剩少量 `memclr`）；`tags1` + `subP` 合计约 9.2%；最高热点重新变为 Salsa20（46%）与 Poly1305（22%）。

### 仍在 Go 侧保留、留待 Rust

- `recvmmsg`/`sendmmsg`/io_uring 批量、GSO/GRO、零拷贝：Go 标准库无可用接口，改造成本与风险高。
- 每 peer 一个 ticker：Go runtime timer 本身是堆实现，10k 级别的 15s 心跳不是数据面热点；未改。
- TCP 的"搜索期望 nonce 密文 + memmove"：由协议定界方式决定，改成环形缓冲区需要改动 TCP 状态机，风险高，暂留。
- encless 的 SIMD 批量化：Go 版已用标量专用公式拿到 4–7×，仍有 5–10× 的 SIMD 空间留给 Rust。
- XTEA：独立复测约 87–176 ns（随负载波动），手写展开版无显著收益，未改动。

---

## 1. 项目现状

### 1.1 组成

| 组件 | 位置 | 职责 |
|---|---|---|
| 协议核心 | `src/cypherpunks.ru/govpn/` | 握手 `handshake.go`、传输 `peer.go`、非重放窗口、encless `encless.go`、AONT/Chaff `aont/`、`cnw/`、身份缓存 `identity.go` |
| 服务端 | `cmd/govpn-server/` | UDP/TCP/HTTP proxy 监听、握手分发、peer 表、配置热加载、统计 |
| 客户端 | `cmd/govpn-client/` | UDP/TCP/HTTP proxy 客户端、重握手、心跳 |
| verifier | `cmd/govpn-verifier/` | Argon2d 生成口令验证令牌 |
| TAP | `tap.go` + `water` 库 | `/dev/net/tun` + `IFF_TAP | IFF_NO_PI`，每个 peer 一个设备 |
| 外部依赖 | `src/github.com/*`、`src/golang.org/x/crypto` | ed25519、water、blake2b、go-yaml、argon2、x/crypto |

### 1.2 协议要素（重写必须锁死）

- **握手**：PAKE DH A-EKE，4 条消息；使用 extra25519（Elligator 代表元编码 + X25519）、Ed25519 签名、BLAKE2b-256、Salsa20/XSalsa20、XTEA；消息末尾 8 字节 `IDtag = XTEA(PeerId, 首 8 字节明文 ⊕ timesync)`。
- **传输**：`TAG(16) || CIPHERTEXT(PAYLOAD||PAD(0x80)||ZEROS) || PRP(SERIAL)(8)`。
  - 密钥流前 32 字节作 Poly1305 one-time key，`[32,64)` 丢弃，从第 64 字节开始加密载荷。
  - `PRP` = **XTEA**（大端块），key = Salsa20(KEY, nonce=0) 的前 128 bit；序列号 client 奇、server 偶，步长 2，初值 0/1，接收期望 2/3。
  - Salsa20 的 nonce 是**加密后的序列号密文**（不是明文 serial）。
- **encless**：`ENCODED || PRP(SERIAL)`；`ENCLESS = CnW(AONT(payload))`，固定膨胀 **4128 字节**（AONT 头 48 + CnW 4096）；CnW 使用 XSalsa20（24 字节 nonce）派生 32 字节 MAC key；强制 noise。
- **噪声**：所有出站包填充到配置 MTU；**注意：noise 模式下实际有效载荷上限是 `MTU-25`，而 `EthProcess` 只校验 `len(data) ≤ MTU-1`，超出部分会被截断/丢弃**（见 §3.9，需互通测试确认，Rust 侧要按原语义并加断言）。
- **不重放**：UDP 用两个 128 项的 map 做滑动窗口；TCP 用期望值精确匹配 + 在字节流中搜索"期望 nonce 密文"定界。
- **verifier**：`$argon2d$m=...,t=...,p=...$base64(id)[$base64(pub)]`，Argon2d **v1.3**，默认 `m=4096 KiB, t=128, p=1`，输出 32 字节直接作为 Ed25519 seed。
- **重协商**：客户端累计字节数超过 `4 GiB` 触发；服务端不主动发起。超时（默认 60s，心跳为 timeout/4）删除 peer；CPR 模式下 timeout 等于发包周期。
- **encless 客户端仅允许 TCP**（`cmd/govpn-client/main.go:92`）。

> Go 文档（`doc/handshake.texi`）与代码存在少量出入时，**以代码为准**，并通过 oracle 生成黄金向量固化。

---

## 2. 实测性能基线（优化前）

> 本节保留 2026-11-25 优化前的原始基线，用于对比；优化后的复测见 §0.5。

测试环境：AMD Ryzen 5 PRO 5675U（Zen3，AVX2 可用），Go 1.22.2 linux/amd64，`-benchmem`，GOPATH 模式编译。数据为**单线程、纯内存/密码学路径**，不含 TAP 与真实网卡。

### 2.1 数据面基准

| 场景 | 输入/包 | ns/op | 吞吐（payload） | 分配 |
|---|---:|---:|---:|---:|
| `BenchmarkEnc`（经典，非 noise） | 789 B | 2,805 | 281 MB/s | 1 alloc / 896 B |
| `BenchmarkDec`（经典，非 noise） | 789 B | 2,068 | 381 MB/s | 3 allocs / 200 B* |
| `BenchmarkEncNoiseMTU`（经典 noise） | 1,514 B | 4,217 | 359 MB/s | 1 alloc / 1,536 B |
| `BenchmarkEnclessEncodeMTU` | 1,514 B | 42,288 | **35.8 MB/s** | 6 allocs / 12,880 B |
| `BenchmarkEnclessDecodeMTU` | 1,514 B | 75,593 | **20.0 MB/s** | 5 allocs / 3,664 B |
| `BenchmarkEnclessEncode` | 128 B | 32,817 | — | 6 allocs / 9,728 B |
| `BenchmarkEnclessDecode` | 128 B | 54,688 | — | 5 allocs / 416 B |
| `BenchmarkChaff` | 16 B | 39,828 | — | 1 alloc / 4,096 B |
| `BenchmarkWinnow` | 16 B | 59,609 | — | 1 alloc / 16 B |
| `BenchmarkNonceCipher`（XTEA） | 8 B | **176.2** | — | 0 |

\* `BenchmarkDec` 的 3 次分配主要来自基准本身每轮重建 map；稳态下每 128 包重建一次非重放窗口 map。

换算成包率与线速：

| 场景 | pps/核 | payload 吞吐 | 线速（含膨胀） |
|---|---:|---:|---:|
| 经典 789 B 加密 | 356k | 281 MB/s | 290 MB/s |
| 经典 789 B 解密 | 484k | 381 MB/s | 394 MB/s |
| 经典 noise MTU 加密 | 237k | 359 MB/s | 363 MB/s |
| encless MTU 加密 | 23.7k | 35.8 MB/s | **133 MB/s** |
| encless MTU 解密 | 13.2k | 20.0 MB/s | **74.6 MB/s** |

> encless 每包在线上约 **5,642 字节**（1,514 载荷 + 4,128 膨胀），因此线速仍高于 payload 吞吐，但包率被 CnW 锁死。

### 2.2 CPU / 分配 profile（全部基准聚合）

| 热点 | 占比 |
|---|---:|
| `poly1305.poly1305` | 41.6% |
| `salsa20/salsa.salsa2020XORKeyStream` | 26.5% |
| **`govpn.SliceZero`** | **11.5%** |
| `subtle.ConstantTimeCompare` | 3.0% |
| `cnw.zero` | 2.4% |
| XTEA encrypt/decrypt | 2.4% |
| `runtime.mallocgc` | 4.2% |

| 分配点 | 占比 |
|---|---:|
| `Peer.EthProcess`（`append(tagT, frameT...)`，每包 1 次） | 44.4% |
| `EnclessEncode` | 42.3% |
| `cnw.Chaff` | 17.7% |
| `Peer.PktProcess` | 6.1% |

### 2.3 每包固定成本微基准（同机，供量级参考）

| 项目 | 成本 |
|---|---:|
| goroutine + channel 交接 | **233 ns** |
| 纯 channel send+recv | 224 ns |
| `getrandom(8B)` | 601 ns |
| `write(/dev/null, 1500B)` | 508 ns |
| pipe `write+read(1500B)` | 1,330 ns |
| C `sendto+recvfrom(1500B, loopback)` | 5,876 ns/包 |
| C `sendmmsg/recvmmsg(64, loopback)` | 5,427 ns/包 |
| `memcpy(1500B)` | 26 ns |
| `getpid` | 354 ns |

> 该环境 syscall 偏慢（`getpid` 354 ns），loopback 受虚拟化/共享 CPU 影响，**绝对数值不可外推**；但"每包 goroutine ≈ 200–400 ns""每包至少 3–4 次 syscall""批处理在纯 syscall 受限场景才有明显收益"这三个结论是稳定的。

### 2.4 成本结构解读

- 经典模式：密码学本身已由汇编实现，微基准单核 ~3 Gbps 量级；聚合 profile（含 encless 样本）中 Poly1305 + Salsa20 占 ~68%，说明**非密码开销（清零、分配、锁、调度）在总成本中占比可观**。Rust 侧重点应是"把非密码开销压到接近 0"，密码学争取 1.2–2×（RustCrypto AVX2）或持平。
- encless：**算法占绝对主导**。Winnow 每包进行 512 次 1 字节 Poly1305 调用（256 个 one-time key × 2 个候选 tag），完全不适合通用 Poly1305 实现；这是可被专用公式 + SIMD 大幅优化的典型场景。
- `SliceZero` 11.5%：每发一包把整个 `bufT`（经典 3 KB、encless 5.7 KB）清零，纯浪费；只是为了让 noise 填充的尾部为零。Rust 侧只需写需要的填充区，且非 noise 模式完全不需要。
- `getrandom` 601 ns/次：encless 每包调用 `Rand.Read` 取 128-bit `r`（`encless.go:39`），约占包处理 0.8–1.5%，可换用户态 CSPRNG。

---

## 3. 性能瓶颈与可提升点

> 以下为优化前分析。标【已修复】的条目已在 Go 侧落地（§0.5）；标【保留】的条目留待 Rust 或后续评估。

### 3.1 每包堆分配 / GC（经典 1 次、encless 6 次）【已修复】

- `peer.go:283` `out = append(p.tagT[:], p.frameT...)`：`tagT` 是长度 16、容量 16 的数组切片，`append` 必分配。每包 1,536–5,642 字节。应改为"在发送缓冲区预留 tag 头空间，就地写"。
- `peer.go:308/339/340`、`encless.go:36-51`、`cnw.go:65-67` 等大量 `make`/`append`。
- 影响：GC 压力、CPU 4.2%、cache 抖动、尾延迟。**目标：稳态零分配。**

### 3.2 全缓冲区清零（CPU 11.5%）【已修复】

- `peer.go:231` 每包 `SliceZero(p.bufT)`；`peer.go:322-324` 每包清 32 字节 Salsa 前缀；`cnw.go:94/146` 每字节清 512 B keys。
- 优化：只在 noise 模式写零到尾，或把填充区长度显式记录；非 noise 模式不需要清零；密钥材料用 `zeroize` 在生命周期末尾处理，而不是每包。

### 3.3 UDP 服务端一包一 goroutine + 受限缓冲区池【已修复】

- `cmd/govpn-server/udp.go:82`：`go func(...) { peer.PktProcess(...); udpBufs <- buf }`。
- 每包成本：goroutine 创建/调度 + channel 收发 ≈ 400–700 ns，外加栈对象。高 pps 时调度器成为瓶颈，goroutine 数量随 in-flight 包增长。
- 缓冲区池 `udpBufs`（容量 256）实际只投放 1 + 2×会话数个缓冲区（`udp.go:53,106-108`），**每个 peer 最多 2 个 in-flight 包**，且 `PktProcess` 内的 `tap.Write` 同步阻塞占用缓冲区。
- 优化：固定 worker 池 + 每 worker 无锁环形队列；每 peer 有界发送队列；TAP 写完成后归还 slot；不 spawn。

### 3.4 每包字符串/对象分配 + 全局锁【已修复】

- `udp.go:74` `addr = raddr.String()` 每包构造字符串；`ReadFromUDP` 每包分配 `*net.UDPAddr`。
- `udp.go:76-78` 每包 `peersLock.RLock()` + 字符串键 map 查找；`go func` 内部不再加锁但钱包依赖地址稳定。
- `identity.go:103,105` 每次身份查找在 `RWMutex` 下遍历全部 peer 的 XTEA，且 map 遍历顺序随机；10k peer 时握手扫描成本 O(N)，也是 DoS 面。
- 优化：直接解析 `sockaddr`，用 `SocketAddr`（Copy、栈上）做 key；worker 内用 `hashbrown`/开放寻址表；会话表分片；身份扫描改为 `Vec<Entry>` + 批量 XTEA / 速率限制。

### 3.5 非重放窗口用 map（每包两次查找 + 插入）【已修复】

- `peer.go:353-365`：两个 `map[uint64]struct{}`，每包最多 2 次查找 + 1 次插入，每 128 包重建一个 map（分配）。
- 优化：256 位滑动窗口（4×`u64` bitmask 或 `[4]u64`），O(1)、无分配、cache 友好；语义保持不变。预计节省 30–60 ns/包（经典模式 ~2–3%）。

### 3.6 XTEA 每包 176 ns【评估后未改】

- `peer.go:255-260`：每包一次 XTEA（8 字节块，32 轮）。
- 优化：
  - 标量重写（展开、无 bounds check）预计 30–60 ns；
  - **预计算**：序列号严格递增（步长 2），可后台批量预生成未来 N 个 nonce 密文（SIMD 4/8 路 bitslice），热路径只取表；
  - 接收侧配合 recvmmsg 批处理也可批量解密。
- 预计节省 4–8% 经典模式成本。

### 3.7 锁与同步粒度【部分修复】

- `Peer.BusyT/BusyR` 每包加锁；`EthProcess` 在持锁期间执行 `Conn.Write`，**CPR 模式下还会 `time.Sleep` 持锁**（`peer.go:287-293`），TAP 读取方被拖住。
- 服务端 UDP 路径每包两次全局 RLock；统计、超时扫描在全局锁下遍历（`cmd/govpn-server/main.go:117-140`）。
- 优化：peer 状态单 owner（worker 独占），无锁；CPR 用 token bucket + 定时器，不 sleep；超时用定时器轮；统计用 per-worker 原子计数，查询时聚合。

### 3.8 Syscall 与 I/O 模型【保留给 Rust】

- 每包路径：`recvfrom` + `sendto`（UDP）、TAP `read` + `write`，4 次 syscall/包；TCP 路径同理。
- Go 侧无 `recvmmsg`/`sendmmsg`，无法批量；netpoller 的 goroutine park/wake 进一步放大接收侧成本。
- 优化：
  - `recvmmsg`/`sendmmsg` 批量（32–64）；
  - io_uring 多 shot recv + provided buffers（Linux 5.19+），发送侧 io_uring/sendmmsg；
  - TAP 读写走 io_uring；
  - noise 模式等长包可用 UDP GSO（`UDP_SEGMENT`）减少发送 syscall。
- 注意：在 loopback 微基准里批处理只提升 8%，说明 **批处理收益依赖真实网卡/NIC 队列和 syscall 成本**，必须在目标硬件上验收，不能拿本机数字承诺。

### 3.9 noise/encless 的 MTU 语义与潜在缺陷【已修复校验】

- noise 经典：`frameT` 长度 `MTU-16`，末 8 字节写 nonce → 有效载荷上限 `MTU-24-1 = MTU-25`（默认 MTU=1515 → **1,490**）；而 `EthProcess` 只拒绝 `> MTU-1`（1,514）。
- 结果：1,491–1,514 字节的以太帧在 noise 模式会被截断/对端丢弃（接收端找不到 pad 字节）。encless 类似：`frameT = MTU`，末 8 字节被 nonce 覆盖，pad 必须落在此之前 → 有效载荷上限 `MTU-9`（默认 1,506）。
- 已在 Go 侧落地：`Peer.maxPayload()` 按模式返回 `MTU-1` / `MTU-25` / `MTU-9`，超限包明确拒绝并记录，不再静默截断；`TestMaxPayload` 与边界测试覆盖。
- Rust 侧仍需保持同样的字节行为与校验；边界互通测试覆盖 1,490/1,491、1,506/1,507。

### 3.10 TCP 帧解析【保留】

- `cmd/govpn-server/tcp.go:174`：每包在缓冲区里 `bytes.Index` 搜索 8 字节"期望 nonce 密文"；之后 `copy` 把剩余数据移到头部（`:186`），每包一次 memmove。
- 非密码开销不大，但在高吞吐 TCP 下 O(n²) 风险（一次 read 包含大量小包时反复搬移）。
- 优化：环形缓冲区 + `memchr::memmem`；或按协议约束直接按长度解析；保持"搜索 nonce 定界 + MAC 失败即断连"的原语义。

### 3.11 定时器 / 心跳扩展性【评估后未改】

- 每 peer 一个 `time.Ticker` + `select`（`cmd/govpn-server/common.go:50-67`）；10k peer 即有 10k 定时器与 goroutine，超时扫描又是 O(N) 加全局锁。
- 优化：单定时器轮（hierarchical timing wheel，quinn 式），100 ms/1 s 粒度；心跳、CPR、超时、重协商统一调度。

### 3.12 其他

- `stats.go:40-64`：串行 accept，一次只服务一个连接；非热路径，但建议改成并发 + 读超时。
- `tap.go:45-65`：单 reader goroutine + 阻塞 channel，每包一次上下文切换；Rust 侧 TAP FD 由 worker 独占、io_uring 读。
- `encless.go:39` 每包 `getrandom`：换用户态 CSPRNG（ChaCha20 DRBG，进程启动时 `getrandom` 播种）。
- `handshake.go:104-109` 生成 DH 时循环重试 Elligator 编码；握手路径，可接受。
- 服务端 Argon2 不参与在线握手（只在生成 verifier 时用），握手 CPU 主要是 X25519 + Ed25519 验证。

---

## 4. 重写目标与非目标

### 4.1 目标

| 类别 | 目标 |
|---|---|
| 兼容性 | 与 GoVPN 5.7 **wire-compatible**；`govpn-client` / `govpn-server` / `govpn-verifier` 可直接替换任意一端 |
| 配置/运维 | `peers.yaml`、verifier 字符串、CLI 参数/默认值、stats JSON、up/down 脚本环境变量、HTTP proxy、EGD 行为一致 |
| 性能（验收目标，待硬件确认） | 经典模式：单核 ≥500k pps（1,514B，端到端含 TAP）、≥600 MB/s payload；4 核 ≥5 Gbps。encless：单核 ≥150 MB/s payload（≥7.5× 基线），目标 300+ MB/s |
| 延迟 | 批处理引入的额外 p99 ≤200 µs（批大小/等待时间可配） |
| 资源 | 10k peer RSS：经典 ≤128 MB，encless ≤384 MB（16 KiB slot 下每 peer 至多 1 个 TAP 读缓冲）；稳态零分配；无 GC 停顿 |
| 安全 | 恒定时间密码学、密钥 zeroize、内存/队列有界、fuzz 覆盖所有外部输入、供应链可审计 |
| 代码 | 核心 crate `#![forbid(unsafe_code)]`；`unsafe` 仅限审计过的 SIMD/io_uring 模块 |

### 4.2 非目标（首版）

- 不引入协议 v2 / 新握手（可在 M6 之后独立提案）。
- 不做 Windows/macOS；FreeBSD 放到 M5。
- 不做 GUI、不做多路复用/负载均衡控制面、不做 IPv6 之外的地址族扩展。
- 不改变密码学算法（Salsa20/Poly1305/XTEA/Ed25519/X25519/BLAKE2b/Argon2d），否则失去互通。

---

## 5. 总体架构

```
┌──────────────────────────── 控制面（tokio 运行时） ────────────────────────────┐
│ 配置热加载(arc-swap) │ verifier/身份表 │ 信号/子进程 │ stats HTTP │ TCP 会话任务 │
│                     握手任务（可调度到 blocking 池）                          │
└───────────────┬───────────────────────────────────────────┬──────────────────┘
                │ 控制消息（有界 SPSC/MPSC）                 │ 会话创建/销毁
┌───────────────▼───────────────────────────────────────────▼──────────────────┐
│                        数据面：N × thread-per-core worker                      │
│  每个 worker：                                                                 │
│    - 1 个 UDP socket（SO_REUSEPORT）                                           │
│    - 若干 TAP fd（服务端每 peer 一个；客户端一个）                             │
│    - io_uring（epoll+recvmmsg 回退）                                           │
│    - 本分片 peer 表（无锁、单 owner）、缓冲区池、发送批、定时器轮              │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 运行时选型

- **控制面**：`tokio`（成熟、生态好），负责 TCP 会话、握手调度、配置、信号、脚本、stats。
- **数据面**：不跑 tokio task-per-packet；**每核一个 worker**，`io_uring` + provided buffers（首选），`epoll + recvmmsg` 作为可移植回退。候选运行时：
  - 自研 epoll/uring 事件循环（可控、可审计，推荐给 UDP/TAP 这一小块）；
  - 或 `monoio` / `compio`（thread-per-core io_uring 运行时），减少自研量，但引入依赖与审计面。
- **分片**：`SO_REUSEPORT` + 每 worker 一个 UDP socket，内核按 4 元组散列，天然把同一 peer 的包送到同一 worker；worker 独占 peer 状态，无锁。
  - 重握手换了源端口 → 可能落到别的 worker：按"新会话"处理，旧会话通过控制面的 session directory 通知结束。这与 Go 行为（按地址建新 peer、按 PeerId 顶掉旧 peer）一致。
- **为什么不用 tokio 单运行时跑数据面**：每包 waker/park 成本接近 goroutine/channel；批处理需要自己管缓冲区生命周期，async 抽象反而复杂。

### 5.2 关键不变量

1. 一个 peer 在任一时刻只属于一个 worker；peer 状态无共享可变别名。
2. 热路径（收包、发包、加解密、重放窗口）**零堆分配**；缓冲区以 slot index 传递，所有权显式。
3. 所有队列有界；过载时**丢包**（VPN 语义允许）或对 TCP 施加反压，绝不无界增长。
4. 密码学模块不依赖 async/IO；可单独做差分测试与 fuzz。
5. 任何 `unsafe` 只在 `govpn-simd`（及 io_uring 封装）中出现，并有 safety 注释与 Miri/ASan/TSan 覆盖。

---

## 6. 数据面热路径设计

### 6.1 缓冲区与报文布局

- 固定 slot 大小按 MTU 分档：`2 KiB`（经典 ≤1.5k）、`16 KiB`（jumbo + encless 最大 13,143）。每 slot 前缀预留 **`HEADROOM = 64`** 字节（tag 16 + nonce 8 + 对齐余量），尾部预留 64 字节。
- `PacketBuf { slot_idx: u32, len: u16 }`，`Pool` 为每 worker 的 slab + 空闲链表（`Vec<u32>`），不跨 worker 共享。
- TAP 直接读进 slot 的 payload 区 → 原地加密 → 在前面写 tag → 发送；接收路径反向。**全程一次 copy 都不做额外拷贝**（Go 已做到从 TAP 到内部缓冲一次 copy，Rust 直接省掉）。

### 6.2 发送（TAP → 网络）

1. 从 TAP 读一帧到 slot（io_uring read / 非阻塞 read）。
2. 校验长度（noise/encless 的有效上限，见 §3.9），写 `0x80` pad，noise 模式补零到目标长度。
3. serial = 本地计数（+2），`nonce_ct = XTEA_PRP(serial)`（可预计算表）。
4. Salsa20：keystream[0..32] = auth key；keystream[64..] XOR payload；tag = Poly1305(auth key, ciphertext||nonce_ct)。
5. 在 slot 头部写 tag，尾部写 nonce；提交 `sendmmsg`（同 worker 同 socket 聚合）或 io_uring send。
6. `BytesOut/FramesOut` 原子计数；完成后归还 slot。
7. **批处理**：每 worker 积累到 32–64 包或 100 µs 截止即 flush。noise 模式可用 GSO 进一步合并。

### 6.3 接收（网络 → TAP）

1. `recvmmsg` / io_uring multishot recv 批量拿包（provided buffers）。
2. 每包：`addr`（栈上 `SocketAddr`）→ worker 本地表的 peer。
3. Salsa20 前 64 字节 keystream：`[0..32)` auth key；Poly1305 验证 `ciphertext||nonce_ct`；失败计数并丢包。
4. 验证通过后解密 payload，查找最后一个 `0x80` 并校验其后全零；得到以太帧长度。
5. 经 XTEA 解出 serial，更新滑动窗口（位图）；重复/过期即丢。
6. TAP 写（io_uring write），完成后归还 slot；`HeartbeatRecv/BytesIn/...` 更新。
7. **批处理**：TAP 写也批量提交；每 worker 的 io_uring 完成队列统一回收 buffer。

### 6.4 重放窗口（位图）

```
window: [u64; 4]  // 256 个 serial 槽位（serial 步长 2，实际映射 serial>>1）
latest: u64
```
- 收到 serial：若 `< latest - 255` → 丢；否则置位；若已置位 → 丢。
- 语义与 Go 的两个 128 map 等价（Go 的窗口 = `2*NonceBucketSize = 256` 个 nonce 值）。
- 内存 32 字节，无分配、无哈希。

### 6.5 CPR / 心跳 / 重协商

- 统一定时器轮：每 entry 记录 `next_deadline`、`kind`（心跳 / CPR / 超时 / 重协商）。
- CPR：token bucket，按 `CPR*1024/MTU` 包/秒补充；到期发送心跳或排队载荷；**不 sleep**，由 worker 的定时事件驱动。
- 心跳：`LastSent + timeout`；`EthProcess(nil)` 等价逻辑保留（发送 1 字节 pad → 空载荷包）。
- 4 GiB 重协商：客户端发送计数触发；服务端沿用"重新握手、按 PeerId 顶掉旧会话"的行为。
- 10k peer 定时器：分层轮（spokes 64/256/…），O(1) 插入/删除。

### 6.6 TCP 与 HTTP proxy

- tokio task/连接；读缓冲 32–64 KiB，解析"期望 nonce 密文"用 `memchr::memmem`；避免每包 memmove（环形缓冲）。
- 握手期间固定大小消息；保持 Go 的"握手完成后丢弃多余字节"行为（互通测试覆盖）。
- HTTP proxy 服务端：接受 CONNECT，回 `HTTP/1.0 200 OK\n\n`，hijack 后进入同一 TCP 会话状态机；客户端：CONNECT + Basic auth，读响应后进入。
- TCP 一个连接就是一个 peer；TAP fd 在该会话生命周期内由该 task 持有。

---

## 7. 密码学模块

### 7.1 算法与 crate 选型

| 算法/用途 | 建议实现 | 说明 |
|---|---|---|
| Salsa20（8B nonce）/ XSalsa20（24B nonce） | RustCrypto `salsa20`（`Salsa20` / `XSalsa20`）或自研 AVX2 | 先基准；若低于 Go asm，则自研多块 AVX2 |
| Poly1305 | RustCrypto `poly1305`（AVX2 后端） | 经典模式单消息；cnw 另行专用实现 |
| XTEA（PRP） | 自研（~60 行，块内大端 u32，**必须与 Go 的字节序一致**） | 标量展开 + 可选 bitslice 批量 |
| BLAKE2b-256 | `blake2b_simd`（AVX2/SSE）或 RustCrypto `blake2` | 用 RFC 7693 向量与 Go 差分 |
| Argon2d v1.3 | RustCrypto `argon2` | `m_cost=KiB(M), t_cost=T, p_cost=P, out=32`，`Algorithm::Argon2d` |
| Ed25519 | `ed25519-dalek` v2 `SigningKey::from_bytes(seed)` | 与 agl/ed25519 做差分（签名/验签向量） |
| X25519 | `x25519-dalek`（clamped scalar mult on arbitrary u） | 对应 Go `curve25519.ScalarMult` |
| Elligator 代表元（extra25519） | **移植** `agl/ed25519/extra25519`（`ScalarBaseMult` / `RepresentativeToPublicKey`） | 公开 API 无等价物；用 5×51 或 ref10 域实现，恒定时间，差分测试 |
| CSPRNG | `chacha20` DRBG（进程启动 `getrandom` 播种）+ `getrandom` 兜底 | 避免 encless 每包 `getrandom`（~600 ns） |
| 常量时间 | `subtle` / `constant_time_eq` | MAC/pad 比较；pad 校验在 MAC 之后 |

> Go 的 Ed25519 是 2016 年的 `agl/ed25519`（标准 RFC 8032 格式），与 dalek 签名格式兼容，但**必须做双向差分**（含 `sig[63]&224` 等边界）。

### 7.2 cnw（Chaffing-and-Winnowing）专用优化 —— 最大收益点

当前实现：AONT 头 16 字节 = 128 bit；每个 bit 有 2 个 one-time key（一个 Salsa20 块的前/后 32 字节）。Chaff 对每个 key 计算 1 个 MAC（共 **256 次** `poly1305.Sum`）；Winnow 对每个 key 计算 2 个候选 MAC（共 **512 次** `poly1305.Sum`）+ **512 次**常量时间比较。

**关键观察**：Poly1305 对 1 字节消息的末尾块会补 `0x01` 再补零（小端），因此消息整数不是 0x30/0x31，而是：

```
block("0") = 0x30 + 0x01 * 2^8 = 0x130
block("1") = 0x131
```

对同一 32 字节 one-time key `(r, s)`：

```
h0   = 0x130 * r  mod (2^130 - 5)     // 1 次 130-bit 乘法
h1   = (h0 + r)   mod (2^130 - 5)     // 条件减
tag0 = low128(h0 + s)
tag1 = low128(h1 + s)
```

- Chaff：一次乘法得到两个 16 字节 tag，按 bit 值常量时间选择顺序写入。
- Winnow：每个 key 一次乘法 + 两次比较，替代该 key 的 2 次 `poly1305.Sum`；每个 bit 由 4 次 Sum 降为 2 次乘法 + 4 次比较。
- 该公式已用本项目 Go 版 `poly1305.Sum` 做随机 key 验证，`tag0/tag1` 完全一致（注意 `r` 需按 RFC 8439 clamp：`r &= 0x0ffffffc0ffffffc0ffffffc0fffffff`）。
- **已在 Go 侧实现**（`cnw.go` 的 `tags1/subP` 与 `chaff/winnow`）：Chaff 41.1µs → 9.2µs（4.45×），Winnow 58.9µs → 8.8µs（6.72×）；输出与旧实现逐字节一致。
- **再叠加 SIMD**：4 路 AVX2 / 8 路 AVX-512 并行处理 4/8 个 key；Salsa20 侧同样多块并行（每个输入字节需要 8 个 Salsa 块 = 512 字节 keystream）。
- XSalsa20 优化：24 字节 nonce 的 HSalsa20 只依赖前 16 字节（= PRP nonce 前缀），**每包只算一次**，之后每个字节索引只需 Salsa20(8B nonce=index) 8 块；Go 当前每字节都重算 HSalsa20。
- 实测（Go 标量版）：encless MTU 解码 75.6 µs → **13.9 µs/包**（5.44×），编码 42.3 µs → 15.3 µs（2.76×）。剩余空间主要来自 Salsa20 keystream 生成；Rust 用 4/8 路 SIMD 后可望再提升 3–5×。
- Go POC 已完成并合入；Rust 版按同一公式实现 SIMD 批量化即可。

### 7.3 经典模式密码学

- 单包单 nonce，天然无法 SIMD 跨包；优先用 RustCrypto AVX2 Poly1305/Salsa20。
- 如果基准显示仍低于目标：对 `recvmmsg` 批内 4–8 个包做 multi-buffer（Salsa20 4 路 AVX2；Poly1305 4 路转置）。复杂度高，作为 M6 可选优化，不阻塞主线。
- 关键：**保持 Salsa20 分段语义**——同一 nonce 下是不可分割的 keystream；Rust 侧按字节偏移（0..32 auth key、32..64 丢弃、64.. 载荷）严格对齐，不要拆成多次以同一 nonce 初始化的调用。

### 7.4 密钥与内存安全

- 会话密钥、握手中间量、Argon2 输出使用 `ZeroizeOnDrop`；`mlock` 可选。
- 是否每包清零载荷缓冲：Go 会清零整个 `bufT`。Rust 建议**默认只清零密钥材料**，提供 `--zero-buffers` 兼容开关；需在安全评审中明确该姿态变化（性能 vs. 内存残留）。
- 连接/会话销毁时清零密钥并释放 TAP；`mlock`/禁 core dump 作为运维选项。

---

## 8. 模块划分与依赖

```
govpn/                          # cargo workspace
├── crates/govpn-proto/         # 常量、包布局、serial/窗口、握手/传输状态机（纯逻辑，可 no_std）
├── crates/govpn-crypto/        # 算法封装；aont/cnw/elligator
│   └── src/simd/               # 唯一允许 unsafe 的密码学模块（AVX2/AVX-512/NEON）
├── crates/govpn-config/        # YAML、verifier 字符串、CLI 定义、校验
├── crates/govpn-io/            # TAP（ioctl IFF_TAP|IFF_NO_PI）、UDP/TCP、buffer pool、mmsg/uring 封装
├── crates/govpn-transport/     # per-peer session、心搏/CPR/重协商/定时器轮、统计
├── crates/govpn-server/        # bin
├── crates/govpn-client/        # bin
├── crates/govpn-verifier/      # bin
└── crates/govpn-oracle/        # 测试辅助：调用 Go 版生成/校验向量（dev-dependency）
```

| 功能 | 候选 crate | 备注 |
|---|---|---|
| 异步/控制面 | `tokio` | TCP 会话、配置、stats |
| socket/tap | `socket2`、`nix`、`libc` | SO_REUSEPORT、recvmmsg、TUNSETIFF |
| io_uring | `io-uring`（或 `monoio`/`compio`） | 数据面首选；epoll 回退 |
| 序列化 | `serde` + `serde_yaml_ng` / `saphyr` | Go yaml v2 语义需兼容（未知字段忽略、默认值） |
| HTTP proxy | `hyper` 或 `httparse` 手写 CONNECT | 服务端 CONNECT + hijack；客户端 CONNECT + Basic auth |
| CLI | `clap` 或 `lexopt` | 参数名/默认值逐一对照 |
| 终端口令 | `rpassword` | 不回显 |
| 日志/追踪 | `tracing` + `tracing-subscriber` | 保留类似日志字段 |
| 配置热更新 | `arc-swap` | 每分钟刷新 |
| 哈希表/池 | `hashbrown`、`slab` | 分片内无锁 |
| 错误 | `thiserror`、`anyhow`（仅 bin） | 核心库用具体错误类型 |
| 供应链 | `cargo-deny`、`cargo-audit`、`cargo-vet` | GPLv3 兼容（MIT/Apache-2.0） |
| 可复现构建 | `cargo vendor` + `--locked` | 与项目"自包含、可审计"风格一致 |

- 工具链：`rust-toolchain.toml` 固定版本；MSRV 由评测决定（建议 1.75+）；`-C target-cpu` 不用于发行包，运行时 SIMD 分派。
- 发布：musl 静态二进制（`x86_64-unknown-linux-musl`），保留与 Go 版一致的路径/权限；systemd unit + capabilities（`CAP_NET_ADMIN`）。

---

## 9. 兼容性清单（必须逐项测试）

| 项 | 兼容要求 |
|---|---|
| 握手字节 | 4 条消息长度、字段顺序、加密/签名算法、padding 位置完全一致 |
| IDtag | XTEA(id, 首 8B ⊕ timesync)，8 字节；服务端按"尾 8B 解密 + 常量时间比较"发现身份 |
| 传输包 | tag/ciphertext/nonce 布局；Salsa20 偏移；Poly1305 覆盖范围 |
| serial | 奇偶、步长 2、初值/期望、XTEA 字节序 |
| 重放 | UDP 256 窗口语义、TCP 精确期望 |
| encless | AONT/CnW 字节序列、4128 膨胀、XSalsa20 nonce 布局、强制 noise |
| noise | 填充长度/字节值（0x00）、有效 MTU 上限（已知差异） |
| timesync | `Unix()/ts*ts` 秒粒度、8 字节大端 XOR |
| 4 GiB rekey | 客户端触发阈值与流程 |
| 配置 | `peers.yaml` 字段、默认值、MTU 上限 9015、timeout 默认 60、encless→noise |
| verifier | 字符串格式（RawStdEncoding 无 `=`）、Argon2d v1.3 参数、Ed25519 seed 派生 |
| CLI | 全部 flag 名称、默认值、帮助文本语义、`-warranty` 输出 |
| 脚本 | `GOVPN_IFACE`/`GOVPN_REMOTE` 环境变量；up 脚本 stdout 首行作为 iface 名 |
| TAP | `IFF_TAP|IFF_NO_PI`、非 persistent（close 即消失）、每 server peer 一个设备 |
| stats | HTTP/1.0 + JSON 数组，字段名与类型一致 |
| proxy | 服务端 CONNECT 200、客户端 Basic auth、失败行为 |
| EGD | unix socket `0x02 len` 协议（长度 1 字节，保留原行为） |
| 平台 | Linux 首版；FreeBSD `/dev/tapN` 二阶段 |

---

## 10. 测试与验证策略

### 10.1 Go oracle（最高优先级）

- 在 `govpn-oracle/` 中提供一个 dev-only Go 二进制，暴露确定性接口：
  - `encode_packet(key, serial, payload, noise, encless)` → bytes
  - `decode_packet(...)` → payload / error
  - `handshake_vectors(...)`：固定随机源（`Rand` 可注入）与固定 Argon2/Ed25519 seed，输出全部消息字节 + 会话密钥
  - `aont/cnw/elligator/xtea` 单元向量
- CI 中：Rust 单测消费预生成的黄金文件；夜间任务运行 live oracle 做大规模随机差分。
- **固定随机源**是能否复现握手的关键；Go 侧通过包内测试（`package govpn`）替换 `Rand`。

### 10.2 互通矩阵

`{Go, Rust} × {server, client} × {UDP, TCP, HTTP proxy} × {noise on/off} × {encless on/off} × {timesync 0/1} × {CPR 0/非0}`，用 netns/veth + TAP 自动化，含：
- 双向 ping / iperf3 / 大数据完整性（校验和）；
- 重协商（把 4 GiB 阈值做成测试可配）；
- 超时与 peer 顶替；
- 边界 MTU（§3.9）；
- 乱序/重复/损坏包（UDP），半包/合并包（TCP）。

### 10.3 Fuzz

- `cargo-fuzz`：包解析、握手状态机、TCP 流解析、YAML/verifier 解析、AONT/CnW 解码。
- 非密码学逻辑尽量 pure，便于 `proptest` 做 encode/decode 往返、窗口性质。

### 10.4 安全

- 恒定时间审查（secret-dependent branch/索引）；SIMD 模块做 dudect 风格泄漏测试（可选）。
- `cargo-audit` + `cargo-deny`（licenses/bans/sources）CI 门禁。
- ASan/TSan（nightly）跑集成测试；`unsafe` 模块跑 Miri（不涉及 io_uring 的部分）。
- 依赖最小化，锁定 lockfile，发行包 vendor。

---

## 11. 性能工程计划

### 11.1 验收基准

| 指标 | 基线（本机，Go） | Rust 目标 |
|---|---|---|
| 经典 1,514B 单核 | 237k pps / 359 MB/s（纯加密） | ≥500k pps / ≥600 MB/s（端到端） |
| 经典 789B 单核解密 | 484k pps / 381 MB/s | ≥800k pps |
| encless 1,514B 单核解密 | 13.2k pps / 20 MB/s | ≥100k pps / ≥150 MB/s |
| encless 加密 | 23.7k pps / 35.8 MB/s | ≥150k pps / ≥220 MB/s |
| 每包分配 | 1（经典）/ 6（encless） | 0 |
| 10k peer RSS | 未测 | 经典 ≤128 MB / encless ≤384 MB |
| 握手 | 未测 | ≥1k/s/核（含 X25519+Ed25519） |
| 尾延迟 | — | 批处理附加 p99 ≤200 µs |

> 目标值基于"零分配 + 批处理 + 无锁分片 + encless 专用 MAC"的推算，**需在目标硬件实测后调整**；建议先做 §11.3 的 Go POC 来校准 encless 的乐观程度。

### 11.2 测量方法

- 微基准：`criterion`（密码学/编解码、alloc 计数用自定义全局 allocator 断言）。
- 端到端：`iperf3` + `pktgen`/自研 UDP 压测器，分别测 64/512/1,500 B；记录 pps、Gbps、p99、CPU、RSS。
- 剖析：`perf`、`samply`/pprof 导出；对比 Go `go tool pprof` 同一场景。
- CI 性能曲线：固定机器/固定 governor，防回归门禁（±5%）。

### 11.3 Go 侧 POC 结果（已完成）

1. **encless 专用 1 字节 MAC**：已实现。Winnow 6.72×、Chaff 4.45×，输出逐字节一致。
2. **去掉每包清零 + 复用发送缓冲**：已实现。经典 789B 加密 1.54×、解密 1.13×；noise MTU 1.39×；每包分配 1 → 0。

收益模型已被验证，Rust 重写的性能目标可维持。

---

## 12. 里程碑

| 阶段 | 内容 | 退出标准 | 预估 |
|---|---|---|---|
| M0 基建 | workspace、CI、`cargo-deny`、oracle 框架、基准脚手架、协议黄金向量 | 差分测试能跑通一个包的最小编解码 | 1–2 周 |
| M1 密码学 | Salsa20/XSalsa20、Poly1305、XTEA、BLAKE2b、Argon2d、Ed25519、X25519、Elligator、AONT、CnW（标量） | 全部与 Go 逐字节一致；fuzz 通过 | 3–5 周 |
| M2 客户端 | config/verifier/CLI、TAP、TCP 客户端（经典模式）、up/down 脚本、stats | Rust client ↔ Go server 端到端 | 3–4 周 |
| M3 服务端 | TCP/UDP 服务端、握手分发、peer 表、超时/顶替、proxy | 双向互通矩阵（经典模式）通过 | 4–6 周 |
| M4 特性 | noise、timesync、CPR、4 GiB 重协商、EGD、encless（标量） | 全矩阵 + 边界测试通过 | 3–4 周 |
| M5 性能 | io_uring/批处理、SO_REUSEPORT 分片、位图窗口、XTEA 预计算、定时器轮、encless SIMD | 达到 §11.1 目标 ≥80%；10k peer soak | 4–6 周 |
| M6 硬化 | FreeBSD、fuzz 长跑、安全评审、打包/文档、可选 multi-buffer 经典模式 | 发布候选 | 2–4 周 |

总计约 **20–30 人周**（单人 5–7 个月；并行可压缩）。

---

## 13. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| 协议细节理解偏差（握手长度、padding、XTEA 字节序、TCP 定界） | 无法互通 | oracle 黄金向量 + 双向互通 CI；以代码而非文档为准 |
| extra25519 Elligator 移植错误 | 握手失败/安全问题 | 逐函数移植 + Go 差分 + 固定向量 + 边界测试 |
| Argon2d 版本/参数不一致 | verifier 不兼容 | 官方 KAT + Go 差分（多组 m,t,p） |
| Ed25519 旧实现的边界语义 | 验签差异 | 双向签名/验签随机差分 + 已知边界 |
| noise/encless MTU 语义缺陷 | 丢包/互通边界问题 | §3.9 显式测试与启动告警；保持原语义 |
| SIMD 实现错误/侧信道 | 崩溃/安全 | 标量参考实现 + 差分 + 常量时间审查；运行时分派 |
| io_uring 内核/权限限制（容器、旧内核） | 部署失败 | `epoll+recvmmsg` 自动回退；能力探测 |
| 批处理增加延迟 | 交互体验 | 批大小/等待上限可配；小流量立即 flush |
| 依赖供应链/许可证 | 发布受阻 | `cargo-deny`/`audit`/`vet`；vendor；只选 GPLv3 兼容许可 |
| 每包零化的安全姿态变化 | 安全评审争议 | 默认 zeroize 密钥；`--zero-buffers` 兼容开关；评审记录 |
| 服务端身份扫描 O(N) DoS | 握手放大攻击 | 每 IP 限速、pending 上限、扫描分片/批量；文档说明 |
| 超大 peer 数定时器 | 内存/CPU | 定时器轮 + 惰性清理 |
| "Rust 一定更快"的预期落空 | 项目信心 | §11.3 先在 Go 验证两项算法级收益；经典模式以端到端指标而非微基准验收 |

---

## 14. 待确认决策

1. **兼容级别**：是否要求 100% wire-compatible（推荐：是，首版）；协议 v2（修 MTU/定界/身份扫描）另立项目。
2. **平台**：首版是否只做 Linux（推荐），FreeBSD 放 M6。
3. **`unsafe` 边界**：允许 `govpn-simd` 与 io_uring 封装使用 `unsafe`（推荐）；其余 crate `forbid(unsafe_code)`。
4. **安全姿态**：是否保留"每包整块清零"（影响 10%+ 性能）；推荐默认关闭并提供开关。
5. **性能目标**：§11.1 是否作为硬门禁；批处理延迟预算 200 µs 是否可接受。
6. **运行时**：数据面自研 epoll/uring 循环 vs `monoio`/`compio`（推荐前者，控制审计面）。
7. **分发**：静态 musl 单文件 + vendor 源码包，是否满足发布流程。

---

## 附录 A：实测原始数据

### A.1 优化后复测（2026-11-25，`-count=3` 的中位数）

```text
BenchmarkEnc-12               1827 ns/op     0 B/op   0 allocs/op
BenchmarkDec-12               1827 ns/op     0 B/op   0 allocs/op
BenchmarkEncNoiseMTU-12       3040 ns/op  490 MB/s  0 B/op  0 allocs/op
BenchmarkEnclessEncode-12    11232 ns/op  5120 B/op  5 allocs/op
BenchmarkEnclessDecode-12     9964 ns/op   160 B/op  1 allocs/op
BenchmarkEnclessEncodeMTU-12 15326 ns/op  98.3 MB/s  8016 B/op 5 allocs/op
BenchmarkEnclessDecodeMTU-12 13889 ns/op 108.8 MB/s  1792 B/op 1 allocs/op
BenchmarkChaff-12             9235 ns/op  4096 B/op  1 allocs/op
BenchmarkWinnow-12            8769 ns/op    16 B/op  1 allocs/op
BenchmarkEncode(aont)-12      1167 ns/op   240 B/op  3 allocs/op
BenchmarkDecode(aont)-12      1167 ns/op   224 B/op  3 allocs/op
```

端到端回归（本机 loopback，root TAP）：
- UDP：handshake 完成，5×100B → `FramesIn=5`、`BytesPayloadIn=500`、`FramesUnauth=0`。
- TCP：same，`FramesIn=5`、`FramesUnauth=0`。

### A.2 优化前原始基线

```text
# go test -benchmem -bench . cypherpunks.ru/govpn/...
cpu: AMD Ryzen 5 PRO 5675U with Radeon Graphics (Go 1.22.2)

BenchmarkEnclessEncode-12    33338   32817 ns/op    9728 B/op   6 allocs/op
BenchmarkEnclessDecode-12    22450   54688 ns/op     416 B/op   5 allocs/op
BenchmarkEnc-12             399525    2805 ns/op     896 B/op   1 allocs/op
BenchmarkDec-12             582832    2068 ns/op     200 B/op   3 allocs/op
BenchmarkEncode(aont)-12    879094    1398 ns/op     240 B/op   3 allocs/op
BenchmarkDecode(aont)-12    642328    1671 ns/op     224 B/op   3 allocs/op
BenchmarkChaff-12            30154   39828 ns/op    4096 B/op   1 allocs/op
BenchmarkWinnow-12           20115   59609 ns/op      16 B/op   1 allocs/op

# 追加 MTU 定向基准
BenchmarkEncNoiseMTU-12     272414    4217 ns/op 358.99 MB/s 1536 B/op 1 allocs/op
BenchmarkEnclessEncodeMTU-12 28146   42288 ns/op  35.80 MB/s 12880 B/op 6 allocs/op
BenchmarkEnclessDecodeMTU-12 18378   75593 ns/op  20.03 MB/s  3664 B/op 5 allocs/op
BenchmarkNonceCipher-12    6032529     176.2 ns/op       0 B/op 0 allocs/op
```

CPU profile（聚合，`go tool pprof -top`）：

```text
poly1305.poly1305                        41.57%
salsa20/salsa.salsa2020XORKeyStream      26.51%
govpn.SliceZero                          11.45%
crypto/subtle.ConstantTimeCompare         3.01%
cnw.zero                                  2.41%
xtea.encryptBlock+decryptBlock            2.40%
runtime.mallocgc                          4.22%
```

分配 profile（`-alloc_space`）：

```text
Peer.EthProcess        44.43%
EnclessEncode          42.31% (cum)
cnw.Chaff              17.73%
Peer.PktProcess         6.06%
```

## 附录 B：关键代码索引

| 主题 | 位置 |
|---|---|
| 传输加密/解密 | `src/cypherpunks.ru/govpn/peer.go:222-404` |
| 每包整块清零 / append 分配 | `peer.go:231, 283` |
| CPR 持锁 sleep | `peer.go:287-293` |
| XTEA nonce | `peer.go:255-260, 347-351` |
| 重放窗口 map | `peer.go:353-374` |
| encless 编解码 | `encless.go:36-71` |
| Chaff/Winnow | `cnw/cnw.go:65-157` |
| AONT | `aont/oaep.go:56-95` |
| 握手状态机 | `handshake.go:151-481` |
| DH/Elligator 密钥生成 | `handshake.go:99-118` |
| 身份扫描 | `identity.go:99-116` |
| UDP 一包一 goroutine | `cmd/govpn-server/udp.go:53, 74-85` |
| TCP nonce 定界 | `cmd/govpn-server/tcp.go:155-189`、`cmd/govpn-client/tcp.go:117-163` |
| 每 peer ticker | `cmd/govpn-server/common.go:50-67` |
| 超时扫描/全局锁 | `cmd/govpn-server/main.go:107-141` |
| TAP 读取 goroutine | `tap.go:35-84` |
| stats | `stats.go:40-64` |
| Argon2d/verifier | `verifier.go:36-102` |

## 附录 C：参考命令

```bash
# 当前项目编译（GOPATH 模式）
GO111MODULE=off make all
GO111MODULE=off make bench

# 目标 Rust 工程
cargo build --release --locked
cargo test --workspace
cargo fuzz run parse_packet
cargo deny check
```