# GoVPN 5.7 性能优化记录

> **Note:** 本文的性能数据与结论已合并进 Rust 代码树的三语文档：
> [`rust/docs/en/performance.md`](../rust/docs/en/performance.md) ·
> [`rust/docs/zh/performance.md`](../rust/docs/zh/performance.md) ·
> [`rust/docs/ru/performance.md`](../rust/docs/ru/performance.md)。本文保留为 Go 侧原始记录。

> 日期：2026-11-25
> 范围：Go 版 `govpn`（GOPATH 工程）热路径、encless 编解码、UDP 服务端数据面
> 状态：已实现、已回归、已复测；改动未提交 git
> 配套文档：`docs/rust-rewrite-design.md`（Rust 重写设计，尚未实施）

---

## 1. 摘要

本轮优化针对之前性能分析中确认的瓶颈，全部保持**线协议字节不变**：

| 优化项 | 结果 |
|---|---|
| cnw 1 字节 Poly1305 专用公式 + 每包一次 HSalsa20 | Chaff **4.45×**、Winnow **6.72×** |
| encless 编解码去掉中间切片/拷贝 | 128B 解码 **5.49×**、MTU 解码 **5.44×**；解码分配 5 → 1 |
| peer 发送路径去分配 + 定点清零 | 经典加密 **1.54×**、解密 **1.13×**；每包分配 1 → 0 |
| noise/encless MTU 有效载荷校验 | 不再静默截断，超限包明确拒绝并告警 |
| UDP 服务端数据面重构 | 去掉每包 goroutine、每 peer 2 缓冲区限制、每包字符串/全局锁 |
| 身份缓存、配置/TAP 并发安全 | 顺序扫描、读写锁、TAP 读错误不再 panic |

encless MTU 单核解码从 **20.0 MB/s → 108.8 MB/s（5.44×）**，是本次最大收益。

---

## 2. 测试环境与方法

- CPU：AMD Ryzen 5 PRO 5675U（Zen3，AVX2）
- Go：1.22.2 linux/amd64；代码现在要求 **Go ≥ 1.18**（`net/netip`、`ReadFromUDPAddrPort`、`Mutex.TryLock`）
- 编译：`GO111MODULE=off GOPATH=$(pwd) go build/test`（项目无 `go.mod`）
- 基准：`go test -run XXX -bench . -benchmem -count 3`，取中位数
- 这台机器为共享环境，单次结果波动可到 ±50%；本文数字均来自同一时段、同一批命令的稳定复测
- 端到端：本机 loopback + root TAP，UDP/TCP 各跑一次 handshake + 5×100B 载荷

复测命令：

```bash
GO111MODULE=off GOPATH=$(pwd) go test \
  -run XXX -bench . -benchmem -count 3 \
  cypherpunks.ru/govpn cypherpunks.ru/govpn/aont cypherpunks.ru/govpn/cnw

# CPU/分配 profile
GO111MODULE=off GOPATH=$(pwd) go test -run XXX -bench . -benchtime 500ms \
  -cpuprofile /tmp/cpu.out -memprofile /tmp/mem.out cypherpunks.ru/govpn
go tool pprof -top /tmp/cpu.out
go tool pprof -top -alloc_space /tmp/mem.out
```

---

## 3. 优化前基线

| 场景 | ns/op | payload 吞吐 | 分配 |
|---|---:|---:|---:|
| 经典 789B 加密 | 2,805 | 281 MB/s | 1 / 896B |
| 经典 789B 解密 | 2,068 | 381 MB/s | 3* |
| 经典 noise MTU 加密 | 4,217 | 359 MB/s | 1 / 1.5KB |
| encless 128B 编码 | 32,817 | — | 6 |
| encless 128B 解码 | 54,688 | — | 5 |
| encless MTU 编码 | 42,288 | 35.8 MB/s | 6 / 12.9KB |
| encless MTU 解码 | 75,593 | 20.0 MB/s | 5 / 3.7KB |
| cnw Chaff（16B） | 41,097 | — | 1 / 4KB |
| cnw Winnow（16B） | 58,928 | — | 1 / 16B |

\* 基准自身每轮重建 map，稳态分配更低。

CPU profile（全部基准聚合）：Poly1305 41.6%、Salsa20 26.5%、**`SliceZero` 11.5%**、`ConstantTimeCompare` 3.0%、`cnw.zero` 2.4%、XTEA 2.4%、`mallocgc` 4.2%。

分配 profile：`Peer.EthProcess` 44.4%、`EnclessEncode` 42.3%、`cnw.Chaff` 17.7%、`Peer.PktProcess` 6.1%。

---

## 4. 优化方法详解

### 4.1 cnw：1 字节 Poly1305 专用公式

文件：`src/cypherpunks.ru/govpn/cnw/cnw.go`

**问题**

Chaff / Winnow 对 AONT 头的 16 个字节逐 bit 计算 Poly1305，消息长度恒为 1 字节：

- Chaff：每包 256 次 `poly1305.Sum`
- Winnow：每包 512 次 `poly1305.Sum` + 512 次常量时间比较

通用 Poly1305 每次调用都要做完整的 key 解析、130-bit 乘加和收尾，对 1 字节消息极度不划算。

**观察**

Poly1305 对最后一块不足 16 字节的消息会先补 `0x01` 再补零。因此单字节 `"0"`、`"1"` 对应的消息整数是：

```
block("0") = 0x30 + 0x01 * 2^8 = 0x130
block("1") = 0x131
```

对同一个 32 字节 one-time key `(r, s)`：

```
h0   = 0x130 * r  mod (2^130 - 5)     // 一次 130-bit 乘法
h1   = (h0 + r)   mod (2^130 - 5)     // 条件减
tag0 = low128(h0 + s)
tag1 = low128(h1 + s)
```

即**一次乘法得到两个候选 tag**，而不是两次通用 Poly1305。

**实现要点**

- `tags1()` 用 `math/bits.Mul64/Add64/Sub64` 实现 130-bit 算术，`r` 按 RFC 8439 clamp：
  `r &= 0x0ffffffc0ffffffc0ffffffc0fffffff`。
- `subP()` 用 borrow + mask 做常量时间条件减，不分支。
- Chaff 用 `mask = -uint64(bit)` 常量时间选择 `[tag1,tag0]` / `[tag0,tag1]`，避免通过分支泄漏明文 bit。
- Winnow 用 `ceq()`（`((x|-x)>>63)^1`）做常量时间比较，`is11` 通过位或合并，不分支。
- **HSalsa20 只算一次**：XSalsa20 的 24 字节 nonce 是 `prefix(8) || zeros(8) || BE(index)`，HSalsa20 只依赖前 16 字节。每包先派生一次 subkey，之后每个字节索引只需 Salsa20(8B nonce=index) 生成 8 个块（512B）。
- 生成 keystream 时传入只读全零缓冲 `zeroKeys`，避免每字节 `zero(keys)`（原实现每字节清 512B）。
- 新增 `ChaffInto` / `WinnowInto`，让调用方直接写入目标缓冲区。

**正确性验证**

`cnw/cnw_opt_test.go`：

- 5,000 个随机 key：`tags1` 的 tag0/tag1 与 `poly1305.Sum` 完全一致；
- 200 组随机 key/nonce/长度：新 Chaff 输出与内置参考实现逐字节一致；
- 新 Winnow 与参考 Winnow 结果一致，且能拒绝篡改。

### 4.2 encless 编解码去分配/去拷贝

文件：`src/cypherpunks.ru/govpn/encless.go`、`src/cypherpunks.ru/govpn/aont/oaep.go`

原实现：

- `EnclessEncode`：`aont.Encode` 分配 → `cnw.Chaff` 分配 4KB → `append` 再分配并复制整包 → `EthProcess` 再 `append` 8 字节 nonce。
- `EnclessDecode`：`cnw.Winnow` 分配 → 拼接 winnowed+r 再分配 → `aont.Decode` 再分配。

优化后：

- `EnclessEncode` 只分配 `aonted` 和最终 `out`，用 `ChaffInto` 直接写 `out[:4096]`，再 `copy` 尾部；`out` 预留 8 字节 cap 供调用方 `append` nonce/IDtag，避免二次扩容复制。
- 新增 `aont.DecodeParts(first, second)`，直接按 `winnowed(16) || rest` 两个片段解码，不再拼接；`EnclessDecode` 用栈上 `[16]byte` 接收 Winnow 结果。

结果：128B 解码分配 5 → 1；MTU 解码 5 → 1。

### 4.3 peer 发送路径：去分配、定点清零、位图重放窗口

文件：`src/cypherpunks.ru/govpn/peer.go`

1. **去掉每包 `append`**
   - 原：`out = append(p.tagT[:], p.frameT...)`，`tagT` cap=16，必分配。
   - 现：每个 peer 持有持久 `outT`（cap = `TagSize+2*MTU`），每包 `out = outT[:TagSize+len(frameT)]`，再 `copy` tag 和 frame。分配降为 0。
   - encless 模式不使用 `outT`，不为它分配额外内存。

2. **只清零必要区域**
   - 原：每包 `SliceZero(p.bufT)`，noise/encless 下 3–6KB。
   - 现：只清 Salsa20 scratch 的前 32 字节（它们会成为 Poly1305 one-time key），其余头部不参与计算。
   - noise/encless 只在 pad 字节与 nonce 之间填充零（协议要求线上为零），非 noise 模式完全不清零。
   - `SliceZero` 从 profile 的 11.5% 降到 ~1.4% memclr。

3. **重放窗口由 map 改位图**
   - 原：两个 `map[uint64]struct{}`，每包两次查找 + 一次插入，每 128 包重建 map。
   - 现：`[5]uint64` = 257-bit 滑动窗口 + `nonceLatest`，`nonceAccept()` O(1)、零分配。
   - 语义保持原窗口跨度（`nonce+256 < latest` 拒绝），支持乱序与重复检测。

4. **MTU 有效载荷校验**
   - 原：只校验 `len(data) <= MTU-1`；noise 模式下 frame 实际只有 `MTU-16`，payload+pad+nonce 超出部分被截断/对端丢弃。
   - 现：`maxPayload()` 按模式返回：
     - plain：`MTU-1`
     - noise：`MTU-25`（去掉 tag 16 + nonce 8 + pad 1）
     - encless：`MTU-9`（去掉 nonce 8 + pad 1）
   - 超限包记录日志并丢弃，不再静默截断。

### 4.4 UDP 服务端数据面重构

文件：`src/cypherpunks.ru/govpn/cmd/govpn-server/udp.go`、`common.go`、`conf.go`

**原结构**

- 单 reader goroutine；
- 每个已建连数据包 `go func(){ PktProcess; udpBufs <- buf }`；
- 缓冲区池 `udpBufs` 实际 1 + 2×会话数个，每 peer 最多 2 个 in-flight；
- 每包 `raddr.String()`、全局 `RLock` + 字符串键 map；
- 握手（含 O(N) 身份扫描）在数据 reader 里同步执行。

**新结构**

- `GOMAXPROCS` 个 reader goroutine，共用同一个 `*net.UDPConn`；
- 已建连数据包**在 reader 内联处理**，不再 spawn goroutine；
- 每 reader 一个 13KB 接收缓冲（覆盖 encless + `MTUMax`），不再有 per-peer 2 缓冲区限制；
- `ReadFromUDPAddrPort` + `netip.AddrPort` 键，去掉每包字符串分配；
- 每 reader 256 槽直接映射流缓存：命中时只做 hash/比较 + 一次 atomic load，**不加锁、不查 map**；
- 全局 `peersGeneration atomic.Uint64`，任何 peer 表增删都 bump，缓存条目通过 stamp 自动失效；
- 未知地址的包（握手/迟到包）复制到有界队列，按地址 hash 分发到 `min(4, GOMAXPROCS)` 个握手 worker；同地址同 worker，天然串行；
- 握手完成与首包并发时，worker 会重新检查 peer 表，把已注册 peer 的数据包交给 `PktProcess`，避免首包被误判为握手；
- 握手队列满时丢包并记录，避免无界内存。

**并发安全修复**

- `confs` 配置表加 `RWMutex`，`confGet()` 返回不可变快照，解决配置热加载与多 reader 的竞争；
- `taps` 全局表加锁，解决多个握手 worker 并发 `TAPListen` 的 map 竞争；
- `PeerState.terminate()` 改为 buffered channel + 非阻塞发送，删除 `peerReady` 里对 channel 的 close，避免重复终止 panic。

### 4.5 身份缓存：切片顺序扫描

文件：`src/cypherpunks.ru/govpn/identity.go`

- 原：`Find()` 在 RLock 下遍历 `map[PeerId]*CipherAndTimeSync`。
- 现：`Update()` 维护 `list []*CipherAndTimeSync`，`Find()` 顺序遍历切片，缓存局部性更好；条目内含 id，命中无需二次 map 查找。
- 握手路径已移到握手 worker，身份扫描不再阻塞数据 reader。

### 4.6 TAP：读错误不再 crash

文件：`src/cypherpunks.ru/govpn/tap.go`

- 原：`tap.dev.Read` 出错直接 `panic`，整个守护进程退出。
- 现：记录错误（同一错误只打印一次）、`time.Sleep(1s)` 后重试；peer 状态不再被连带清零。
- 在本机 `read /dev/net/tun: not pollable` 环境中，第一次 Read 会返回该错误；重试后转入可用的阻塞读，TCP 端到端回归能正常读到 TAP 帧。原实现会在第一次 Read 时 panic。

### 4.7 TCP 会话

文件：`src/cypherpunks.ru/govpn/cmd/govpn-server/tcp.go`、client 侧同步修正

- map 键改为 `netip.AddrPort`，与 UDP 统一；
- 会话结束用 `ps.terminate()` 停止 `peerReady` goroutine（原实现会遗留 goroutine）；
- 握手/重握手分支复用 `peersChanged()` 失效流缓存；
- TAP Sink 关闭检查（客户端/服务端）。

### 4.8 XTEA：评估后未改

- 原 profile 中 `BenchmarkNonceCipher` 约 176 ns/8B；隔离复测在 87–176 ns 之间随负载波动。
- 手写 64 轮完全展开版本与 `x/crypto/xtea` 无显著差异（甚至更慢），预计算只是把成本搬到别处，不降低每包摊销。
- 结论：不改；若追求极致，可在 Rust 版做多包 bitslice/SIMD 批量。

---

## 5. 优化后结果

### 5.1 吞吐 / 延迟

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

### 5.2 分配

| 路径 | 优化前 | 优化后 |
|---|---:|---:|
| 经典发送 | 1 alloc / ~1.5KB | **0** |
| encless 128B 编码 | 6 allocs | 5 allocs |
| encless 128B 解码 | 5 allocs | **1 alloc** |
| encless MTU 编码 | 6 allocs / 12.9KB | 5 allocs / 8KB |
| encless MTU 解码 | 5 allocs / 3.7KB | **1 alloc / 1.8KB** |

### 5.3 Profile 变化

优化后（同一套基准聚合）：

| 热点 | 占比 |
|---|---:|
| Salsa20 keystream | 46.0% |
| Poly1305（经典传输） | 22.2% |
| BLAKE2b | 7.9% |
| `cnw.tags1` | 4.9% |
| `cnw.subP` | 4.3% |
| `runtime.memclrNoHeapPointers` | 1.4% |
| `cnw.zero` | 0.8% |

`SliceZero` 已不在热点列表；瓶颈回到密码学本体。

---

## 6. 兼容性与回归

### 6.1 字节级兼容

- cnw：`tags1` 对照 `poly1305.Sum` 5,000 组随机 key；Chaff/Winnow 对照旧实现 200 组随机输入，**逐字节一致**。
- 传输：`TestTransportSymmetric` / `...Noise` / `...Encless` 全部通过；握手 symmetric 测试通过。
- aont：新增 `TestDecodeParts`，`DecodeParts` 与 `Decode` 对 1–200B 随机数据结果一致。
- MTU：新增 `TestMaxPayload`（1514/1490/1506）、`TestEthProcessRejectsOversized`（1490 发送成功、1491 拒绝）。

### 6.2 端到端

本机 root TAP + loopback：

| 协议 | 结果 |
|---|---|
| UDP | handshake 完成；5×100B → `FramesIn=5`、`BytesPayloadIn=500`、`FramesUnauth=0` |
| TCP | handshake 完成；5×100B → `FramesIn=5`、`BytesPayloadIn=500`、`FramesUnauth=0` |

复现要点：

```bash
# 1. 生成临时 verifier（小参数）
printf 'testpass\n' > /tmp/gvpass
./govpn-verifier -key /tmp/gvpass -m 1024 -t 4 -p 1 > /tmp/gvver

# 2. /tmp/gvpeers.yaml 使用长格式 verifier，iface 指向一个可创建的 TAP 名

# 3. 以 root 启动服务端
sudo ./govpn-server -proto udp -bind 127.0.0.1:11940 \
  -conf /tmp/gvpeers.yaml -stats 127.0.0.1:12940

# 4. 用一个只做握手 + 发送 5 个 Ethernet 载荷的 Go 客户端连接
# 5. curl 访问 stats 端口核对 FramesIn/BytesPayloadIn/FramesUnauth
```

> TAP 在本机首次 `Read` 返回 `not pollable`；重试逻辑使后续读取正常工作（TCP 回归中服务端确实读到了 TAP 帧）；这是本轮 TAP 修复的直接验证场景。

### 6.3 测试/静态检查

```bash
GO111MODULE=off GOPATH=$(pwd) go test cypherpunks.ru/govpn/...
GO111MODULE=off GOPATH=$(pwd) go test -race cypherpunks.ru/govpn/...
GO111MODULE=off GOPATH=$(pwd) go vet cypherpunks.ru/govpn/...
```

全部通过。三个二进制已重新编译到仓库根目录。

---

## 7. 兼容性注意（行为变化）

1. **noise / encless 的有效 MTU 变小**：
   - noise：`MTU-25`；encless：`MTU-9`。
   - 原实现会静默截断/丢弃超限帧；现在会记录日志并丢弃。
   - 若用户原来用 `MTU=1515 + noise` 承载完整 1500B IP 包（以太帧 1514B），现在会被判超限。需要把 MTU 配置增大（如 1540）或接受载荷上限降低。这是协议/MTU 语义原本就存在的限制，本轮只是显式暴露。
2. **UDP 握手队列有界**：极端握手洪峰下会丢包并记录，替代原来的无界处理。
3. **TAP 读错误策略**：从 panic 改为重试；接口永久损坏时会每秒打一条（相同错误只打一次）并持续重试。
4. **MTU 下限**：全局最小 68；noise/encless 最低 120。低于下限的服务端配置会被提升并记录，客户端直接拒绝启动。小于 120 的 noise/encless 配置在旧代码里会在握手阶段 panic 或失败。
4. **TCP 会话结束**：会主动停止 peer 处理 goroutine；peer 表条目仍按原逻辑等待超时清理。

---

## 8. 遗留问题

| 项 | 说明 | 建议 |
|---|---|---|
| `recvmmsg`/`sendmmsg`/io_uring | Go 标准库无可用批量接口；当前仍是每包 syscall | 留给 Rust 数据面；Go 侧可考虑 raw syscall 但风险高 |
| 每 peer ticker | Go timer 堆可扩展，15s 心跳不是热点 | 未改；大规模（10k+）可在 Rust 用定时器轮 |
| TCP nonce 定界 + memmove | 协议要求搜索期望 nonce 密文，环形缓冲改造动到状态机 | 暂留；Rust 可用 `memmem` + 环形缓冲 |
| encless 编码仍 5 allocs | 主要来自 `aont.Encode` 的哈希/输出分配 | 可继续用 `EncodeInto` + 对象池压到 2–3 |
| encless SIMD | Go 版已用标量专用公式拿到 4–7× | Rust 可再拿 3–5× |
| XTEA | 评估后无收益 | Rust 可 bitslice 批量 |

---

## 9. 代码审查补充修复（2026-11-25）

在提交后的对抗性 review 中发现并修复了以下问题（均已补回归测试）：

### 9.1 encless 短包远程 panic

`EnclessDecode` 原先直接切 `in[:16*256]`。攻击者向 encless peer 发送 25 字节 UDP 包即可触发 slice 越界 panic，导致服务端崩溃。现增加最小长度校验：

```
len(in) >= aont.RSize*cnw.EnlargeFactor + aont.HSize  // 4096 + 32
```

`TestEnclessDecodeRejectsShort` 覆盖 0/1/100/4095/4096/4127 长度；`TestPktProcessEnclessShort` 直接验证 25 字节真实数据包被拒绝而不是 panic。

### 9.2 握手阶段空指针 panic

- Server：第一条 encless 消息解码失败后 `rNonce` 已设置但 `key` 为 nil；下一条消息会进入第二阶段并用 nil key 解码 → panic。现第二阶段的进入条件要求 `key != nil && rServer != nil`。
- Client：服务端第一条回复的"公钥部分"解码成功、但 RS/SS 部分失败时，`key` 已设置而 `rClient` 为 nil；下一包会比较 nil `rClient[:]` → panic。现第二阶段条件要求 `rServer/sServer/rClient` 均非 nil。

`TestHandshakeMalformedStages` 构造两端的半完成状态并验证后续消息被拒绝、不会 panic。

### 9.3 握手状态并发与清理

- `Handshake` 增加内部 `busy sync.Mutex` 与 `closed` 标志：`Server`/`Client`/`Zero` 串行化，已清理状态不会被迟到 worker 使用。
- 新增 `Expire(timeout, now)`：使用 `TryLock`，若握手正在处理则跳过本轮清理，避免清理线程被卡在慢速 `Write` 上；同时保证检查与清零原子。
- 手握手状态清理不再与 worker 的 `LastPing` 写入竞争。

### 9.4 stats 并发安全

- `KnownPeers` 由裸 `map` 改为带 `RWMutex` 的结构（`NewKnownPeers`/`Set`/`Delete`/`Snapshot`），消除 stats 读与 peer 增删之间的 map 并发 panic。
- 新增 `PeerStats` 快照：在 `BusyT` + `BusyR` 下读取字段（`BytesIn/Out` 用 atomic load），stats JSON 字段名与旧版完全一致。
- 服务端退出流程对 `peers` 做加锁快照后再执行 down 脚本，避免并发 map 迭代。

### 9.5 其他健壮性

- UDP 握手队列：先取"槽位"令牌再分配/复制数据，队列满时不再产生无用的每包分配；丢弃日志每 1000 条打一次，防日志洪水。
- UDP reader 非关闭类读错误增加 100 ms 退避，避免错误循环打满 CPU。
- MTU 下限校验：全局最小 `MTUMin=68`；noise/encless 需 `MTUMinNoise=120`（否则握手消息/第三阶段载荷长度不足）。
- `outT` 容量改为 `Tag + MTU + Nonce + Tag`，消除极小 MTU 下的潜在切片越界。
- encless 随机数改用 `io.ReadFull`，避免短读导致 `r` 未填满。
- TCP/UDP 对 IPv4-in-IPv6 地址做 `Unmap` 格式化，保证脚本的 `GOVPN_REMOTE` 与旧实现一致；内部 map/写回仍使用原始 `netip.AddrPort`。

### 9.6 审查后仍保留

- TAP reader 在 peer 终止后可能在 `tap.Sink <-` 上阻塞（接口仍被缓存，重连后可恢复消费）；这是原设计遗留，未改。
- TCP 的 nonce 定界搜索 + memmove（协议决定）。
- 批量 syscall / io_uring（Rust 版处理）。
- `recvmmsg` 等平台能力未在 Go 侧实现。

回归结果：`go test`、`go test -race`、`go vet`、`-shuffle=on -count=3` 全部通过；UDP/TCP loopback + root TAP 端到端均保持 `FramesIn=5`、`FramesUnauth=0`；用 `-race` 编译的服务端跑 UDP/TCP 及 8 客户端并发握手 stress，未出现 `DATA RACE`/panic。

---

## 10. 变更文件

核心：

- `src/cypherpunks.ru/govpn/cnw/cnw.go`
- `src/cypherpunks.ru/govpn/cnw/cnw_opt_test.go`（新增）
- `src/cypherpunks.ru/govpn/aont/oaep.go`
- `src/cypherpunks.ru/govpn/aont/decodeparts_test.go`（新增）
- `src/cypherpunks.ru/govpn/encless.go`、`encless_test.go`
- `src/cypherpunks.ru/govpn/peer.go`、`peer_test.go`
- `src/cypherpunks.ru/govpn/handshake.go`、`handshake_test.go`
- `src/cypherpunks.ru/govpn/stats.go`、`stats_test.go`（新增）
- `src/cypherpunks.ru/govpn/identity.go`
- `src/cypherpunks.ru/govpn/common.go`（MTU 下限常量）
- `src/cypherpunks.ru/govpn/tap.go`
- `src/cypherpunks.ru/govpn/tap_linux.go`、`tap_freebsd.go`（gofmt 补 `//go:build`）

服务端/客户端：

- `cmd/govpn-server/udp.go`（重构）
- `cmd/govpn-server/common.go`
- `cmd/govpn-server/conf.go`
- `cmd/govpn-server/tcp.go`
- `cmd/govpn-server/main.go`
- `cmd/govpn-client/main.go`
- `cmd/govpn-client/udp.go`、`cmd/govpn-client/tcp.go`

文档：

- `docs/performance-optimization.md`（本文）
- `docs/rust-rewrite-design.md`（已同步 §0.5 落地状态与复测数据）

---

## 附录：优化前后的关键代码形态

### Poly1305 专用公式（简化）

```go
r0 := binary.LittleEndian.Uint64(key[0:8]) & 0x0FFFFFFC0FFFFFFF
r1 := binary.LittleEndian.Uint64(key[8:16]) & 0x0FFFFFFC0FFFFFFC
s0 := binary.LittleEndian.Uint64(key[16:24])
s1 := binary.LittleEndian.Uint64(key[24:32])

// h = 0x130 * r mod (2^130-5)，一次 128×64 乘法
hi, lo := bits.Mul64(0x130, r0)
p1hi, p1lo := bits.Mul64(0x130, r1)
c0 := lo
c1, carry := bits.Add64(hi, p1lo, 0)
c2 := p1hi + carry
k := c2 >> 2
h0, c := bits.Add64(c0, 5*k, 0)
h1, c2c := bits.Add64(c1, 0, c)
h2 := (c2 & 3) + c2c
h0, h1, h2 = subP(h0, h1, h2)     // 常量时间条件减

t0lo, c := bits.Add64(h0, s0, 0)
t0hi, _ := bits.Add64(h1, s1, c)
r0h, c := bits.Add64(h0, r0, 0)
r1h, c2b := bits.Add64(h1, r1, c)
r0h, r1h, _ = subP(r0h, r1h, h2+c2b)
t1lo, c := bits.Add64(r0h, s0, 0)
t1hi, _ := bits.Add64(r1h, s1, c)
```

### 重放窗口（简化）

```go
if serial > p.nonceLatest {
    diff := serial - p.nonceLatest
    if diff > 256 {
        p.nonceWindow = [5]uint64{}
    } else {
        nonceWindowShift(&p.nonceWindow, int(diff))
    }
    p.nonceLatest = serial
    p.nonceWindow[0] |= 1
    return true
}
diff := p.nonceLatest - serial
if diff > 256 {
    return false
}
word, bit := diff/64, uint(diff%64)
mask := uint64(1) << bit
if p.nonceWindow[word]&mask != 0 {
    return false
}
p.nonceWindow[word] |= mask
```

### UDP reader（简化）

```go
for {
    n, addr, err := udpConn.ReadFromUDPAddrPort(buf)
    ...
    if ps := cache.lookup(addr); ps != nil {
        ps.peer.PktProcess(buf[:n], ps.tap, true)
        continue
    }
    // 复制后投递到有界握手队列
}
```

其中 `cache.lookup` 在 `peersGeneration` 未变时直接返回缓存，只有失效时才 `RLock + map`。