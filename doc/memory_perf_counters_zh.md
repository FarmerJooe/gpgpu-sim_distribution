# GPGPU-Sim 访存与 MEE 安全流水线性能模型

本文件把 L2↔DRAM 通路中的多层安全模块 (MEE) 纳入访存模型，说明各阶段的时间窗口、阻塞来源，以及需要新增的性能计数器。配合 `polybench-2DConvolution_performance.log` 等输出，可精细拆分总延迟并评估 AES/CTR/MAC/BMT 对 DRAM 带宽的影响。

---

## 1. 访存流程分解

| 阶段 | 描述 | 入口 / 出口 | 关键代码 |
| --- | --- | --- | --- |
| **T₀：SM → Sub-partition** | warp 访存发起，经互连到达 memory sub-partition | `mem_fetch::mem_fetch` → `memory_sub_partition::push` | `src/gpgpu-sim/mem_fetch.cc`, `src/gpgpu-sim/l2cache.cc:1204-1325` |
| **T₁：Sub-partition 仲裁** | 请求在本地仲裁、等待送入 MEE 队列或 DRAM latency queue | `memory_sub_partition::cache_cycle` 中的 `mee_dram_queue_*` 仲裁逻辑 | `src/gpgpu-sim/l2cache.cc:500-559` |
| **T₂：MEE 内部流水线** | 普通数据在 Cipher/AES/MAC/BMT 队列间流动；每个步骤可触发元数据访问 | `mee.cc` 中的 `CT_cycle` / `AES_cycle` / `META_cycle` / `BMT_cycle` | `src/gpgpu-sim/mee.cc:227-1188` |
| **T₃：安全元数据访存** | CTR/MAC/BMT cache miss 时发出新的 `mem_fetch` 访问 DRAM | `meta_access` → `mee_dram_queue_push` → `memory_partition_unit::mee_dram_queue_*` | `src/gpgpu-sim/mee.cc:148-222`, `src/gpgpu-sim/l2cache.cc:698-764` |
| **T₄：DRAM 服务** | 无论密文或元数据，最终在 `m_dram_latency_queue` → `dram_t::mrqq` → `dram_cycle` 中完成 | `src/gpgpu-sim/l2cache.cc:533-558`, `src/gpgpu-sim/dram.cc`, `src/gpgpu-sim/dram_sched.cc` |
| **T₅：返回 & 解密** | 密文返回 MEE，AES 解密、MAC/BMT 校验，写回 L2 | `CT_cycle` / `AES_cycle` 把数据送入 `mee_L2_queue` | `src/gpgpu-sim/mee.cc:227-598` |

> 说明：T₀~T₅ 的和近似等于 `averagemflatency`。其中 T₂ 与 T₃ 在传统模型中是隐含在 L2→DRAM 延迟中的，本方案将其显式化。

---

## 2. 延迟窗口定义

建议在 `mem_fetch` 中新增若干时间戳字段，以便统计不同阶段的等待时间：

| 字段 | 含义 | 设置位置 |
| --- | --- | --- |
| `subpartition_arrival_time` | T₀ 结束时间点 | `memory_sub_partition::push` | 
| `cipher_enqueue_time` | 进入 `m_Ciphertext_queue` 的时间 | `mee.cc:CT_cycle` push 之前 |
| `aes_enqueue_time` | 进入 `m_AES_queue` 的时间 | `mee.cc:AES_cycle` push 时 |
| `mac_enqueue_time` / `bmt_enqueue_time` | 进入 MAC/BMT 队列的时间 | `meta_access` push 时 |
| `meta_issue_time` | 元数据 miss 发出 DRAM 请求的时间 | `mee_dram_queue_push` |
| `cipher_dram_issue_time` | 密文（或写回密文）发送至 DRAM 的时间 | `mee_dram_queue_push(NORM)` |
| `decrypt_finish_time` | AES 解密完成时间 | `AES_cycle` 将明文推回 `mee_L2_queue` 前 |

利用这些字段即可计算：

- `lat_T1 = cipher_enqueue_time - subpartition_arrival_time`
- `lat_T2_cipher = (转出 Cipher 队列时间) - cipher_enqueue_time`
- `lat_AES_queue = (AES pop 时间) - aes_enqueue_time`
- `lat_AES_service = decrypt_finish_time - (AES pop 时间)` （约为 `m_config->m_crypto_latency`）
- `lat_MAC_queue`, `lat_BMT_queue` 等同理；
- `lat_meta = (memlatstat_read_done 时间) - meta_issue_time`；
- `lat_cipher_dram = (memlatstat_read_done 时间) - cipher_dram_issue_time`；
- `lat_T5 = (L2 接收时间) - decrypt_finish_time`。

---

## 3. Stall 指标定义

为捕捉每周期的阻塞来源，可在各阶段加入以下计数器：

| 计数器 | 累加条件 | 位置 |
| --- | --- | --- |
| `subpartition_arbitration_stall` | `mee_dram_queue` 满或 `can_issue_to_dram` 失败 | `memory_sub_partition::cache_cycle` |
| `cipher_queue_full_stall` | `m_Ciphertext_queue->full()` 导致本周期无法 push | `CT_cycle` |
| `aes_input_stall` | `m_AES_queue` 满或 OTP 未准备好 | `AES_cycle` |
| `mac_queue_full_stall` / `hash_queue_full_stall` | `m_MAC_queue` / `m_HASH_queue` 满 | `META_cycle` / `HASH_cycle` |
| `bmt_queue_full_stall` | `m_BMT_queue` 或 `m_BMT_CHECK_queue` 满 | `BMT_cycle` |
| `ctr_meta_resrv_stall` 等 | 元数据 cache 返回 `RESERVATION_FAIL` | `meta_access` |
| `mee_dram_queue_full_stall[type]` | `mee_dram_queue_full(type)` 为 true | `mee.cc` & `memory_partition_unit` |
| `mee_l2_queue_full_stall` | `mee_L2_queue_full()` | `CT_cycle` / `AES_cycle` |

所有 stall 计数均按 “周期数” 累加，便于和 GPU 总周期数对比。

---

## 4. 新增性能计数器总览

### 4.1 Sub-partition 层（T₁）

- `tot_subpartition_latency` / `max_subpartition_latency` / `subpartition_lat_table[32]`
- `subpartition_issued_requests`、`subpartition_arbitration_stall`

### 4.2 MEE Cipher/AES 阶段（T₂）

- `tot_cipher_queue_wait` / `max_cipher_queue_wait` / `cipher_queue_lat_table`
- `cipher_queue_full_stall`
- `tot_aes_queue_wait`、`max_aes_queue_wait`
- `tot_aes_service_time`（近似为 `请求数 × m_crypto_latency`）
- `aes_busy_cycles`、`aes_idle_cycles`、`aes_input_stall`

### 4.3 MAC 阶段

- `mac_cache_accesses` / `mac_cache_hits` / `mac_cache_misses`
- `tot_mac_queue_wait` / `max_mac_queue_wait`
- `mac_queue_full_stall`
- `tot_hash_queue_wait` / `hash_queue_full_stall`

### 4.4 BMT 阶段

- `bmt_cache_accesses` / `bmt_cache_misses`
- `tot_bmt_queue_wait` / `bmt_queue_full_stall`
- `tot_bmt_check_wait` / `bmt_check_queue_full_stall`

### 4.5 元数据 DRAM 访存（T₃）

- `ctr_meta_requests`, `ctr_meta_bytes`, `avg_ctr_meta_latency`, `max_ctr_meta_latency`
- `mac_meta_requests`, `mac_meta_bytes`, `avg_mac_meta_latency`, ...
- `bmt_meta_requests`, ...
- `meta_dram_bandwidth_ratio = meta_bytes_to_dram / total_dram_bytes`
- `mee_dram_queue_full_stall[CTR|MAC|BMT]`

### 4.6 普通数据 DRAM 访存（T₄）

- `cipher_dram_requests`, `cipher_dram_bytes`
- `avg_cipher_dram_latency`, `max_cipher_dram_latency`
- `normal_vs_meta_dram_conflicts`（两类请求争用 DRAM 接口时的周期数）

### 4.7 返回阶段（T₅）

- `tot_decrypt_to_l2_latency`, `max_decrypt_to_l2_latency`
- `mee_l2_queue_full_stall`
- `mee_l2_queue_occupancy_histogram`

---

## 5. 传统指标对照

| 指标 | 定义 | 代码 |
| --- | --- | --- |
| `averagemflatency` / `maxmflatency` | T₀~T₅ 总延迟 | `memlatstat_done` (`src/gpgpu-sim/mem_latency_stat.cc:189-208`) |
| `avg_icnt2mem_latency` / `max_icnt2mem_latency` | T₀ → T₁ 入口 | `memlatstat_icnt2mem_pop` (`同上`) |
| `avg_mrq_latency` / `maxmrqlatency` | T₄ 内部 (MRQ 排队) | `dram_sched.cc:230-249` |
| `avg_icnt2sh_latency` / `max_icnt2sh_latency` | T₅ 末尾 | `memlatstat_read_done` (`src/gpgpu-sim/mem_latency_stat.cc:205-219`) |
| `gpgpu_stall_shd_mem[*]` | Shader pipeline stall | `src/gpgpu-sim/shader.cc:640-689` |

新增的 T₁~T₅ 细分指标需要在 `memlatstat_print()` 或新增的 `mee_print_stats()` 中统一输出，方便与旧指标对比。

---

## 6. 输出格式建议

示例：

```
[SubPartition]
  requests                     : 123456
  avg_latency / max            : 220 / 1780
  latency_hist (cycles)        : ...
  stall_cycles (arbitration)   : 33450

[MEE-Cipher]
  avg_queue_wait / max         : 340 / 2500
  queue_full_stall_cycles      : 12890

[MEE-AES]
  avg_queue_wait / max         : 210 / 1180
  avg_service_time             : 40 (来自 crypto_latency)
  input_stall_cycles           : 452
  busy_cycles / idle_cycles    : 980000 / 120000

[MEE-MAC]
  cache_hit / miss             : 2.1M / 0.4M (miss_rate=16.0%)
  avg_meta_latency             : 820
  queue_full_stall_cycles      : 3200

[MEE-BMT]
  ...

[Meta-DRAM]
  ctr/meta requests / bytes    : 800K / 25 MB
  avg_ctr_meta_latency         : 1050
  mee_dram_queue_full_stall    : 5400

[Cipher-DRAM]
  requests / avg_latency       : 1.6M / 1600
  meta_contention_cycles       : 2100

[Return]
  avg_decrypt_to_l2_latency    : 120
  mee_l2_queue_full_stall      : 90

legacy averagemflatency        : 2286
legacy avg_icnt2mem_latency    : 2070
legacy avg_mrq_latency         : 16
legacy avg_icnt2sh_latency     : 2
```

输出越详细越好，即便包含冗余信息，也能帮助定位瓶颈。

---

## 7. 调试提示

1. 验证 `avg_subpartition_latency + avg_cipher_queue_wait + ... ≈ averagemflatency`，确保时间窗口统计正确。  
2. 若 `queue_full_stall` 类计数较大，可调大对应 FIFO 深度或增加并行 AES 单元。  
3. 观察 `meta_bytes_to_dram` 占比，评估安全元数据带宽占用；必要时考虑预取或元数据压缩。  
4. 利用 `*_lat_table` 中的对数直方图分析极端尾延迟，确定是否需要更细的排队策略。  
5. 将新增计数器与 `gpgpu_stall_shd_mem`、`mrq_lat_table` 原有指标一并导出便于回归比较。
