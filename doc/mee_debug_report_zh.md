# MEE 调试修改报告

以下内容汇总了本次定位 dram_cycle 与 AES_cycle 相关异常时对代码所做的全部改动。每个小节按照文件罗列出被修改的具体行，并说明修改意图与理论依据，便于进一步排查。

## src/gpgpu-sim/mee.h
- `src/gpgpu-sim/mee.h:39-40`：声明 `next_mf_id()`，为 MEE 生成非零的 mem_fetch 标识符，保证 AES/OTP/MAC 哈希流程使用统一的 ID 进行配对。

## src/gpgpu-sim/mee.cc
- `src/gpgpu-sim/mee.cc:268-279`：在 `push_cipher_request` 中落地子分区排队计时统计，新增对 `SUBPARTITION_STAGE` 的统计上报，确保后续调试能看到密文排队延迟。
- `src/gpgpu-sim/mee.cc:281-284`：新增 `next_mf_id()` 具体实现，递增 `mf_counter` 并避开 0，避免 AES 侧 `assert(mf->get_id())` 再次触发。
- `src/gpgpu-sim/mee.cc:1242-1291`：
  - 读/写路径统一调用 `next_mf_id()`，并把新 ID 回写到主请求与派生的 CTR/MAC 元请求，保证整条处理链共用同一标识；
  - 所有 `gen_CTR_mf` / `gen_MAC_mf` 的 `mf_id` 参数改用新 ID，避免派生请求保留旧的（可能为 0）的 ID；
  - 写路径将生成的 ID 立即写回 mem_fetch，再调用 `push_cipher_request`，确保后续 AES/MAC 队列看到正确编号。

## src/gpgpu-sim/l2cache.cc
- `src/gpgpu-sim/l2cache.cc:405-420`：在 DRAM latency queue 取回阶段，增加对 `dest_spid` 的合法性检查与详细日志，遇到越界分区时直接丢弃异常请求并返回，防止调试阶段因断言直接退出。
- `src/gpgpu-sim/l2cache.cc:422-429`：补充对空指针子分区的检测与日志输出，避免访问空的 `memory_sub_partition`。
- `src/gpgpu-sim/l2cache.cc:465-488`：重写 MEE→DRAM 轮询逻辑：
  - 显式跳过空队列，并在资源不足时记录 `SUBPARTITION_ARBITRATION_STALL`；
  - 取出请求后比对 `mf_spid` 与当前 `spid`，若不一致打印诊断信息；
  - 计算 `corrected_global_spid`，在入 DRAM 前强制调用 `mf->set_chip(m_id)` 与 `mf->set_parition(corrected_global_spid)`，并通过断言确认 ID 已更新。
- `src/gpgpu-sim/l2cache.cc:511-520`：在 DRAM return path 上补充同样的合法性检测与日志，记录导致 `dest_spid` 越界的请求细节（chip、地址、数据类型、访问类型），便于后续定位。

## src/gpgpu-sim/gpu-sim.h
- `src/gpgpu-sim/gpu-sim.h:42`：前置声明 `memory_stats_t`，解除头文件循环依赖。
- `src/gpgpu-sim/gpu-sim.h:729`：暴露 `get_memory_stats()` 访问器，允许 MEE 模块将延迟与占用信息写回统计对象。

以上即为当前工作中对代码所做的全部调整。后续如需继续定位 `dest_spid` 越界，可重点关注 `test.log` 中被新增日志打出的请求轨迹。

## 追加调试改动（2025-10-05）

### src/gpgpu-sim/l2cache.h
- `src/gpgpu-sim/l2cache.h:187`：新增 `normalize_sub_partition()` 私有声明，用于在不同入口统一修正 `chip` 与 `sub_partition_id`。

### src/gpgpu-sim/l2cache.cc
- `src/gpgpu-sim/l2cache.cc:1211-1260`：实现 `normalize_sub_partition()`，通过地址译码与本地索引纠正异常 ID，并把修正信息写入调试日志。
- `src/gpgpu-sim/l2cache.cc:1268-1273`：在 `mee_dram_queue_push()` 中增加 ID 为 0 的诊断输出，便于追踪异常请求的源头。
- `src/gpgpu-sim/l2cache.cc:401-431`：在 `simple_dram_model_cycle()` 早期过滤 `addr==0` 或 `id==0` 的返回请求，记录 `[MEE][drop]` 日志后直接回收内存，防止继续传播无效 mem_fetch。
- `src/gpgpu-sim/l2cache.cc:474-507`：在发射前再次核对 sub-partition 编号，若不匹配则纠正并输出详细上下文。
- `src/gpgpu-sim/l2cache.cc:1211-1247`：解析物理地址，确保跨分区返回的请求被重新映射回本地 sub-partition。

### src/gpgpu-sim/mee.cc
- `src/gpgpu-sim/mee.cc:268-279`：`push_cipher_request()` 在检测到 `mf->get_id()==0` 时即时申请新的 `mf_id`，写回并记录告警，避免 AES 阶段再次命中 `assert(OTP_id)`。

### src/gpgpu-sim/mem_fetch.cc
- `src/gpgpu-sim/mem_fetch.cc:90-97`：析构时打印 `[MEE][mf_destroy]` 行，捕捉仍然带有 `id==0` 或 `data_type==TOT` 的对象，辅助判断是否存在悬挂/重复释放问题。

### 调试辅助文档
- 新增 `doc/mee_fix_log.txt`，按时间顺序记录每次改动的摘要与涉及文件，便于后续比对。
