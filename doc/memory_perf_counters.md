# GPGPU-Sim Memory Performance Counters

## 1. Stall and Access Taxonomy
- Memory-stage access types (`C_MEM`, `T_MEM`, `S_MEM`, `G_MEM_LD`, `L_MEM_LD`, `G_MEM_ST`, `L_MEM_ST`) define which memory pipeline a stall belongs to, as declared in `src/gpgpu-sim/stats.h#L33`.
- Stall causes (`BK_CONF`, `MSHR_RC_FAIL`, `ICNT_RC_FAIL`, `COAL_STALL`, `TLB_STALL`, `DATA_PORT_STALL`, `WB_ICNT_RC_FAIL`, `WB_CACHE_RSRV_FAIL`) enumerate the resource that blocked progress in `src/gpgpu-sim/stats.h#L43`.

## 2. Shader-Core Memory Stall Counters
- `shader_core_ctx::cycle` records memory-pipeline stalls: it patches `rc_fail` and `type` from the individual memory pipelines and increments both `gpgpu_n_stall_shd_mem` (total occurrences) and the 2D histogram `gpu_stall_shd_mem_breakdown[type][rc_fail]` (`src/gpgpu-sim/shader.cc#L2768`, `src/gpgpu-sim/shader.cc#L2770`, `src/gpgpu-sim/shader.cc#L2771`).
- These counters live in `shader_core_stats_pod`, which also stores derived metrics such as `gpgpu_n_cmem_portconflict` and per-SM shared-bank access counts (`src/gpgpu-sim/shader.h#L1765`, `src/gpgpu-sim/shader.h#L1766`, `src/gpgpu-sim/shader.h#L1772`).

### 2.1 Stall Producers
- Shared memory: `shared_cycle` flags bank conflicts by calling `inst.dispatch_delay()` and, on failure, tags the stall as `S_MEM/BK_CONF` while incrementing the shared bank access counter (`src/gpgpu-sim/shader.cc#L1874`, `src/gpgpu-sim/shader.cc#L1884`).
- Constant memory: `constant_cycle` invokes the L1C cache path and, when a bank or coalescing stall occurs, bumps both the stall histogram (`C_MEM`) and the dedicated `gpgpu_n_cmem_portconflict` counter (`src/gpgpu-sim/shader.cc#L2116`, `src/gpgpu-sim/shader.cc#L2122`).
- Texture memory: `texture_cycle` funnels stalls from the texture cache into the histogram with access type `T_MEM` (`src/gpgpu-sim/shader.cc#L2131`, `src/gpgpu-sim/shader.cc#L2136`).
- Global/local memory: `memory_cycle` decides between bypassing L1D or accessing it. Network back-pressure (`ICNT_RC_FAIL`), cache-port saturation (`DATA_PORT_STALL`), or outstanding coalescers (`COAL_STALL`) become histogram entries with the correct access type (`G_MEM_*` or `L_MEM_*`) (`src/gpgpu-sim/shader.cc#L2143`, `src/gpgpu-sim/shader.cc#L2164`, `src/gpgpu-sim/shader.cc#L2170`, `src/gpgpu-sim/shader.cc#L2189`).

## 3. GPU-Level Congestion Counters
- The top-level simulator tracks interconnect and DRAM back-pressure independently of per-SM stalls. When memory replies are ready but the network ejection buffer is saturated, `gpu_stall_icnt2sh` increments (`src/gpgpu-sim/gpu-sim.cc#L2133`, `src/gpgpu-sim/gpu-sim.cc#L2137`).
- When the memory sub-partition input queue is full, incoming requests are counted in `gpu_stall_dramfull` (`src/gpgpu-sim/gpu-sim.cc#L2176`, `src/gpgpu-sim/gpu-sim.cc#L2177`). These counters quantify macroscopic pipeline bubbles caused by the memory fabric.

## 4. Cache Stall Cycle Accounting
- Every `mem_fetch` records the cycle when a miss is issued (`set_miss_cycle`) and when the fill completes (`set_fill_cycle`), enabling latency measurements per cache (`src/gpgpu-sim/gpu-cache.cc#L1864`, `src/gpgpu-sim/gpu-cache.cc#L1214`). The timestamps are stored inside `mem_fetch` (`src/gpgpu-sim/mem_fetch.h#L204`, `src/gpgpu-sim/mem_fetch.h#L214`).
- `cache_stats::inc_stall_cycles` aggregates the delta (fill minus miss) into cumulative stall cycles and counts, both globally and per sampling window (`src/gpgpu-sim/gpu-cache.cc#L811`).
- Because `baseline_cache::fill` always invokes `inc_stall_cycles`, both L1 and L2 caches naturally collect latency-derived stall time whenever a miss completes (`src/gpgpu-sim/gpu-cache.cc#L1212`, `src/gpgpu-sim/gpu-cache.cc#L1215`).

## 5. Memory-Latency Instrumentation (`memory_stats_t`)
- `memlatstat_icnt2mem_pop` logs the delay between shader issue and arrival at the memory partition input, updating histograms and maxima for the interconnect path (`src/gpgpu-sim/mem_latency_stat.cc#L248`, `src/gpgpu-sim/mem_latency_stat.cc#L253`). It is triggered when a request leaves the interconnect for L2/DRAM (`src/gpgpu-sim/l2cache.cc#L1300`).
- `memlatstat_dram_access` classifies DRAM bank activity and counts per-bank accesses when the DRAM front-end enqueues a request (`src/gpgpu-sim/mem_latency_stat.cc#L222`, `src/gpgpu-sim/dram.cc#L260`).
- `memlatstat_read_done` captures the full round-trip latency (issue to data return) and the return-path interconnect delay, maintaining maxima, totals, and logarithmic histograms (`src/gpgpu-sim/mem_latency_stat.cc#L205`, `src/gpgpu-sim/mem_latency_stat.cc#L213`). It is invoked as soon as a response enters the SIMT cluster ejection FIFO (`src/gpgpu-sim/shader.cc#L4526`).
- `memlatstat_done` serves as the common helper that tallies per-fetch latency, per-bank sums, and the global histogram (`src/gpgpu-sim/mem_latency_stat.cc#L189`).
- Periodically, `gpgpu_sim::update_stats` folds per-window latency accumulations into long-term averages via `memlatstat_lat_pw`, while `memlatstat_print` reports extrema and averages for the various latency paths (`src/gpgpu-sim/gpu-sim.cc#L1159`, `src/gpgpu-sim/mem_latency_stat.cc#L260`, `src/gpgpu-sim/mem_latency_stat.cc#L271`).

### 5.1 DRAM Scheduler Queue Latency
- When the FR-FCFS scheduler dequeues a request into a bank, it measures queue residency (`mrq_latency`) and updates both the running average (`tot_mrq_latency`/`tot_mrq_num`) and the histogram/max tracker (`mrq_lat_table`, `max_mrq_latency`) (`src/gpgpu-sim/dram_sched.cc#L236`, `src/gpgpu-sim/dram_sched.cc#L244`).

## 6. Related Conflict Counters
- Shared-memory bank conflict attempts are counted via `gpgpu_n_shmem_bank_access` whenever `inst.has_dispatch_delay()` returns true in `shared_cycle`, providing additional texture on shared-memory stalls (`src/gpgpu-sim/shader.cc#L1880`).
- Constant-memory port conflicts (`gpgpu_n_cmem_portconflict`) rise whenever the constant pipeline reports `BK_CONF` or `COAL_STALL`, aligning that counter with the stall histogram for correlation studies (`src/gpgpu-sim/shader.cc#L2122`).

## 7. How to Use These Counters
- Combine the shader-stage histogram with the global `gpu_stall_*` counters to separate SM-local bottlenecks from network/DRAM back-pressure.
- Cross-check cache stall cycles against DRAM latency histograms to determine whether long round-trip times or cache structural hazards dominate observed stalls.
- The logarithmic histograms (`mf_lat_table`, `icnt2mem_lat_table`, `mrq_lat_table`) are ready-made for plotting latency distributions without modifying the simulator; dump them through the existing `memlatstat_print` hook.
