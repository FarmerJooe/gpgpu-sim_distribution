// Copyright (c) 2009-2011, Tor M. Aamodt
// The University of British Columbia
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. Neither the name of
// The University of British Columbia nor the names of its contributors may be
// used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef MEM_LATENCY_STAT_H
#define MEM_LATENCY_STAT_H

#include <stdio.h>
#include <zlib.h>
#include <map>

enum mee_latency_stage {
  SUBPARTITION_STAGE = 0,
  CIPHER_QUEUE_STAGE,
  AES_QUEUE_STAGE,
  AES_SERVICE_STAGE,
  CTR_QUEUE_STAGE,
  MAC_QUEUE_STAGE,
  PAR_QUEUE_STAGE,
  BMT_QUEUE_STAGE,
  HASH_QUEUE_STAGE,
  BMT_CHECK_STAGE,
  CTR_META_STAGE,
  MAC_META_STAGE,
  BMT_META_STAGE,
  PAR_META_STAGE,
  CIPHER_DRAM_STAGE,
  RETURN_STAGE,
  NUM_MEE_LATENCY_STAGE
};

enum mee_stall_stage {
  SUBPARTITION_ARBITRATION_STALL = 0,
  CIPHER_QUEUE_FULL_STALL,
  AES_INPUT_STALL,
  MAC_QUEUE_FULL_STALL,
  HASH_QUEUE_FULL_STALL,
  BMT_QUEUE_FULL_STALL,
  BMT_CHECK_QUEUE_FULL_STALL,
  PAR_QUEUE_FULL_STALL,
  CTR_META_RESERVATION_STALL,
  MAC_META_RESERVATION_STALL,
  BMT_META_RESERVATION_STALL,
  PAR_META_RESERVATION_STALL,
  MEE_DRAM_QUEUE_FULL_STALL_CTR,
  MEE_DRAM_QUEUE_FULL_STALL_MAC,
  MEE_DRAM_QUEUE_FULL_STALL_BMT,
  MEE_DRAM_QUEUE_FULL_STALL_PAR,
  MEE_DRAM_QUEUE_FULL_STALL_DATA,
  MEE_L2_QUEUE_FULL_STALL,
  NUM_MEE_STALL_STAGE
};

enum meta_access_type {
  META_ACCESS_CTR = 0,
  META_ACCESS_MAC,
  META_ACCESS_BMT,
  META_ACCESS_PAR,
  META_ACCESS_CCSM,
  NUM_META_ACCESS_TYPE
};

struct stage_latency_stats {
  unsigned long long total;
  unsigned long long max;
  unsigned long long samples;
  unsigned long long hist[32];
  void clear() {
    total = 0;
    max = 0;
    samples = 0;
    for (unsigned i = 0; i < 32; ++i) hist[i] = 0;
  }
  void add(unsigned long long latency);
};

class memory_config;
class memory_stats_t {
 public:
  memory_stats_t(unsigned n_shader,
                 const class shader_core_config *shader_config,
                 const memory_config *mem_config, const class gpgpu_sim *gpu);

  unsigned memlatstat_done(class mem_fetch *mf);
  void memlatstat_read_done(class mem_fetch *mf);
  void memlatstat_dram_access(class mem_fetch *mf);
  void memlatstat_icnt2mem_pop(class mem_fetch *mf);
  void memlatstat_lat_pw();
  void memlatstat_print(unsigned n_mem, unsigned gpu_mem_n_bk);

  void record_subpartition_queue_latency(unsigned sub_partition_id,
                                         unsigned long long latency);

  void record_stage_latency(enum mee_latency_stage stage,
                            unsigned long long latency);
  void record_stage_stall(enum mee_stall_stage stage,
                          unsigned long long cycles = 1);
  void record_meta_request(enum meta_access_type type, unsigned bytes);
  void record_meta_latency(enum meta_access_type type,
                           unsigned long long latency);
  void record_cipher_dram_request(unsigned bytes);
  void record_cipher_dram_latency(unsigned long long latency);
  void record_return_latency(unsigned long long latency);
  void record_aes_busy(unsigned long long cycles);
  void record_aes_idle(unsigned long long cycles = 1);

  void visualizer_print(gzFile visualizer_file);

  // Reset local L2 stats that are aggregated each sampling window
  void clear_L2_stats_pw();

  unsigned m_n_shader;

  const shader_core_config *m_shader_config;
  const memory_config *m_memory_config;
  const class gpgpu_sim *m_gpu;

  unsigned max_mrq_latency;
  unsigned max_dq_latency;
  unsigned max_mf_latency;
  unsigned max_icnt2mem_latency;
  unsigned long long int tot_icnt2mem_latency;
  unsigned long long int tot_icnt2sh_latency;
  unsigned long long int tot_mrq_latency;
  unsigned long long int tot_mrq_num;
  unsigned max_icnt2sh_latency;
  unsigned mrq_lat_table[32];
  unsigned dq_lat_table[32];
  unsigned mf_lat_table[32];
  unsigned icnt2mem_lat_table[24];
  unsigned icnt2sh_lat_table[24];
  unsigned mf_lat_pw_table[32];  // table storing values of mf latency Per
                                 // Window
  unsigned mf_num_lat_pw;
  unsigned max_warps;
  unsigned mf_tot_lat_pw;  // total latency summed up per window. divide by
                           // mf_num_lat_pw to obtain average latency Per Window
  unsigned long long int mf_total_lat;

  unsigned long long subpartition_queue_wait_sum;
  unsigned long long subpartition_queue_wait_max;
  unsigned long long subpartition_queue_wait_samples;
  unsigned subpartition_queue_wait_hist[32];
  unsigned long long *subpartition_queue_wait_sum_per_sp;
  unsigned long long *subpartition_queue_wait_max_per_sp;
  unsigned long long *subpartition_queue_wait_samples_per_sp;
  unsigned long long int *
      *mf_total_lat_table;      // mf latency sums[dram chip id][bank id]
  unsigned **mf_max_lat_table;  // mf latency sums[dram chip id][bank id]
  unsigned num_mfs;
  unsigned int ***bankwrites;  // bankwrites[shader id][dram chip id][bank id]
  unsigned int ***bankreads;   // bankreads[shader id][dram chip id][bank id]
  unsigned int **totalbankwrites;    // bankwrites[dram chip id][bank id]
  unsigned int **totalbankreads;     // bankreads[dram chip id][bank id]
  unsigned int **totalbankaccesses;  // bankaccesses[dram chip id][bank id]
  unsigned int
      *num_MCBs_accessed;  // tracks how many memory controllers are accessed
                           // whenever any thread in a warp misses in cache
  unsigned int *position_of_mrq_chosen;  // position of mrq in m_queue chosen

  unsigned ***mem_access_type_stats;  // dram access type classification

  // AerialVision L2 stats
  unsigned L2_read_miss;
  unsigned L2_write_miss;
  unsigned L2_read_hit;
  unsigned L2_write_hit;

  // L2 cache stats
  unsigned int *L2_cbtoL2length;
  unsigned int *L2_cbtoL2writelength;
  unsigned int *L2_L2tocblength;
  unsigned int *L2_dramtoL2length;
  unsigned int *L2_dramtoL2writelength;
  unsigned int *L2_L2todramlength;

  // DRAM access row locality stats
  unsigned int *
      *concurrent_row_access;    // concurrent_row_access[dram chip id][bank id]
  unsigned int **num_activates;  // num_activates[dram chip id][bank id]
  unsigned int **row_access;     // row_access[dram chip id][bank id]
  unsigned int **max_conc_access2samerow;  // max_conc_access2samerow[dram chip
                                           // id][bank id]
  unsigned int **max_servicetime2samerow;  // max_servicetime2samerow[dram chip
                                           // id][bank id]

  // Power stats
  unsigned total_n_access;
  unsigned total_n_reads;
  unsigned total_n_writes;

  stage_latency_stats m_stage_latency[NUM_MEE_LATENCY_STAGE];
  unsigned long long m_stage_stall[NUM_MEE_STALL_STAGE];

  unsigned long long m_meta_requests[NUM_META_ACCESS_TYPE];
  unsigned long long m_meta_bytes[NUM_META_ACCESS_TYPE];
  stage_latency_stats m_meta_latency[NUM_META_ACCESS_TYPE];

  unsigned long long m_cipher_dram_requests;
  unsigned long long m_cipher_dram_bytes;
  stage_latency_stats m_cipher_dram_latency;

  stage_latency_stats m_return_latency;

  unsigned long long m_aes_busy_cycles;
  unsigned long long m_aes_idle_cycles;
};

#endif /*MEM_LATENCY_STAT_H*/
