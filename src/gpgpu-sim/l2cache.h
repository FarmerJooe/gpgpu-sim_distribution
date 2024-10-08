// Copyright (c) 2009-2021, Tor M. Aamodt, Vijay Kandiah, Nikos Hardavellas
// The University of British Columbia, Northwestern University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer;
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution;
// 3. Neither the names of The University of British Columbia, Northwestern 
//    University nor the names of their contributors may be used to
//    endorse or promote products derived from this software without specific
//    prior written permission.
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

#ifndef MC_PARTITION_INCLUDED
#define MC_PARTITION_INCLUDED

#include "../abstract_hardware_model.h"
#include "dram.h"
#include "gpu-cache.h"

#include <list>
#include <queue>

class mem_fetch;

class partition_mf_allocator : public mem_fetch_allocator {
 public:
  partition_mf_allocator(const memory_config *config) {
    m_memory_config = config;
  }
  virtual mem_fetch *alloc(const class warp_inst_t &inst,
                           const mem_access_t &access,
                           unsigned long long cycle) const {
    abort();
    return NULL;
  }
  virtual mem_fetch *alloc(new_addr_type addr, mem_access_type type,
                           unsigned size, bool wr,
                           unsigned long long cycle) const;
  virtual mem_fetch *alloc(new_addr_type addr, mem_access_type type,
                           const active_mask_t &active_mask,
                           const mem_access_byte_mask_t &byte_mask,
                           const mem_access_sector_mask_t &sector_mask,
                           unsigned size, bool wr, unsigned long long cycle,
                           unsigned wid, unsigned sid, unsigned tpc,
                           mem_fetch *original_mf) const;

 private:
  const memory_config *m_memory_config;
};

// Memory partition unit contains all the units assolcated with a single DRAM
// channel.
// - It arbitrates the DRAM channel among multiple sub partitions.
// - It does not connect directly with the interconnection network.
class memory_partition_unit {
 public:
  memory_partition_unit(unsigned partition_id, const memory_config *config,
                        class memory_stats_t *stats, class gpgpu_sim *gpu);
  ~memory_partition_unit();

  bool busy() const;

  void dram_to_mee_cycle();
  void mee_to_dram_cycle();
  void cache_cycle(unsigned cycle);
  void dram_cycle();
  void simple_dram_model_cycle();

  void set_done(mem_fetch *mf);

  void visualizer_print(gzFile visualizer_file) const;
  void print_stat(FILE *fp) { m_dram->print_stat(fp); }
  void visualize() const { m_dram->visualize(); }
  void print(FILE *fp) const;
  void accumulate_METAcache_stats(class cache_stats &l2_stats, char META[]) const;
  void get_METAcache_sub_stats(struct cache_sub_stats &css, char META[]) const;
  void handle_memcpy_to_gpu(size_t dst_start_addr, unsigned subpart_id,
                            mem_access_sector_mask_t mask);

  class memory_sub_partition *get_sub_partition(int sub_partition_id) {
    return m_sub_partition[sub_partition_id];
  }

  // Power model
  void set_dram_power_stats(unsigned &n_cmd, unsigned &n_activity,
                            unsigned &n_nop, unsigned &n_act, unsigned &n_pre,
                            unsigned &n_rd, unsigned &n_wr, unsigned &n_wr_WB,
                            unsigned &n_req) const;

  int global_sub_partition_id_to_local_id(int global_sub_partition_id) const;

  unsigned get_mpid() const { return m_id; }

  class gpgpu_sim *get_mgpu() const {
    return m_gpu;
  }

  bool L2_mee_queue_empty(unsigned spid) const;
  class mem_fetch *L2_mee_queue_top(unsigned spid) const;
  void L2_mee_queue_pop(unsigned spid);

  bool mee_dram_queue_empty() const;
  class mem_fetch *mee_dram_queue_top() const;
  void mee_dram_queue_pop();
  bool mee_dram_queue_full(enum data_type dtype) const;
  bool mee_dram_queue_full(int size, enum data_type dtype) const;
  void mee_dram_queue_push(class mem_fetch *mf, enum data_type dtype);

  bool dram_mee_queue_empty(enum data_type dtype) const;
  class mem_fetch *dram_mee_queue_top(enum data_type dtype) const;
  void dram_mee_queue_pop(enum data_type dtype);
  bool dram_mee_queue_full() const;
  void dram_mee_queue_push(class mem_fetch *mf);

  void mee_L2_queue_push(unsigned spid, class mem_fetch *mf);
  bool mee_L2_queue_full(unsigned spid) const;

  class memory_sub_partition **m_sub_partition;
  
 private:
  unsigned m_id;
  const memory_config *m_config;
  class memory_stats_t *m_stats;
  // class memory_sub_partition **m_sub_partition;
  class dram_t *m_dram;

  class meta_cache *m_CTRcache;
  class meta_cache *m_MACcache;
  class meta_cache *m_BMTcache;
  class mee *m_mee;
  // class metainterface *m_metainterface;
  class metainterface *m_BMTinterface;
  class metainterface *m_CTRinterface;
  class metainterface *m_MACinterface;
  partition_mf_allocator *m_mf_allocator;

 public:
  unsigned long long m_cache_NORM_acc;
  unsigned long long m_cache_CTR_acc;
  unsigned long long m_cache_MAC_acc;
  unsigned long long m_cache_BMT_acc;
  unsigned long long m_cache_meta_wb;

 private:
  fifo_pipeline<mem_fetch> *m_mee_dram_queue[5]; 
  fifo_pipeline<mem_fetch> *m_dram_mee_queue[5]; 
  const unsigned send_trigger_threshold = 16;
  const unsigned receive_stop_threshold = 16;
  unsigned last_send = 0;
  // fifo_pipeline<mem_fetch> *m_NORM_dram_queue; 
  // fifo_pipeline<mem_fetch> *m_CTR_dram_queue; 
  // fifo_pipeline<mem_fetch> *m_MAC_dram_queue; 
  // fifo_pipeline<mem_fetch> *m_BMT_dram_queue;

  // fifo_pipeline<mem_fetch> *m_dram_NORM_queue;
  // fifo_pipeline<mem_fetch> *m_dram_CTR_queue;
  // fifo_pipeline<mem_fetch> *m_dram_MAC_queue;
  // fifo_pipeline<mem_fetch> *m_dram_BMT_queue; 

  class arbitration_metadata {
   public:
    arbitration_metadata(const memory_config *config);

    // check if a subpartition still has credit
    bool has_credits(int inner_sub_partition_id) const;
    // borrow a credit for a subpartition
    void borrow_credit(int inner_sub_partition_id);
    // return a credit from a subpartition
    void return_credit(int inner_sub_partition_id);

    // return the last subpartition that borrowed credit
    int last_borrower() const { return m_last_borrower; }

    void print(FILE *fp) const;

   private:
    // id of the last subpartition that borrowed credit
    int m_last_borrower;

    int m_shared_credit_limit;
    int m_private_credit_limit;

    // credits borrowed by the subpartitions
    std::vector<int> m_private_credit;
    int m_shared_credit;
  };
  arbitration_metadata m_arbitration_metadata;

  // determine wheither a given subpartition can issue to DRAM
  bool can_issue_to_dram(int inner_sub_partition_id);

  // model DRAM access scheduler latency (fixed latency between L2 and DRAM)
  struct dram_delay_t {
    unsigned long long ready_cycle;
    class mem_fetch *req;
  };
  std::list<dram_delay_t> m_dram_latency_queue;

  class gpgpu_sim *m_gpu;

  friend class mee;
};

class memory_sub_partition {
 public:
  memory_sub_partition(unsigned sub_partition_id, const memory_config *config,
                       class memory_stats_t *stats, class gpgpu_sim *gpu);
  ~memory_sub_partition();

  unsigned get_id() const { return m_id; }

  bool busy() const;

  void cache_cycle(unsigned cycle);

  bool full() const;
  bool full(unsigned size) const;
  void push(class mem_fetch *mf, unsigned long long clock_cycle);
  class mem_fetch *pop();
  class mem_fetch *top();
  void set_done(mem_fetch *mf);

  unsigned flushL2();
  unsigned invalidateL2();

  // interface to L2_mee_queue
  bool L2_mee_queue_empty() const;
  class mem_fetch *L2_mee_queue_top() const;
  void L2_mee_queue_pop();

  // interface to mee_dram_queue
  bool mee_dram_queue_full() const;
  void mee_dram_queue_push(class mem_fetch *mf);

  bool mee_dram_queue_empty() const;
  class mem_fetch *mee_dram_queue_top() const;
  void mee_dram_queue_pop();

  // interface to dram_mee_queue
  bool dram_mee_queue_full() const;
  void dram_mee_queue_push(class mem_fetch *mf);

  bool dram_mee_queue_empty() const;
  class mem_fetch *dram_mee_queue_top() const;
  void dram_mee_queue_pop();

  // interface to mee_L2_queue
  bool mee_L2_queue_full() const;
  void mee_L2_queue_push(class mem_fetch *mf);

  void visualizer_print(gzFile visualizer_file);
  void print_cache_stat(unsigned &accesses, unsigned &misses) const;
  void print(FILE *fp) const;

  void accumulate_L2cache_stats(class cache_stats &l2_stats) const;
  void get_L2cache_sub_stats(struct cache_sub_stats &css) const;

  // Support for getting per-window L2 stats for AerialVision
  void get_L2cache_sub_stats_pw(struct cache_sub_stats_pw &css) const;
  void clear_L2cache_stats_pw();

  void force_l2_tag_update(new_addr_type addr, unsigned time,
                           mem_access_sector_mask_t mask) {
    m_L2cache->force_tag_access(addr, m_memcpy_cycle_offset + time, mask);
    m_memcpy_cycle_offset += 1;
  }
  // class l2_cache *m_CTRcache;
  std::vector<mem_fetch *> breakdown_request_to_sector_requests(mem_fetch *mf);

  // these are various FIFOs between units within a memory partition
  fifo_pipeline<mem_fetch> *m_icnt_L2_queue;
  fifo_pipeline<mem_fetch> *m_L2_mee_queue;
  // fifo_pipeline<mem_fetch> *m_mee_dram_queue; 
  // fifo_pipeline<mem_fetch> *m_dram_mee_queue; 
  fifo_pipeline<mem_fetch> *m_mee_L2_queue;
  fifo_pipeline<mem_fetch> *m_L2_icnt_queue;  // L2 cache hit response queue
  
 private:
  // data
  unsigned m_id;  //< the global sub partition ID
  const memory_config *m_config;
  class l2_cache *m_L2cache;
  class L2interface *m_L2interface;
  // class l2_cache *m_CTRcache;
  // class l2_cache *m_MACcache;
  // class l2_cache *m_BMTcache;
  // class mee *m_mee;
  // class metainterface *m_metainterface;
  class gpgpu_sim *m_gpu;
  partition_mf_allocator *m_mf_allocator;

  // model delay of ROP units with a fixed latency
  struct rop_delay_t {
    unsigned long long ready_cycle;
    class mem_fetch *req;
  };
  std::queue<rop_delay_t> m_rop;

  class mem_fetch *L2dramout;
  unsigned long long int wb_addr;

  class memory_stats_t *m_stats;

  std::set<mem_fetch *> m_request_tracker;

  friend class L2interface;
  friend class metainterface;

  // std::vector<mem_fetch *> breakdown_request_to_sector_requests(mem_fetch *mf);

  // This is a cycle offset that has to be applied to the l2 accesses to account
  // for the cudamemcpy read/writes. We want GPGPU-Sim to only count cycles for
  // kernel execution but we want cudamemcpy to go through the L2. Everytime an
  // access is made from cudamemcpy this counter is incremented, and when the l2
  // is accessed (in both cudamemcpyies and otherwise) this value is added to
  // the gpgpu-sim cycle counters.
  unsigned m_memcpy_cycle_offset;
};

class L2interface : public mem_fetch_interface {
 public:
  L2interface(memory_sub_partition *unit) { m_unit = unit; }
  virtual ~L2interface() {}
  virtual bool full(unsigned size, bool write) const {
    // assume read and write packets all same size
    return m_unit->m_L2_mee_queue->full();
  }
  virtual void push(mem_fetch *mf) {
    mf->set_status(IN_PARTITION_L2_TO_DRAM_QUEUE, 0 /*FIXME*/);
    m_unit->m_L2_mee_queue->push(mf);
    // if (mf->get_access_type() == 9)
    // printf("%saddr: %x\tsp_id: %d\tsp_addr: %x\twr: %d\taccess type:%d\n", "L2 to mee:", mf->get_addr(), mf->get_sid(), mf->get_is_write(), mf->get_partition_addr(), mf->get_access_type());

    // printf("l2 to mee access type: %d\n",mf->get_access_type());
  }

 private:
  memory_sub_partition *m_unit;
};

class metainterface : public mem_fetch_interface {
 public:
  // metainterface(memory_partition_unit *unit, enum cache_type dtype) { 
  metainterface(fifo_pipeline<mem_fetch> *pipeline) { 
    // m_unit = unit;
    // m_dtype = dtype;
    this->pipeline = pipeline;
  }
  virtual ~metainterface() {}
  virtual bool full(unsigned size, bool write) const {
    // assume read and write packets all same size
    // return m_unit->mee_dram_queue_full();
    return pipeline->full();
  }
  virtual void push(mem_fetch *mf) {
    mf->set_status(IN_PARTITION_L2_TO_DRAM_QUEUE, 0 /*FIXME*/);
    // printf("%saddr: %x\tmf_type: %d\tsp_addr: %x\taccess type:%d\n", "mee to dram:\t", mf->get_addr(), mf->get_data_type(), mf->get_partition_addr(), mf->get_access_type());

    // m_unit->mee_dram_queue_push(mf);
    pipeline->push(mf);
  }

 private:
  memory_partition_unit *m_unit;
  enum cache_type m_dtype;
  fifo_pipeline<mem_fetch> *pipeline;
};

#endif
