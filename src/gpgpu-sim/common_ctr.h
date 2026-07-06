#include "mee.h"

#ifndef COMMON_CTR_H
#define COMMON_CTR_H

class common_ctr {
public:

    common_ctr(class mee* _mee, class memory_partition_unit *unit, const memory_config *config, class memory_stats_t *stats, class gpgpu_sim *gpu);
    
    new_addr_type get_global_addr(new_addr_type partition_id, new_addr_type partition_addr);

    void gen_META_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id);

    void meta_access(new_addr_type addr, mem_access_type type, 
        unsigned size, bool wr, unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc, 
        mem_fetch *original_mf, unsigned mf_id, enum BMT_Layer m_Layer) const;

    void print_addr(char s[], mem_fetch *mf) const;
    void META_fill();
    void META_fill_responses();
    void META_cache_cycle();
    void cycle();

    bool full();

    void CCSM_handing(unsigned OTP_id);
    new_addr_type get_CCSM_index(new_addr_type addr);
    bool CCSM_scope(new_addr_type addr);
    void update_CCSM(new_addr_type addr, unsigned CCSM_val);
    void update_region_map(new_addr_type addr);
    void scan_region(new_addr_type region_addr);
    void scan_segment(new_addr_type segment_addr);

    void record_counter_service(bool common) {
        if (common) m_common_counter_served++;
        else m_normal_counter_served++;
    }
    unsigned long long get_common_counter_served() const {
        return m_common_counter_served;
    }
    unsigned long long get_normal_counter_served() const {
        return m_normal_counter_served;
    }

    class mee* m_mee;
    class memory_partition_unit *m_unit;
    const memory_config *m_config;
    class gpgpu_sim *m_gpu;
    partition_mf_allocator *m_mf_allocator;
    class memory_stats_t *m_stats;

    counterMap *m_updated_mem_region_map;
    counterMap *m_CCSM_map;
    class metainterface *m_METAinterface;
    class meta_cache *m_METAcache;
    fifo_pipeline<mem_fetch> *m_META_queue;
    fifo_pipeline<mem_fetch> *m_META_RET_queue;
    enum data_type m_data_type;
    unsigned long long m_common_counter_served = 0;
    unsigned long long m_normal_counter_served = 0;

    unsigned m_META_base = 0x00;
    unsigned m_meta_scale_shift = 12;
    unsigned m_meta_slot_shift = 0;

    new_addr_type m_region_block_mask   = 0xFFE00000;
    new_addr_type m_region_offset_mask  = 0x001E0000;
    new_addr_type m_segment_block_mask  = 0xFFFE0000;
    new_addr_type m_segment_offset_mask = 0x0001C0E0;
};

#endif
