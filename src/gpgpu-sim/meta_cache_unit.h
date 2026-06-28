#include "mee.h"

#ifndef META_CACHE_UNIT_H
#define META_CACHE_UNIT_H

class META_CACHE_UNIT {
public:

    META_CACHE_UNIT(class mee* _mee, class memory_partition_unit *unit, const memory_config *config, class memory_stats_t *stats, class gpgpu_sim *gpu, enum data_type _data_type);

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

    class mee* m_mee;
    class memory_partition_unit *m_unit;
    const memory_config *m_config;
    class gpgpu_sim *m_gpu;
    partition_mf_allocator *m_mf_allocator;
    class memory_stats_t *m_stats;

    class metainterface *m_METAinterface;
    class meta_cache *m_METAcache;
    fifo_pipeline<mem_fetch> *m_META_queue;
    fifo_pipeline<mem_fetch> *m_META_RET_queue;
    enum data_type m_data_type;

    unsigned m_META_base = 0x00;
    unsigned m_meta_scale_shift = 12;
    unsigned m_meta_slot_shift = 0;

};

#endif