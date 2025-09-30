#include "ctr-cache.h"
#include "l2cache.h"

enum cache_request_status ctr_cache::access(new_addr_type addr, mem_fetch *mf,
                                             unsigned time,
                                             std::list<cache_event> &events) {

    if (overflow()) {
        // printf("befor evict:\n");
        // print_set_segments_stats();
        prevent_overflow(mf, time, events);
        // printf("after evict:\n");
        // print_set_segments_stats();
        update_ctr_cache_segments_stats();
        if (overflow()) {
            return RESERVATION_FAIL;
        }
    }

    assert(mf->get_data_size() <= m_config.get_atom_sz());
    bool wr = mf->get_is_write();
    new_addr_type block_addr = m_config.block_addr(addr);
    unsigned cache_index = (unsigned)-1;
    enum cache_request_status probe_status =
        m_tag_array->probe(block_addr, cache_index, mf, mf->is_write(), true);
    enum cache_request_status access_status =
        process_tag_probe(wr, probe_status, addr, cache_index, mf, time, events);

    if (access_status != RESERVATION_FAIL) {
        m_line_used_sigments[cache_index] = std::max(m_line_used_sigments[cache_index], get_ctr_data_sigments(mf->get_addr()));
        // printf("insert line[%d] = %u:\n", cache_index, m_line_used_sigments[cache_index]);
        // print_line_segments_stats();
        update_ctr_cache_segments_stats();
    }

    m_stats.inc_stats(mf->get_access_type(),
                        m_stats.select_stats_status(probe_status, access_status));
    m_stats.inc_stats_pw(mf->get_access_type(), m_stats.select_stats_status(
                                                    probe_status, access_status));
    if (access_status == MISS || access_status == SECTOR_MISS)
        mf->set_miss_cycle(get_cache_form(), time);                                              
    return access_status;
}

mem_fetch* gen_mf(class mem_fetch_allocator *m_mf_allocator, unsigned long long cycle) {

    new_addr_type m_addr = 0xdeadbeef;

    mem_fetch *mf = m_mf_allocator->alloc(
        m_addr, META_ACC, 32, true, cycle);
    
    return mf;
}

void test_access(class ctr_cache *m_CTRcache, class mem_fetch_allocator *m_mf_allocator, 
        unsigned long long cycle) {

    std::list<cache_event> events;

    mem_fetch *mf = gen_mf(m_mf_allocator, cycle);
    m_CTRcache->access(mf->get_addr(), mf, cycle, events);

}

void test_ctr_cache(class gpgpu_sim *gpu) {

    char CTRc_name[32];

    class ctr_cache *m_CTRcache;

    class mem_fetch_interface *m_CTRinterface;

    class mem_fetch_allocator *m_mf_allocator;

    // // class gpgpu_sim *gpu;

    // m_CTRcache =
    //     new ctr_cache(CTRc_name, m_CTR_config, -1, -1, m_CTRinterface,
    //                  m_mf_allocator, IN_PARTITION_L2_MISS_QUEUE, new ctr_tag_array(m_CTR_config, -1, -1, NULL), gpu);
        // 获取 memory_config
    memory_config* mem_config = const_cast<memory_config*>(gpu->getMemoryConfig());
    // 获取 CTR cache config
    l2_cache_config& ctr_config = mem_config->m_CTR_config;

    // 构造 mem_fetch_allocator
    m_mf_allocator = new partition_mf_allocator(mem_config);

    // 构造 ctr_tag_array
    m_CTRcache =
        new ctr_cache(CTRc_name, ctr_config, -1, -1, m_CTRinterface,
                     m_mf_allocator, IN_PARTITION_L2_MISS_QUEUE, gpu);
    
    test_access(m_CTRcache, m_mf_allocator, gpu->gpu_tot_sim_cycle + gpu->gpu_sim_cycle);
}