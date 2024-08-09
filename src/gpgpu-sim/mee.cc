#include "mee.h"
#include <list>

sub_mee::sub_mee(class memory_sub_partition *sub_partition, class l2_cache *CTRcache, class l2_cache *MACcache, class l2_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu) : 
    m_sub_partition(sub_partition), 
    m_CTRcache(CTRcache),
    m_MACcache(MACcache),
    m_BMTcache(BMTcache),
    m_config(config),
    m_gpu(gpu) {

}
int decode(int addr) {
    return (addr & 16128) >> 8;
}
void sub_mee::print_addr(char s[], mem_fetch *mf) {
    if (mf->get_sub_partition_id() == 0) {
        printf("%saddr: %x\tsp_id: %d\tsp_addr: %x\tmask_id: %d\tmask_addr:%x\taccess type:%d\n", s, mf->get_addr(), mf->get_sub_partition_id(), mf->get_partition_addr(), get_sub_partition_id(mf), get_partition_addr(mf), mf->get_access_type());
        // print_tag();
    }
}

void sub_mee::print_tag() {
    // if (get_sub_partition_id(mf) == 0) {
        // for (unsigned i = 0; i < m_config->m_META_config.get_num_lines(); i++) {
        for (unsigned i = 188; i < 192; i++) {
            printf("line %d:\t", i);
            for (unsigned j = 0; j < SECTOR_CHUNCK_SIZE; j++)
                // printf("%d\t", 
                m_CTRcache->m_tag_array->m_lines[i]->print_status();
            printf("\n");
        }
    // }
}

new_addr_type sub_mee::get_partition_addr(mem_fetch *mf) {
    new_addr_type partition_addr = mf->get_addr() >> (8 + 6) << 8;
    partition_addr |= mf->get_addr() & ((1 << 8) - 1);
    // return partition_addr;
    // printf("%x %x\n", mf->get_addr(), mf->get_partition_addr());
    return mf->get_partition_addr();
}

new_addr_type sub_mee::get_sub_partition_id(mem_fetch *mf) {
    // return (mf->get_addr() >> 8) & ((1 << 6) - 1);
    
    return mf->get_sub_partition_id();
}

bool sub_mee::META_queue_empty() {
    return m_CTR_queue.empty() && m_Ciphertext_queue.empty() && m_MAC_queue.empty();
}

new_addr_type sub_mee::get_addr(new_addr_type sub_partition_id, new_addr_type partition_addr) {
    new_addr_type new_addr = partition_addr >> 8 << (8 + 6);
    new_addr |= partition_addr & ((1 << 8) - 1);
    new_addr |= sub_partition_id << 8;
    // printf("%x %x %x\n", new_addr, sub_partition_id, partition_addr);
    return new_addr;
}

void sub_mee::gen_CTR_mf(mem_fetch *mf, bool wr) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 14 << 7;
    new_addr_type CTR_addr  = get_addr(sub_partition_id, partition_addr);
    CTR_addr |= CTR_mask;

    meta_access(m_CTR_queue, CTR_addr, META_ACC, 
            128, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf);
}

void sub_mee::gen_MAC_mf(mem_fetch *mf, bool wr) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 7 << 3;
    new_addr_type MAC_addr  = get_addr(sub_partition_id, partition_addr);
    MAC_addr |= MAC_mask;

    meta_access(m_MAC_queue, MAC_addr, META_ACC, 
            64, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf);
}

void sub_mee::meta_access(
        std::list<mem_fetch *> &m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr,
        unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc,
        mem_fetch *original_mf) const {

    mem_access_byte_mask_t byte_mask;
    mem_access_sector_mask_t sector_mask;
    for (unsigned i = 0; i < size; i++) byte_mask.set(i);
    for (unsigned i = 0; i < size/32; i++) sector_mask.set(i + (addr & (1 << 7) ? 2 : 0));

    mem_access_t acc(type, addr, size, wr, original_mf->get_access_warp_mask(), byte_mask, sector_mask, m_gpu->gpgpu_ctx);
    mem_fetch *mf = new mem_fetch(
        acc, NULL /*we don't have an instruction yet*/, wr ? WRITE_PACKET_SIZE : READ_PACKET_SIZE,
        wid, sid, tpc, m_config, cycle, original_mf);
    // mf->set_chip(original_mf->get_sub_partition_id)

    std::vector<mem_fetch *> reqs;
    // if (m_config->m_L2_config.m_cache_type == SECTOR)
    reqs = m_sub_partition->breakdown_request_to_sector_requests(mf);
    // else
    //   reqs.push_back(mf);

    for (unsigned i = 0; i < reqs.size(); ++i) {
        mem_fetch *req = reqs[i];
        m_META_queue.push_back(req);
    }
}

void sub_mee::CTR_cycle() {
    m_CTRcache->cycle();
    if (!m_CTR_queue.empty() && !m_sub_partition->mee_dram_queue_full()) {
        mem_fetch *mf = m_CTR_queue.front();
        std::list<cache_event> events;
        enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status == HIT) {
            m_CTR_queue.pop_front();
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            // print_addr("CTR cycle access:\t\t", mf);
            m_CTR_queue.pop_front();
        } else {
            // print_addr("CTR cycle RESERVATION_FAIL:\t", mf);
            if (get_sub_partition_id(mf) == 0)
                enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            assert(!write_sent);
            assert(!read_sent);
        }
    }
};

void sub_mee::MAC_cycle() {
    m_MACcache->cycle();
    if (!m_MAC_queue.empty() && !m_sub_partition->mee_dram_queue_full()) {
        mem_fetch *mf = m_MAC_queue.front();
        std::list<cache_event> events;
        enum cache_request_status status = m_MACcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        if (status == HIT) {
            m_MAC_queue.pop_front();
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            m_MAC_queue.pop_front();
        } else {
            assert(!write_sent);
            assert(!read_sent);
        }
    }
};

void sub_mee::BMT_cycle() {

};
void sub_mee::AES_cycle() {

};

void sub_mee::META_fill_responses(class l2_cache *m_METAcache, const new_addr_type MASK) {
    if (m_METAcache->access_ready()) {
        mem_fetch *mf = m_METAcache->next_access();
        // print_addr("fill responses:", mf);
        // reply(m_METAcache, mf);
        delete mf;
    }
}

void sub_mee::META_fill(class l2_cache *m_METAcache, mem_fetch *mf, const new_addr_type MASK) {
    if (!(mf->get_addr() & MASK) && m_METAcache->waiting_for_fill(mf)) {
        // print_addr("wating for fill:\t\t", mf); 
        if (m_METAcache->fill_port_free()) {
            m_METAcache->fill(mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle +
                                    m_memcpy_cycle_offset);
            // print_addr("fill:\t\t\t\t", mf); 
            m_sub_partition->dram_mee_queue_pop();
        }
    }
}

void sub_mee::simple_cycle(unsigned cycle) {
    // META Cache fill responses
    META_fill_responses(m_CTRcache, CTR_mask);
    META_fill_responses(m_MACcache, MAC_mask);
    // META_fill_responses(m_BMTcache);
    // dram to mee
    if (!m_sub_partition->dram_mee_queue_empty()) {
        mem_fetch *mf_return = m_sub_partition->dram_mee_queue_top();
        // print_addr("dram_mee_queue_top:\t", mf_return);
        // mee to L2
        META_fill(m_CTRcache, mf_return, CTR_mask);
        META_fill(m_MACcache, mf_return, MAC_mask);
        // META_fill(m_BMTcache, mf_return);
        // if (!m_sub_partition->mee_L2_queue_full()) {

        if (mf_return->get_access_type() == META_ACC) { // META访存的返回，需要响应
            // printf("Success handle CTR_ACC: ");
            // print_addr(mf_return);
            // delete mf_return;
        } else {    // 密文访存返回
            // reply L2 read
            // reply L2 write back
            m_sub_partition->mee_L2_queue_push(mf_return);
            m_sub_partition->dram_mee_queue_pop();
            // print_addr(mf_return);
        }
        
        // }
    }
    // L2 to mee
    if (!m_sub_partition->L2_mee_queue_empty()) {
        mem_fetch *mf = m_sub_partition->L2_mee_queue_top();
        // mee to dram
        if (!m_sub_partition->mee_dram_queue_full() && META_queue_empty()) {
            if (!mf->is_write()) { // L2 read 
                // CTR access
                gen_CTR_mf(mf, false);
                // Ciphertext access
                m_Ciphertext_queue.push_back(mf);
                // MAC access
                gen_MAC_mf(mf, false);
                // AES Decryption
                AES_cycle();
                // Hash MAC
                
                // MAC Check
                // BMT Check
            } else { // L2 write back
                // CTR access
                gen_CTR_mf(mf, false);
                // CTR update
                gen_CTR_mf(mf, true);
                // AES Ecryption
                // Ciphertext Update
                // MAC access
                gen_MAC_mf(mf, false);
                // MAC Hash
                // MAC Update
                gen_MAC_mf(mf, true);
                // BMT Update
            }
            
            m_sub_partition->L2_mee_queue_pop();
            
        } else {
        }
    }
    CTR_cycle();
    if (!m_Ciphertext_queue.empty() && !m_sub_partition->mee_dram_queue_full() && m_CTR_queue.empty()) {
        mem_fetch *mf = m_Ciphertext_queue.front();
        m_sub_partition->mee_dram_queue_push(mf);
        m_Ciphertext_queue.pop_front();
    }
    MAC_cycle();
}

void sub_mee::cycle(unsigned cycle) {
}