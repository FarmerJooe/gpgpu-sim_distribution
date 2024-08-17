#include "mee.h"
#include <list>

mee::mee(class memory_partition_unit *unit, class l2_cache *CTRcache, class l2_cache *MACcache, class l2_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu) : 
    m_unit(unit), 
    m_CTRcache(CTRcache),
    m_MACcache(MACcache),
    m_BMTcache(BMTcache),
    m_config(config),
    m_gpu(gpu) {
    m_CTR_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_Ciphertext_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_MAC_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_BMT_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);

    m_CTR_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_MAC_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_BMT_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
    m_Ciphertext_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);

    m_OTP_queue = new fifo_pipeline<mem_fetch>("meta-queue", 10, 64);
    m_AES_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);

    m_MAC_HASH_queue = new fifo_pipeline<mem_fetch>("meta-queue", 10, 64);
    m_MAC_CHECK_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, 64);
}
int decode(int addr) {
    return (addr & 16128) >> 8;
}
void mee::print_addr(char s[], mem_fetch *mf) {
    if (mf->get_sub_partition_id() == 0) {
        printf("%saddr: %x\tsp_id: %d\tsp_addr: %x\tmask_id: %d\tmask_addr:%x\taccess type:%d\n", s, mf->get_addr(), mf->get_sid(), mf->get_partition_addr(), get_sub_partition_id(mf), get_partition_addr(mf), mf->get_access_type());
        // print_tag();
    }
}

void mee::print_tag() {
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

new_addr_type mee::get_partition_addr(mem_fetch *mf) {
    new_addr_type partition_addr = mf->get_addr() >> (8 + 6) << 8;
    partition_addr |= mf->get_addr() & ((1 << 8) - 1);
    // return partition_addr;
    // printf("%x %x\n", mf->get_addr(), mf->get_partition_addr());
    return mf->get_partition_addr();
}

new_addr_type mee::get_sub_partition_id(mem_fetch *mf) {
    // return (mf->get_addr() >> 8) & ((1 << 6) - 1);
    
    return mf->get_sub_partition_id();
}

bool mee::META_queue_empty() {
    return m_CTR_queue->empty() && m_Ciphertext_queue->empty() && m_MAC_queue->empty();
}

new_addr_type mee::get_addr(new_addr_type sub_partition_id, new_addr_type partition_addr) {
    new_addr_type new_addr = partition_addr >> 8 << (8 + 6);
    new_addr |= partition_addr & ((1 << 8) - 1);
    new_addr |= sub_partition_id << 8;
    // printf("%x %x %x\n", new_addr, sub_partition_id, partition_addr);
    return new_addr;
}

void mee::gen_CTR_mf(mem_fetch *mf, mem_access_type meta_acc, bool wr) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 18 << 7;
    new_addr_type CTR_addr  = get_addr(sub_partition_id, partition_addr);
    CTR_addr |= CTR_mask;

    meta_access(m_CTR_queue, CTR_addr, meta_acc, 
            128, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf);
}

void mee::gen_MAC_mf(mem_fetch *mf, bool wr) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 7 << 3;
    new_addr_type MAC_addr  = get_addr(sub_partition_id, partition_addr);
    MAC_addr |= MAC_mask;

    meta_access(m_MAC_queue, MAC_addr, META_ACC, 
            8, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf);
}

void mee::meta_access(
        fifo_pipeline<mem_fetch> *m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr,
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
    if (m_config->m_META_config.m_cache_type == SECTOR)
        reqs = m_unit->m_sub_partition[0]->breakdown_request_to_sector_requests(mf);
    else
        reqs.push_back(mf);

    for (unsigned i = 0; i < reqs.size(); ++i) {
        mem_fetch *req = reqs[i];
        m_META_queue->push(req);
    }
}

void mee::CT_cycle() {
    if (!m_Ciphertext_RET_queue->empty()) {
        mem_fetch *mf_return = m_Ciphertext_RET_queue->top();
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
        if (mf_return->is_write()) { // write
            // print_addr("mee to L2 W:\t", mf_return);
            if (!m_unit->mee_L2_queue_full(spid)){
                m_unit->mee_L2_queue_push(spid, mf_return);
                m_Ciphertext_RET_queue->pop();
            }
        } else if (!m_AES_queue->full() && !m_MAC_HASH_queue->full()) {              // read
            m_AES_queue->push(mf_return);
            m_MAC_HASH_queue->push(mf_return);
            m_Ciphertext_RET_queue->pop();
        }
    }

    if (!m_Ciphertext_queue->empty()) {
        mem_fetch *mf = m_Ciphertext_queue->top();
        if (mf->is_write() && !m_AES_queue->full()) { // write
            m_AES_queue->push(mf);
            m_Ciphertext_queue->pop();
        } else if (!m_unit->mee_dram_queue_full()) {              // read
            m_unit->mee_dram_queue_push(mf);
            m_Ciphertext_queue->pop();
        }
    }
}

void mee::AES_cycle() {
    if (!m_AES_queue->empty()) {
        mem_fetch *mf = m_AES_queue->top();
        new_addr_type REQ_addr = (new_addr_type) mf;
        new_addr_type OTP_addr = m_OTP_table[REQ_addr];
        int spid = m_unit->global_sub_partition_id_to_local_id(mf->get_sub_partition_id());
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        if (m_OTP_set[OTP_addr]) {
            if (mf->is_write()) {
                if (!m_unit->mee_dram_queue_full() && !m_MAC_HASH_queue->full()) {
                    m_OTP_set[OTP_addr]--;
                    m_OTP_table[REQ_addr] = 0;
                    m_unit->mee_dram_queue_push(mf);
                    m_MAC_HASH_queue->push(mf);
                    m_AES_queue->pop();
                }
            } else if (!m_unit->mee_L2_queue_full(spid)) {
                m_OTP_set[OTP_addr]--;
                m_OTP_table[REQ_addr] = 0;
                // print_addr("mee to L2 R:\t", mf);
                m_unit->mee_L2_queue_push(spid, mf);
                m_AES_queue->pop();
                
            }
        }
    }

    if (!m_OTP_queue->empty()){
        mem_fetch *mf = m_OTP_queue->top();
        if (mf) {
            m_OTP_set[(new_addr_type)mf]++;
        }
        delete mf;
        m_OTP_queue->pop();
    }
}

void mee::MAC_CHECK_cycle() {
    if (!m_MAC_CHECK_queue->empty()) {
        // printf("AAAAAAAAAAAAA\n");
        mem_fetch *mf = m_MAC_CHECK_queue->top();
        new_addr_type REQ_addr = (new_addr_type) mf;
        new_addr_type HASH_addr = m_MAC_table[REQ_addr];
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        if (true || m_MAC_set[HASH_addr]) {
            m_MAC_set[HASH_addr]--;
            m_MAC_table[REQ_addr] = 0;
            m_MAC_CHECK_queue->pop();
        }
    }

    if (!m_MAC_HASH_queue->empty()) {
        // printf("BBBBBBBBBBBBBBB\n");
        mem_fetch *mf = m_MAC_HASH_queue->top();
        if (mf) {
            m_MAC_set[(new_addr_type)mf]++;
        }
        // delete mf;
        m_MAC_HASH_queue->pop();
    }
}

void mee::CTR_cycle() {
    if (!m_CTR_RET_queue->empty()) {
        mem_fetch *mf_return = m_CTR_RET_queue->top();
        if (mf_return->get_type() == META_RBW) {
            m_CTR_RET_queue->pop();
            gen_CTR_mf(mf_return->get_original_mf(), META_ACC, true);
            delete mf_return;
        } else {
                // print_addr("MISS OTP:\t\t", mf_return);
            if (!m_OTP_queue->full()) {
                m_OTP_queue->push(mf_return);
                m_CTR_RET_queue->pop();
            }
        }
    }

    m_CTRcache->cycle();
    
    if (!m_CTR_queue->empty() && !m_unit->mee_dram_queue_full() && !m_OTP_queue->full()) {
        mem_fetch *mf = m_CTR_queue->top();
        // print_addr("CTR cycle access:\t\t", mf);

        if (mf->is_write()) {
            if (m_CTRcache->probe(mf->get_addr(), mf) != HIT) {
                return;
            }
        }

        if (mf->get_type() != META_RBW) {
            m_OTP_table[(new_addr_type)mf->get_original_mf()] = (new_addr_type)mf;
        }

        std::list<cache_event> events;
        enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status == HIT) {
            // if (!m_OTP_queue->full()) {
            // print_addr("HIT OTP:\t\t", mf);
            m_OTP_queue->push(mf);
            m_CTR_queue->pop();
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            // print_addr("CTR cycle access:\t\t", mf);
            m_CTR_queue->pop();
        } else {
            // print_addr("CTR cycle RESERVATION_FAIL:\t", mf);
            // if (get_sub_partition_id(mf) == 0)
            //     enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            assert(!write_sent);
            assert(!read_sent);
        }
    } 
    // else if (mf->get_sub_partition_id() == 1) {
        // if (m_unit->mee_dram_queue_full()) printf("AAAAAAAAAAAAAA\n");
        // if (m_OTP_queue->full()) printf("BBBBBBBBBBBBBBBBB\n");
        // if (!m_OTP_queue->empty() && m_CTR_queue->empty()) printf("CCCCCCCCCCCCCCCCCCCCCCCC\n");
    //}
};

void mee::MAC_cycle() {
    if (!m_MAC_RET_queue->empty()) {
        mem_fetch *mf_return = m_MAC_RET_queue->top();
        if (mf_return->is_write()) {
            m_MAC_RET_queue->pop();
            delete mf_return;
        } else {
                // print_addr("MISS OTP:\t\t", mf_return);
            if (!m_MAC_CHECK_queue->full()) {
                // m_MAC_CHECK_queue->push(mf_return);
                m_MAC_RET_queue->pop();
            } else {
                if (mf_return->get_sub_partition_id() == 1) {
                    print_addr("MAC Full:", mf_return);
                }
            }
        }
    }

    m_MACcache->cycle();
    
    if (!m_MAC_queue->empty() && !m_unit->mee_dram_queue_full() && !m_MAC_CHECK_queue->full()) {
        mem_fetch *mf = m_MAC_queue->top();
        print_addr("MAC cycle access:\t\t", mf);

        if (mf->is_write()) {
            if (!m_MAC_set[(new_addr_type)mf]) {
                return;
            } else {

            }
        } else {
            m_MAC_table[(new_addr_type)mf->get_original_mf()] = (new_addr_type)mf;
        }

        std::list<cache_event> events;
        enum cache_request_status status = m_MACcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status == HIT) {
            // if (!m_OTP_queue->full()) {
            // print_addr("HIT OTP:\t\t", mf);
            if (mf->is_write()) {
                m_MAC_set[(new_addr_type)mf]--;
            } else {
                // m_MAC_CHECK_queue->push(mf);
            }
            m_MAC_queue->pop();
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            // print_addr("CTR cycle access:\t\t", mf);
            if (mf->is_write()) {
                m_MAC_set[(new_addr_type)mf]--;
            }
            m_MAC_queue->pop();
        } else {
            // print_addr("CTR cycle RESERVATION_FAIL:\t", mf);
            // if (get_sub_partition_id(mf) == 0)
            //     enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            assert(!write_sent);
            assert(!read_sent);
        }
    } 
    else {
        if (m_unit->mee_dram_queue_full()) printf("AAAAAAAAAAAAAA\n");
        if (m_MAC_CHECK_queue->full()) printf("BBBBBBBBBBBBBBBBB\n");
        // if (!m_OTP_queue->empty() && m_CTR_queue->empty()) printf("CCCCCCCCCCCCCCCCCCCCCCCC\n");
    }
};

void mee::BMT_cycle() {

};

void mee::META_fill_responses(class l2_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, const new_addr_type MASK) {
    if (m_METAcache->access_ready()) {
        mem_fetch *mf = m_METAcache->next_access();
        m_META_RET_queue->push(mf);
        print_addr("fill responses:", mf);
        // reply(m_METAcache, mf);
        // delete mf;
    }
}

void mee::META_fill(class l2_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, mem_fetch *mf, const new_addr_type MASK) {
    if ((mf->get_addr() & MASK) && m_METAcache->waiting_for_fill(mf)) {
        // print_addr("wating for fill:\t\t", mf); 
        if (m_METAcache->fill_port_free() && !m_META_RET_queue->full()) {
            m_METAcache->fill(mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle +
                                    m_memcpy_cycle_offset);
            print_addr("fill:\t\t\t\t", mf); 
            // if (mf->get_sub_partition_id() == 1) { 
            //     printf("CTR Fill: %p\n", mf);
            //     // printf("CTR Next: %p\n", m_CTR_queue->top());
            // }
            m_unit->dram_mee_queue_pop();
        }
    }
}

void mee::simple_cycle(unsigned cycle) {
    // META Cache fill responses
    META_fill_responses(m_CTRcache, m_CTR_RET_queue, CTR_mask);
    META_fill_responses(m_MACcache, m_MAC_RET_queue, MAC_mask);
    // META_fill_responses(m_BMTcache);
    // dram to mee
    if (!m_unit->dram_mee_queue_empty()) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top();
        // print_addr("dram_mee_queue_top:\t", mf_return);
        // mee to L2
        
        // META_fill(m_MACcache, mf_return, MAC_mask);
        // META_fill(m_BMTcache, mf_return);
        // if (!m_unit->mee_L2_queue_full()) {

        if (mf_return->get_access_type() >= META_ACC) { // META访存的返回，需要响应
            // printf("Success handle CTR_ACC: ");
            // print_addr("META return to mee", mf_return);
            // delete mf_return;
            META_fill(m_CTRcache, m_CTR_RET_queue, mf_return, CTR_mask);
            META_fill(m_MACcache, m_MAC_RET_queue, mf_return, MAC_mask);
        } else {    // 密文访存返回
            // reply L2 read
            // reply L2 write back
            //m_unit->mee_L2_queue_push(m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id()), mf_return);
            if (!m_Ciphertext_RET_queue->full()) {
                m_Ciphertext_RET_queue->push(mf_return);
                m_unit->dram_mee_queue_pop();
            }
            // print_addr("mee to L2: ", mf_return);
        }
        
        // }
    }
    // printf("L2 to mee queue: %d %d\n", m_unit->m_sub_partition[0]->m_L2_mee_queue->empty(), m_unit->m_sub_partition[0]->m_L2_mee_queue->empty());
    // L2 to mee
    if (!m_unit->L2_mee_queue_empty(cycle&1)) {
        mem_fetch *mf = m_unit->L2_mee_queue_top(cycle&1);
        // print_addr("L2 to mee: ", mf);
        // mee to dram
        if (!m_unit->mee_dram_queue_full() && !m_CTR_queue->full() && !m_MAC_queue->full() && !m_BMT_queue->full() && !m_Ciphertext_queue->full()) {
            // print_addr("L2 to mee: ", mf);
            if (!mf->is_write()) { // L2 read 
                // CTR access
                gen_CTR_mf(mf, META_ACC, false);
                // Ciphertext access
                m_Ciphertext_queue->push(mf);
                // MAC access
                gen_MAC_mf(mf, false);
                // AES Decryption
                // AES_cycle();
                // Hash MAC
                
                // MAC Check
                // BMT Check
            } else { // L2 write back
                // CTR access
                gen_CTR_mf(mf, META_RBW, false);
                // CTR update
                // gen_CTR_mf(mf, META_ACC, true);
                // AES Ecryption

                // AES_queue.push(mf);
                
                // Ciphertext Update
                m_Ciphertext_queue->push(mf);
                // MAC access
                // gen_MAC_mf(mf, false);
                // MAC Hash
                // MAC Update
                gen_MAC_mf(mf, true);
                // BMT Update
            }
            
            m_unit->L2_mee_queue_pop(cycle&1);
            
        } else {
        }
    }
    AES_cycle();
    CTR_cycle();
    CT_cycle();
    MAC_CHECK_cycle();
    MAC_cycle();
}

void mee::cycle(unsigned cycle) {
}