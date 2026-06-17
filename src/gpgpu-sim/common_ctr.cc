#include "common_ctr.h"

void common_ctr::print_addr(char s[], mem_fetch *mf) const{
    // if (m_unit->get_mpid() == 0) {
    //     printf("%s\t", s);
    //     // if (mf->get_original_mf())
    //     //     printf("original_addr: %x\toriginal_sp_addr: %x\t", mf->get_original_mf()->get_addr(), mf->get_original_mf()->get_partition_addr());
    //     printf("addr: %x\twr: %d\tdata_type: %d\tBMT_Layer: %d\tsp_id: %d\tsp_addr: %x\taccess type:%d\tmf_id: %d\tcycle: %d\n", mf->get_addr(),mf->is_write(), mf->get_data_type(), mf->get_BMT_Layer(), mf->get_sub_partition_id(), mf->get_partition_addr(), mf->get_access_type(), mf->get_id(), m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);        // print_tag();
    // }
}

new_addr_type common_ctr::get_global_addr(new_addr_type sub_partition_id, new_addr_type partition_addr) {
    new_addr_type new_addr = partition_addr >> 8 << (8 + 5);
    new_addr |= partition_addr & ((1 << 8) - 1);
    new_addr |= sub_partition_id << 8;
    return new_addr;
}

void common_ctr::gen_META_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id) {

    new_addr_type partition_addr = m_mee->get_partition_addr(mf->get_addr());
    new_addr_type sub_partition_id = m_mee->get_partition_id(mf->get_addr());

    partition_addr = partition_addr >> m_meta_scale_shift << m_meta_slot_shift;

    new_addr_type META_addr = get_global_addr(sub_partition_id, partition_addr);
    META_addr |= m_META_base;

    // if (mf->get_sub_partition_id() / 2 == 0)
    //     printf("addr: %x\tCCSM_addr: %x\n", mf->get_addr(), META_addr);

    meta_access(META_addr, meta_acc, 
            size, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, DEFAULT);
}

void common_ctr::meta_access(new_addr_type addr, mem_access_type type, unsigned size, bool wr,
        unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc,
        mem_fetch *original_mf, unsigned mf_id, enum BMT_Layer m_Layer) const {

    mem_access_byte_mask_t byte_mask;
    mem_access_sector_mask_t sector_mask;
    unsigned data_size = 0;
    if (size == 128) {
        assert(m_config->m_META_config.m_cache_type == SECTOR);
        for (unsigned i = 0; i < size / 32; i++) 
            sector_mask.set(i);
        addr = addr >> 7 << 7;
        for (unsigned i = addr & 127; i < (addr & 127) + size; i++) byte_mask.set(i);
        data_size = 128;
    }
    else {
        for (unsigned i = (addr >> 5) & 3; i < ((addr >> 5) & 3) + ((size + 31) / 32); i++) 
            sector_mask.set(i);
        addr = addr >> 5 << 5;
        for (unsigned i = addr & 127; i < (addr & 127) + size; i++) byte_mask.set(i);
        data_size = 32;
        // sector_mask.set((addr >> 5) & 3);
    }
    mem_access_t acc(type, addr, data_size, wr, original_mf->get_access_warp_mask(), byte_mask, sector_mask, m_gpu->gpgpu_ctx);
    mem_fetch *mf = new mem_fetch(
        acc, NULL /*we don't have an instruction yet*/, wr ? WRITE_PACKET_SIZE : READ_PACKET_SIZE,
        wid, sid, tpc, m_config, cycle, original_mf);

    std::vector<mem_fetch *> reqs;
    if (m_config->m_META_config.m_cache_type == SECTOR)
        reqs = m_unit->m_sub_partition[0]->breakdown_request_to_sector_requests(mf);
    else
        reqs.push_back(mf);

    assert(m_data_type != MAC || reqs.size() == 1);

    for (unsigned i = 0; i < reqs.size(); ++i) {
        assert(reqs.size() == 1);
        mem_fetch *req = reqs[i];
        // req->set_id(mf_id);
        req->set_data_type(m_data_type);
        req->set_BMT_Layer(m_Layer);
        if (i == reqs.size() - 1)
            req->set_id(mf_id);
        else
            req->set_id(0);
        assert(!m_META_queue->full());
        m_META_queue->push(req);
        switch (m_data_type) {
          case CTR:
            req->set_ctr_enqueue_time(cycle);
            break;
          case MAC:
            req->set_mac_enqueue_time(cycle);
            break;
          case BMT:
            req->set_bmt_enqueue_time(cycle);
            break;
          default:
            break;
        }
    }
}

common_ctr::common_ctr(class mee* _mee, class memory_partition_unit *unit, const memory_config *config, class memory_stats_t *stats, class gpgpu_sim *gpu):
    m_mee(_mee),
    m_unit(unit),
    m_config(config),
    m_stats(stats),
    m_gpu(gpu) {
    unsigned int icnt_L2;
    unsigned int L2_dram;
    unsigned int dram_L2;
    unsigned int L2_icnt;
    sscanf(m_config->gpgpu_L2_queue_config, "%u:%u:%u:%u", &icnt_L2, &L2_dram,
            &dram_L2, &L2_icnt);
    unsigned len = L2_dram;
    unsigned m_id = m_unit->get_mpid();

    m_mf_allocator = new partition_mf_allocator(m_config);
    m_METAinterface = new metainterface(m_unit->m_mee_dispather_queue[CCSM], m_gpu, m_stats);

    m_META_queue = new fifo_pipeline<mem_fetch>("meta-CCSM-queue", m_id, 0, len);
    m_META_RET_queue = new fifo_pipeline<mem_fetch>("meta-CCSM-RET-queue", m_id, 0, len);

    char METAc_name[32];
    snprintf(METAc_name, 32, "CCSM_bank_%03d\0", m_id);

    m_METAcache =
        new meta_cache(METAc_name, m_config->m_META_config, -1, -1, m_METAinterface,
                     m_mf_allocator, IN_PARTITION_L2_MISS_QUEUE, gpu);

    m_data_type = CCSM;
            
    m_updated_mem_region_map = new counterMap;
    m_CCSM_map = new counterMap;

}

bool common_ctr::full() {
    return m_META_queue->full();
}

void common_ctr::META_fill_responses() {
    if (m_METAcache->access_ready() && !m_META_RET_queue->full()) {
        mem_fetch *mf = m_METAcache->next_access();
        enum data_type m_data_type = mf->get_data_type();
        memory_stats_t *stats = m_gpu->get_memory_stats();
        unsigned long long now =
            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
        if (mf->get_access_type() == META_ACC_R && mf->get_id())
            m_META_RET_queue->push(mf);
        // assert(mf->get_access_type() == META_ACC_R);
        // if (m_METAcache == m_BMTcache)
        print_addr("META fill responses:\t", mf);
        // reply(m_METAcache, mf);
        // delete mf;
        if (mf && mf->get_meta_issue_time() && stats) {
            mee_latency_stage stage = NUM_MEE_LATENCY_STAGE;
            meta_access_type meta_type = NUM_META_ACCESS_TYPE;
            switch (m_data_type) {
              case CTR:
                stage = CTR_META_STAGE;
                meta_type = META_ACCESS_CTR;
                break;
              case MAC:
                stage = MAC_META_STAGE;
                meta_type = META_ACCESS_MAC;
                break;
              case BMT:
                stage = BMT_META_STAGE;
                meta_type = META_ACCESS_BMT;
                break;
              default:
                break;
            }
            if (stage != NUM_MEE_LATENCY_STAGE &&
                meta_type != NUM_META_ACCESS_TYPE) {
                unsigned long long latency =
                    now - mf->get_meta_issue_time();
                stats->record_stage_latency(stage, latency);
                stats->record_meta_latency(meta_type, latency);
            }
            mf->reset_meta_issue_time();
        }
    }
}

void common_ctr::META_fill() {
    
    if (!m_unit->dram_dispather_queue_empty(m_data_type)) {
        mem_fetch *mf_return = NULL;
        mf_return = m_unit->dram_dispather_queue_top(m_data_type);
        
        if ((mf_return->get_data_type() == m_data_type) && m_METAcache->waiting_for_fill(mf_return)) {
            if (m_METAcache->fill_port_free()) {
                // print_addr("fill: \t\t", mf_return);
                m_METAcache->fill(mf_return, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
                
                assert(!mf_return->is_write());
                m_unit->dram_dispather_queue_pop(m_data_type);
            }
        } else if (mf_return->get_data_type() == m_data_type) {
            if (mf_return->is_write() && mf_return->get_type() == WRITE_ACK)
                mf_return->set_status(IN_PARTITION_L2_TO_ICNT_QUEUE,
                            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
            m_unit->dram_dispather_queue_pop(m_data_type);
        }
    }
}

void common_ctr::META_cache_cycle() {
    if (!m_META_RET_queue->empty()) {
        mem_fetch *mf_return = m_META_RET_queue->top();
        assert(mf_return->get_id());
        if (!m_mee->OTP_queue_full()) {
            CCSM_handing(mf_return->get_id());
            m_META_RET_queue->pop();
        }
    }

    m_METAcache->cycle();
    
    bool output_full = m_META_RET_queue->full() || m_mee->OTP_queue_full();
    bool port_free = m_METAcache->data_port_free();

    if (!m_META_queue->empty() && !m_unit->mee_dispather_queue_full(m_data_type) && !output_full && port_free) {
        mem_fetch *mf = m_META_queue->top();
        print_addr("META cycle access:\t\t", mf);
        memory_stats_t *stats = m_gpu->get_memory_stats();
        unsigned long long now =
            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;

        std::list<cache_event> events;
        enum cache_request_status status = m_METAcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);

        if (status == HIT) {
            m_META_queue->pop();
            if (mf->is_write()) {
                print_addr("META Write Hit:\t", mf);
            } else {
                CCSM_handing(mf->get_id());
            }
        } else if (status != RESERVATION_FAIL) {
            print_addr("META MISS:\t", mf);
            m_META_queue->pop();
        } else {
            assert(!write_sent);
            assert(!read_sent);
        }
    }
}

void common_ctr::cycle() {
    META_fill_responses();
    META_fill();
    META_cache_cycle();
    
}

void common_ctr::CCSM_handing(unsigned OTP_id) {
    if (OTP_id == 0) {
        return;
    } else {
        m_mee->OTP_queue_push(OTP_id);
    }
}

new_addr_type common_ctr::get_CCSM_index(new_addr_type addr) {
    new_addr_type partition_addr = m_mee->get_partition_addr(addr);
    new_addr_type sub_partition_id = m_mee->get_partition_id(addr);

    partition_addr = partition_addr >> (m_meta_scale_shift - 1) << (m_meta_scale_shift - 1);

    new_addr_type META_addr = get_global_addr(sub_partition_id, partition_addr);

    return META_addr;
}

bool common_ctr::CCSM_scope(new_addr_type addr) {
    new_addr_type CCSM_index = get_CCSM_index(addr);
    return (*m_CCSM_map)[CCSM_index] == 0;
}

void common_ctr::update_CCSM(new_addr_type addr, unsigned CCSM_val) {
    new_addr_type CCSM_index = get_CCSM_index(addr);
    (*m_CCSM_map)[CCSM_index] = CCSM_val;
}

void common_ctr::update_region_map(new_addr_type addr) {

    new_addr_type region_addr = addr & m_region_block_mask;

    (*m_updated_mem_region_map)[region_addr] = 1;
}

void common_ctr::scan_region(new_addr_type region_addr) {
    new_addr_type offset = m_region_offset_mask;
    unsigned and_sum = 0xffffffff;
    unsigned or_sum = 0;
    bool common_valid = 1;

    do {
        new_addr_type sector_addr = region_addr | offset;

        new_addr_type partition_addr = m_mee->get_partition_addr(sector_addr);
        new_addr_type sub_partition_id = m_mee->get_partition_id(sector_addr);

        // if (meta_acc == META_ACC)
        //     partition_addr |= minor_addr;

        new_addr_type segment_addr  = get_global_addr(sub_partition_id, partition_addr);
        
        scan_segment(segment_addr);

        offset = (offset - 1) & m_region_offset_mask;
    } while(offset != m_region_offset_mask);

    (*m_updated_mem_region_map)[region_addr] = 0;
}

void common_ctr::scan_segment(new_addr_type segment_addr) {
    new_addr_type offset = m_segment_offset_mask;
    unsigned and_sum = 0xffffffff;
    unsigned or_sum = 0;
    bool common_valid = 1;

    do {
        new_addr_type sector_addr = segment_addr | offset;

        new_addr_type partition_addr = m_mee->get_partition_addr(sector_addr);
        new_addr_type sub_partition_id = m_mee->get_partition_id(sector_addr);
        partition_addr = (partition_addr >> 5); // per minor ctr map to 32B cache line

        // if (meta_acc == META_ACC)
        //     partition_addr |= minor_addr;

        new_addr_type CTR_addr  = get_global_addr(sub_partition_id, partition_addr);
        
        and_sum &= (*m_mee->m_ctrModCount)[CTR_addr];
        or_sum  |= (*m_mee->m_ctrModCount)[CTR_addr];
        if (and_sum != or_sum) {
            common_valid = 1;
            break;
        }

        offset = (offset - 1) & m_segment_offset_mask;
    } while(offset != m_segment_offset_mask);

    if (common_valid) {
        new_addr_type CCSM_index = get_CCSM_index(segment_addr);

        (*m_CCSM_map)[CCSM_index] = 0;
    } else {
        new_addr_type CCSM_index = get_CCSM_index(segment_addr);

        (*m_CCSM_map)[CCSM_index] = 1;
    }
}