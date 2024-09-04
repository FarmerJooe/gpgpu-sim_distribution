#include "mee.h"
#include <list>
#define BMT_Enable
#define MAC_Enable

mee::mee(class memory_partition_unit *unit, class meta_cache *CTRcache, class meta_cache *MACcache, class meta_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu) : 
    m_unit(unit), 
    m_CTRcache(CTRcache),
    m_MACcache(MACcache),
    m_BMTcache(BMTcache),
    m_config(config),
    m_gpu(gpu) {
    unsigned len = 8;
    m_CTR_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_Ciphertext_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_MAC_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_BMT_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);

    m_CTR_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_MAC_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_BMT_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_Ciphertext_RET_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len + 100);

    m_OTP_queue = new fifo_pipeline<unsigned>("meta-queue", 40, 40 + len);
    m_AES_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);

    m_HASH_queue = new fifo_pipeline<hash>("meta-queue", 40, 40 + len);
    m_MAC_CHECK_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);

    // m_HASH_queue = new fifo_pipeline<unsigned>("meta-queue", 40, 40 + len);
    m_BMT_CHECK_queue = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);
    m_CTR_BMT_Buffer = new fifo_pipeline<mem_fetch>("meta-queue", 0, len);

    BMT_busy = false;
}
int decode(int addr) {
    return (addr & 16128) >> 8;
}
void mee::print_addr(char s[], mem_fetch *mf) {
    if (m_unit->get_mpid() == 0) {
        // printf("%saddr: %x\twr: %d\tdata_type: %d\tsp_id: %d\tsp_addr: %x\taccess type:%d\tmf_id: %d\tcycle: %d\n", s, mf->get_addr(),mf->is_write(), mf->get_data_type(), mf->get_sub_partition_id(), mf->get_partition_addr(), mf->get_access_type(), mf->get_id(), m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);        // print_tag();
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
    return mf->get_partition_addr();
}

new_addr_type mee::get_sub_partition_id(mem_fetch *mf) {
    // return (mf->get_addr() >> 8) & ((1 << 6) - 1);
    
    return mf->get_sub_partition_id();
}

unsigned int mee::get_BMT_Layer(new_addr_type addr) {
    for (int i = 0; i <= 4; i++) {
        if ((addr & BMT_mask[i]) == BMT_base[i]) {
            return i;
        }
    }
    return 5;
}

bool mee::META_queue_empty() {
    return m_CTR_queue->empty() && m_Ciphertext_queue->empty() && m_MAC_queue->empty();
}

new_addr_type mee::get_addr(new_addr_type sub_partition_id, new_addr_type partition_addr) {
    new_addr_type new_addr = partition_addr >> 8 << (8 + 6);
    new_addr |= partition_addr & ((1 << 8) - 1);
    new_addr |= sub_partition_id << 8;
    return new_addr;
}

void mee::gen_CTR_mf(mem_fetch *mf, mem_access_type meta_acc, bool wr, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 14 << 7;
    new_addr_type CTR_addr  = get_addr(sub_partition_id, partition_addr);
    CTR_addr |= CTR_base;

    meta_access(m_CTR_queue, CTR_addr, meta_acc, 
            128, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, CTR);
}

void mee::gen_MAC_mf(mem_fetch *mf, bool wr, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    partition_addr = partition_addr >> 7 << 3;
    new_addr_type MAC_addr  = get_addr(sub_partition_id, partition_addr);
    MAC_addr |= MAC_base;

    meta_access(m_MAC_queue, MAC_addr, META_ACC, 
            8, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, MAC);
}

void mee::gen_BMT_mf(mem_fetch *mf, bool wr, mem_access_type type, unsigned size, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    // unsigned int Layer = get_BMT_Layer(mf->get_addr());
    // if (Layer == 4) //由L4生成ROOT，由于ROOT是单独的寄存器，这里不生成访存请求
    //     return;
    partition_addr = partition_addr & 0x003fffff;
    partition_addr = partition_addr >> 7 << 3;
    new_addr_type BMT_addr  = get_addr(sub_partition_id, partition_addr);
    BMT_addr |= 0xf2000000;

    enum data_type BMT_type = static_cast<data_type>(mf->get_data_type() + 1);

    meta_access(m_BMT_queue, BMT_addr, type, 
            size, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, BMT_type);
}

void mee::meta_access(
        fifo_pipeline<mem_fetch> *m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr,
        unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc,
        mem_fetch *original_mf, unsigned mf_id, enum data_type m_data_type) const {

    mem_access_byte_mask_t byte_mask;
    mem_access_sector_mask_t sector_mask;
    for (unsigned i = 0; i < size; i++) byte_mask.set(i);
    if (size == 128)
        for (unsigned i = 0; i < size / 32; i++) 
            sector_mask.set(i);
    else
        sector_mask.set((addr >> 5) & 3);

    mem_access_t acc(type, addr, size, wr, original_mf->get_access_warp_mask(), byte_mask, sector_mask, m_gpu->gpgpu_ctx);
    mem_fetch *mf = new mem_fetch(
        acc, NULL /*we don't have an instruction yet*/, wr ? WRITE_PACKET_SIZE : READ_PACKET_SIZE,
        wid, sid, tpc, m_config, cycle, original_mf);

    std::vector<mem_fetch *> reqs;
    if (m_config->m_META_config.m_cache_type == SECTOR)
        reqs = m_unit->m_sub_partition[0]->breakdown_request_to_sector_requests(mf);
    else
        reqs.push_back(mf);

    for (unsigned i = 0; i < reqs.size(); ++i) {
        assert(reqs.size() == 1);
        mem_fetch *req = reqs[i];
        req->set_id(mf_id);
        req->set_data_type(m_data_type);
        assert(!m_META_queue->full());
        m_META_queue->push(req);
    }
}

void mee::CT_cycle() {
    if (!m_Ciphertext_RET_queue->empty()) {
        mem_fetch *mf_return = m_Ciphertext_RET_queue->top();
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
        // if (mf_return->get_access_type() != L1_WR_ALLOC_R && mf_return->get_access_type() != L2_WR_ALLOC_R) {
        if (mf_return->is_write()) { // write
        // assert(!mf_return->is_write());
            // print_addr("mee to L2 W:\t", mf_return);
            if (!m_unit->mee_L2_queue_full(spid)){
                // assert(!mf_return->is_write());
                // assert(mf_return->get_access_type() != 4);
                m_unit->mee_L2_queue_push(spid, mf_return); //写密文完成，返回L2
                m_Ciphertext_RET_queue->pop();
            // } else  {
            //     assert(mf_return->get_access_type() != 4);
            }
        } else if (!m_AES_queue->full() && !m_HASH_queue->full()) {              // read
            m_AES_queue->push(mf_return);   //密文从DRAM返回，送往AES解密
            // m_MAC_table[(new_addr_type)mf_return] = ++MAC_counter;
            // assert(m_MAC_table[(new_addr_type)mf_return]);
            // if (m_unit->get_mpid() == 0)
            //     printf("HASH :%d\n", mf_return->get_id());
            m_HASH_queue->push(new hash(MAC, mf_return->get_id()));         //从DRAM中取到密文，对密文进行MAC Hash
            m_Ciphertext_RET_queue->pop();
        }
    }

    if (!m_Ciphertext_queue->empty() && CT_counter < OTP_counter) {
        mem_fetch *mf = m_Ciphertext_queue->top();
        // print_addr("L2 to mee:\t", mf);
        if (mf->is_write()) { // write
        // assert(!mf->is_write());
            if (mf->is_raw() && !m_AES_queue->full()) {
                // assert(!mf->is_write());
                // printf("QQQQQQQQQQQQQQQQ\n");
                m_AES_queue->push(mf);  //写密文请求，将明文送入AES中解密
                mf->set_cooked_status();
                // m_MAC_table[(new_addr_type)mf] = ++MAC_counter;
                // assert(m_MAC_table[(new_addr_type)mf]);
                // m_HASH_queue->push(new unsigned(mf->get_id()));         //加密完后得到密文，对密文进行MAC Hash
                // m_Ciphertext_queue->pop();   //加密完后才可以生成访存
            } else {
                if (!mf->is_raw()) {
                    // printf("RRRRRRRRRRRRRRR");
                }
                if (m_AES_queue->full()) {
                    // printf("SSSSSSSSSSSSSSSSSSS");
                }
            }
        } else if (!m_unit->mee_dram_queue_full()) {              // read
            m_unit->mee_dram_queue_push(mf);    //读密文请求，发往DRAM中读密文
            m_Ciphertext_queue->pop();
            CT_counter++;
        }
    }
}

void mee::AES_cycle() {
    if (!m_AES_queue->empty()) {
        mem_fetch *mf = m_AES_queue->top();
        new_addr_type REQ_addr = (new_addr_type) mf;    //加密/解密请求的明文/密文
        unsigned OTP_id = mf->get_id(); //OTP
        int spid = m_unit->global_sub_partition_id_to_local_id(mf->get_sub_partition_id());
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        // print_addr("waiting for AES:\t", mf);
        assert(OTP_id);
        // if (mf->is_write())
        //     printf("PPPPPPPPPPPPPP\n");
        if (m_OTP_set[OTP_id]) {  // 得到了OTP和明文/密文，AES加密/解密完成 
            if (mf->is_write()) {   //加密
            // assert(!mf->is_write());
                // printf("OOOOOOOOOOOOOOOOOOOOOO\n");
                if (!m_unit->mee_dram_queue_full() && !m_HASH_queue->full()) {
                    m_OTP_set[OTP_id]--;
                    m_unit->mee_dram_queue_push(mf);    //加密完后更新DRAM中的密文
                    CT_counter++;
                    m_HASH_queue->push(new hash(MAC, mf->get_id()));          //加密完后得到密文，对密文进行MAC Hash
                    m_AES_queue->pop();
                    m_Ciphertext_queue->pop();  //写密文发往DRAM
                }
            } else if (!m_unit->mee_L2_queue_full(spid)) {  //解密
                m_OTP_set[OTP_id]--;
                // m_OTP_table[REQ_addr] = 0;
                // print_addr("mee to L2 R:\t", mf);
                m_unit->mee_L2_queue_push(spid, mf);    //解密完后返回L2
                // printf("JJJJJJJJJJJJJJJJJJJJJJJJJ");
                m_AES_queue->pop();
                
            } else {
                // printf("IIIIIIIIIIIIIIII\n");
            }
        } else {
            print_addr("waiting for AES:\t", mf);
            // if (mf->is_write()) 
            //     printf("%p %d AES waiting for OTP %d\n", mf, mf->get_sub_partition_id(), OTP_id);
        }
    }

    if (!m_OTP_queue->empty()){
        unsigned *mf = m_OTP_queue->top();
        if (mf) {
            m_OTP_set[*mf]++; //OTP计算完成
        }
        // delete mf;
        m_OTP_queue->pop();
    }
}

void mee::MAC_CHECK_cycle() {
    if (!m_MAC_CHECK_queue->empty()) {
        // printf("AAAAAAAAAAAAA\n");
        mem_fetch *mf = m_MAC_CHECK_queue->top();
        // print_addr("waiting for MAC Check:\t", mf);
        new_addr_type REQ_addr = (new_addr_type) mf->get_original_mf();    //MAC Cache的值
        unsigned HASH_id = mf->get_id();    //MAC Hash值
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        assert(HASH_id);
        if (m_MAC_set[HASH_id]) { //得到了MAC与Hash值，MAC Check完成
            // printf("MAC check: id %d sid %d\n", HASH_id, mf->get_sub_partition_id());
            m_MAC_set[HASH_id]--;
            // m_MAC_table[REQ_addr] = 0;
            m_MAC_CHECK_queue->pop();
            // printf("%p %d MAC HASH %d\n", mf, mf->get_sub_partition_id(), HASH_id);
        } else {
            // print_addr("waiting for MAC Check:\t", mf);
            // if (mf->get_sub_partition_id() == 32) 
                // printf("%p %d MAC waiting for HASH %d\n", mf, mf->get_sub_partition_id(), HASH_id);
        }
    }

    if (!m_HASH_queue->empty()) {
        // printf("BBBBBBBBBBBBBBB\n");
        hash *mf = m_HASH_queue->top();
        if (mf) {
            // if (m_unit->get_mpid() == 0)
            //     printf("type:%d HASH :%d\n", mf->first, mf->get_id());
            if (mf->first == MAC)
                m_MAC_set[mf->second]++; //MAC Hash计算完成
            if (mf->first >= BMT)
                m_BMT_set[mf->second]++; //BMT Hash计算完成
            m_HASH_queue->pop();
        }
        // delete mf;
        else 
            m_HASH_queue->pop();
    }
}

void mee::BMT_CHECK_cycle() {
    if (!m_BMT_CHECK_queue->empty()) {
        // printf("AAAAAAAAAAAAA\n");
        mem_fetch *mf = m_BMT_CHECK_queue->top();
        new_addr_type REQ_addr = (new_addr_type) mf;    //BMT Cache的值
        unsigned HASH_id = mf->get_id();    //BMT Hash值
        assert(mf->get_access_type() != META_RBW);
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        // assert(mf);
        if (m_BMT_set[HASH_id] && !m_BMT_queue->full(2)) { //得到了BMT与Hash值，BMT Check完成, 计算下一层BMT
            m_BMT_set[HASH_id]--;
            m_BMT_CHECK_queue->pop();
            //计算下一层BMT
            if (mf->get_data_type() == BMT_L4) {
                // printf("AAAAAAAAAAAA\n");
                BMT_busy = false;
                BMT_counter++;
            } else {
                if (mf->is_write()) {
                    gen_BMT_mf(mf, mf->is_write(), META_ACC, 8, HASH_id);
                    assert(!m_BMT_queue->full());
                    gen_BMT_mf(mf, false, META_RBW, 128, 0);
                } else
                    gen_BMT_mf(mf, false, META_ACC, 128, HASH_id);
            }
        }
    }

    // if (!m_HASH_queue->empty()) {
    //     // printf("BBBBBBBBBBBBBBB\n");
    //     hash *mf = m_HASH_queue->top();
    //     if (mf) {
    //         if (mf->first == BMT)
    //             m_BMT_set[mf->first]++; //BMT Hash计算完成
    //     }
    //     // delete mf;
    //     else
    //         m_HASH_queue->pop();
    // }

    // CTR to BMT
    if (!m_CTR_BMT_Buffer->empty() && !m_BMT_CHECK_queue->full() && !m_HASH_queue->full() && !BMT_busy) {
        // assert(cnt);
        mem_fetch *mf = m_CTR_BMT_Buffer->top();
            // gen_BMT_mf(mf, mf->is_write(), META_ACC, 8, mf->get_id());
            m_BMT_CHECK_queue->push(mf);
            m_HASH_queue->push(new hash(BMT, mf->get_id()));
            m_CTR_BMT_Buffer->pop();
            BMT_busy = true;
    }
}

void mee::CTR_cycle() {
    if (!m_CTR_RET_queue->empty()) {
        mem_fetch *mf_return = m_CTR_RET_queue->top();
        if (mf_return->get_access_type() == META_RBW) {    //更新CTR前的CTR读MISS返回
            m_CTR_RET_queue->pop();
            // delete mf_return;//删除1
        } else {    //CTR读MISS返回，CTR写一定命中
            assert(!mf_return->is_write());
                // print_addr("MISS OTP:\t\t", mf_return);
            if (!m_OTP_queue->full() && !m_CTR_BMT_Buffer->full()) { //CTR读MISS，则应生成CTR to BMT任务
                m_OTP_queue->push(new unsigned(mf_return->get_id()));   //得到CTR值，计算OTP用于解密
                #ifdef BMT_Enable
                m_CTR_BMT_Buffer->push(mf_return);
                #endif
                m_CTR_RET_queue->pop();
            }
        }
    }

    m_CTRcache->cycle();
    CT_cycle();
    
    bool output_full = m_OTP_queue->full() || m_CTR_RET_queue->full() || m_CTR_BMT_Buffer->full();
    bool port_free = m_unit->m_CTRcache->data_port_free();

    if (!m_CTR_queue->empty() && !m_unit->mee_dram_queue_full() && !output_full && port_free && CTR_counter <= BMT_counter) {
        mem_fetch *mf = m_CTR_queue->top();
        // print_addr("CTR cycle access:\t\t", mf);

        if (mf->is_write()) {
            if (m_CTRcache->probe(mf->get_addr(), mf) != HIT) {//读到CTR后，才可以CTR++，然后写CTR
                return;
            }
        }

        std::list<cache_event> events;
        enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        if (status == HIT) {
            m_CTR_queue->pop();
            if (mf->is_write()) {   //CTR更新了，BMT也要更新，生成CTR to BMT任务
                #ifdef BMT_Enable
                m_CTR_BMT_Buffer->push(mf);
                CTR_counter++;
                #endif
            }
            if (mf->get_access_type() != META_RBW) {
                m_OTP_queue->push(new unsigned(mf->get_id()));  //CTR HIT后计算OTP用于加密/解密
                OTP_counter++;
            }
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            // print_addr("CTR cycle access:\t\t", mf);
            m_CTR_queue->pop();
            if (mf->get_access_type() != META_RBW) {
                OTP_counter++;
                #ifdef BMT_Enable
                CTR_counter++;
                #endif
            }
        } else {
            assert(!write_sent);
            assert(!read_sent);
        }
    }

    // m_CTRcache->cycle();
};

void mee::MAC_cycle() {
    if (!m_MAC_RET_queue->empty()) {
        mem_fetch *mf_return = m_MAC_RET_queue->top();
        if (mf_return->is_write()) {    //写MAC完成
            m_MAC_RET_queue->pop();
            // delete mf_return;//删除2
        } else {    //MAC读MISS返回
            assert(!mf_return->is_write());
            if (!m_MAC_CHECK_queue->full()) {
                m_MAC_CHECK_queue->push(mf_return); //MAC读MISS完成，得到MAC值，发往MAC Check
                m_MAC_RET_queue->pop();
            }
        }
    }

    m_MACcache->cycle();

    bool output_full = m_MAC_CHECK_queue->full() || m_MAC_RET_queue->full();// && 
    bool port_free = m_unit->m_MACcache->data_port_free();
    
    if (!m_MAC_queue->empty() && !m_unit->mee_dram_queue_full() && !output_full && port_free && MAC_counter < CT_counter) {
        mem_fetch *mf = m_MAC_queue->top();
        // print_addr("MAC cycle access:\t\t", mf);

        if (mf->is_write()) {   //对于写MAC请求，则应等待密文被Hash为新MAC值
            if (!m_MAC_set[mf->get_id()]) {
                return;
            }
        }

        std::list<cache_event> events;
        enum cache_request_status status = m_MACcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status == HIT) {
            if (mf->is_write()) {   //MAC写HIT，则MAC Hash值使用结束
                // m_MAC_set[mf->get_id()]--;
            } else {
                m_MAC_CHECK_queue->push(mf);    //MAC读HIT，得到MAC值，发往MAC Check
            }
            m_MAC_queue->pop();
            MAC_counter++;
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            // print_addr("MAC cycle access MISS:\t\t", mf);
            if (mf->is_write()) {   //MAC写MISS，则MAC Hash值使用结束
                // m_MAC_set[mf->get_id()]--;
            }
            m_MAC_queue->pop();
            MAC_counter++;
        } else {
            // print_addr("CTR cycle RESERVATION_FAIL:\t", mf);
            // if (get_sub_partition_id(mf) == 0)
            //     enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            // print_addr("MAC cycle RESERVATION_FAIL:\t", mf);
            assert(!write_sent);
            assert(!read_sent);
        }
    }
};

void mee::BMT_cycle() {
    if (!m_BMT_RET_queue->empty()) {
        mem_fetch *mf_return = m_BMT_RET_queue->top();
        // print_addr("MISS OTP:\t\t", mf_return);
        if (mf_return->get_access_type() != META_RBW) {
            if (!m_BMT_CHECK_queue->full() && !m_HASH_queue->full()) {
                m_BMT_CHECK_queue->push(mf_return);
                m_HASH_queue->push(new hash(BMT, mf_return->get_id()));
                m_BMT_RET_queue->pop();
            }
        } else {
            m_BMT_RET_queue->pop();
        }
    }

    m_BMTcache->cycle();

    bool output_full = m_BMT_CHECK_queue->full() || m_BMT_RET_queue->full() || m_HASH_queue->full();
    bool port_free = m_unit->m_BMTcache->data_port_free();
    
    if (!m_BMT_queue->empty()) {
        mem_fetch *mf = m_BMT_queue->top();
        // assert(mf->get_access_type() == META_RBW);
    }

    if (!m_BMT_queue->empty() && !m_unit->mee_dram_queue_full() && !output_full && port_free) {
        mem_fetch *mf = m_BMT_queue->top();
        // print_addr("MAC cycle access:\t\t", mf);
        // assert(mf->get_access_type() == mf->get_access_type());

        // if (mf->get_access_type() == META_RBW) {
        //     //对于BMT写，要等待上一层BMT Hash计算完，得到新的BMT值，才可以更新当前层BMT
        //     if (m_BMTcache->probe(mf->get_addr(), mf) != HIT) {//读到CTR后，才可以CTR++，然后写CTR
        //         return;
        //     }
        // }

        std::list<cache_event> events;
        enum cache_request_status status = m_BMTcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status == HIT) {
            if (mf->get_access_type() != META_RBW) {
                m_BMT_CHECK_queue->push(mf);
                m_HASH_queue->push(new hash(BMT, mf->get_id()));
            }
            m_BMT_queue->pop();
        } else if (status != RESERVATION_FAIL) {
            m_BMT_queue->pop();
        } else {
            assert(!write_sent);
            assert(!read_sent);
        }
    }
};

void mee::META_fill_responses(class meta_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, const new_addr_type MASK) {
    if (m_METAcache->access_ready() && !m_META_RET_queue->full()) {
        mem_fetch *mf = m_METAcache->next_access();
        if (mf->get_access_type() == META_ACC)
            m_META_RET_queue->push(mf);
        // assert(mf->get_access_type() == META_ACC);
        // if (m_METAcache == m_BMTcache)
        print_addr("fill responses:\t", mf);
        // reply(m_METAcache, mf);
        // delete mf;
    } else {
        // if (mf->get_sub_partition_id() == 32 && m_META_RET_queue->full()){
        //     print_addr("fill responses ERROR:", mf);
        // }
    }
}

void mee::META_fill(class meta_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, mem_fetch *mf, const new_addr_type MASK, const new_addr_type BASE, enum data_type m_data_type) {
    // if (m_METAcache == m_BMTcache) printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE);
    
    if ((mf->get_data_type() == m_data_type) && m_METAcache->waiting_for_fill(mf)) {
        // print_addr("wating for fill:\t\t", mf); 
        if (m_METAcache->fill_port_free()) {
            // assert(mf->get_access_type() != META_WR_ALLOC_R);
            m_METAcache->fill(mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle +
                                    m_memcpy_cycle_offset);
            // if (m_data_type == MAC)
            //     print_addr("MAC fill:\t", mf);
            assert(!mf->is_write());
            // if (m_METAcache == m_BMTcache)
            //     print_addr("fill:\t\t\t\t", mf);
                // printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE); 
            // if (mf->get_sub_partition_id() == 1) { 
            //     printf("CTR Fill: %p\n", mf);
            //     // printf("CTR Next: %p\n", m_CTR_queue->top());
            // }
            m_unit->dram_mee_queue_pop();
        }
    } else if (mf->get_data_type() == m_data_type) {
      if (mf->is_write() && mf->get_type() == WRITE_ACK)
        mf->set_status(IN_PARTITION_L2_TO_ICNT_QUEUE,
                       m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
    //   m_META_RET_queue->push(mf);
      m_unit->dram_mee_queue_pop();
    }
}

void mee::pr(fifo_pipeline<mem_fetch> *m_META_RET_queue) {
    printf("%d\n",m_META_RET_queue->get_length());
}

void mee::simple_cycle(unsigned cycle) {
    // printf("AAAAAAAAAAAAAAAAAAAAAA");
    // pr(m_CTR_BMT_Buffer);
    // META Cache fill responses
    META_fill_responses(m_CTRcache, m_CTR_RET_queue, CTR_mask);
    META_fill_responses(m_MACcache, m_MAC_RET_queue, MAC_mask);
    // for (int layer = 1; layer <= 4; layer++){
    META_fill_responses(m_BMTcache, m_BMT_RET_queue, BMT_mask[1]);
    // }
    // META_fill_responses(m_BMTcache);

    // dram to mee
    if (!m_unit->dram_mee_queue_empty()) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top();
        // assert(!mf_return->is_write());
        // if (mf_return->get_sub_partition_id() == 58)
        print_addr("waiting for fill:\t", mf_return);
        // printf("%saddr: %x\tdata_type: %d\tsp_addr: %x\taccess type:%d\n", "fill queue:\t", mf->get_addr(), mf->get_data_type(), mf->get_partition_addr(), mf->get_access_type());

        if (false
            // mf_return->get_access_type() == L1_WR_ALLOC_R || 
            // // mf_return->get_access_type() == L2_WR_ALLOC_R ||
            // mf_return->get_access_type() == L1_WRBK_ACC || 
            // mf_return->get_access_type() == L2_WRBK_ACC
            ) {
                assert(mf_return->get_access_type() == 4 && !mf_return->is_write());
            m_unit->dram_mee_queue_pop();
        } else {
        
            // print_addr("dram_mee_queue_top:\t", mf_return);
            // mee to L2
            
            // META_fill(m_MACcache, mf_return, MAC_mask);
            // META_fill(m_BMTcache, mf_return);
            // if (!m_unit->mee_L2_queue_full()) {

            if (mf_return->get_access_type() >= META_ACC) { // META访存的返回，需要响应
                // printf("Success handle CTR_ACC: ");
                // print_addr("META return to mee", mf_return);
                // delete mf_return;
                META_fill(m_CTRcache, m_CTR_RET_queue, mf_return, CTR_mask, CTR_base, CTR);
                META_fill(m_MACcache, m_MAC_RET_queue, mf_return, MAC_mask, MAC_base, MAC);
                // for (int layer = 1; layer <= 4; layer++) {
                    META_fill(m_BMTcache, m_BMT_RET_queue, mf_return, BMT_mask[1], BMT_base[1], BMT_L1);
                    META_fill(m_BMTcache, m_BMT_RET_queue, mf_return, BMT_mask[1], BMT_base[1], BMT_L2);
                    META_fill(m_BMTcache, m_BMT_RET_queue, mf_return, BMT_mask[1], BMT_base[1], BMT_L3);
                    META_fill(m_BMTcache, m_BMT_RET_queue, mf_return, BMT_mask[1], BMT_base[1], BMT_L4);
                // }
            } else {    // 密文访存返回
                // assert(mf_return->get_access_type() != 4);
                // reply L2 read
                // reply L2 write back
                //m_unit->mee_L2_queue_push(m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id()), mf_return);
                int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
                assert(mf_return->get_access_type() < META_ACC);
                if (!m_Ciphertext_RET_queue->full()) {              
                    // m_AES_queue->push(mf_return);   //密文从DRAM返回，送往AES解密
                    // m_MAC_table[(new_addr_type)mf_return] = ++MAC_counter;
                    // assert(m_MAC_table[(new_addr_type)mf_return]);
                    // m_HASH_queue->push(new unsigned(m_MAC_table[(new_addr_type)mf_return]));  //对密文进行hash，用于MAC Check
                    m_Ciphertext_RET_queue->push(mf_return);
                    m_unit->dram_mee_queue_pop();
                    // printf("HHHHHHHHHHHHHHHH");
                } else {
                    // printf("HHHHHHHHHHHHHHHH");
                }
                // print_addr("mee to L2: ", mf_return);
            }
        }
    } else if (!m_unit->mee_dram_queue_empty()) {
        // printf("SSSSSSSSSSSSSSS %d\n", );
    }
    // printf("L2 to mee queue: %d %d\n", m_unit->m_sub_partition[0]->m_L2_mee_queue->empty(), m_unit->m_sub_partition[0]->m_L2_mee_queue->empty());
    // L2 to mee
    if (!m_unit->L2_mee_queue_empty(cycle&1)) {
        mem_fetch *mf = m_unit->L2_mee_queue_top(cycle&1);
        // print_addr("waiting for access:\t", mf);
        // if (mf->get_access_type() == 9)
                        // printf("%saddr: %x\tsp_id: %d\tsp_addr: %x\taccess type:%d\n", "L2 to mee:\t", mf->get_addr(), mf->get_sid(), mf->get_partition_addr(), mf->get_access_type());

        // print_addr("L2 to mee: ", mf);
        // mee to dram
        assert(mf->is_raw());
        // printf("TTTTTTTTTTTTTTTT\n");
        
        if (!m_CTR_queue->full(2) && !m_MAC_queue->full() && !m_Ciphertext_queue->full()) {
            // assert(!mf->is_write());
            if (mf->is_write()) { // write
                assert(mf->is_raw());
                // printf("LLLLLLLLLLLLLLLLLLL");
                // if (!m_Ciphertext_queue->full()) {
                mf_counter++;
                mf->set_id(mf_counter);
                gen_CTR_mf(mf, META_RBW, false, 0);
                gen_CTR_mf(mf, META_ACC, true, mf_counter);
                #ifdef MAC_Enable
                gen_MAC_mf(mf, true, mf_counter);
                #endif
                // m_AES_queue->push(mf);  //写密文请求，将明文送入AES中解密
                m_Ciphertext_queue->push(mf);
                m_unit->L2_mee_queue_pop(cycle&1);
                // mf->set_cooked_status();
                // printf("BBBBBBBBBBBBBBBBB");
                // }
            } else if (!m_unit->mee_dram_queue_full()) {              // read
                // printf("CCCCCCCCCCCCCCCC");
                // m_unit->mee_dram_queue_push(mf);    //读密文请求，发往DRAM中读密文
                mf_counter++;
                mf->set_id(mf_counter);
                m_Ciphertext_queue->push(mf);
                gen_CTR_mf(mf, META_ACC, false, mf_counter);
                #ifdef MAC_Enable
                gen_MAC_mf(mf, false, mf_counter);
                #endif
                m_unit->L2_mee_queue_pop(cycle&1);
            }
        } else {
            // if (m_unit->get_mpid() <= 32){
            //     if (m_CTR_RET_queue->full())
            //         printf("AAAAAAAAAAAAAAAAAAAAAA");
            //     if (m_MAC_RET_queue->full())
            //         printf("BBBBBBBBBBBBBBBBB");
            //     if (m_BMT_RET_queue->full())
            //         printf("CCCCCCCCCCCC");
            //     if (m_AES_queue->full())
            //         printf("DDDDDDDDDDDDDDDD");
            //     // if (m_AES_queue->full())
            //     //     printf("EEEEEEEEEEEEEEEE");
            //     // if (m_unit->mee_dram_queue_empty())
            //     //     printf("FFFFFFFFFFFFFFFFFF");
            // }
                
        }
    } else {
        // printf("GGGGGGGGGGGGGG\n");
    }
    MAC_CHECK_cycle();
    MAC_cycle();
    BMT_CHECK_cycle();
    BMT_cycle();
    AES_cycle();
    CTR_cycle();
    // CT_cycle();
}

void mee::cycle(unsigned cycle) {
    if (!m_unit->dram_mee_queue_empty()) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top();
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
         if (false
            // mf_return->get_is_write() ||
            // mf_return->get_access_type() == L1_WR_ALLOC_R || 
            // mf_return->get_access_type() == L2_WR_ALLOC_R ||
            // mf_return->get_access_type() == L1_WRBK_ACC || 
            // mf_return->get_access_type() == L2_WRBK_ACC
            ) {
                // assert(mf_return->get_access_type() == 4 && !mf_return->is_write());
            m_unit->dram_mee_queue_pop();
        } else {
            if (!m_unit->mee_L2_queue_full(spid)) { 
                // m_OTP_table[REQ_addr] = 0;
                // print_addr("mee to L2 R:\t", mf);
                m_unit->mee_L2_queue_push(spid, mf_return);
                m_unit->dram_mee_queue_pop();
                
            }
        }
    }
    if (!m_unit->L2_mee_queue_empty(cycle&1)) {
        mem_fetch *mf = m_unit->L2_mee_queue_top(cycle&1);
        if (!m_unit->mee_dram_queue_full()) {              
            m_unit->mee_dram_queue_push(mf);
            m_unit->L2_mee_queue_pop(cycle&1);
        }
    }
}

//BMT next Layer
//BMT buzy
//BMT erase
//BMT write需要阻塞，CTR read可以连续访问 
//BMT 写前读 ok

//ok BMT
//ok 检查写操作
//ok 读密文在CTR访存前阻塞
//ok 实现mf id匹配
//ok BMT不需要每层都Check
//ok 增加访存类型的属性
//ok 单个HASH单元
//ok None Sector
//lazy_fetch_on_read不能和None_Sector混用，因为设置modified会Sector_MISS