#include "mee.h"
#include <list>

mee::mee(class memory_partition_unit *unit, class data_cache *CTRcache, class meta_cache *MACcache, class meta_cache *BMTcache, const memory_config *config, counterMap *ctrModCount, class gpgpu_sim *gpu, class ECCEngine *ecc) : 
    m_unit(unit), 
    m_CTRcache(CTRcache),
    m_MACcache(MACcache),
    m_BMTcache(BMTcache),
    m_config(config),
    m_ctrModCount(ctrModCount),
    m_gpu(gpu),
    m_ecc(ecc) {
    unsigned int icnt_L2;
    unsigned int L2_dram;
    unsigned int dram_L2;
    unsigned int L2_icnt;
    sscanf(m_config->gpgpu_L2_queue_config, "%u:%u:%u:%u", &icnt_L2, &L2_dram,
            &dram_L2, &L2_icnt);
    unsigned len = L2_dram;
    unsigned m_id = m_unit->get_mpid();
    m_CTR_queue = new fifo_pipeline<mem_fetch>("meta-CTR-queue", m_id, 0, len);
    m_Ciphertext_queue = new fifo_pipeline<mem_fetch>("meta-Ciphertext-queue", m_id, 0, len);
    #ifdef CTR_HIERACHY
    m_mee_dram_sync_queue = new fifo_pipeline<mem_fetch>("meta-mee-dram-sync-queue", m_id, 0, len);
    #endif
    m_MAC_queue = new fifo_pipeline<mem_fetch>("meta-MAC-queue", m_id, 0, len);
    m_BMT_queue = new fifo_pipeline<mem_fetch>("meta-BMT-queue", m_id, 0, len);

    m_CTR_RET_queue = new fifo_pipeline<mem_fetch>("meta-CTR-RET-queue", m_id, 0, len);
    m_MAC_RET_queue = new fifo_pipeline<mem_fetch>("meta-MAC-RET-queue", m_id, 0, len);
    m_BMT_RET_queue = new fifo_pipeline<mem_fetch>("meta-BMT-RET-queue", m_id, 0, len);
    m_Ciphertext_RET_queue = new fifo_pipeline<mem_fetch>("meta-Ciphertext-RET-queue", m_id, 0, len);

    m_OTP_queue = new fifo_pipeline<unsigned>("meta-OTP-queue", m_id, m_config->m_crypto_latency, m_config->m_crypto_latency + len);
    m_AES_queue = new fifo_pipeline<mem_fetch>("meta-AES-queue", m_id, 0, len);

    m_HASH_queue = new fifo_pipeline<hash>("meta-HASH-queue", m_id, m_config->m_crypto_latency, m_config->m_crypto_latency + len);
    m_MAC_CHECK_queue = new fifo_pipeline<mem_fetch>("meta-MAC-CHECK-queue", m_id, 0, len);

    // m_HASH_queue = new fifo_pipeline<unsigned>("meta-queue", 40, 40 + len);
    m_BMT_CHECK_queue = new fifo_pipeline<mem_fetch>("meta-BMT-CHECK-queue", m_id, 0, len);
    m_CTR_BMT_Buffer = new fifo_pipeline<mem_fetch>("meta-CTR-BMT-Buffer-queue", m_id, 0, len);

    m_ctrModCount = new counterMap;
    m_ctrMajor = new counterMap;
    m_ctrSet = new counterSet;

    BMT_busy = false;
}

void mee::print_mee_fifo_busy() const{
    m_CTR_queue->print_busy();
    m_Ciphertext_queue->print_busy();
    #ifdef CTR_HIERACHY
    m_mee_dram_sync_queue->print_busy();
    #endif
    m_MAC_queue->print_busy();
    m_BMT_queue->print_busy();

    m_CTR_RET_queue->print_busy();
    m_MAC_RET_queue->print_busy();
    m_BMT_RET_queue->print_busy();
    m_Ciphertext_RET_queue->print_busy();

    m_OTP_queue->print_busy();
    m_AES_queue->print_busy();

    m_HASH_queue->print_busy();
    m_MAC_CHECK_queue->print_busy();

    // m_HASH_queue = new fifo_pipeline<unsigned>("meta-queue", 40, 40 + len);
    m_BMT_CHECK_queue->print_busy();
    m_CTR_BMT_Buffer->print_busy();
}

int decode(int addr) {
    return (addr & 16128) >> 8;
}
void mee::print_addr(char s[], mem_fetch *mf) const{
    // if (m_unit->get_mpid() == 1) {
    //     printf("%s\t", s);
    //     if (mf->get_original_mf())
    //         printf("original_addr: %x\toriginal_sp_addr: %x\t", mf->get_original_mf()->get_addr(), mf->get_original_mf()->get_partition_addr());
    //     printf("addr: %x\twr: %d\tdata_type: %d\tBMT_Layer: %d\tsp_id: %d\tsp_addr: %x\taccess type:%d\tmf_id: %d\tcycle: %d\n", mf->get_addr(),mf->is_write(), mf->get_data_type(), mf->get_BMT_Layer(), mf->get_sub_partition_id(), mf->get_partition_addr(), mf->get_access_type(), mf->get_id(), m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);        // print_tag();
    // }
}

void mee::print_status(class data_cache *m_METAcache, mem_fetch *mf) {
    // if (m_unit->get_mpid() == 14) {
    //     unsigned idx = m_METAcache->m_config.set_index(mf->get_addr());
    //     enum cache_request_status status = m_METAcache->m_tag_array->probe(mf->get_addr(), idx, mf->get_access_sector_mask(), mf->is_write());
    //     printf("idx is %u\t", idx);
    //     printf("sector mask is %u\n", mf->get_access_sector_mask().to_ulong());
    //     m_METAcache->m_tag_array->m_lines[idx]->print_status();
    // }
}

void mee::print_tag() {
    // if (get_sub_partition_id(mf) == 0) {
        // for (unsigned i = 0; i < m_config->m_META_config.get_num_lines(); i++) {
        for (unsigned i = 188; i < 192; i++) {
            // printf("line %d:\t", i);
            // for (unsigned j = 0; j < SECTOR_CHUNCK_SIZE; j++)
            //     // printf("%d\t", 
            //     m_CTRcache->m_tag_array->m_lines[i]->print_status();
            // printf("\n");
        }
    // }
}

void mee::print_ctr(new_addr_type sub_partition_id, new_addr_type partition_addr) {
    new_addr_type ctr_sector_addr = CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5);
    new_addr_type ctr_minor_addr = (CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5)) + (partition_addr & 31);
    
    if ((*m_ctrModCount)[ctr_minor_addr] == 128) {
        (*m_ctrMajor)[ctr_sector_addr]++;
        for (int offset = 0; offset < 32; offset++) {
            (*m_ctrModCount)[ctr_sector_addr + offset] = 0;
        }
    }
    
    std::string kernel_info_str = "ctrModificationCountStat.log";
    FILE *log = fopen(kernel_info_str.c_str(), "a");
    fprintf(log, "%x,%d,%d,%d", ctr_sector_addr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, (*m_ctrMajor)[ctr_sector_addr], (*m_ctrModCount)[ctr_sector_addr]);// - 6
    for (unsigned offset = 1; offset < 32; offset++) {
        fprintf(log, ",%d", (*m_ctrModCount)[ctr_sector_addr + offset]);// - 6
    }
    fprintf(log, "\n");
    fclose(log);
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

void mee::gen_CTR_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    // new_addr_type minor_addr = (partition_addr >> 7) & 127;
    // minor_addr = 128 + minor_addr * 7;
    // bool res = minor_addr & 7 > 1;
    // minor_addr >>= 3;
    partition_addr = (partition_addr >> 7);

    // if (meta_acc == META_ACC)
    //     partition_addr |= minor_addr;

    new_addr_type CTR_addr  = get_addr(sub_partition_id, partition_addr);
    CTR_addr |= CTR_base;
    if (wr) {
        (*m_ctrModCount)[CTR_addr]++;
        assert(CTR_addr == (CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5)) + (partition_addr & 31));
        (*m_ctrSet).insert(CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5));
        print_ctr(sub_partition_id, partition_addr);
    } else {
        // (*m_ctrModCount)[CTR_addr] += 0;
        (*m_ctrSet).insert(CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5));
        assert(CTR_addr == (CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5)) + (partition_addr & 31));
    }
    // printf("CTR_addr:\t%xCTR_sector_addr:%x\n", CTR_addr, (CTR_base | get_addr(sub_partition_id, (partition_addr >> 5) << 5)));

    // if (meta_acc == META_ACC && res)
    //     size <<= 1;

    meta_access(m_CTR_queue, CTR_addr, meta_acc, 
            size, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, CTR, DEFAULT);
}

void mee::gen_MAC_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    if (m_config->m_META_config.m_cache_type == SECTOR)
        partition_addr = partition_addr >> 6 << 2;
    else
        partition_addr = partition_addr >> 7 << 3;
    new_addr_type MAC_addr  = get_addr(sub_partition_id, partition_addr);
    MAC_addr |= MAC_base;

    meta_access(m_MAC_queue, MAC_addr, meta_acc, 
            size, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, MAC, DEFAULT);
}

void mee::gen_BMT_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id) {
    new_addr_type partition_addr = get_partition_addr(mf);
    new_addr_type sub_partition_id = get_sub_partition_id(mf);
    // unsigned int Layer = get_BMT_Layer(mf->get_addr());
    // if (Layer == 4) //由L4生成ROOT，由于ROOT是单独的寄存器，这里不生成访存请求
    //     return;
    partition_addr = partition_addr & 0x003fffff;
    if (size == 128)
        partition_addr = partition_addr >> 11 << 7;
    else
        partition_addr = partition_addr >> 9 << 5;
    new_addr_type BMT_addr  = get_addr(sub_partition_id, partition_addr);
    BMT_addr |= 0xF2000000;

    enum BMT_Layer BMT_type = static_cast<BMT_Layer>(mf->get_BMT_Layer() + 1);

    meta_access(m_BMT_queue, BMT_addr, meta_acc, 
            size, wr, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, 
            mf->get_wid(), mf->get_sid(), mf->get_tpc(), mf, mf_id, BMT, BMT_type);
}

void mee::meta_access(
        fifo_pipeline<mem_fetch> *m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr,
        unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc,
        mem_fetch *original_mf, unsigned mf_id, enum data_type m_data_type, enum BMT_Layer m_Layer) const {

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
        if (m_data_type == CTR)
            print_addr("gen CTR mf:", req);
    }
}

void mee::push_cipher_request(mem_fetch *mf) {
    unsigned long long now =
        m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
    memory_stats_t *stats = m_gpu->get_memory_stats();
    if (mf && mf->get_id() == 0) {
        unsigned new_id = next_mf_id();
        fprintf(stderr,
                "[MEE][warn] mpid %u push_cipher_request zero id addr 0x%llx access %d data %d -> assign %u\n",
                m_unit->get_mpid(), (unsigned long long)mf->get_addr(),
                mf->get_access_type(), mf->get_data_type(), new_id);
        mf->set_id(new_id);
    }
    if (mf->get_subpartition_arrival_time()) {
        stats->record_stage_latency(SUBPARTITION_STAGE,
                                    now - mf->get_subpartition_arrival_time());
        mf->set_subpartition_arrival_time(0);
    }
    mf->set_cipher_enqueue_time(now);
    m_Ciphertext_queue->push(mf);
}

unsigned mee::next_mf_id() {
    ++mf_counter;
    if (mf_counter == 0) ++mf_counter;
    return mf_counter;
}

void mee::CT_cycle() {
    #ifdef CTR_HIERACHY
    //MEE向DRAM发送访存请求
    if (!m_mee_dram_sync_queue->empty() && !m_unit->mee_dram_queue_full(NORM)) {
        mem_fetch *mf = m_mee_dram_sync_queue->top();
        assert(mf->get_addr());
        if (mf->is_write()) {
            if (m_MAC_set[mf->get_id()]) {
                print_addr("sync Wdata to dram:\t", mf);
                m_unit->mee_dram_queue_push(mf, NORM);
                m_MAC_set[mf->get_id()]--;  //生成的MAC与写密文一起写入DRAM
                m_mee_dram_sync_queue->pop();
            } else 
                print_addr("sync Wdata pending:\t", mf);
        } else {
            print_addr("sync Rdata to dram:\t", mf);
            m_unit->mee_dram_queue_push(mf, NORM);
            // m_MAC_set[mf->get_id()]--;  //此时还没读到MAC
            m_mee_dram_sync_queue->pop();
        }
    }
    #endif

    //DRAM向MEE传回数据
    if (!m_Ciphertext_RET_queue->empty() && !m_gpu->hasGlobalECCError()) {
        //ECC纠错时，为保证访存一致性，不接受新的密文
        //ECC纠错完成后，需要重新对密文进行解密，增加20周期延迟
        //TODO：理论上，应该将发生错误的请求，以及在这之前的请求，都重新加密
        mem_fetch *mf_return = m_Ciphertext_RET_queue->top();
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
        // if (mf_return->get_access_type() != L1_WR_ALLOC_R && mf_return->get_access_type() != L2_WR_ALLOC_R) {
        if (mf_return->is_write()) { // write
        // assert(!mf_return->is_write());
            print_addr("mee to L2 writeack:\t", mf_return);
            if (!m_unit->mee_L2_queue_full(spid)){
                // assert(!mf_return->is_write());
                // assert(mf_return->get_access_type() != 4);
                #ifdef AES_Enable
                m_unit->mee_L2_queue_push(spid, mf_return); //写密文完成，返回L2
                #else
                delete mf_return;
                #endif
                m_Ciphertext_RET_queue->pop();
            // } else  {
            //     assert(mf_return->get_access_type() != 4);
            }
        } else if (!m_AES_queue->full() && !m_HASH_queue->full()) {              // read
            assert(mf_return->get_id());
            m_AES_queue->push(mf_return);   //密文从DRAM返回，送往AES解密
            mf_return->set_aes_enqueue_time(
                m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
            print_addr("DRAM to AES:", mf_return);
            // m_MAC_table[(new_addr_type)mf_return] = ++MAC_counter;
            // assert(m_MAC_table[(new_addr_type)mf_return]);
            // if (m_unit->get_mpid() == 0)
            //     printf("HASH :%d\n", mf_return->get_id());
            m_HASH_queue->push(new hash{MAC, mf_return->get_id(), mf_return->is_write()});         //从DRAM中取到密文，对密文进行MAC Hash
            m_Ciphertext_RET_queue->pop();
        }
    }

    if (!m_Ciphertext_queue->empty()) {
        mem_fetch *mf = m_Ciphertext_queue->top();
        print_addr("L2 to mee:\t", mf);
        if (mf->is_write()) { // write
        // assert(!mf->is_write());
            if (mf->is_raw() && !m_AES_queue->full()) {
                // assert(!mf->is_write());
                // printf("QQQQQQQQQQQQQQQQ\n");
                assert(mf->get_id());
                m_AES_queue->push(mf);  //写密文请求，将明文送入AES中解密
                mf->set_aes_enqueue_time(m_gpu->gpu_sim_cycle +
                                         m_gpu->gpu_tot_sim_cycle);
                mf->set_cooked_status();
                // m_MAC_table[(new_addr_type)mf] = ++MAC_counter;
                // assert(m_MAC_table[(new_addr_type)mf]);
                // m_HASH_queue->push(new unsigned(mf->get_id()));         //加密完后得到密文，对密文进行MAC Hash
                // m_Ciphertext_queue->pop();   //加密完后才可以生成访存
                print_addr("L2 Wdata to AES:", mf);
        } else {
            if (!mf->is_raw()) {
                // printf("RRRRRRRRRRRRRRR");
            }
            if (m_AES_queue->full()) {
                // printf("SSSSSSSSSSSSSSSSSSS");
                m_gpu->get_memory_stats()->record_stage_stall(AES_INPUT_STALL);
            }
        }
#ifdef CTR_HIERACHY
        } else if (!m_mee_dram_sync_queue->full()) {              // read
            // m_unit->mee_dram_queue_push(mf, NORM);    //读密文请求，发往DRAM中读密文
            print_addr("L2 Rdata to sync:", mf);
            m_mee_dram_sync_queue->push(mf);
            m_Ciphertext_queue->pop();
            CT_counter++; 
        } else {
            memory_stats_t *stats_local = m_gpu->get_memory_stats();
            stats_local->record_stage_stall(MEE_DRAM_QUEUE_FULL_STALL_DATA);
            if (m_HASH_queue->full())
                stats_local->record_stage_stall(HASH_QUEUE_FULL_STALL);
        #else
        } else if (!m_unit->mee_dram_queue_full(NORM)) {              // read
            #ifdef AES_Enable
            m_unit->mee_dram_queue_push(mf, NORM);    //读密文请求，发往DRAM中读密文
            #endif
            m_Ciphertext_queue->pop();
            CT_counter++;    
        } else {
            memory_stats_t *stats_local = m_gpu->get_memory_stats();
            stats_local->record_stage_stall(MEE_DRAM_QUEUE_FULL_STALL_DATA);
            if (m_HASH_queue->full())
                stats_local->record_stage_stall(HASH_QUEUE_FULL_STALL);
        #endif
            memory_stats_t *stats = m_gpu->get_memory_stats();
            unsigned long long now =
                m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
            if (mf->get_cipher_enqueue_time()) {
                stats->record_stage_latency(CIPHER_QUEUE_STAGE,
                                            now - mf->get_cipher_enqueue_time());
                mf->reset_cipher_enqueue_time();
            }
        }
    }
}

void mee::AES_cycle() {
  memory_stats_t *stats = m_gpu->get_memory_stats();
  if (m_AES_queue->empty()) {
    stats->record_aes_idle();
    return;
  }

  mem_fetch *mf = m_AES_queue->top();
  const unsigned long long now =
      m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
  const unsigned OTP_id = mf->get_id();
  const int spid =
      m_unit->global_sub_partition_id_to_local_id(mf->get_sub_partition_id());

  print_addr("waiting for AES:\t", mf);
  assert(OTP_id);

  if (m_OTP_set[OTP_id]) {
    if (mf->is_write()) {
      bool issued = false;
#ifdef CTR_HIERACHY
      if (!m_mee_dram_sync_queue->full() && !m_HASH_queue->full()) {
        print_addr("AES Wdata to sync:\t", mf);
        m_mee_dram_sync_queue->push(mf);
        issued = true;
      }
#else
      if (!m_unit->mee_dram_queue_full(NORM) && !m_HASH_queue->full()) {
        m_OTP_set[OTP_id]--;
#ifdef AES_Enable
        m_unit->mee_dram_queue_push(mf, NORM);
#endif
        issued = true;
      }
#endif

      if (issued) {
        CT_counter++;
        m_HASH_queue->push(new hash{MAC, mf->get_id(), mf->is_write()});
        if (mf->get_aes_enqueue_time()) {
          stats->record_stage_latency(AES_QUEUE_STAGE,
                                      now - mf->get_aes_enqueue_time());
          mf->reset_aes_enqueue_time();
        }
        stats->record_stage_latency(AES_SERVICE_STAGE,
                                    m_config->m_crypto_latency);
        stats->record_aes_busy(m_config->m_crypto_latency);
        m_AES_queue->pop();
        if (mf->get_cipher_enqueue_time()) {
          stats->record_stage_latency(CIPHER_QUEUE_STAGE,
                                      now - mf->get_cipher_enqueue_time());
          mf->reset_cipher_enqueue_time();
        }
        m_Ciphertext_queue->pop();
      } else {
        stats->record_stage_stall(AES_INPUT_STALL);
        stats->record_aes_idle();
      }
    } else if (!m_unit->mee_L2_queue_full(spid)) {
      m_OTP_set[OTP_id]--;
#ifdef AES_Enable
      m_unit->mee_L2_queue_push(spid, mf);
#else
      delete mf;
#endif
      print_addr("AES Rdata to L2:\t", mf);
      if (mf->get_aes_enqueue_time()) {
        stats->record_stage_latency(AES_QUEUE_STAGE,
                                    now - mf->get_aes_enqueue_time());
        mf->reset_aes_enqueue_time();
      }
      stats->record_stage_latency(AES_SERVICE_STAGE,
                                  m_config->m_crypto_latency);
      stats->record_aes_busy(m_config->m_crypto_latency);
      m_AES_queue->pop();
      mf->set_decrypt_finish_time(now);
    } else {
      stats->record_stage_stall(MEE_L2_QUEUE_FULL_STALL);
    }
  } else {
    stats->record_stage_stall(AES_INPUT_STALL);
    stats->record_aes_idle();
  }

  if (!m_OTP_queue->empty()) {
    unsigned *otp_token = m_OTP_queue->top();
    if (otp_token) {
      m_OTP_set[*otp_token]++;
    }
    delete otp_token;
    m_OTP_queue->pop();
  }
}

void mee::HASH_cycle() {
    m_ecc->accumulateError();
    if (m_gpu->hasGlobalECCError()) {
        // if (m_ecc->hasECCError())
        //     printf("correctECC mpid:%d \n", m_unit->get_mpid());
        m_ecc->correctECC();
    }
    else if (!m_HASH_queue->empty() ) {
        // printf("BBBBBBBBBBBBBBB\n");
        hash *mf = m_HASH_queue->top();
        if (mf) {
            // if (m_unit->get_mpid() == 0)
            //     printf("type:%d HASH :%d\n", mf->first, mf->get_id());
            if (mf->type == MAC) {
                m_MAC_set[mf->id]++; //MAC Hash计算完成
                if (mf->wr) {
                    m_ecc->generateECC();
                } else {
                    m_ecc->checkECC();
                }
            }
            if (mf->type == BMT)
                m_BMT_set[mf->id]++; //BMT Hash计算完成
            m_HASH_queue->pop();
        }
        // delete mf;
        else 
            m_HASH_queue->pop();
    }
}

void mee::MAC_CHECK_cycle() {
    memory_stats_t *stats = m_gpu->get_memory_stats();
    unsigned long long now =
        m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
    if (!m_MAC_CHECK_queue->empty()) {
        // printf("AAAAAAAAAAAAA\n");
        mem_fetch *mf = m_MAC_CHECK_queue->top();
        unsigned HASH_id = mf->get_id();    //MAC Hash值
        assert(HASH_id);
        if (m_MAC_set[HASH_id]) { //得到了MAC与Hash值，MAC Check完成
            // if (m_unit->get_mpid() == 12)
            // printf("MAC check: id %d sid %d\n", HASH_id, mf->get_sub_partition_id());
            m_MAC_set[HASH_id]--;
            // m_MAC_table[REQ_addr] = 0;
            if (mf->get_hash_enqueue_time()) {
                stats->record_stage_latency(HASH_QUEUE_STAGE,
                                            now - mf->get_hash_enqueue_time());
                mf->reset_hash_enqueue_time();
            }
            m_MAC_CHECK_queue->pop();
            // printf("%p %d MAC HASH %d\n", mf, mf->get_sub_partition_id(), HASH_id);
        } else {
            print_addr("waiting for MAC Check:\t", mf);
            // if (mf->get_sub_partition_id() == 32) 
                // printf("%p %d MAC waiting for HASH %d\n", mf, mf->get_sub_partition_id(), HASH_id);
            stats->record_stage_stall(HASH_QUEUE_FULL_STALL);
        }
    }

}

// void mee::ECC_CHECK_cycle() {

// }

void mee::BMT_CHECK_cycle() {
    memory_stats_t *stats = m_gpu->get_memory_stats();
    unsigned long long now =
        m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
    if (!m_BMT_CHECK_queue->empty()) {
        // printf("AAAAAAAAAAAAA\n");
        mem_fetch *mf = m_BMT_CHECK_queue->top();
        new_addr_type REQ_addr = (new_addr_type) mf;    //BMT Cache的值
        unsigned HASH_id = mf->get_id();    //BMT Hash值
        assert(mf->get_access_type() != META_RBW);
        // if (mf->get_sub_partition_id() == 0) 
        //     printf("%x\n", OTP_addr);
        // assert(mf);
        if (m_BMT_set[HASH_id] && ((m_config->m_META_config.m_cache_type == SECTOR && !m_BMT_queue->full(2)) || (m_config->m_META_config.m_cache_type != SECTOR && !m_BMT_queue->full(2)))) { //得到了BMT与Hash值，BMT Check完成, 计算下一层BMT
            m_BMT_set[HASH_id]--;
            m_BMT_CHECK_queue->pop();
            if (mf->get_hash_enqueue_time()) {
                stats->record_stage_latency(BMT_CHECK_STAGE,
                                            now - mf->get_hash_enqueue_time());
                mf->reset_hash_enqueue_time();
            }
            // print_addr("BMT Hash:\t", mf);
            //计算下一层BMT
            if (mf->get_BMT_Layer() == BMT_L4) {
                // printf("AAAAAAAAAAAA\n");
                BMT_busy = false;
                m_n_reqs_in_BMT--;
                if (mf->get_id())
                    BMT_counter++;
            } else {
                if (mf->is_write()) {
                    if (m_config->m_META_config.m_cache_type == SECTOR) {
                        gen_BMT_mf(mf, mf->is_write(), META_ACC, 2, HASH_id); // Lazy fetch on read策略下，写操作不会发给dram
                        assert(!m_BMT_queue->full());
                        gen_BMT_mf(mf, false, META_ACC, 32, HASH_id);
                    } else {
                        gen_BMT_mf(mf, mf->is_write(), META_ACC, 8, HASH_id); // Lazy fetch on read策略下，写操作不会发给dram
                        assert(!m_BMT_queue->full());
                        gen_BMT_mf(mf, false, META_ACC, 128, HASH_id);
                    }
                } else {
                    if (m_config->m_META_config.m_cache_type == SECTOR) {
                        gen_BMT_mf(mf, false, META_ACC, 32, HASH_id);
                    } else {
                        gen_BMT_mf(mf, false, META_ACC, 128, HASH_id);
                    }
                }
            }
            // if (m_unit->get_mpid() == 13)
            //     printf("BMT_queue size = %d\n", m_BMT_queue->get_n_element());
        } else {
            stats->record_stage_stall(BMT_CHECK_QUEUE_FULL_STALL);
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
    if (!m_CTR_BMT_Buffer->empty() && m_n_reqs_in_BMT < 64 && !m_HASH_queue->full()) {
        // assert(cnt);
        mem_fetch *mf = m_CTR_BMT_Buffer->top();
            // gen_BMT_mf(mf, mf->is_write(), META_ACC, 8, mf->get_id());
        print_addr("CTR to BMT:\t", mf);
        // if (m_unit->get_mpid() == 13)
        //     printf("BMT_CHECK_queue size = %d\n", m_BMT_CHECK_queue->get_n_element());
        m_n_reqs_in_BMT++;
        m_BMT_CHECK_queue->push(mf);
        m_HASH_queue->push(new hash{BMT, mf->get_id(), mf->is_write()});
        m_CTR_BMT_Buffer->pop();
        BMT_busy = true;
    }
}

void mee::CTR_cycle() {
    if (!m_CTR_RET_queue->empty()) {
        mem_fetch *mf_return = m_CTR_RET_queue->top();
        if (!mf_return->get_id() || mf_return->get_access_type() == META_RBW) {    //更新CTR前的CTR读MISS返回
            m_CTR_RET_queue->pop();
            // delete mf_return;//删除1
        } else {    //CTR读MISS返回，CTR写一定命中
            // assert(!mf_return->is_write());
            print_addr("CTR MISS return:\t\t", mf_return);
            if (!m_OTP_queue->full()) { //CTR读MISS，则应生成CTR to BMT任务
                // m_ctr_rdret_addr = mf_return->get_addr();
                // m_ctr_wr_addr[mf_return->get_addr()]++; //CTR读MISS后，CTR++，然后写CTR
                m_OTP_queue->push(new unsigned(mf_return->get_id()));   //得到CTR值，计算OTP用于解密
                m_CTR_RET_queue->pop();
            }
        }
    }

    m_CTRcache->cycle();
    CT_cycle();
    
    bool output_full = m_OTP_queue->full() || m_CTR_RET_queue->full() || m_CTR_BMT_Buffer->full();
    #ifdef CTR_HIERACHY
    output_full |= m_unit->m_ctr_L2_bundle_queue->full();
    #endif
    bool port_free = m_unit->m_CTRcache->data_port_free();

    if (!m_CTR_queue->empty() && !m_unit->mee_dram_queue_full(CTR) && !output_full && port_free) {
        mem_fetch *mf = m_CTR_queue->top();
        print_addr("CTR cycle access:\t\t", mf);
        memory_stats_t *stats = m_gpu->get_memory_stats();
        unsigned long long now =
            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
        // if (mf->get_ctr_enqueue_time()) {
        //     stats->record_stage_latency(CTR_META_STAGE,
        //                                 now - mf->get_ctr_enqueue_time());
        //     mf->reset_ctr_enqueue_time();
        // }

        // if (mf->is_write()) {
        //     // if (m_unit->get_mpid() == 23)
        //     //     printf("ctr write access:\tm_pid:%d\tOTP_id:%d\tctr_rdhit_addr: %x\tctr_rdret_addr: %x\tctr_write_addr: %x\n", 
        //     //         m_unit->get_mpid(), mf->get_id(), m_ctr_rdhit_addr, m_ctr_rdret_addr, mf->get_addr());
        //     if (!m_OTP_set[mf->get_id()] && !m_ctr_wr_addr[mf->get_addr()]) {//读到CTR后，才可以CTR++，然后写CTR
        //         // todo: CTR更新需要先读后写，需要完善读完成的检测
        //         // return;
        //     }
        // }

        std::list<cache_event> events;
        enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        if (status != RESERVATION_FAIL) { 
            if (mf->get_ctr_enqueue_time()) {
                stats->record_stage_latency(CTR_QUEUE_STAGE,
                                            now - mf->get_ctr_enqueue_time());
                mf->reset_ctr_enqueue_time();
            }
        }
        if (status == HIT) {
            m_CTR_queue->pop();
            if (mf->is_write()) {   //CTR更新了，BMT也要更新，生成CTR to BMT任务
                print_addr("CTR Write Hit:\t", mf);
                // m_OTP_set[mf->get_id()]--;
                #ifdef BMT_Enable
                if (mf->get_id())
                    m_CTR_BMT_Buffer->push(mf);
                if (mf->get_id())
                    CTR_counter++;
                #endif
            }
            else if (mf->get_access_type() != META_RBW) {
                print_addr("CTR Read Hit:\t", mf);
                if (mf->get_id())
                    m_OTP_queue->push(new unsigned(mf->get_id()));  //CTR HIT后计算OTP用于加密/解密
                if (mf->get_id())
                    OTP_counter++;
                // m_ctr_wr_addr[mf->get_addr()]++;
            }
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            print_addr("CTR MISS:\t", mf);
            m_CTR_queue->pop();
            // assert(!mf->is_write());
            if (mf->get_access_type() != META_RBW) {
                if (mf->get_id())
                    OTP_counter++;
                #ifdef BMT_Enable
                if (mf->get_id())
                    CTR_counter++;
                #endif
            }
        } else {
            assert(!write_sent);
            assert(!read_sent);
            memory_stats_t *stats = m_gpu->get_memory_stats();
            stats->record_stage_stall(CTR_META_RESERVATION_STALL);
        }
    } else if (!m_CTR_queue->empty()) {
        memory_stats_t *stats = m_gpu->get_memory_stats();
        if (m_unit->mee_dram_queue_full(CTR))
            stats->record_stage_stall(MEE_DRAM_QUEUE_FULL_STALL_CTR);
        if (output_full) stats->record_stage_stall(CTR_META_RESERVATION_STALL);
        if (!port_free) stats->record_stage_stall(CTR_META_RESERVATION_STALL);
    }

    // m_CTRcache->cycle();
};

void mee::MAC_cycle() {
    memory_stats_t *stats = m_gpu->get_memory_stats();
    unsigned long long now =
        m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
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
            } else {
                stats->record_stage_stall(HASH_QUEUE_FULL_STALL);
            }
        }
    }

    m_MACcache->cycle();

    bool output_full = m_MAC_CHECK_queue->full() || m_MAC_RET_queue->full();// && 
    bool port_free = m_unit->m_MACcache->data_port_free();
    
    if (!m_MAC_queue->empty() && !m_unit->mee_dram_queue_full(MAC) && !output_full && port_free) {
        mem_fetch *mf = m_MAC_queue->top();
        print_addr("MAC cycle access:\t\t", mf);
        // if (mf->get_mac_enqueue_time()) {
        //     stats->record_stage_latency(MAC_QUEUE_STAGE,
        //                                 now - mf->get_mac_enqueue_time());
        //     mf->reset_mac_enqueue_time();
        // }

        assert(mf->get_id());

        // 写操作前先读
        // 读命中则写也命中
        // 读MISS则写也MISS
        // if (mf->is_write()) {   //对于写MAC请求，则应等待密文被Hash为新MAC值
        //     if (!m_MAC_set[mf->get_id()]) {
        //         // return;
        //     }
        // }

        std::list<cache_event> events;
        enum cache_request_status status = m_MACcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
        bool write_sent = was_write_sent(events);
        bool read_sent = was_read_sent(events);
        // print_addr("CTR cycle access:\t\t", mf);
        if (status != RESERVATION_FAIL) { 
            if (mf->get_mac_enqueue_time()) {
                stats->record_stage_latency(MAC_QUEUE_STAGE,
                                            now - mf->get_mac_enqueue_time());
                mf->reset_mac_enqueue_time();
            }
        }
        if (status == HIT) {
            if (mf->is_write()) {   //MAC写HIT，则MAC Hash值使用结束
                // m_MAC_set[mf->get_id()]--;
            } else {
                mf->set_hash_enqueue_time(now);
                m_MAC_CHECK_queue->push(mf);    //MAC读HIT，得到MAC值，发往MAC Check
            }
            print_addr("MAC cycle access HIT:\t", mf);
            print_status(m_MACcache, mf);
            m_MAC_queue->pop();
            MAC_counter++;
            // }
        } else if (status != RESERVATION_FAIL) {
            // set wating for CTR fill
            print_addr("MAC cycle access MISS:\t", mf);
            print_status(m_MACcache, mf);
            if (mf->is_write()) {   //MAC写MISS，则MAC Hash值使用结束
                // m_MAC_set[mf->get_id()]--;
            }
            m_MAC_queue->pop();
            MAC_counter++;
        } else {
            print_addr("MAC cycle RESERVATION_FAIL:\t", mf);
            print_status(m_MACcache, mf);
            stats->record_stage_stall(MAC_META_RESERVATION_STALL);
            // m_MACcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            // if (get_sub_partition_id(mf) == 0)
            //     enum cache_request_status status = m_CTRcache->access(mf->get_addr(), mf, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle, events);
            // print_addr("MAC cycle RESERVATION_FAIL:\t", mf);
            assert(!write_sent);
            assert(!read_sent);
        }
    } else if (!m_MAC_queue->empty()) {
        if (m_unit->mee_dram_queue_full(MAC))
            stats->record_stage_stall(MEE_DRAM_QUEUE_FULL_STALL_MAC);
        if (output_full) stats->record_stage_stall(MAC_QUEUE_FULL_STALL);
        if (!port_free) stats->record_stage_stall(MAC_QUEUE_FULL_STALL);
    }
};

void mee::BMT_cycle() {
    memory_stats_t *stats = m_gpu->get_memory_stats();
    if (!m_BMT_RET_queue->empty()) {
        mem_fetch *mf_return = m_BMT_RET_queue->top();
        // print_addr("MISS OTP:\t\t", mf_return);
        if (mf_return->get_id() && !mf_return->is_write()) {
            if (!m_BMT_CHECK_queue->full() && !m_HASH_queue->full()) {
                m_BMT_CHECK_queue->push(mf_return);
                m_HASH_queue->push(new hash{BMT, mf_return->get_id(), mf_return->is_write()});
                m_BMT_RET_queue->pop();
            } else {
                if (m_BMT_CHECK_queue->full())
                    stats->record_stage_stall(BMT_CHECK_QUEUE_FULL_STALL);
                if (m_HASH_queue->full())
                    stats->record_stage_stall(HASH_QUEUE_FULL_STALL);
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

    if (!m_BMT_queue->empty() && !m_unit->mee_dram_queue_full(BMT) && !output_full && port_free) {
        mem_fetch *mf = m_BMT_queue->top();
        print_addr("BMT waiting access:\t", mf);
        // if (mf->get_bmt_enqueue_time()) {
        //     unsigned long long now =
        //         m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
        //     stats->record_stage_latency(BMT_QUEUE_STAGE,
        //                                 now - mf->get_bmt_enqueue_time());
        //     mf->reset_bmt_enqueue_time();
        // }
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
        if (status != RESERVATION_FAIL) { 
            unsigned long long now =
                m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
            if (mf->get_bmt_enqueue_time()) {
                stats->record_stage_latency(BMT_QUEUE_STAGE,
                                            now - mf->get_bmt_enqueue_time());
                mf->reset_bmt_enqueue_time();
            }
        }
        if (status == HIT) {
            print_addr("BMT access HIT:\t", mf);
            if (mf->get_id() && !mf->is_write()) {
                unsigned long long now =
                    m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
                mf->set_hash_enqueue_time(now);
                m_BMT_CHECK_queue->push(mf);
                m_HASH_queue->push(new hash{BMT, mf->get_id(), mf->is_write()});
            }
            m_BMT_queue->pop();
        } else if (status != RESERVATION_FAIL) {
            print_addr("BMT access MISS:\t", mf);
            m_BMT_queue->pop();
        } else {
            print_addr("BMT access reservation_fail:\t", mf);
            assert(!write_sent);
            assert(!read_sent);
            stats->record_stage_stall(BMT_META_RESERVATION_STALL);
        }
    } else if (!m_BMT_queue->empty()) {
        if (m_unit->mee_dram_queue_full(BMT))
            stats->record_stage_stall(MEE_DRAM_QUEUE_FULL_STALL_BMT);
        if (output_full) {
            stats->record_stage_stall(BMT_QUEUE_FULL_STALL);
            if (m_HASH_queue->full())
                stats->record_stage_stall(HASH_QUEUE_FULL_STALL);
        }
        if (!port_free) stats->record_stage_stall(BMT_QUEUE_FULL_STALL);
    }
};

void mee::META_fill_responses(class data_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, const new_addr_type MASK) {
    if (m_METAcache->access_ready() && !m_META_RET_queue->full()) {
        mem_fetch *mf = m_METAcache->next_access();
        enum data_type m_data_type = mf->get_data_type();
        memory_stats_t *stats = m_gpu->get_memory_stats();
        unsigned long long now =
            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
        if (mf->get_access_type() == META_ACC && mf->get_id())
            m_META_RET_queue->push(mf);
        // assert(mf->get_access_type() == META_ACC);
        // if (m_METAcache == m_BMTcache)
        print_addr("fill responses:\t", mf);
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
    } else {
        if (m_META_RET_queue->full()){
            // printf("fill responses ERROR: %d\n", m_unit->get_mpid());
        }
    }
}

#ifdef CTR_HIERACHY
void mee::CTR_fill() {
    // if (m_METAcache == m_BMTcache) printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE);
    
    if (!m_unit->m_L2_ctr_bundle_queue->empty()) {
        mem_fetch *mf_return = m_unit->m_L2_ctr_bundle_queue->top();
        assert(mf_return->get_data_type() == CTR);
        
        #ifdef BMT_Enable
        // assert(mf_return->get_access_type() == META_ACC);
        if (mf_return->get_access_type() == META_ACC)
            if (!m_CTR_BMT_Buffer->full()) 
                m_CTR_BMT_Buffer->push(mf_return);
            else
                return;
        #endif
        if (m_CTRcache->waiting_for_fill(mf_return)) {
            // print_addr("wating for fill:\t\t", mf); 
            if (m_CTRcache->fill_port_free()) {
                // assert(mf->get_access_type() != META_WR_ALLOC_R);
                print_addr("ctr fill: \t\t", mf_return);
                m_CTRcache->fill(mf_return, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle +
                                        m_memcpy_cycle_offset);
                //     print_addr("MAC fill:\t", mf);
                assert(!mf_return->is_write());
                // if (m_METAcache == m_BMTcache)
                //     print_addr("fill:\t\t\t\t", mf);
                    // printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE); 
                // if (mf->get_sub_partition_id() == 1) { 
                //     printf("CTR Fill: %p\n", mf);
                //     // printf("CTR Next: %p\n", m_CTR_queue->top());
                // }
                m_unit->m_L2_ctr_bundle_queue->pop();
            } else {
                // print_addr("fill ERROR:\t", mf_return);
            }
        } else {
            if (mf_return->is_write() && mf_return->get_type() == WRITE_ACK)
                mf_return->set_status(IN_PARTITION_L2_TO_ICNT_QUEUE,
                            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
            //   m_META_RET_queue->push(mf);
            m_unit->m_L2_ctr_bundle_queue->pop();
        }
    }
}
#endif

void mee::META_fill(class data_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, mem_fetch *mf, const new_addr_type MASK, const new_addr_type BASE, enum data_type m_data_type) {
    // if (m_METAcache == m_BMTcache) printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE);
    
    if (!m_unit->dram_mee_queue_empty(m_data_type)) {
        mem_fetch *mf_return = NULL;
        #ifdef CTR_HIERACHY
        if (m_data_type == CTR) {
            if (!m_unit->m_L2_ctr_bundle_queue->empty())
                mf_return = m_unit->m_L2_ctr_bundle_queue->top();
            else
                return;
        } else {
            mf_return = m_unit->dram_mee_queue_top(m_data_type);
        }
        #else
        mf_return = m_unit->dram_mee_queue_top(m_data_type);
        #endif
        
        #ifdef BMT_Enable
        if (m_data_type == CTR && mf_return->get_access_type() == META_ACC)
            if (!m_META_RET_queue->full()) 
                m_META_RET_queue->push(mf_return);
            else
                return;
        #endif
        if ((mf_return->get_data_type() == m_data_type) && m_METAcache->waiting_for_fill(mf_return)) {
            // print_addr("wating for fill:\t\t", mf); 
            if (m_METAcache->fill_port_free()) {
                // assert(mf->get_access_type() != META_WR_ALLOC_R);
                print_addr("fill: \t\t", mf_return);
                m_METAcache->fill(mf_return, m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle +
                                        m_memcpy_cycle_offset);
                if (m_METAcache == m_MACcache)
                    print_status(m_METAcache, mf_return);
                //     print_addr("MAC fill:\t", mf);
                assert(!mf_return->is_write());
                // if (m_METAcache == m_BMTcache)
                //     print_addr("fill:\t\t\t\t", mf);
                    // printf("%llx & %llx == %llx\n", mf->get_addr(), BASE, mf->get_addr() & BASE); 
                // if (mf->get_sub_partition_id() == 1) { 
                //     printf("CTR Fill: %p\n", mf);
                //     // printf("CTR Next: %p\n", m_CTR_queue->top());
                // }
                m_unit->dram_mee_queue_pop(m_data_type);
            } else {
                // print_addr("fill ERROR:\t", mf_return);
            }
        } else if (mf_return->get_data_type() == m_data_type) {
            if (mf_return->is_write() && mf_return->get_type() == WRITE_ACK)
                mf_return->set_status(IN_PARTITION_L2_TO_ICNT_QUEUE,
                            m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle);
            //   m_META_RET_queue->push(mf);
            m_unit->dram_mee_queue_pop(m_data_type);
        }
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
    #ifdef CTR_HIERACHY
    CTR_fill(); // todo: CTR L1 cache fill
    #else
    META_fill(m_CTRcache, m_CTR_BMT_Buffer, NULL, CTR_mask, CTR_base, CTR);
    #endif
    META_fill(m_MACcache, m_MAC_RET_queue, NULL, MAC_mask, MAC_base, MAC);
    META_fill(m_BMTcache, m_BMT_RET_queue, NULL, BMT_mask[1], BMT_base[1], BMT);

    // dram ctr to mee
    #ifdef CTR_HIERACHY
    if (!m_unit->dram_mee_queue_empty(CTR)) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top(CTR);
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
        // assert(mf_return->get_access_type() < META_ACC);
        if (!m_unit->mee_L2_queue_full(spid)) {
            print_addr("dram to mee ctr:\t", mf_return);
            m_unit->mee_L2_queue_push(spid, mf_return);
            // m_Ciphertext_RET_queue->push(mf_return);
            m_unit->dram_mee_queue_pop(CTR);
            // printf("HHHHHHHHHHHHHHHH");
        } else {
            // printf("HHHHHHHHHHHHHHHH");
        }
    } else if (!m_unit->mee_dram_queue_empty()) {
        // printf("SSSSSSSSSSSSSSS %d\n", );
    }
    #endif

    // dram data to mee
    if (!m_unit->dram_mee_queue_empty(NORM)) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top(NORM);
        // assert(!mf_return->is_write());
        // if (mf_return->get_sub_partition_id() == 58)
        // print_addr("waiting for fill:\t", mf_return);
        // printf("%saddr: %x\tdata_type: %d\tsp_addr: %x\taccess type:%d\n", "fill queue:\t", mf->get_addr(), mf->get_data_type(), mf->get_partition_addr(), mf->get_access_type());

        if (false
            // mf_return->get_access_type() == L1_WR_ALLOC_R || 
            // // mf_return->get_access_type() == L2_WR_ALLOC_R ||
            // mf_return->get_access_type() == L1_WRBK_ACC || 
            // mf_return->get_access_type() == L2_WRBK_ACC
            ) {
                assert(mf_return->get_access_type() == 4 && !mf_return->is_write());
            m_unit->dram_mee_queue_pop(NORM);
        } else {
        
            print_addr("dram to mee data:\t", mf_return);
            // mee to L2
            
            // META_fill(m_MACcache, mf_return, MAC_mask);
            // META_fill(m_BMTcache, mf_return);
            // if (!m_unit->mee_L2_queue_full()) {
            // reply L2 read
            // reply L2 write back
            //m_unit->mee_L2_queue_push(m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id()), mf_return);
            int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
            assert(mf_return->get_access_type() < META_ACC);
            if (!m_Ciphertext_RET_queue->full() && !m_unit->mee_L2_queue_full(spid)) {
                memory_stats_t *stats = m_gpu->get_memory_stats();
                if (stats && mf_return->get_cipher_dram_issue_time()) {
                    unsigned long long now =
                        m_gpu->gpu_sim_cycle + m_gpu->gpu_tot_sim_cycle;
                    stats->record_stage_latency(
                        CIPHER_DRAM_STAGE,
                        now - mf_return->get_cipher_dram_issue_time());
                }
                // m_AES_queue->push(mf_return);   //密文从DRAM返回，送往AES解密
                // m_MAC_table[(new_addr_type)mf_return] = ++MAC_counter;
                // assert(m_MAC_table[(new_addr_type)mf_return]);
                // m_HASH_queue->push(new unsigned(m_MAC_table[(new_addr_type)mf_return]));  //对密文进行hash，用于MAC Check
                #ifndef AES_Enable
                m_Ciphertext_RET_queue->push(mf_return->get_original_wr_mf());
                m_unit->mee_L2_queue_push(spid, mf_return);
                #else
                m_Ciphertext_RET_queue->push(mf_return);
                #endif
                m_unit->dram_mee_queue_pop(NORM);
                // printf("HHHHHHHHHHHHHHHH");
            } else {
                // printf("HHHHHHHHHHHHHHHH");
            }
        }
    } else if (!m_unit->mee_dram_queue_empty()) {
        // printf("SSSSSSSSSSSSSSS %d\n", );
    }
    // printf("L2 to mee queue: %d %d\n", m_unit->m_sub_partition[0]->m_L2_mee_queue->empty(), m_unit->m_sub_partition[0]->m_L2_mee_queue->empty());
    // L2 to mee
    // DL_CNT++;
    if (DL_CNT >= 10000) {
        printf("DEAD LOCK! mpid: %d\n", m_unit->get_mpid());
    }
    for (unsigned p = 0; p < m_config->m_n_sub_partition_per_memory_channel; p++) {
        
        int spid = (p + last_issued_partition + 1) %
                m_config->m_n_sub_partition_per_memory_channel;
        #ifdef CTR_HIERACHY
        // CTR to mee
        if (!m_unit->L2_mee_queue_empty(spid, CTR)) {
            mem_fetch *mf = m_unit->L2_mee_queue_top(spid, CTR);
            if (mf->get_data_type() == CTR) {
                if (!m_unit->mee_dram_queue_full(CTR)) {
                    DL_CNT = 0;
                    last_issued_partition = spid;
                    print_addr("L2 ctr to mee: ", mf);
                    m_unit->mee_dram_queue_push(mf, CTR);
                    // 因为要break，所以必须在这里pop
                    m_unit->L2_mee_queue_pop(spid, CTR);
                    last_issued_partition = spid;
                    break;
                } else {
                    DL_CNT++;
                    // continue;
                }
            }
        } else if (!m_unit->L2_mee_queue_empty((spid + 1) % m_config->m_n_sub_partition_per_memory_channel, CTR)) {
            continue;
        }

        // L2 to mee
        if (!m_unit->L2_mee_queue_empty(spid, NORM)) {
            mem_fetch *mf = m_unit->L2_mee_queue_top(spid, NORM);
        #else
        if (!m_unit->L2_mee_queue_empty(spid)) {
            #ifndef AES_Enable
            mem_fetch *mf_original = m_unit->L2_mee_queue_top(spid);
            mem_fetch *mf = new mem_fetch(*mf_original);
            mf_original->original_wr_mf = mf;
            #else
            mem_fetch *mf = m_unit->L2_mee_queue_top(spid);
            #endif
        #endif
            assert(mf->is_raw());
            // printf("TTTTTTTTTTTTTTTT\n");
            // mee to dram
            if (((m_config->m_META_config.m_cache_type == SECTOR && !m_CTR_queue->full(2)) || (m_config->m_META_config.m_cache_type != SECTOR && !m_CTR_queue->full(2)))
                && !m_MAC_queue->full() && !m_Ciphertext_queue->full()) {
                // mf->get_access_size() 可能大于32？
                // assert(mf->get_access_size() <= 32);
                // last_issued_partition = spid;
                DL_CNT = 0;
                // assert(!mf->is_write());
                if (mf->is_write()) { // write
                    assert(mf->is_raw());
                    // printf("LLLLLLLLLLLLLLLLLLL");
                    // if (!m_Ciphertext_queue->full()) {
                    unsigned mf_id = next_mf_id();
                    mf->set_id(mf_id);
                    print_addr("L2 to mee Write: ", mf);
                    // gen_CTR_mf(mf, false, META_RBW, 16, mf_counter);//Lazy_ftech_on_read
                    // gen_CTR_mf(mf, false, META_ACC,  1, mf_counter);//Lazy_ftech_on_read
                    // gen_CTR_mf(mf, true,  META_RBW, 16, mf_counter);
                    // gen_CTR_mf(mf, true,  META_ACC,  1, mf_counter);
                    // gen_CTR_mf(mf, false, META_ACC, 128, mf_counter);//Lazy_ftech_on_read
                    // gen_CTR_mf(mf, true,  META_ACC, 128, mf_counter);

                    if (m_config->m_META_config.m_cache_type == SECTOR) {
                        gen_CTR_mf(mf, false, META_ACC, 32, mf_id);//Lazy_ftech_on_read
                        gen_CTR_mf(mf, true,  META_ACC, 32, mf_id);
                    }
                    else {
                        gen_CTR_mf(mf, false, META_ACC, 128, mf_id);//Lazy_ftech_on_read
                        gen_CTR_mf(mf, true,  META_ACC, 128, mf_id);
                    }

                    #ifdef MAC_Enable
                    if (m_config->m_META_config.m_cache_type == SECTOR)
                        gen_MAC_mf(mf, true, META_ACC, 4, mf_id);
                    else
                        gen_MAC_mf(mf, true, META_ACC, 8, mf_id);
                    #endif

                    // m_AES_queue->push(mf);  //写密文请求，将明文送入AES中解密
                    push_cipher_request(mf);
                    // mf->set_cooked_status();
                    // printf("BBBBBBBBBBBBBBBBB");
                    // }
                } else {              // read
                    // printf("CCCCCCCCCCCCCCCC");
                    // m_unit->mee_dram_queue_push(mf);    //读密文请求，发往DRAM中读密文
                    unsigned mf_id = next_mf_id();
                    mf->set_id(mf_id);
                    print_addr("L2 to mee Read: ", mf);
                    push_cipher_request(mf);
                    if (m_config->m_META_config.m_cache_type == SECTOR) {
                        gen_CTR_mf(mf, false, META_ACC, 32, mf_id);
                    }
                    else {
                        gen_CTR_mf(mf, false, META_ACC, 128, mf_id);
                    }
                    // gen_CTR_mf(mf, false, META_ACC, 128, mf_counter);
                    #ifdef MAC_Enable
                    if (m_config->m_META_config.m_cache_type == SECTOR)
                        gen_MAC_mf(mf, false, META_ACC, 4, mf_id);
                    else
                        gen_MAC_mf(mf, false, META_ACC, 8, mf_id);
                    #endif
                }
                #ifdef CTR_HIERACHY
                m_unit->L2_mee_queue_pop(spid, NORM);
                #else
                m_unit->L2_mee_queue_pop(spid);
                #endif
                #ifndef AES_Enable
                m_unit->mee_dram_queue_push(mf_original, NORM);
                #endif
                last_issued_partition = spid;
                break;
            } else {
                DL_CNT++;
                memory_stats_t *stats = m_gpu->get_memory_stats();
                if (m_Ciphertext_queue->full())
                    stats->record_stage_stall(CIPHER_QUEUE_FULL_STALL);
                if (m_MAC_queue->full())
                    stats->record_stage_stall(MAC_QUEUE_FULL_STALL);
                if ((m_config->m_META_config.m_cache_type == SECTOR &&
                     m_CTR_queue->full(8)) ||
                    (m_config->m_META_config.m_cache_type != SECTOR &&
                     m_CTR_queue->full(2)))
                    stats->record_stage_stall(CTR_META_RESERVATION_STALL);
            //     if (DL_CNT >= 10000) {
            //         printf("DEAD LOCK! mpid: %d\n", m_unit->get_mpid());
            //     }
            //     // if (m_unit->get_mpid() == 0){
            //     //     if (m_CTR_RET_queue->full())
            //     //         printf("AAAAAAAAAAAAAAAAAAAAAA");
            //     //     if (m_MAC_RET_queue->full())
            //     //         printf("BBBBBBBBBBBBBBBBB");
            //     //     if (m_BMT_RET_queue->full())
            //     //         printf("CCCCCCCCCCCC");
            //     //     if (m_AES_queue->full())
            //     //         printf("DDDDDDDDDDDDDDDD");
            //     //     if (m_AES_queue->full())
            //     //         printf("EEEEEEEEEEEEEEEE");
            //     //     if (m_unit->mee_dram_queue_empty())
            //     //         printf("FFFFFFFFFFFFFFFFFF");
            //     // }
                    
            }
        } else {
            // printf("GGGGGGGGGGGGGG\n");
        }
    }
    #ifdef MAC_Enable
    MAC_CHECK_cycle();
    MAC_cycle();
    #endif
    BMT_CHECK_cycle();
    BMT_cycle();
    HASH_cycle();
    AES_cycle();
    CTR_cycle();
    // CT_cycle();
}

void mee::cycle(unsigned cycle) {
    #ifndef CTR_HIERACHY
    if (!m_unit->dram_mee_queue_empty(NORM)) {
        mem_fetch *mf_return = m_unit->dram_mee_queue_top(NORM);
        int spid = m_unit->global_sub_partition_id_to_local_id(mf_return->get_sub_partition_id());
         if (false
            // mf_return->get_is_write() ||
            // mf_return->get_access_type() == L1_WR_ALLOC_R || 
            // mf_return->get_access_type() == L2_WR_ALLOC_R ||
            // mf_return->get_access_type() == L1_WRBK_ACC || 
            // mf_return->get_access_type() == L2_WRBK_ACC
            ) {
                // assert(mf_return->get_access_type() == 4 && !mf_return->is_write());
            m_unit->dram_mee_queue_pop(NORM);
        } else {
            if (!m_unit->mee_L2_queue_full(spid)) { 
                // m_OTP_table[REQ_addr] = 0;
                // print_addr("mee to L2 R:\t", mf);
                m_unit->mee_L2_queue_push(spid, mf_return);
                m_unit->dram_mee_queue_pop(NORM);
                
            }
        }
    }
    for (unsigned p = 0; p < m_config->m_n_sub_partition_per_memory_channel;
        p++) {
        int spid = (p + last_issued_partition + 1) %
                m_config->m_n_sub_partition_per_memory_channel;
        if (!m_unit->L2_mee_queue_empty(spid)) {
            mem_fetch *mf = m_unit->L2_mee_queue_top(spid);
            if (!m_unit->mee_dram_queue_full(NORM)) {      
                unsigned mf_id = next_mf_id();
                mf->set_id(mf_id);        
                m_unit->mee_dram_queue_push(mf, NORM);
                m_unit->L2_mee_queue_pop(spid);
                last_issued_partition = spid;
                break;
            }
        }
    }
    #endif
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

//Sector
//deepbench
//可配置
//lazy_fetch_on_read

//mee<-->dram queue
//write back
//BMT_Layer

//CTR_counter <= BMT_counter 
//CT_counter  < OTP_counter
//MAC_counter < CT_counter


//实现一个中间类，bridge
//
