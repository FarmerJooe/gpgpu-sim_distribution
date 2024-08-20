
// class mem_fetch;
// class memory_sub_partition;
// class gpgpu_sim;
// class new_addr_type;
// class mem_access_type;
// class memory_config;
#include "mem_fetch.h"
#include "l2cache.h"
#include "shader.h"
#include "gpu-sim.h"

class mee {
    public:
        mee(class memory_partition_unit *unit, class l2_cache *CTRcache, class l2_cache *MACcache, class l2_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu);
        void cycle(unsigned cycle);
        void simple_cycle(unsigned cycle);
        void print_addr(char s[], mem_fetch *mf);
        void print_tag();
        void meta_access(fifo_pipeline<mem_fetch> *m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr, unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc, mem_fetch *original_mf) const;
        void CTR_cycle();
        void MAC_cycle();
        void BMT_cycle();
        void AES_cycle();
        void CT_cycle();
        void MAC_CHECK_cycle();
        void BMT_CHECK_cycle();
        new_addr_type get_partition_addr(mem_fetch *mf);
        new_addr_type get_sub_partition_id(mem_fetch *mf);
        new_addr_type get_addr(new_addr_type partition_id, new_addr_type partition_addr);

        unsigned int get_BMT_Layer(new_addr_type addr);
        void gen_CTR_mf(mem_fetch *mf, mem_access_type meta_acc, bool wr);
        void gen_MAC_mf(mem_fetch *mf, bool wr);
        void gen_BMT_mf(mem_fetch *mf, bool wr, mem_access_type type, unsigned size);
        bool META_queue_empty();

        void META_fill_responses(class l2_cache *m_METAcache,  fifo_pipeline<mem_fetch> *m_META_RET_queue, const new_addr_type MASK);
        void META_fill(class l2_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, mem_fetch *mf, const new_addr_type MASK, const new_addr_type BASE);

        bool CTR_busy();
        bool MAC_busy();
        bool BMT_busy;
        

        
    private:
        class l2_cache *m_CTRcache;
        class l2_cache *m_MACcache;
        class l2_cache *m_BMTcache;
        class memory_partition_unit *m_unit;
        const memory_config *m_config;
        class gpgpu_sim *m_gpu;
        fifo_pipeline<mem_fetch> *m_CTR_queue;
        fifo_pipeline<mem_fetch> *m_Ciphertext_queue;
        fifo_pipeline<mem_fetch> *m_MAC_queue;
        fifo_pipeline<mem_fetch> *m_BMT_queue;

        fifo_pipeline<mem_fetch> *m_CTR_RET_queue;
        fifo_pipeline<mem_fetch> *m_MAC_RET_queue;
        fifo_pipeline<mem_fetch> *m_BMT_RET_queue;
        fifo_pipeline<mem_fetch> *m_Ciphertext_RET_queue;

        fifo_pipeline<mem_fetch> *m_OTP_queue;
        fifo_pipeline<mem_fetch> *m_AES_queue;
        fifo_pipeline<mem_fetch> *m_MAC_HASH_queue;
        fifo_pipeline<mem_fetch> *m_MAC_CHECK_queue;

        //m_CTR_BMT_Buffer-->m_BMT_CHECK_queue--|-->
        //                |->m_BMT_HASH_queue---|
        //              m_BMT_queue-->m_BMT_RET_queue-->
        fifo_pipeline<mem_fetch> *m_BMT_CHECK_queue;
        fifo_pipeline<mem_fetch> *m_BMT_HASH_queue;
        fifo_pipeline<mem_fetch> *m_CTR_BMT_Buffer;

        //CTR: 1111 1110 0000 0000 0000 0000 0000 0000
        //L1 : 1111 1111 1110 0000 0000 0000 0000 0000
        //L2 : 1111 1111 1111 1110 0000 0000 0000 0000
        //L3 : 1111 1111 1111 1111 1100 0000 1000 0000
        //L4 : 1111 1111 1111 1111 1100 0000 1111 1000
        //ROOT:1111 1111 1111 1111 1100 0000 1111 1000 
        const new_addr_type BMT_mask[5] = {0xFE000000, 0xFFE00000, 0xFFFE0000, 0xFFFFC080, 0xFFFFC0F8};
        
        const new_addr_type CTR_mask = 0xFE000000;//1111 000x xxxx xxxx xxxx xxxx xxxx xxxx
        const new_addr_type MAC_mask = 0xF0000000;//1110 xxxx xxxx xxxx xxxx xxxx xxxx x000
        
        //CTR: 1111 000x xxxx xxxx xxxx xxxx xxxx xxxx
        //L1 : 1111 0010 000x xxxx xxxx xxxx xxxx x000
        //L2 : 1111 0010 0010 000x xxxx xxxx xxxx x000
        //L3 : 1111 0010 0010 0010 00xx xxxx 0xxx x000
        //L4 : 1111 0010 0010 0010 00xx xxxx 1000 0000
        //ROOT:1111 0010 0010 0010 00xx xxxx 1000 1000 
        const new_addr_type BMT_base[5] = {0xF0000000, 0xF2000000, 0xF2200000, 0xF2220000, 0xF2220080};
        
        const new_addr_type CTR_base = 0xF0000000;//1111 000x xxxx xxxx xxxx xxxx xxxx xxxx
        const new_addr_type MAC_base = 0xE0000000;//1110 xxxx xxxx xxxx xxxx xxxx xxxx x000

        const int m_memcpy_cycle_offset = 0;
        const int mee_busy_mask = 0;

        typedef tr1_hash_map<new_addr_type, new_addr_type> table;
        typedef tr1_hash_map<new_addr_type, int> set;
        table m_OTP_table;  //<密文，OTP(CTR)>
        set m_OTP_set;  //<OTP(CTR), cnt>
        table m_MAC_table;  //<MAC, hash(密文)>
        set m_MAC_set;      //<hash(密文), cnt>
        table m_BMT_table;  //<BMT, hash(CTR/LBMT)>
        set m_BMT_set;      //<hash, cnt>
        //1111 1111 1111 1111 1100 0000 1111 1000
        mem_fetch *BMT_ROOT_mf = NULL;
        int cnt = 0;

};