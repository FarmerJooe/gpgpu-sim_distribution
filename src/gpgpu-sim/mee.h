
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
        mee(class memory_partition_unit *unit, class meta_cache *CTRcache, class meta_cache *MACcache, class meta_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu);
        void cycle(unsigned cycle);
        void simple_cycle(unsigned cycle);
        void print_addr(char s[], mem_fetch *mf);
        void print_status(class meta_cache *m_METAcache, mem_fetch *mf);
        void print_tag();
        void meta_access(fifo_pipeline<mem_fetch> *m_META_queue, new_addr_type addr, mem_access_type type, 
            unsigned size, bool wr, unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc, 
            mem_fetch *original_mf, unsigned mf_id, enum data_type m_data_type, enum BMT_Layer m_Layer) const;
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
        void gen_CTR_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id);
        void gen_MAC_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id);
        void gen_BMT_mf(mem_fetch *mf, bool wr, mem_access_type meta_acc, unsigned size, unsigned mf_id);
        bool META_queue_empty();

        void META_fill_responses(class meta_cache *m_METAcache,  fifo_pipeline<mem_fetch> *m_META_RET_queue, const new_addr_type MASK);
        void META_fill(class meta_cache *m_METAcache, fifo_pipeline<mem_fetch> *m_META_RET_queue, mem_fetch *mf, const new_addr_type MASK, const new_addr_type BASE, enum data_type m_data_type);

        bool CTR_busy();
        bool MAC_busy();
        bool BMT_busy;
        void pr(fifo_pipeline<mem_fetch> *m_META_RET_queue);
        

        
    private:
        typedef std::pair<enum data_type, int> hash;
        class meta_cache *m_CTRcache;
        class meta_cache *m_MACcache;
        class meta_cache *m_BMTcache;
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

        fifo_pipeline<unsigned> *m_OTP_queue;
        fifo_pipeline<mem_fetch> *m_AES_queue;
        
        fifo_pipeline<hash> *m_HASH_queue;
        fifo_pipeline<mem_fetch> *m_MAC_CHECK_queue;

        //m_CTR_BMT_Buffer-->m_BMT_CHECK_queue--|-->
        //                |->m_HASH_queue---|
        //              m_BMT_queue-->m_BMT_RET_queue-->
        fifo_pipeline<mem_fetch> *m_BMT_CHECK_queue;
        // fifo_pipeline<unsigned> *m_HASH_queue;
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

        typedef tr1_hash_map<new_addr_type, unsigned> table;
        typedef tr1_hash_map<unsigned, int> set;
        table m_OTP_table;  //<密文，OTP(CTR)>
        set m_OTP_set;  //<OTP(CTR), cnt>
        table m_MAC_table;  //<MAC, hash(密文)>
        set m_MAC_set;      //<hash(密文), cnt>
        table m_BMT_table;  //<BMT, hash(CTR/LBMT)>
        set m_BMT_set;      //<hash, cnt>
        //1111 1111 1111 1111 1100 0000 1111 1000
        mem_fetch *BMT_ROOT_mf = NULL;
        int cnt = 0;

        unsigned mf_counter = 0;
        unsigned CT_counter = 0;
        unsigned OTP_counter = 0;
        unsigned MAC_counter = 0;
        unsigned CTR_counter = 0;
        unsigned BMT_counter = 0;
        unsigned m_n_reqs_in_BMT = 0;
        int var;
        unsigned DL_CNT = 0;

        
    
    public:
        counterMap *m_ctrModCount;
        counterMap* get_ctrModCount() { return m_ctrModCount; }
};