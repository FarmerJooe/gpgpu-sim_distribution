
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

    private:

};

class sub_mee {
    public:
        sub_mee(class memory_sub_partition *sub_partition, class l2_cache *CTRcache, class l2_cache *MACcache, class l2_cache *BMTcache, const memory_config *config, class gpgpu_sim *gpu);
        void cycle(unsigned cycle);
        void simple_cycle(unsigned cycle);
        void print_addr(char s[], mem_fetch *mf);
        void print_tag();
        void meta_access(std::list<mem_fetch *> &m_META_queue, new_addr_type addr, mem_access_type type, unsigned size, bool wr, unsigned long long cycle, unsigned wid, unsigned sid, unsigned tpc, mem_fetch *original_mf) const;
        void CTR_cycle();
        void MAC_cycle();
        void BMT_cycle();
        void AES_cycle();
        new_addr_type get_partition_addr(mem_fetch *mf);
        new_addr_type get_sub_partition_id(mem_fetch *mf);
        new_addr_type get_addr(new_addr_type partition_id, new_addr_type partition_addr);

        void gen_CTR_mf(mem_fetch *mf, bool wr);
        void gen_MAC_mf(mem_fetch *mf, bool wr);
        // void gen_BMT_mf(mem_fetch *mf, bool wr);
        bool META_queue_empty();

        void META_fill_responses(class l2_cache *m_METAcache, const new_addr_type MASK);
        void META_fill(class l2_cache *m_METAcache, mem_fetch *mf, const new_addr_type MASK);

        bool CTR_busy();
        bool MAC_busy();
        bool BMT_busy();
        

        
    private:
        class l2_cache *m_CTRcache;
        class l2_cache *m_MACcache;
        class l2_cache *m_BMTcache;
        class memory_sub_partition *m_sub_partition;
        const memory_config *m_config;
        class gpgpu_sim *m_gpu;
        std::list<mem_fetch *> m_CTR_queue;
        std::list<mem_fetch *> m_Ciphertext_queue;
        std::list<mem_fetch *> m_MAC_queue;
        std::list<mem_fetch *> m_BMT_queue;
        const new_addr_type CTR_mask = 0x10000000;
        const new_addr_type MAC_mask = 0x00000000;
        const int m_memcpy_cycle_offset = 0;
        const int mee_busy_mask = 0;

    
};