// ctr-cache.h
#include "gpu-cache.h"
#include "../abstract_hardware_model.h"
#include "mem_fetch.h"
#include "addrdec.h"
#include "gpu-sim.h"

#ifndef CTR_CACHE_H
#define CTR_CACHE_H

// class ctr_tag_array : public tag_array {
// public: 
//     ctr_tag_array(cache_config &config, int core_id, int type_id,
//                 cache_block_t **new_lines)
//         : tag_array(config, core_id, type_id, new_lines) {
//         m_tot_num_sigments = config.get_num_lines();
//         m_line_used_sigments = new unsigned[config.get_num_lines()];
//         for (unsigned i = 0; i < config.get_num_lines(); ++i) {
//             m_line_used_sigments[i] = 0;
//         }
//     }

//     ~ctr_tag_array() {
//         delete[] m_line_used_sigments;
//     }

//     bool overflow() {
//         return m_tot_used_sigments > m_tot_num_sigments;
//     }

//     bool full() {
//         return m_tot_used_sigments >= m_tot_num_sigments;
//     }

//     void insert(new_addr_type addr) {
//         m_tot_used_sigments++;
//     }

//     void remove(new_addr_type addr) {
//         m_tot_used_sigments--;
//     }

// protected:
//     unsigned *m_line_used_sigments;  // number of sigments used in the cache line

//     unsigned m_tot_num_sigments;  // number of sigments in the cache line
//     unsigned m_tot_used_sigments;  // number of sigments used in the cache line

// };

class ctr_cache : public data_cache {
public:
    ctr_cache(const char *name, cache_config &config, int core_id, int type_id,
                mem_fetch_interface *memport, mem_fetch_allocator *mfcreator,
                enum mem_fetch_status status, class gpgpu_sim *gpu)
        : data_cache(name, config, core_id, type_id, memport, mfcreator, status,
                    META_WR_ALLOC_R, META_WRBK_ACC, gpu) { 
        m_tot_num_sigments = config.get_num_lines(); // 每个cache line有4个sector，每个sector有4个sigments
        m_tot_used_sigments = 0;
        m_line_used_sigments = new unsigned[config.get_num_lines()];
        for (unsigned i = 0; i < config.get_num_lines(); ++i) {
            m_line_used_sigments[i] = 0;
        }
        m_ctrModCount = new counterMap; 
    }

    virtual ~ctr_cache() {}

    virtual enum cache_request_status access(new_addr_type addr, mem_fetch *mf,
                                           unsigned time,
                                           std::list<cache_event> &events);

    unsigned get_set_segments(unsigned set_index) {
        unsigned m_set_used_sigments = 0;

        for (unsigned way = 0; way < m_config.get_assoc(); way++) {
            unsigned index = set_index * m_config.get_assoc() + way;
            assert(index < m_config.get_num_lines());
            m_set_used_sigments += m_line_used_sigments[index];
        }

        return m_set_used_sigments;
    }
    
    void print_set_segments_stats() {
        for (unsigned set_index = 0; set_index < m_config.get_nset(); ++set_index) {
            printf("set %u used sigments: %u\n", set_index, get_set_segments(set_index));
        }
    }

    void print_line_segments_stats() {
        for (unsigned i = 0; i < m_config.get_num_lines(); ++i) {
            printf("line %u used sigments: %u\n", i, m_line_used_sigments[i]);
        }
    }


    
    bool set_overflow(unsigned set_index) {

        unsigned m_set_used_sigments = 0;

        for (unsigned way = 0; way < m_config.get_assoc(); way++) {
            unsigned index = set_index * m_config.get_assoc() + way;
            m_set_used_sigments += m_line_used_sigments[index];
        }

        return m_set_used_sigments > m_tot_num_sigments / m_config.get_nset();
    }

    bool overflow() {
        for (unsigned set_index = 0; set_index < m_config.get_nset(); ++set_index) {
            if (set_overflow(set_index))
                return true;
        }
        return false;
    }

    bool full() {
        return m_tot_used_sigments >= m_tot_num_sigments;
    }

    void insert(new_addr_type addr) {
        m_tot_used_sigments++;
    }

    void remove(new_addr_type addr) {
        m_tot_used_sigments--;
    }

    unsigned get_ctr_data_sigments(new_addr_type addr) {
        unsigned cnt = 0;
        int min = 256;
        int max = 0;

        for (unsigned offset = 1; offset < 32; offset++) {
            int minor_cnt = (*m_ctrModCount)[addr + offset];
            min = std::min(min, minor_cnt);
            max = std::max(max, minor_cnt);
        }

        if (max - min < 2) {
            return 1;
        } else if (max - min < 8){
            return 2;
        } 

        return 4;
    }

    void update_ctr_cache_segments_stats() {
        m_tot_used_sigments = 0;
        for (unsigned i = 0; i < m_config.get_num_lines(); ++i) {
            if (m_tag_array->is_invalid_line(i))
                m_line_used_sigments[i] = 0;
            else
                m_tot_used_sigments += m_line_used_sigments[i];
        }
    }

    void writeback(unsigned idx, bool wb, evicted_block_info &evicted, mem_fetch *mf, unsigned time, std::list<cache_event> &events) {
        if (wb) {
            mem_fetch *wb = m_memfetch_creator->alloc(
                evicted.m_block_addr, m_wrbk_type, mf->get_access_warp_mask(),
                evicted.m_byte_mask, evicted.m_sector_mask, evicted.m_modified_size,
                true, m_gpu->gpu_tot_sim_cycle + m_gpu->gpu_sim_cycle, -1, -1, -1,
                NULL);
            // the evicted block may have wrong chip id when advanced L2 hashing  is
            // used, so set the right chip address from the original mf
            wb->set_data_type(mf->get_data_type());
            wb->set_chip(mf->get_tlx_addr().chip);
            wb->set_parition(mf->get_tlx_addr().sub_partition);
            wb->set_id(mf->get_id());
            send_write_request(wb, cache_event(WRITE_BACK_REQUEST_SENT, evicted),
                            time, events);
        }
    }

    bool manage_set_overflow_eviction(unsigned set_index, mem_fetch *mf, unsigned time, std::list<cache_event> &events) {
        unsigned idx = (unsigned)-1;
        bool wb = false;
        evicted_block_info evicted;
        if (m_tag_array->find_victim_line(set_index, idx, wb, evicted)) {
            m_line_used_sigments[idx] = 0;
            writeback(idx, wb, evicted, mf, time, events);
            update_ctr_cache_segments_stats();
        } else {
            return false;
        }
        return true;
    }

    bool prevent_overflow(mem_fetch *mf, unsigned time, std::list<cache_event> &events) {
        // 验证通过
        bool valid = true;
        for (unsigned set_index = 0; set_index < m_config.get_nset(); ++set_index) {
            if (set_overflow(set_index)) {
                manage_set_overflow_eviction(set_index, mf, time, events);
                if (set_overflow(set_index))
                    valid = false;
            }
        }
        return valid;
    }

public:
    unsigned *m_line_used_sigments;  // number of sigments used in the cache line

    unsigned m_tot_num_sigments;  // number of sigments in the cache line
    unsigned m_tot_used_sigments;  // number of sigments used in the cache line
    counterMap *m_ctrModCount;
};

void test_ctr_cache(class gpgpu_sim *gpu);

#endif // CTR_CACHE_H