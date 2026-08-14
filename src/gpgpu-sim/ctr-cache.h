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

    // 压缩格式枚举
    enum ctr_compress_format {
        CTR_COMPRESS_NONE = 0,            // 无法压缩，需要4 L-line (8 seg)
        CTR_COMPRESS_BASE_1BIT = 1,       // 基础1-bit编码，需要1 L-line (2 seg)
        CTR_COMPRESS_BASE_2_3BIT = 2,     // 基础2-3bit编码，需要2 L-line (4 seg)
        CTR_COMPRESS_DUAL_LENGTH = 3,     // 双长度编码，需要2 L-line (4 seg)
        CTR_COMPRESS_DUAL_BASE_DELTA = 4  // 双Base-Delta编码，需要2 L-line (4 seg)
    };

    // 计算值的位宽
    inline int get_bit_width(int value) {
        if (value <= 0) return 1;
        int width = 0;
        while (value > 0) {
            width++;
            value >>= 1;
        }
        return width;
    }

    // 判断压缩格式并返回所需的 L-line 数量
    // 返回值: 1 = 基础1-bit压缩 (1 L-line = 2 seg = 64 bits)
    //         2 = 压缩成功 (2 L-line = 4 seg = 128 bits)
    //         4 = 无法压缩 (4 L-line = 8 seg = 256 bits)
    unsigned get_ctr_data_sigments(new_addr_type addr) {
        int min_value = 256;
        int max_value = 0;
        int minors[32];
        
        // 收集32个7-bit minor值
        for (unsigned offset = 0; offset < 32; offset++) {
            int minor_cnt = (*m_ctrModCount)[addr + offset];
            minors[offset] = minor_cnt;
            min_value = std::min(min_value, minor_cnt);
            max_value = std::max(max_value, minor_cnt);
        }
        
        int max_delta = max_value - min_value;
        int max_delta_width = get_bit_width(max_delta);
        
        // 基础格式1：1-bit编码
        // 条件：max_delta <= 1，每个值只需1-bit
        // 数据区：32×1 = 32 bits delta，加上 major 区共 64 bits = 1 L-line
        if (max_delta_width <= 1) {
            return 1;  // 需要1 L-line
        }
        
        // 基础格式2：2-3bit编码
        // 条件：1 < max_delta <= 7，每个值需2-3 bits
        // 数据区：32×3 = 96 bits delta，加上 major 区共 128 bits = 2 L-line
        if (max_delta_width <= 3) {
            return 2;  // 需要2 L-line
        }
        
        // // 格式3：双长度编码
        // // 将32个值分成4个slice，每个slice 8个值
        // // 3个slice用2-bit delta，1个slice用3-bit delta
        // int extend_slice_count = 0;
        // for (int slice = 0; slice < 4; slice++) {
        //     int slice_max = 0;
        //     for (int i = 0; i < 8; i++) {
        //         slice_max = std::max(slice_max, minors[slice * 8 + i]);
        //     }
        //     // 判断该slice需要的编码长度
        //     if (slice_max - min_value > 3) {
        //         extend_slice_count += 2;  // 需要更长编码，权重+2
        //     } else if (slice_max - min_value > 1) {
        //         extend_slice_count += 1;  // 需要3-bit编码，权重+1
        //     }
        //     // slice_max - min_value <= 1 时使用2-bit编码，不增加权重
        // }
        
        // // 最多只有1个slice需要扩展编码时可压缩
        // // 数据区：24×2 + 8×3 = 72 bits + 24 bits padding = 96 bits
        // if (extend_slice_count <= 1) {
        //     return 2;  // 压缩成功，需要2 L-line
        // }
        
        // // 格式4：双Base-Delta编码
        // // Base1 = min_value（常规值用 Base1 + 2-bit delta，delta ∈ {0,1,2,3}）
        // // Base2 = 异常值的最小值（异常值用 Base2 + 2-bit delta）
        // // 条件：异常值也能用 2-bit delta 表示（max_value - base2 <= 3）
        // int base2 = -1;  // 异常值的最小值
        // for (int i = 0; i < 32; i++) {
        //     int delta = minors[i] - min_value;
        //     if (delta > 3) {  // 不在 {0,1,2,3} 范围内的是异常值
        //         if (base2 < 0) {
        //             base2 = minors[i];
        //         } else {
        //             base2 = std::min(base2, minors[i]);
        //         }
        //     }
        // }
        
        // // 如果没有异常值，或者异常值可以用 base2 + 2-bit delta 表示
        // if (base2 < 0 || max_value - base2 <= 3) {
        //     return 2;  // 压缩成功，需要2 L-line
        // }
        
        return 4;  // 无法压缩，需要4 L-line
    }

    // 获取压缩格式类型（用于统计和调试）
    ctr_compress_format get_ctr_compress_format(new_addr_type addr) {
        int min_value = 256;
        int max_value = 0;
        int minors[32];
        
        for (unsigned offset = 0; offset < 32; offset++) {
            int minor_cnt = (*m_ctrModCount)[addr + offset];
            minors[offset] = minor_cnt;
            min_value = std::min(min_value, minor_cnt);
            max_value = std::max(max_value, minor_cnt);
        }
        
        int max_delta = max_value - min_value;
        int max_delta_width = get_bit_width(max_delta);
        
        // 检查基础1-bit编码条件
        if (max_delta_width <= 1) {
            return CTR_COMPRESS_BASE_1BIT;
        }
        
        // 检查基础2-3bit编码条件
        if (max_delta_width <= 3) {
            return CTR_COMPRESS_BASE_2_3BIT;
        }
        
        // 检查双长度编码条件
        int extend_slice_count = 0;
        for (int slice = 0; slice < 4; slice++) {
            int slice_max = 0;
            for (int i = 0; i < 8; i++) {
                slice_max = std::max(slice_max, minors[slice * 8 + i]);
            }
            if (slice_max - min_value > 3) {
                extend_slice_count += 2;
            } else if (slice_max - min_value > 1) {
                extend_slice_count += 1;
            }
        }
        
        if (extend_slice_count <= 1) {
            return CTR_COMPRESS_DUAL_LENGTH;
        }
        
        // 检查双Base-Delta编码条件
        // Base1 = min_value, Base2 = 异常值的最小值
        int base2 = -1;
        for (int i = 0; i < 32; i++) {
            int delta = minors[i] - min_value;
            if (delta > 3) {
                if (base2 < 0) {
                    base2 = minors[i];
                } else {
                    base2 = std::min(base2, minors[i]);
                }
            }
        }
        
        if (base2 < 0 || max_value - base2 <= 3) {
            return CTR_COMPRESS_DUAL_BASE_DELTA;
        }
        
        return CTR_COMPRESS_NONE;
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
            wb->set_id(0);
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