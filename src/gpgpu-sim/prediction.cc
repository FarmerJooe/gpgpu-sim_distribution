#include "prediction.h"

predictor::predictor() {
    m_bit_vector = new counterMap;
}

new_addr_type predictor::get_index(new_addr_type addr, unsigned scale_shift) {
    new_addr_type partition_addr = mee::get_partition_addr(addr);
    new_addr_type sub_partition_id = mee::get_partition_id(addr);

    partition_addr = partition_addr >> scale_shift << scale_shift;

    new_addr_type index = mee::get_global_addr(sub_partition_id, partition_addr);

    return index;
}

void predictor::set(new_addr_type addr, unsigned value) {
    new_addr_type index = get_index(addr);
    (*m_bit_vector)[index] = value;

    // printf("predictor set: addr=0x%llx, index=0x%llx, value=%u\n", addr, index, value);
}

bool predictor::match(new_addr_type addr, unsigned value) {
    new_addr_type index = get_index(addr);
    // if ((*m_bit_vector)[index] == value) {
    //     printf("predictor match: addr=0x%llx, index=0x%llx, value=%u\n", addr, index, value);
    // } else {
    //     printf("predictor mismatch: addr=0x%llx, index=0x%llx, value=%u, actual=%u\n", addr, index, value, (*m_bit_vector)[index]);
    // }
    return (*m_bit_vector)[index] == value;
}

read_only_predictor::read_only_predictor():
    predictor() {
}

streaming_predictor::streaming_predictor():
    predictor() {
    m_mat_unit = new MAT_UNIT(this);
}

void streaming_predictor::update(new_addr_type addr, bool wr, unsigned long long cycle) {
    m_mat_unit->update(addr, wr, cycle);
}

void streaming_predictor::check_streaming(unsigned long long cycle) {
    m_mat_unit->check_streaming(cycle);
}

MAT::MAT(MAT_UNIT* unit):
    m_unit(unit) {
    init();
}

new_addr_type MAT::get_offset(new_addr_type addr) {
    new_addr_type partition_addr = mee::get_partition_addr(addr);
    partition_addr = partition_addr & 0x3FF;
    partition_addr = partition_addr >> 5;
    return partition_addr;
}

void MAT::init() {
    m_valid = 0;
    m_tag = 0;
    m_dirty = 0;
    m_tot_ctr = 0;
    for (unsigned i = 0; i < 32; i++) {
        m_ctr[i] = 0;
    }
    m_last_cycle = 0;
}

void MAT::update(new_addr_type addr, bool wr, unsigned long long cycle) {
    unsigned index = predictor::get_index(addr, CHUNK_SCALE_SHIFT);
    if (m_tag != index) {
        m_valid = 1;
        m_tag = index;
        m_dirty = wr;
        m_last_cycle = cycle;
        m_tot_ctr = 0;
        for (unsigned i = 0; i < 32; i++) {
            m_ctr[i] = 0;
        }
    }
    m_dirty |= wr;
    m_tot_ctr++;
    m_ctr[get_offset(addr)]++;
}

bool MAT::check_streaming(unsigned long long cycle) {
    if (cycle - m_last_cycle > 6000) {
        return false;
    }
    for (unsigned i = 0; i < 32; i++) {
        if (m_ctr[i] > 1) {
            return false;
        }
    }
    return true;
}

MAT_UNIT::MAT_UNIT(streaming_predictor *str_pred)
    : m_str_pred(str_pred) {
    for (unsigned i = 0; i < m_num_mat; i++) {
        m_mat[i] = new MAT(this);
    }
}

unsigned MAT_UNIT::access(new_addr_type addr) {
    unsigned index = 0;
    for (unsigned i = 0; i < m_num_mat; i++) {
        if (m_mat[i]->is_valid() && m_mat[i]->get_tag() == predictor::get_index(addr, CHUNK_SCALE_SHIFT)) {
            return i;
        }
    }
    for (unsigned i = 0; i < m_num_mat; i++) {
        if (!m_mat[i]->is_valid()) {
            return i;
        }
    }
    return lru();
}

unsigned MAT_UNIT::lru() {
    unsigned lru_index = 0;
    unsigned long long min_cycle = m_mat[0]->get_last_cycle();
    for (unsigned i = 1; i < m_num_mat; i++) {
        if (m_mat[i]->get_last_cycle() < min_cycle) {
            min_cycle = m_mat[i]->get_last_cycle();
            lru_index = i;
        }
    }
    m_str_pred->set(m_mat[lru_index]->get_tag(), PREDICTED_NON_STREAMING);
    return lru_index;
}

void MAT_UNIT::update(new_addr_type addr, bool wr, unsigned long long cycle) {
    unsigned index = access(addr);
    m_mat[index]->update(addr, wr, cycle);
}

void MAT_UNIT::check_streaming(unsigned long long cycle) {
    for (unsigned i = 0; i < m_num_mat; i++) {
        if (m_mat[i]->is_valid()) {
            if(!m_mat[i]->check_streaming(cycle)) {
                //to-do match

                m_str_pred->set(m_mat[i]->get_tag(), PREDICTED_NON_STREAMING);
                m_mat[i]->init();
            } else if (m_mat[i]->get_tot_ctr() == 32) {
                //to-do match

                // chunck-level MAC check

                m_str_pred->set(m_mat[i]->get_tag(), PREDICTED_STREAMING);
                m_mat[i]->init();
            }
        }
    }
    return;
}