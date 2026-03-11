#include "prediction.h"

prediction::prediction(unsigned scale_shift):
    m_scale_shift(scale_shift) {
    m_bit_vector = new counterMap;
}

prediction::~prediction() {
    delete m_bit_vector;
}

new_adr_type prediction::get_index(new_adr_type addr) {
    new_adr_type partition_addr = mee::get_partition_addr(addr);
    new_adr_type block_addr = mee::get_partition_id(addr);

    partition_addr = partition_addr >> m_scale_shift << m_scale_shift;

    new_adr_type index = mee::get_global_addr(sub_partition_id, partition_addr);

    return index;
}

void prediction::set(new_adr_type addr, unsigned value) {
    new_adr_type index = get_index(addr);
    (*m_bit_vector)[index] = value;

    printf("prediction set: addr=0x%llx, index=0x%llx, value=%u\n", addr, index, value);
}

bool prediction::match(new_adr_type addr, unsigned value) {
    new_adr_type index = get_index(addr);
    if ((*m_bit_vector)[index] == value) {
        printf("prediction match: addr=0x%llx, index=0x%llx, value=%u\n", addr, index, value);
    } else {
        printf("prediction mismatch: addr=0x%llx, index=0x%llx, value=%u, actual=%u\n", addr, index, value, (*m_bit_vector)[index]);
    }
    return (*m_bit_vector)[index] == value;
}

read_only_predictor::read_only_predictor():
    prediction(m_region_scale_shift) {
}


