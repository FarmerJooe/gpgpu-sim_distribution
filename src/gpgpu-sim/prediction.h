#ifndef PREDICTION_H
#define PREDICTION_H

#include "mee.h"
// #include "abstract_hardware_model.h"

#define REGION_SCALE_SHIFT 12
#define CHUNK_SCALE_SHIFT 10

class predictor {
public:
    predictor();
    virtual ~predictor() {
        delete m_bit_vector;
    }

    static new_addr_type get_index(new_addr_type addr, unsigned scale_shift);
    virtual new_addr_type get_index(new_addr_type addr) = 0;

    void set(new_addr_type addr, unsigned value);
 
    bool match(new_addr_type addr, unsigned value);

    counterMap* get_bit_vector() {
        return m_bit_vector;
    }

private:

    counterMap* m_bit_vector;

};

class read_only_predictor : public predictor {
public:
    read_only_predictor();

    new_addr_type get_index(new_addr_type addr) {
        return predictor::get_index(addr, REGION_SCALE_SHIFT);
    }
    
private:
};

class streaming_predictor : public predictor {
public:
    streaming_predictor();

    new_addr_type get_index(new_addr_type addr) {
        return predictor::get_index(addr, CHUNK_SCALE_SHIFT);
    }

    void update(new_addr_type addr, bool wr, unsigned long long cycle);

    void check_streaming(unsigned long long cycle);
    
private:

    class MAT_UNIT* m_mat_unit;

};

class MAT_UNIT {
public:
    MAT_UNIT(streaming_predictor* str_pred);

    unsigned access(new_addr_type addr);

    unsigned lru();

    void update(new_addr_type addr, bool wr, unsigned long long cycle);

    void check_streaming(unsigned long long cycle);
private:
    const unsigned m_num_mat = 8;
    class MAT* m_mat[8];
    streaming_predictor* m_str_pred;
};

class MAT {
public:
    MAT(MAT_UNIT* m_unit);

    new_addr_type get_offset(new_addr_type addr);

    void init();

    void update(new_addr_type addr, bool wr, unsigned long long cycle);

    bool check_streaming(unsigned long long cycle);

    unsigned get_tot_ctr() {
        return m_tot_ctr;
    }

    new_addr_type get_tag() {
        return m_tag;
    }

    bool is_dirty() {
        return m_dirty;
    }

    bool is_valid() {
        return m_valid;
    }

    unsigned long long get_last_cycle() {
        return m_last_cycle;
    }
private:
    unsigned m_tag;
    bool m_dirty;
    bool m_valid;
    unsigned m_tot_ctr;
    unsigned m_ctr[32];
    unsigned long long m_last_cycle;
    class MAT_UNIT* m_unit;
};

#endif