#include "mee.h"

#ifndef PREDICTION_H
#define PREDICTION_H

class predictor {
public:
    predictor(unsigned scale_shift);
    virtual ~predictor() {
    }

    new_adr_type get_index(new_adr_type addr);

    void set(new_adr_type addr, unsigned value);
 
    bool match(new_adr_type addr, unsigned value);

    counterMap* get_bit_vector() {
        return m_bit_vector;
    }

private:

    counterMap* m_bit_vector;
    unsigned m_scale_shift;

};

class read_only_predictor : public predictor {
public:
    read_only_predictor() : predictor();
    
private:
    const unsigned m_region_scale_shift = 12;
}

#endif