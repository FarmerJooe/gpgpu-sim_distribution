#include "ecc.h"
#include "gpu-sim.h"
#include <stdlib.h>

ECCEngine::ECCEngine(float p_1bit_err_base, float p_2bit_err_base, class gpgpu_sim *gpu) :
  m_gpu(gpu),
  m_p_1bit_err_base(p_1bit_err_base),
  m_p_2bit_err_base(p_2bit_err_base) {
  m_status_correct_1b_ECC = 0;
  m_status_correct_2b_ECC = 0;
  m_status_checkECC = 0;
  m_status_generateECC = 0;
  m_eccCorrectCountdown = 0;
  m_p_accumulated_1bit_err = 0;
  m_p_accumulated_2bit_err = 0;
  // m_p_1bit_err = p_1bit_err;
  // m_p_2bit_err = p_2bit_err;
}

bool ECCEngine::hasECCError() {
  return m_eccCorrectCountdown;
}

void ECCEngine::accumulateError() {
  m_p_accumulated_1bit_err += m_p_1bit_err_base;
  m_p_accumulated_2bit_err += m_p_2bit_err_base;
}

// bool ECCEngine::hasGlobalECCError() {
//   for (unsigned i = 0; i < m_gpu->m_memory_config->m_n_mem; i++) {
//     if (m_gpu->m_memory_partition_unit[i]->hasECCError())
//       return true;
//   }
//   return false;
// }

void ECCEngine::correctECC() {
  if (m_eccCorrectCountdown)
    m_eccCorrectCountdown--;
}

bool ECCEngine::checkECC() {
  m_status_checkECC++;
  float rand_num = (float)rand() / (float)RAND_MAX;
  // m_p_accumulated_1bit_err += m_p_1bit_err_base;
  // m_p_accumulated_2bit_err += m_p_2bit_err_base;
  if (rand_num < m_p_accumulated_1bit_err) {  // 1-bit error
    // correctECC();
    m_status_correct_1b_ECC++;
    m_eccCorrectCountdown = 8 + 20 + 20;
    m_p_accumulated_1bit_err = 0;
    m_p_accumulated_2bit_err = 0;
    return true;
  } else if (rand_num < m_p_accumulated_1bit_err + m_p_accumulated_2bit_err) { // 2-bit error
    m_status_correct_2b_ECC++;
    m_eccCorrectCountdown = 1020 + 20 + 20;
    m_p_accumulated_1bit_err = 0;
    m_p_accumulated_2bit_err = 0;
    return true;
  } else { // no error
    m_p_accumulated_1bit_err = 0;
    m_p_accumulated_2bit_err = 0;
    return true;
  }
}

void ECCEngine::generateECC() {
  m_status_generateECC++;
}