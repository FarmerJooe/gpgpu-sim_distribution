
class ECCEngine{
public:
  ECCEngine(float p_1bit_err_base, float p_2bit_err_base, class gpgpu_sim *gpu);
  bool hasECCError();
  void correctECC();
  bool checkECC();
  void generateECC();
  void accumulateError();
public:
  class gpgpu_sim *m_gpu;

  unsigned m_status_correct_1b_ECC;
  unsigned m_status_correct_2b_ECC;
  unsigned m_status_checkECC;
  unsigned m_status_generateECC;
  float m_p_1bit_err_base;
  float m_p_2bit_err_base;
  float m_p_accumulated_1bit_err;
  float m_p_accumulated_2bit_err;
  unsigned m_eccCorrectCountdown;
};