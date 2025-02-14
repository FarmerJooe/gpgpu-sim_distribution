
class ECCEngine{
public:
  ECCEngine(float p_1bit_err, float p_2bit_err, class gpgpu_sim *gpu);
  bool hasECCError();
  bool hasGlobalECCError();
  void correctECC();
  bool checkECC();
  void generateECC();
public:
  class gpgpu_sim *m_gpu;

  unsigned m_status_correct_1b_ECC;
  unsigned m_status_correct_2b_ECC;
  unsigned m_status_checkECC;
  unsigned m_status_generateECC;
  float m_p_1bit_err;
  float m_p_2bit_err;
  unsigned m_eccCorrectCountdown;
};