#include "ibas-signer.hpp"

namespace ndn {

IbasSigner::IbasSigner(const std::string& publicParamsFilePath,
                       const std::string& privateParamsFilePath) {
  // Loads the public parameters: (G_1, G_2, e, P, Q)

  // Loads the private parameters: (id, s_P_0, s_P_1)

}

Block IbasSigner::sign(const uint8_t* data, size_t dataLength) {
  // TODO: actual signing
  return Block(tlv::SignatureValue);
}

void IbasSigner::pbcPairingInit(char* publicParamsFilePath) {
  char s[16384];
  FILE *fp = fopen(publicParamsFilePath, "r");
  if (!fp) pbc_die("error opening %s", publicParamsFilePath);

  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);

  if (pairing_init_set_buf(m_pairing, s, count)) pbc_die("pairing init failed");
}

} // namespace ndn
