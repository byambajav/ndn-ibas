#include "ibas-signer.hpp"

#define DEFAULT_PARAMS_FILE

namespace ndn {

IbasSigner::IbasSigner(const std::string& publicParamsFilePath, const std::string& privateKeyFilePath) {
  // Loads the public parameters: (G_1, G_2, e, P, Q)

  // Loads the private parameters: (id, s_P_0, s_P_1)

};

Block IbasSigner::sign(const uint8_t* data, size_t dataLength) {
  // TODO: actual signing
  return Block(tlv::SignatureValue);
}

} // namespace ndn
