#ifndef NDN_SECURITY_IBAS_SIGNER_HPP
#define NDN_SECURITY_IBAS_SIGNER_HPP

#include <pbc/pbc.h>

#include "../encoding/block.hpp"

// This class should be merged into SecTpmFile.
// Making it a separate class is just for the ease of implementation.

namespace ndn {

class IbasSigner
{
 public:
  /**
   * @param paramsFilePath Path of a file which includes all public parameters of the IBAS scheme
   * @param privateKeyFilePath Path of file which includes an identity and corresponding private key
   */
  IbasSigner(const std::string& paramsFilePath, const std::string& privateParamsFilePath);

  Block sign(const uint8_t* data, size_t dataLength);

  // TODO: Block signAndAggregate(), verify();

 private:
  void pbcPairingInit(char* publicParamsFilePath);

 private:
  std::string m_identity;
  pairing_t m_pairing;
  // TODO: private keys, various paramaters
};

} // namespace ndn

#endif  // NDN_SECURITY_IBAS_SIGNER_HPP
