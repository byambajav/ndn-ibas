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

  ~IbasSigner();

  Block sign(const uint8_t* data, size_t dataLength);

  // TODO: Block signAndAggregate(), verify();

 private:
  /**
   * @brief Initializes the pairing and public params
   */
  void publicParamsInit(const char* publicParamsFilePath);

  /**
   * @brief Initializes the private params
   */
  void privateParamsInit(const char* privateParamsFilePath);

  /**
   * @brief Generates a random w, mostly current time as a string
   */
  const std::string generateW();

 private:
  std::string identity;

  // Public params
  pairing_t pairing;
  element_t P, Q;

  // Private params
  element_t s_P_0, s_P_1;
};

} // namespace ndn

#endif  // NDN_SECURITY_IBAS_SIGNER_HPP
