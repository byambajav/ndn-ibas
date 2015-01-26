#ifndef NDN_SECURITY_IBAS_SIGNER_HPP
#define NDN_SECURITY_IBAS_SIGNER_HPP

#include <pbc/pbc.h>

#include "../encoding/block.hpp"
#include "../signature.hpp"
#include "../data.hpp"

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

  /**
   * @brief Computes a new IBAS signature of given data
   *
   * @param data The data to sign
   * @param dataLength The data's length
   */
  Block sign(const uint8_t* data, size_t dataLength);

  /**
   * @brief Computes a new IBAS signature by aggregating
   *
   * @param data The data to sign
   * @param dataLength The data's length
   * @param oldSignature The old signature to aggregate
   */
  Block signAndAggregate(const uint8_t* data, size_t dataLength, const Signature& oldSignature);

  /**
   * @brief Verifies given data
   *
   * @param data The data to verify
   */
  bool verifySignature(const Data& data);

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

  /**
   * @brief Calculates T, S signatures of given data using given data and w parameters.
   *        The method assumes that T and S elements are initialized previously.
   */
  void signInternal(element_t T, element_t S, const uint8_t* data, size_t dataLength,
                                const std::string& w);

  /**
   * @brief Writes w, T, S into a block as a signature
   *
   * @param clear If true clear T, S elements after using
   */
  Block signIntoBlock(element_t T, element_t S, const std::string& w, bool clear);

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
