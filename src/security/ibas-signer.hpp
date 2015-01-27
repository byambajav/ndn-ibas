#ifndef NDN_SECURITY_IBAS_SIGNER_HPP
#define NDN_SECURITY_IBAS_SIGNER_HPP

#include <pbc/pbc.h>

#include "../encoding/block.hpp"
#include "../signature.hpp"
#include "../data.hpp"

// This class should be merged into SecTpmFile.
// Making it a separate class is just for the ease of implementation.

namespace ndn {

/**
 * @brief IbasSigner class provides IBAS related sign, verify functions for KeyChain and Validator.
 *
 * There are two possible instance states. In one state the instance can only verify data and its
 * signature; it cannot sign a data. The state can be checked by calling 'canSign()' method.
 */
class IbasSigner
{
 public:
  /**
   * @param publicParamsFilePath Path of a file which includes all public parameters of the IBAS
   * @param privateKeyFilePath Path of file which includes an identity and corresponding private key
   */
  IbasSigner(const std::string& publicParamsFilePath, const std::string& privateParamsFilePath);

  /**
   * @brief Constructs an instance, in this case the instance cannot sign data. It only can verify.
   *
   * @param publicParamsFilePath Path of a file which includes all public parameters of the IBAS
   */
  IbasSigner(const std::string& publicParamsFilePath);

  ~IbasSigner();

  /**
   * @brief True if the instance can be used to sign data, false otherwise.
   */
  bool canSign();

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
   * @brief Generates a random w, current time as a string with random padding at end
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

  /**
   * @brief Loads signature variables T, S, w from a signature
   *        The method assumes that T and S elements are initialized previously.
   *
   * @return True if signature variables was successfully loaded, false otherwise.
   */
  bool loadSignature(element_t T, element_t S, std::string& w, const Signature& signature);


 private:
  bool m_canSign = false;
  std::string identity;

  // Public params
  pairing_t pairing;
  element_t P, Q;

  // Private params
  element_t s_P_0, s_P_1;
};

} // namespace ndn

#endif  // NDN_SECURITY_IBAS_SIGNER_HPP
