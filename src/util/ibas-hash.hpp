#ifndef NDN_UTIL_IBAS_HASH_HPP
#define NDN_UTIL_IBAS_HASH_HPP

#include <pbc/pbc.h>

#include "../common.hpp"

/** @brief Provides implementations of hash functions used in IBAS
 */
namespace ndn {
  namespace util {

    /**
     * @brief Computes the H1:{0,1}*->G1 digest of string.
     *
     * @param hash The element to insert result
     * @param str The string to calculate hash
     * @param pairing The pairing
     */
    void calculateH1(element_t hash, const std::string& str, pairing_t pairing);

    /**
     * @brief Computes the H2:{0,1}*->G1 digest of string.
     *
     * @param hash The element to insert result
     * @param str The string to calculate hash
     * @param pairing The pairing
     */
    void calculateH2(element_t hash, const std::string& str, pairing_t pairing);

    /**
     * @brief Computes the H3:{0,1}*->Z/qZ digest of data.
     *
     * @param hash The element to insert result
     * @param data The data to calculate hash
     * @param pairing The pairing used
     */
    void calculateH3(element_t hash, const std::string& str, pairing_t pairing);

    /**
     * @brief Generates and prints secret key for an identity.
     *        This code should be used only once for each identity.
     *
     * @param identity The identity string
     */
    void generateSecretKeyForIdentity(const std::string& identity, pairing_t pairing);

  } // namespace util
} // namespace ndn

#endif // NDN_UTIL_IBAS_HASH_HPP
