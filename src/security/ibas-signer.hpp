/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2015 Regents of the University of Tokyo.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Byambajav Namsraijav  <http://byambajav.com/>
 */

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
   * @brief Constructs an instance, in this case the instance cannot sign data. It only can verify.
   *        After calling {@code initializePrivateParams()} the instance can sign data.
   */
  IbasSigner();

  ~IbasSigner();

  /**
   * @brief Sets the private params, so that it can sign data using the credentials.
   *        If the private params were set before it overrides the old params.
   *
   * @param privateKeyFilePath Path of file which includes an identity and corresponding private key
   */
  void setPrivateParams(const std::string& privateParamsFilePath);

  void setupPublicParams();

  void setupPrivateParam(const std::string& identity);

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
   * @brief Computes a new IBAS signature of given data
   *        Signature is created from only content part of the data
   *
   * @deprecated
   * @param data The data to sign
   */
  Block sign(const Data& data);

  /**
   * @brief Computes a new IBAS signature by aggregating
   *        Signature is created from only content part of the data
   *
   * @deprecated
   * @param data The data to sign
   * @param oldSignature The old signature to aggregate
   */
  Block signAndAggregate(const Data& data, const Signature& oldSignature);

  /**
   * @brief Verifies given data
   *
   * @param data The data to verify
   */
  bool verifySignature(const Data& data);

 private:
  /**
   * @brief Verify non-moderated data signature, i.e., the data starts with 'From: '
   */
  bool verifySignatureSimple(element_t T, element_t S, element_t P_w,
                             const std::string& w, const std::string& identity,
                             const Data& data);

  /**
   * @brief Initializes the pairing and public params
   */
  void initializePublicParams(const std::string& publicParamsFilePath);

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

  // Public params (public in terms of IBAS)
  pairing_t pairing;
  element_t P, Q;

  // Private params
  std::string identity;
  element_t s_P_0, s_P_1;
};

} // namespace ndn

#endif  // NDN_SECURITY_IBAS_SIGNER_HPP
