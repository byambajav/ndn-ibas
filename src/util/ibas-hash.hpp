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
