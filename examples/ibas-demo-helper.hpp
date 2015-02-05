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
 * @author Byambajav Namsraijav  <http://byambajav.com/>
 */

#ifndef NDN_IBAS_DEMO_HELPER_HPP
#define NDN_IBAS_DEMO_HELPER_HPP

#include <ctime>

#include "data.hpp"

namespace ndn {
namespace ibas_demo {

using std::string;
using std::cout;
using std::endl;

const static string c_paramsFilePathPrefix = string(getenv("HOME")) + string("/.ndn/ibas/");

/**
 * @brief Logs data packet information
 */
void logData(const Data& data) {
  cout <<  "Name: " << data.getName().toUri() << endl;
  cout <<  "Content: " << string(data.getContent().value_begin(),
                                 data.getContent().value_end()) << endl;
  cout << "Signature value value_size: " << data.getSignature().getValue().value_size() << endl;
  cout << "Signature info " << string(data.getSignature().getInfo().wire(),
                                       data.getSignature().getInfo().wire() +
                                       data.getSignature().getInfo().size()) << endl;
  cout << "Signature value " << string(data.getSignature().getValue().wire(),
                                       data.getSignature().getValue().wire() +
                                       data.getSignature().getValue().size()) << endl;
  cout << endl;
}

/**
 * @brief Logs data packets size details
 */
void logDataSizes(const Data& data) {
  cout << "Name: " << data.getName().wireEncode().size() << endl;
  cout << "MetaInfo: " << data.getMetaInfo().wireEncode().size() << endl;
  cout << "Content: " << data.getContent().size() << endl;
  cout << "Signature info: " << data.getSignature().getInfo().size() << endl;
  cout << "Signature value: " << data.getSignature().getValue().size() << endl;
  cout << "Total: " << data.wireEncode().size() << endl;
  cout << endl;
}


/**
 * @brief Gets private params file path
 *
 * @param identity The identity to get private params
 */
const string getPrivateParamsFilePath(const string& identity) {
  return c_paramsFilePathPrefix + identity + ".id";
}

inline std::string generateRandomString(size_t len) {
  std::string s(len, 0);
  static const char alphanum[] =
      "0123456789     _,.;:"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  for (size_t i = 0; i < len; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  return s;
}

inline std::string getCurrentTime() {
  std::time_t result = std::time(NULL);
  return std::ctime(&result);
}

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_HELPER_HPP
