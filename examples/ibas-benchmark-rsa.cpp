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

#include <boost/timer/timer.hpp>
#include "security/key-chain.hpp"
#include "security/validator.hpp"

void signRsa(std::string nameString, std::string content) {
  using namespace ndn;
  Name identityName = Name("Tony");

  // Create a data
  Name dataName(nameString);
  Data data(dataName);
  content.insert(0, "From: Alice\n");
  data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());

  // signing
  KeyChain keyChain ;
  Name defaultCertName = keyChain.createIdentity(identityName);
  keyChain.sign(data, defaultCertName);

  // verifying
  Name keyName = keyChain.getDefaultKeyNameForIdentity(identityName);
  shared_ptr<PublicKey> publicKey = keyChain.getPublicKey(keyName);
  bool verified = Validator::verifySignature(data, *publicKey);
  std::cout << std::boolalpha << verified << std::endl;
}

int main(int argc, char *argv[])
{
  boost::timer::auto_cpu_timer t;
  for (int i = 0; i < 100; ++i) {
    signRsa(argv[1], argv[2]);
  }

  return 0;
}
