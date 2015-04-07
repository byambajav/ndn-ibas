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

#include "publisher.hpp"

int main(int argc, char** argv)
{
  using namespace ndn;
  using namespace ndn::ibas_demo;

  tlv::SignatureTypeValue signatureType;
  size_t loadSize;

  if (argc != 3) {
    cout << "Usage: " << argv[0] << " signatureType(1 => RSA, 4 => IBAS) loadSize" << endl;
    return 1;
  } else {
    signatureType = (tlv::SignatureTypeValue) atoi(argv[1]);
    loadSize = atoi(argv[2]);
  }

  Publisher alice("/wonderland/Alice/safety-confirmation", signatureType, loadSize);

  try {
    alice.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
