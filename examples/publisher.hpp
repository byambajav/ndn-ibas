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

#ifndef NDN_IBAS_DEMO_PUBLISHER_HPP
#define NDN_IBAS_DEMO_PUBLISHER_HPP

#include "encoding/tlv.hpp"
#include "face.hpp"
#include "security/key-chain.hpp"
#include "security/key-params.hpp"
#include "ibas-demo-helper.hpp"

namespace ndn {
namespace ibas_demo {

/**
 * @brief A class which publishes random messages
 */
class Publisher : noncopyable
{
 public:
  /**
   * @brief Constructor
   *
   * @param name It must be of "/organization/identity/application" format
   */
  Publisher(const std::string& name, tlv::SignatureTypeValue signatureType, size_t size) {
    m_name = Name(name);
    m_signatureType = signatureType;
    m_defaultMessageSize = size;

    if (m_signatureType == tlv::SignatureSha256Ibas) {
      m_keyChain.setIdentityIbas(getPrivateParamsFilePath(m_name.get(1).toUri()));
    } else if (m_signatureType == tlv::SignatureSha256WithRsa) {
      m_defaultCertName = m_keyChain.createIdentity(m_name);
    } else if (m_signatureType == tlv::SignatureSha256WithEcdsa) {
      static const EcdsaKeyParams ecdsaKeyParams;
      m_defaultCertName = m_keyChain.createIdentity(m_name, ecdsaKeyParams);
    } else {
      std::cout << "Unsupported signature type: " << m_signatureType << std::endl;
    }

    srand(std::time(NULL));
  }

  void run() {
    m_face.setInterestFilter(m_name,
                             bind(&Publisher::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&Publisher::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

  shared_ptr<Data> createMessage() {
    return createMessage(m_defaultMessageSize);
  }

  shared_ptr<Data> createMessage(size_t messageSize) {
    // Create a new message data
    // Message name is of format: "/organization/identity/application/messageId"
    Name messageName = m_name;
    messageName.appendSequenceNumber(m_currentMessageId++);
    shared_ptr<Data> messageData = make_shared<Data>(messageName);

    // Set content
    std::string message = generateRandomString(messageSize);
    message.insert(0, "From: " + m_name.get(1).toUri() + "\n" +
                   "Published: " + getCurrentTime());
    messageData->setFreshnessPeriod(time::milliseconds(0));
    messageData->setContent(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());

    // Sign
    if (m_signatureType == tlv::SignatureSha256Ibas) {
      m_keyChain.signIbas(*messageData);
    } else if (m_signatureType == tlv::SignatureSha256WithRsa) {
      m_keyChain.signByIdentity(*messageData, m_name);
    } else if (m_signatureType == tlv::SignatureSha256WithEcdsa) {
      m_keyChain.signByIdentity(*messageData, m_name);
    }

    return messageData;
  }

 private:
  void onInterest(const InterestFilter& filter, const Interest& interest) {
    // std::cout << ">> I" << std::endl << interest << std::endl;

    // Create a signed Data packet
    shared_ptr<Data> data = createMessage();

    // Return the Data packet to the requester
    // std::cout << "<< D" << std::endl << *data << std::endl;
    m_face.put(*data);

    // Temporary hack for experiments
    if (m_currentMessageId >= 1) {
      m_face.shutdown();
    }
  }

  void onRegisterFailed(const Name& prefix, const std::string& reason) {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

 private:
  Name m_name;
  KeyChain m_keyChain;
  Face m_face;

  int m_currentMessageId = 0;
  size_t m_defaultMessageSize;

  /* The signature type it uses of publishing messages */
  tlv::SignatureTypeValue m_signatureType;
  Name m_defaultCertName; // Used for RSA, ECDSA
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_PUBLISHER_HPP
