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

#ifndef NDN_IBAS_DEMO_MODERATOR_HPP
#define NDN_IBAS_DEMO_MODERATOR_HPP

#include "face.hpp"
#include "security/key-chain.hpp"
#include "security/validator.hpp"
#include "ibas-demo-helper.hpp"

namespace ndn {
namespace ibas_demo {

/**
 * @brief A moderator class
 */
class Moderator : noncopyable
{
 public:
  /**
   * @brief Constructor
   *
   * @param name It must be of "/organization/identity/application" format
   */
  Moderator(const std::string& name) {
    m_name = Name(name);
    m_keyChain.setIdentityIbas(getPrivateParamsFilePath(m_name.get(1).toUri()));
    static const EcdsaKeyParams ecdsaKeyParams;
    m_defaultCertName = m_keyChain.createIdentity(m_name, ecdsaKeyParams);
    // m_defaultCertName = m_keyChain.createIdentity(m_name);
  }

  void run() {
    m_face.setInterestFilter(m_name,
                             bind(&Moderator::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&Moderator::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

  /**
   * @brief Changes name, signature of the data
   */
  void moderateMessage(Data& messageData) {
    if (!verifySignature(messageData)) {
      std::cout << "Message does not verify!" << std::endl;
      return;
    }

    // Change name of the data
    // Message name is of format: "/org/id/app/publisherOrg/publisherId/messageId/seqNum"
    Name moderatedMessageName = m_name;
    moderatedMessageName.append(messageData.getName().getPrefix(2));
    moderatedMessageName.append(messageData.getName().get(3));
    moderatedMessageName.appendSequenceNumber(m_currentSequenceNumber++);
    messageData.setName(moderatedMessageName);

    // Modify the content
    std::string message = string(messageData.getContent().value_begin(),
                                 messageData.getContent().value_end());
    message.insert(0, "Moderator: " + m_name.get(1).toUri() + "\n" +
                   "Accepted: " + getCurrentTime());

    // Sign and aggregate
    signData(messageData, message);
  }

 private:
  void onData(const Interest& interest, const Data& data) {
    logDataSizes(data);
    // std::cout << ">> D" << std::endl << data << std::endl;

    // Verify and moderate the received Data
    shared_ptr<Data> moderatedData = make_shared<Data>(data);
    moderateMessage(*moderatedData);

    // Send it out to the requesting subscriber(s)
    // std::cout << "<< D" << std::endl << *moderatedData << std::endl;
    m_face.put(*moderatedData);

    // Temporary hack for experiments
    if (m_currentSequenceNumber >= 1) {
      m_face.shutdown();
    }
  }

  void onInterest(const InterestFilter& filter, const Interest& interest) {
    // std::cout << ">> I" << std::endl << interest << std::endl;

    // Create a Interest based on the received Interest's name
    Name outInterestName = interest.getName().getSubName(3, 2)
                           .append(interest.getName().getSubName(2,1));
    Interest outInterest(outInterestName);
    outInterest.setInterestLifetime(time::milliseconds(1000));
    outInterest.setMustBeFresh(true);

    // Send the Interest out to the publisher
    m_face.expressInterest(outInterest,
                           bind(&Moderator::onData, this,  _1, _2),
                           bind(&Moderator::onTimeout, this, _1));

    // std::cout << "<< I" << std::endl << outInterest << std::endl;
  }

  void onRegisterFailed(const Name& prefix, const std::string& reason) {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

  bool verifySignature(const Data& data) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      return Validator::verifySignatureIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa ||
               signatureType == tlv::SignatureSha256WithEcdsa) {
      // Locate publisher's key, then verify
      Name keyName = m_keyChain.getDefaultKeyNameForIdentity(data.getName().getPrefix(3));
      shared_ptr<PublicKey> publicKey = m_keyChain.getPublicKey(keyName);
      return Validator::verifySignature(data, *publicKey);
    }
    return false;
  }

  void onTimeout(const Interest& interest) {
    std::cout << "Timeout " << interest << std::endl;
  }

  /**
   * @brief Re-signs a data, NOTE: existing signature of the data will be overridden
   */
  void signData(Data& data, std::string& content) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());
      m_keyChain.signAndAggregateIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa ||
               signatureType == tlv::SignatureSha256WithEcdsa) {
      // Append old signature into data's content part
      content.append("\nSignature:");
      content.append((const char*) data.getSignature().getInfo().wire(),
                     data.getSignature().getInfo().size());
      content.append((const char*) data.getSignature().getValue().wire(),
                     data.getSignature().getValue().size());
      data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());
      m_keyChain.signByIdentity(data, m_name);
    }
  }

 private:
  Face m_face;
  Name m_name;
  KeyChain m_keyChain;
  int m_currentSequenceNumber = 0;

  Name m_defaultCertName; // Used for RSA, ECDSA
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_MODERATOR_HPP
