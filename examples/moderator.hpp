#ifndef NDN_IBAS_DEMO_MODERATOR_HPP
#define NDN_IBAS_DEMO_MODERATOR_HPP

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
    m_defaultCertName = m_keyChain.createIdentity(m_name);
  }

  inline bool verifySignature(const Data& data) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      return Validator::verifySignatureIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa) {
      // Locate publisher's key, then verify
      Name keyName = m_keyChain.getDefaultKeyNameForIdentity(data.getName().getPrefix(3));
      shared_ptr<PublicKey> publicKey = m_keyChain.getPublicKey(keyName);
      return Validator::verifySignature(data, *publicKey);
    }
    return false;
  }

  inline void signData(Data& data, std::string& content) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());
      m_keyChain.signAndAggregateIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa) {
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
  Name m_name;
  KeyChain m_keyChain;
  int m_currentSequenceNumber = 0;

  Name m_defaultCertName; // Used for RSA, ECDSA
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_MODERATOR_HPP
