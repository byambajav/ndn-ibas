#ifndef NDN_IBAS_DEMO_PUBLISHER_HPP
#define NDN_IBAS_DEMO_PUBLISHER_HPP

#include "encoding/tlv.hpp"
#include "security/key-chain.hpp"
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
  Publisher(const std::string& name, tlv::SignatureTypeValue signatureType) {
    m_name = Name(name);
    m_signatureType = signatureType;

    if (m_signatureType == tlv::SignatureSha256Ibas) {
      m_keyChain.setIdentityIbas(getPrivateParamsFilePath(m_name.get(1).toUri()));
    } else if (m_signatureType == tlv::SignatureSha256WithRsa) {
      m_defaultCertName = m_keyChain.createIdentity(m_name);
    } else {
      std::cout << "Unsupported signature type: " << m_signatureType << std::endl;
    }
  }

  Data publishMessage(size_t messageSize) {
    // Create a new message data
    // Message name is of format: "/organization/identity/application/messageId"
    Name messageName = m_name;
    messageName.appendSequenceNumber(m_currentMessageId++);
    Data messageData(messageName);

    // Set content
    std::string message("I am OK."); // TODO: Make it random string with size of messageSize
    message.insert(0, "From: " + m_name.get(1).toUri() + "\n"); // TODO: Add publish datetime
    messageData.setContent(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());

    // Sign
    if (m_signatureType == tlv::SignatureSha256Ibas) {
      m_keyChain.signIbas(messageData);
    } else if (m_signatureType == tlv::SignatureSha256WithRsa) {
      m_keyChain.signByIdentity(messageData, m_name);
    }

    return messageData;
  }

  shared_ptr<PublicKey> getPublicKey() {
    return m_keyChain.getPublicKey(m_name);
  }

 private:
  Name m_name;
  KeyChain m_keyChain;
  int m_currentMessageId = 0;

  /* The signature type it uses of publishing messages */
  tlv::SignatureTypeValue m_signatureType;
  Name m_defaultCertName; // Used for RSA, ECDSA
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_PUBLISHER_HPP
