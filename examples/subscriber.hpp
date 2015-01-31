#ifndef NDN_IBAS_DEMO_SUBSCRIBER_HPP
#define NDN_IBAS_DEMO_SUBSCRIBER_HPP

#include "security/validator.hpp"

namespace ndn {
namespace ibas_demo {

/**
 * @brief A subscriber class
 */
class Subscriber : noncopyable
{
 public:
  /**
   * @brief Constructor
   *
   * @param name It must be of "/organization/identity/application" format
   */
  Subscriber(const std::string& name) {
    m_name = Name(name);
  }

  bool verifyMessage(const Data& messageData) {
    uint32_t signatureType = messageData.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      return Validator::verifySignatureIbas(messageData);
    } else if (signatureType == tlv::SignatureSha256WithRsa) {
      // Locate moderator's key, then verify
      Name keyName = m_keyChain.getDefaultKeyNameForIdentity(messageData.getName().getPrefix(3));
      shared_ptr<PublicKey> publicKey = m_keyChain.getPublicKey(keyName);
      return Validator::verifySignature(messageData, *publicKey);
    }
    return false;
  }

 private:
  Name m_name;
  KeyChain m_keyChain;
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_SUBSCRIBER_HPP
