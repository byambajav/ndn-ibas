#ifndef NDN_IBAS_DEMO_SUBSCRIBER_HPP
#define NDN_IBAS_DEMO_SUBSCRIBER_HPP

#include "security/validator.hpp"
#include "ibas-demo-helper.hpp"

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

  bool verifyMessage(const Data& data) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      return Validator::verifySignatureIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa) {
      // Locate moderator's key, then verify
      Name keyName = m_keyChain.getDefaultKeyNameForIdentity(data.getName().getPrefix(3));
      shared_ptr<PublicKey> publicKey = m_keyChain.getPublicKey(keyName);
      if (!Validator::verifySignature(data, *publicKey)) {
        return false;
      }

      // Load subscriber's signature from content part using TLV parsing
      using std::string;
      const string contentStr = string(data.getContent().value_begin(),
                                    data.getContent().value_end());
      const static string signaturePlaceholder = "\nSignature:";
      size_t signaturePlaceholderPos = contentStr.find(signaturePlaceholder);
      Block sigInfo(reinterpret_cast<const uint8_t*>(data.getContent().value() +
                                                     signaturePlaceholderPos +
                                                     signaturePlaceholder.size()), 10000);
      Block sigValue(reinterpret_cast<const uint8_t*>(data.getContent().value() +
                                                      signaturePlaceholderPos +
                                                      signaturePlaceholder.size() +
                                                      sigInfo.size()), 10000);
      Signature subscriberSignature = Signature(sigInfo, sigValue);

      // Rebuild previous (pre-moderation) data
      // NOTE: Similar to verify signature method in IbasSigner
      const static string from = "From: ";
      size_t fromPos = contentStr.find(from);
      const Name name = data.getName();
      Name previousName = name.getSubName(3, 2).append(name.get(2)).append(name.get(5));
      Data previousData(previousName);
      previousData.setContent(reinterpret_cast<const uint8_t*>(contentStr.c_str() + fromPos),
                              signaturePlaceholderPos - fromPos);
      previousData.setSignature(subscriberSignature);

      // verify subscriber's signature
      keyName = m_keyChain.getDefaultKeyNameForIdentity(previousName.getPrefix(3));
      publicKey = m_keyChain.getPublicKey(keyName);
      return Validator::verifySignature(previousData, *publicKey);
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
