#ifndef NDN_IBAS_DEMO_PUBLISHER_HPP
#define NDN_IBAS_DEMO_PUBLISHER_HPP

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
  Publisher(const std::string& name) {
    m_name = Name(name);
    m_keyChain.setIdentityIbas(getPrivateParamsFilePath(m_name.get(1).toUri()));
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
    m_keyChain.signIbas(messageData);

    return messageData;
  }

 private:
  Name m_name;
  KeyChain m_keyChain;
  int m_currentMessageId = 0;
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_PUBLISHER_HPP
