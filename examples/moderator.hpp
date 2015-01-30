#ifndef NDN_IBAS_DEMO_MODERATOR_HPP
#define NDN_IBAS_DEMO_MODERATOR_HPP

#include "security/key-chain.hpp"
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
  }

  void moderateMessage(Data& messageData) {
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
    message.insert(0, "Moderator: " + m_name.get(1).toUri() + "\n"); // TODO: Add accepted datetime
    messageData.setContent(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());

    // Sign and aggregate
    m_keyChain.signAndAggregateIbas(messageData);
  }

 private:
  Name m_name;
  KeyChain m_keyChain;
  int m_currentSequenceNumber = 0;
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_MODERATOR_HPP
