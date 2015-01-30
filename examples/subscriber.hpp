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
    return Validator::verifySignatureIbas(messageData);
  }

 private:
  Name m_name;
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_SUBSCRIBER_HPP
