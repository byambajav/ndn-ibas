#include <boost/timer/timer.hpp>
#include "security/key-chain.hpp"
#include "security/validator.hpp"

#include "publisher.hpp"
#include "moderator.hpp"
#include "subscriber.hpp"

#define ALICE_PRIVATE_PARAMS_FILE_PATH "/home/denjo/.ndn/ibas/Alice.id"
#define GOVERNMENTOFFICE_PRIVATE_PARAMS_FILE_PATH "/home/denjo/.ndn/ibas/GovernmentOffice.id"
#define BOB_PRIVATE_PARAMS_FILE_PATH "/home/denjo/.ndn/ibas/Bob.id"

namespace ibas {
  using namespace ndn;

  /**
   * @brief Log a data packet for packet inspection
   */
  void logData(Data& data) {
    std::cout << "Data size: " << data.wireEncode().size() << std::endl;
    std::string dataStr = reinterpret_cast<const char*>(data.wireEncode().value());
    std::cout << "Data: " << dataStr << std::endl;

    std::cout << "SignatureValue size: " << data.getSignature().getValue().size() << std::endl;
    std::string signature = reinterpret_cast<const char*>(data.getSignature().getValue().value());
    std::cout << "SignatureValue: " << signature << std::endl;

    std::cout << "SignatureInfo size: " << data.getSignature().getInfo().size() << std::endl;
    std::string signatureInfo = reinterpret_cast<const char*>(data.getSignature().getInfo().value());
    std::cout << "SignatureInfo: " << signatureInfo << std::endl;

    // KeyLocator keyLocator = data.getSignature().getKeyLocator();
    // Name keyLocatorName = keyLocator.getName();
    // std::cout << "KeyLocatorName: " << keyLocatorName.toUri() << std::endl;
    std::cout << std::endl;
  }

  Data createSignAggregateData(std::string nameString, std::string content) {
    using namespace ndn;

    Name name(nameString);
    Data data(name);
    content.insert(0, "From: Alice\n");
    data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());

    KeyChain keyChain;
    keyChain.setIdentityIbas(ALICE_PRIVATE_PARAMS_FILE_PATH);
    keyChain.signIbas(data);
    // logData(data);

    content.insert(0, "Moderator: GovernmentOffice\n");
    data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());
    keyChain.setIdentityIbas(GOVERNMENTOFFICE_PRIVATE_PARAMS_FILE_PATH);
    keyChain.signAndAggregateIbas(data);
    // logData(data);

    bool verified = Validator::verifySignatureIbas(data);
    std::cout << std::boolalpha << verified << std::endl;

    return data;
  }

} // namespace ibas

int main(int argc, char *argv[])
{
  // boost::timer::auto_cpu_timer t;
  // if (argc == 3) {
  //   for (int i = 0; i < 100; ++i) {
  //     ibas::createSignAggregateData(argv[1], argv[2]);
  //   }
  // } else {
  //   std::cout << argv[0] << " dataName content" << std::endl;
  //   return 1;
  // }

  ndn::ibas_demo::Publisher alice("/wonderland/Alice/safety-confirmation");
  ndn::ibas_demo::Moderator governmentOffice("/rendezvous/GovernmentOffice/safety-confirmation");
  ndn::ibas_demo::Subscriber bob("/wonderland/Bob/safety-confirmation");

  ndn::Data data = alice.publishMessage(0);
  ndn::ibas_demo::logData(data);
  governmentOffice.moderateMessage(data);
  ndn::ibas_demo::logData(data);
  std::cout << std::boolalpha << bob.verifyMessage(data) << std::endl << std::endl;

  data = alice.publishMessage(0);
  ndn::ibas_demo::logData(data);
  governmentOffice.moderateMessage(data);
  ndn::ibas_demo::logData(data);
  std::cout << std::boolalpha << bob.verifyMessage(data) << std::endl << std::endl;

  return 0;
}
