#include "security/key-chain.hpp"
#include "security/validator-null.hpp"

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
  }

  Data createSignAggregateData(std::string nameString, std::string content) {
    using namespace ndn;

    Name name(nameString);
    Data data(name);
    data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());

    KeyChain keyChain;
    keyChain.initializeIbas(ALICE_PRIVATE_PARAMS_FILE_PATH);
    keyChain.signIbas(data);
    logData(data);

    keyChain.initializeIbas(GOVERNMENTOFFICE_PRIVATE_PARAMS_FILE_PATH);
    keyChain.signAndAggregateIbas(data);
    logData(data);

    // ValidatorIbas validator;
    // OnInterestValidated onValidated = bind(&ControllerBackend::onInvitationValidated, this, _1);
    // OnInterestValidationFailed onFailed = bind(&ControllerBackend::onInvitationValidationFailed,
    //                                            this, _1, _2);
    // validator.validate(*invitationInterest, onValidated, onFailed);

    ValidatorNull validator;

    return data;
  }

} // namespace ibas

int main(int argc, char *argv[])
{
  if (argc == 3) {
    ndn::Data signedData = ibas::createSignAggregateData(argv[1], argv[2]);
  } else {
    std::cout << argv[0] << " dataName content" << std::endl;
    return 1;
  }

  return 0;
}
