#include "security/key-chain.hpp"

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

    KeyLocator keyLocator = data.getSignature().getKeyLocator();
    Name keyLocatorName = keyLocator.getName();
    std::cout << "KeyLocatorName: " << keyLocatorName.toUri() << std::endl;
  }

  Data createSignData(std::string nameString, std::string identity, std::string content) {
    using namespace ndn;

    Name name(nameString);
    Data data(name);
    data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());

    KeyChain keyChain;
    keyChain.signByIdentityIbas(data, identity);

    logData(data);
    return data;
  }

} // namespace ibas

int main(int argc, char *argv[])
{
  if (argc < 4) {
    std::cout << argv[0] << " nameString id content" << std::endl;
    return 1;
  }

  ndn::Data signedData = ibas::createSignData(argv[1], argv[2], argv[3]);
  return 0;
}
