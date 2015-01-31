#include <boost/timer/timer.hpp>
#include "security/key-chain.hpp"
#include "security/validator.hpp"

void signRsa(std::string nameString, std::string content) {
  using namespace ndn;
  Name identityName = Name("Tony");

  // Create a data
  Name dataName(nameString);
  Data data(dataName);
  content.insert(0, "From: Alice\n");
  data.setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.length());

  // signing
  KeyChain keyChain ;
  Name defaultCertName = keyChain.createIdentity(identityName);
  keyChain.sign(data, defaultCertName);

  // verifying
  Name keyName = keyChain.getDefaultKeyNameForIdentity(identityName);
  shared_ptr<PublicKey> publicKey = keyChain.getPublicKey(keyName);
  bool verified = Validator::verifySignature(data, *publicKey);
  std::cout << std::boolalpha << verified << std::endl;
}

int main(int argc, char *argv[])
{
  boost::timer::auto_cpu_timer t;
  for (int i = 0; i < 100; ++i) {
    signRsa(argv[1], argv[2]);
  }

  return 0;
}
