#include "publisher.hpp"

int main(int argc, char** argv)
{
  using namespace ndn;
  using namespace ndn::ibas_demo;

  tlv::SignatureTypeValue signatureType;
  size_t loadSize;

  if (argc != 3) {
    cout << "Usage: " << argv[0] << " signatureType(1,3,4) loadSize" << endl;
    return 1;
  } else {
    signatureType = (tlv::SignatureTypeValue) atoi(argv[1]);
    loadSize = atoi(argv[2]);
  }

  Publisher alice("/wonderland/Alice/safety-confirmation", signatureType, loadSize);

  try {
    alice.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
