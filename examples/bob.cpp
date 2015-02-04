#include "subscriber.hpp"

int main(int argc, char** argv)
{
  using namespace ndn::ibas_demo;

  Subscriber bob("/wonderland/Bob/safety-confirmation",
                 "/moderators/GovernmentOffice/safety-confirmation/wonderland/Alice");
  try {
    bob.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
