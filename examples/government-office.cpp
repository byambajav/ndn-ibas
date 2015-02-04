#include "moderator.hpp"

int main(int argc, char** argv)
{
  using namespace ndn::ibas_demo;
  Moderator governmentOffice("/moderators/GovernmentOffice/safety-confirmation");

  try {
    governmentOffice.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
