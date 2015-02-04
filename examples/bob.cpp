#include "subscriber.hpp"

int main(int argc, char** argv)
{
  using namespace ndn::ibas_demo;

  int n;

  if (argc != 2) {
    cout << "Usage: " << argv[0] << " n" << endl;
    return 1;
  } else {
    n = atoi(argv[1]);
  }

  Subscriber bob("/wonderland/Bob/safety-confirmation",
                 "/moderators/GovernmentOffice/safety-confirmation/wonderland/Alice");
  try {
    bob.runBenchmark(n);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
