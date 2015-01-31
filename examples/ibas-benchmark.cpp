#include <chrono>

#include "security/key-chain.hpp"
#include "security/validator.hpp"

#include "publisher.hpp"
#include "moderator.hpp"
#include "subscriber.hpp"

int main(int argc, char *argv[])
{
  using namespace ndn;
  using namespace ndn::ibas_demo;
  using namespace std;
  using namespace std::chrono;

  int n;
  size_t loadSize;

  if (argc != 3) {
    cout << "Usage: " << argv[0] << " n loadSize" << endl;
    return 1;
  } else {
    n = atoi(argv[1]);
    loadSize = atoi(argv[2]);
  }

  vector<Data> vData(n);

  Publisher alice("/wonderland/Alice/safety-confirmation");
  Moderator governmentOffice("/rendezvous/GovernmentOffice/safety-confirmation");
  Subscriber bob("/wonderland/Bob/safety-confirmation");

  high_resolution_clock::time_point t0 = high_resolution_clock::now();
  for (int i = 0; i < n; i++) {
    vData.at(i) = alice.publishMessage(loadSize);
  }

  high_resolution_clock::time_point t1 = high_resolution_clock::now();
  for (int i = 0; i < n; i++) {
    governmentOffice.moderateMessage(vData.at(i));
  }

  high_resolution_clock::time_point t2 = high_resolution_clock::now();
  bool verificationFailed = false;
  for (int i = 0; i < n; i++) {
    if (!bob.verifyMessage(vData.at(i))) {
      verificationFailed = true;
    }
  }
  high_resolution_clock::time_point t3 = high_resolution_clock::now();

  if (!verificationFailed) {
    cout << "Verification successfull" << endl;
  } else {
    cout << "Verification failed" << endl;
  }

  duration<double> publishDuration = duration_cast<duration<double>>(t1 - t0);
  duration<double> aggregationDuration = duration_cast<duration<double>>(t2 - t1);
  duration<double> verificationDuration = duration_cast<duration<double>>(t3 - t2);

  cout << "n: " << n << endl;
  cout << "loadSize: " << loadSize << " bytes" << endl;
  cout << "Publish took " << publishDuration.count() << " seconds" << endl;
  cout << "Aggrgegation took " << aggregationDuration.count() << " seconds" << endl;
  cout << "Verification took " << verificationDuration.count() << " seconds" << endl;

  return 0;
}
