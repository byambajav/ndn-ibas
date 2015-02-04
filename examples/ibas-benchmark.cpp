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

  tlv::SignatureTypeValue signatureType;
  int n;
  size_t loadSize;
  bool log;

  if (argc != 5) {
    cout << "Usage: " << argv[0] << " signatureType(1,3,4) n loadSize log" << endl;
    return 1;
  } else {
    signatureType = (tlv::SignatureTypeValue) atoi(argv[1]);
    n = atoi(argv[2]);
    loadSize = atoi(argv[3]);
    log = atoi(argv[4]) == 1;
  }

  vector<shared_ptr<Data> > vData(n);

  Publisher alice("/wonderland/Alice/safety-confirmation", signatureType, loadSize);
  Moderator governmentOffice("/moderators/GovernmentOffice/safety-confirmation");
  Subscriber bob("/wonderland/Bob/safety-confirmation",
                 "/moderators/GovernmentOffice/safety-confirmation/wonderland/Alice");

  steady_clock::time_point t0 = steady_clock::now();
  for (int i = 0; i < n; i++) {
    vData.at(i) = alice.createMessage();
  }

  steady_clock::time_point t1 = steady_clock::now();
  for (int i = 0; i < n; i++) {
    governmentOffice.moderateMessage(*vData.at(i));
  }

  steady_clock::time_point t2 = steady_clock::now();
  bool verificationFailed = false;
  for (int i = 0; i < n; i++) {
    if (!bob.verifyMessage(*vData.at(i))) {
      verificationFailed = true;
    }
    if (log) {
      logData(*vData.at(i));
    }
  }
  steady_clock::time_point t3 = steady_clock::now();

  duration<double> publishDuration = duration_cast<duration<double>>(t1 - t0);
  duration<double> aggregationDuration = duration_cast<duration<double>>(t2 - t1);
  duration<double> verificationDuration = duration_cast<duration<double>>(t3 - t2);

  cout << signatureType  << ",";
  cout << boolalpha << !verificationFailed << noboolalpha << ",";
  cout << n << ",";
  cout << loadSize << ",";
  cout << publishDuration.count() << ",";
  cout << aggregationDuration.count() << ",";
  cout << verificationDuration.count() << endl;

  return 0;
}
