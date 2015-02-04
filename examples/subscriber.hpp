#ifndef NDN_IBAS_DEMO_SUBSCRIBER_HPP
#define NDN_IBAS_DEMO_SUBSCRIBER_HPP

#include <chrono>

#include "face.hpp"
#include "security/key-chain.hpp"
#include "security/validator.hpp"
#include "ibas-demo-helper.hpp"

namespace ndn {
namespace ibas_demo {

/**
 * @brief A subscriber class
 */
class Subscriber : noncopyable
{
 public:
  /**
   * @brief Constructor
   *
   * @param name It must be of "/organization/identity/application" format
   */
  Subscriber(const std::string& name, const std::string& interestName) {
    m_name = Name(name);
    m_interestName = Name(interestName);
  }

  void run() {
    Interest interest(m_interestName);
    interest.setInterestLifetime(time::milliseconds(1000));
    interest.setMustBeFresh(true);

    m_face.expressInterest(interest,
                           bind(&Subscriber::onData, this,  _1, _2),
                           bind(&Subscriber::onTimeout, this, _1));

    std::cout << "Sending" << std::endl << interest << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();
  }

  /**
   * @brief Runs a benchmark
   *
   * @param n Number of times to express interest
   */
  void runBenchmark(int n) {
    m_benchmarkCurrent = 0;
    m_benchmarkFinish = n;
    m_benchmarkFailed = 0;
    m_benchmarkSuccessed = 0;
    m_benchmarkStartTime = std::chrono::steady_clock::now();

    Interest interest(m_interestName);
    interest.setInterestLifetime(time::milliseconds(1000));
    interest.setMustBeFresh(true);

    m_face.expressInterest(interest,
                           bind(&Subscriber::onDataBenchmark, this,  _1, _2),
                           bind(&Subscriber::onTimeout, this, _1));

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();
  }


  bool verifyMessage(const Data& data) {
    uint32_t signatureType = data.getSignature().getType();
    if (signatureType == tlv::SignatureSha256Ibas) {
      return Validator::verifySignatureIbas(data);
    } else if (signatureType == tlv::SignatureSha256WithRsa) {
      // Locate moderator's key, then verify
      Name keyName = m_keyChain.getDefaultKeyNameForIdentity(data.getName().getPrefix(3));
      shared_ptr<PublicKey> publicKey = m_keyChain.getPublicKey(keyName);
      if (!Validator::verifySignature(data, *publicKey)) {
        std::cout << "Could not verify the modereator's signature" << std::endl;
        return false;
      }

      // Load subscriber's signature from content part using TLV parsing
      using std::string;
      const string contentStr = string(data.getContent().value_begin(),
                                    data.getContent().value_end());
      const static string signaturePlaceholder = "\nSignature:";
      size_t signaturePlaceholderPos = contentStr.find(signaturePlaceholder);
      Block sigInfo(reinterpret_cast<const uint8_t*>(data.getContent().value() +
                                                     signaturePlaceholderPos +
                                                     signaturePlaceholder.size()), 10000);
      Block sigValue(reinterpret_cast<const uint8_t*>(data.getContent().value() +
                                                      signaturePlaceholderPos +
                                                      signaturePlaceholder.size() +
                                                      sigInfo.size()), 10000);
      Signature subscriberSignature = Signature(sigInfo, sigValue);

      // Rebuild previous (pre-moderation) data
      // NOTE: Similar to verify signature method in IbasSigner
      const static string from = "From: ";
      size_t fromPos = contentStr.find(from);
      const Name name = data.getName();
      Name previousName = name.getSubName(3, 2).append(name.get(2)).append(name.get(5));
      Data previousData(previousName);
      previousData.setContent(reinterpret_cast<const uint8_t*>(contentStr.c_str() + fromPos),
                              signaturePlaceholderPos - fromPos);
      previousData.setSignature(subscriberSignature);
      previousData.setFreshnessPeriod(data.getFreshnessPeriod());

      // verify subscriber's signature
      keyName = m_keyChain.getDefaultKeyNameForIdentity(previousName.getPrefix(3));
      publicKey = m_keyChain.getPublicKey(keyName);
      return Validator::verifySignature(previousData, *publicKey);
    }

    return false;
  }

 private:
  void onData(const Interest& interest, const Data& data) {
    std::cout << "Received" << std::endl << data << std::endl;
    std::cout << std::boolalpha << verifyMessage(data) << std::endl;
  }

  void onDataBenchmark(const Interest& interest, const Data& data) {
    if (verifyMessage(data)) {
      m_benchmarkSuccessed++;
    } else {
      m_benchmarkFailed++;
    }

    if (++m_benchmarkCurrent < m_benchmarkFinish) {
      // Send Interest again
      Interest interest(m_interestName);
      interest.setInterestLifetime(time::milliseconds(1000));
      interest.setMustBeFresh(true);

      m_face.expressInterest(interest,
                           bind(&Subscriber::onDataBenchmark, this,  _1, _2),
                           bind(&Subscriber::onTimeout, this, _1));
    } else {
      // Benchmark is finished, output the result
      using namespace std;
      using namespace std::chrono;

      m_benchmarkFinishTime = steady_clock::now();
      duration<double> benchmarkDuration = duration_cast<duration<double>>(
          m_benchmarkFinishTime - m_benchmarkStartTime);

      cout << m_benchmarkFinish << ",";
      cout << m_benchmarkFailed << ",";
      cout << m_benchmarkSuccessed << ",";
      cout << benchmarkDuration.count() << endl;
    }
  }

  void onTimeout(const Interest& interest) {
    std::cout << "Timeout " << interest << std::endl;
  }

 private:
  Name m_name;
  Name m_interestName;
  KeyChain m_keyChain;
  Face m_face;

  // Benchmark related members
  int m_benchmarkCurrent;
  int m_benchmarkFinish;
  int m_benchmarkFailed;
  int m_benchmarkSuccessed;
  std::chrono::steady_clock::time_point m_benchmarkStartTime;
  std::chrono::steady_clock::time_point m_benchmarkFinishTime;
};

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_SUBSCRIBER_HPP
