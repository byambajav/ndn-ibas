#ifndef NDN_IBAS_DEMO_HELPER_HPP
#define NDN_IBAS_DEMO_HELPER_HPP

#include <ctime>

#include "data.hpp"

namespace ndn {
namespace ibas_demo {

using std::string;
using std::cout;
using std::endl;

const static string c_paramsFilePathPrefix = string(getenv("HOME")) + string("/.ndn/ibas/");

/**
 * @brief Logs data packet information
 */
void logData(const Data& data) {
  cout <<  "Name: " << data.getName().toUri() << endl;
  cout <<  "Content: " << string(data.getContent().value_begin(),
                                 data.getContent().value_end()) << endl;
  cout << "Signature value size: " << data.getSignature().getValue().value_size() << endl;
  cout << endl;
}

/**
 * @brief Gets private params file path
 *
 * @param identity The identity to get private params
 */
const string getPrivateParamsFilePath(const string& identity) {
  return c_paramsFilePathPrefix + identity + ".id";
}

inline std::string generateRandomString(size_t len) {
  std::string s(len, 0);
  static const char alphanum[] =
      "0123456789     _,.;:"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  for (size_t i = 0; i < len; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  return s;
}

inline std::string getCurrentTime() {
  std::time_t result = std::time(NULL);
  return std::ctime(&result);
}

} // namespace ibas_demo
} // namespace ndn

#endif  // NDN_IBAS_DEMO_HELPER_HPP
