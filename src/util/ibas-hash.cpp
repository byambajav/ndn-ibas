#include "ibas-hash.hpp"

#include <pbc/pbc.h>

#include "crypto.hpp"

namespace ndn {
namespace util {

void logString(const std::string& str) {
  std::cout << "==========" << std::endl;
  std::cout << str << std::endl;
  std::cout << "==========" << std::endl;
}

void calculateH1(element_t hash, const std::string& str, pairing_t pairing) {
  // NOTE: Currently the pairing parameter is not used
  // Calculate SHA256
  const uint8_t *data = reinterpret_cast<const uint8_t*>(str.data());
  uint8_t digest[crypto::SHA256_DIGEST_SIZE];
  ndn_digestSha256(data, str.size(), digest);

  // Convert the hash to a G_1 field element
  element_from_hash(hash, digest, crypto::SHA256_DIGEST_SIZE);
}

void calculateH2(element_t hash, const std::string& str, pairing_t pairing) {
  calculateH1(hash, str + "dummy", pairing);
}

void calculateH3(element_t hash, const std::string& str, pairing_t pairing) {
  logString(str);

  // Calculate SHA256
  const uint8_t *data = reinterpret_cast<const uint8_t*>(str.data());
  uint8_t digest[crypto::SHA256_DIGEST_SIZE];
  ndn_digestSha256(data, str.size(), digest);

  // Convert the hash to a Z_r field element
  element_from_hash(hash, digest, crypto::SHA256_DIGEST_SIZE);
}

void generateSecretKeyForIdentity(const std::string& identity, pairing_t pairing) {
  std::cout << "Generating secret keys for: " << identity << std::endl;
  element_t s;
  element_init_Zr(s, pairing);

  std::ifstream infile("/home/denjo/.ndn/ibas/params.secret");
  std::string param, value;
  while (infile >> param >> value) {
    if (param == "s") {
      if (!element_set_str(s, value.c_str(), 10)) {
        pbc_die("Could not read s correctly");
      }
      element_printf("s: %B\n", s);
    }
  }

  element_t P_0;
  element_t P_1;
  element_init_G1(P_0, pairing);
  element_init_G1(P_1, pairing);
  calculateH1(P_0, identity + "0", pairing);
  calculateH1(P_1, identity + "1", pairing);

  element_t s_P_0;
  element_t s_P_1;
  element_init_G1(s_P_0, pairing);
  element_init_G1(s_P_1, pairing);
  element_mul_zn(s_P_0, P_0, s);
  element_mul_zn(s_P_1, P_1, s);

  element_printf("s_P_0: %B\n", s_P_0);
  element_printf("s_P_1: %B\n", s_P_1);

  element_clear(s);
  element_clear(P_0);
  element_clear(P_1);
  element_clear(s_P_0);
  element_clear(s_P_1);
}

} // namespace util
} // namespace ndn
