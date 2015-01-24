// #include <ctime>
#include <chrono>

#include "ibas-signer.hpp"

#include "../util/ibas-hash.hpp"
#include "../encoding/buffer-stream.hpp"

namespace ndn {

const static int DEFAULT_PARAMS_FILE_SIZE = 16384;
const static int PARAMS_STORE_BASE = 10; // The PBC library does not work properly if the base is not 10
const static int W_LENGTH = 20;

IbasSigner::IbasSigner(const std::string& publicParamsFilePath,
                       const std::string& privateParamsFilePath) {
  // Loads the public parameters: (G_1, G_2, e, P, Q)
  publicParamsInit(publicParamsFilePath.c_str());

  // Loads the private parameters: (id, s_P_0, s_P_1)
  privateParamsInit(privateParamsFilePath.c_str());
}

IbasSigner::~IbasSigner() {
  element_clear(P);
  element_clear(Q);
  element_clear(s_P_0);
  element_clear(s_P_1);
  pairing_clear(pairing);
}

Block IbasSigner::sign(const uint8_t* data, size_t dataLength) {
  // TODO: actual signing
  element_t P_w;
  element_t c, r;
  element_t S, T, temp1;
  element_init_G1(P_w, pairing);
  element_init_Zr(c, pairing);
  element_init_Zr(r, pairing);
  element_init_G1(S, pairing);
  element_init_G1(T, pairing);
  element_init_G1(temp1, pairing);

  const std::string w = generateW();

  // P_w = H_{2}(w)
  util::calculateH2(P_w, w, pairing);
  element_printf("P_w %B\n", P_w);

  // C_i = H_{3}(m_i, ID_i, w)
  util::calculateH3(c, std::string(data, data + dataLength) + identity + w, pairing);
  element_printf("c %B\n", c);

  element_random(r);
  element_printf("r %B\n", r);

  //computes T_i = r_{i}P
  element_mul_zn(T, P, r); // T_i = r_{i}P
  element_printf("T %B\n", T);

  // Compute S_i = r_{i}P_{w} + sP_{i,0} + c_{i}sP_{i,1}
  element_mul_zn(S, P_w, r); // r_{i}P_{w}
  element_mul_zn(temp1, s_P_1, c); // c_{i}sP_{i,1}
  element_add(S, S, s_P_0);
  element_add(S, S, temp1);
  element_printf("S %B\n", S);

  // Compress T_i and S_i into unsigned char arrays
  size_t T_size = element_length_in_bytes_compressed(T);
  size_t S_size = element_length_in_bytes_compressed(S);
  std::cout << "T_size: " << T_size << ", S_size: " << S_size << std::endl;
  // TODO: Find a workaround for VLA error
  unsigned char T_compressed[T_size];
  unsigned char S_compressed[S_size];
  element_to_bytes_compressed(T_compressed, T);
  element_to_bytes_compressed(S_compressed, S);
  T_compressed[T_size] = '\0';
  S_compressed[S_size] = '\0';

  // Concatenate signature parts
  // TODO: Check required
  OBufferStream os;
  os << w;
  os << T_compressed;
  os << S_compressed;

  element_clear(P_w);
  element_clear(c);
  element_clear(r);
  element_clear(S);
  element_clear(T);
  element_clear(temp1);

  return Block(tlv::SignatureValue, os.buf());
}

void IbasSigner::publicParamsInit(const char* publicParamsFilePath) {
  // Read pairing parameters
  char buffer[DEFAULT_PARAMS_FILE_SIZE];
  FILE *fp = fopen(publicParamsFilePath, "r");
  if (!fp) pbc_die("error opening %s", publicParamsFilePath);

  size_t count = fread(buffer, 1, DEFAULT_PARAMS_FILE_SIZE, fp);
  if (!count) pbc_die("input error");
  fclose(fp);

  if (pairing_init_set_buf(pairing, buffer, count)) pbc_die("pairing init failed");
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  // Read P and Q using ifstream, since that is the easier way in C++
  element_init_G1(P, pairing);
  element_init_G1(Q, pairing);

  std::ifstream infile(publicParamsFilePath);
  std::string param, value;
  while (infile >> param >> value) {
    if (param == "P") {
      if (!element_set_str(P, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read P correctly");
      }
    } else if (param == "Q") {
      if (!element_set_str(Q, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read Q correctly");
      }
    }
  }

  // //generate secret key, this code was used only once to generate the parameters
  // element_t s;
  // element_init_Zr(s, pairing);
  // element_random(s);
  // element_printf("%B\n", s);
  // element_random(P);
  // element_printf("%B\n", P);
  // element_mul_zn(Q, P, s); // Q = sP
  // element_printf("%B\n", Q);
}

void IbasSigner::privateParamsInit(const char* privateParamsFilePath) {
  element_init_G1(s_P_0, pairing);
  element_init_G1(s_P_1, pairing);

  std::ifstream infile(privateParamsFilePath);
  std::string param, value;
  while (infile >> param >> value) {
    if (param == "id") {
      identity = value;
      std::cout << identity << std::endl;
    } else if (param == "s_P_0") {
      if (!element_set_str(s_P_0, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read s_P_0 correctly");
      }
      element_printf("s_P_0: %B\n", s_P_0);
    } else if (param == "s_P_1") {
      if (!element_set_str(s_P_1, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read s_P_1 correctly");
      }
      element_printf("s_P_1: %B\n", s_P_1);
    }
  }

  // //generate private keys
  // util::generateSecretKeyForIdentit/y("Alice", pairing);
  // util::generateSecretKeyForIdentity("GovernmentOffice", pairing);
  // util::generateSecretKeyForIdentity("Bob", pairing);
}

const std::string IbasSigner::generateW() {
  using namespace std::chrono;
  milliseconds ms = duration_cast<milliseconds>(high_resolution_clock::now().time_since_epoch());
  std::string res = std::to_string(ms.count());
  for (int i = res.size(); i < W_LENGTH; i++) {
    // TODO: it should be random
    res += "0";
  }
  return res;
}

} // namespace ndn
