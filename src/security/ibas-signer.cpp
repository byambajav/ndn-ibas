#include "ibas-signer.hpp"

namespace ndn {

const int DEFAULT_PARAMS_FILE_SIZE = 16384;
const int PARAMS_STORE_BASE = 10; // The PBC library does not work properly if the base is not 10

IbasSigner::IbasSigner(const std::string& publicParamsFilePath,
                       const std::string& privateParamsFilePath) {
  // Loads the public parameters: (G_1, G_2, e, P, Q)
  publicParamsInit(publicParamsFilePath.c_str());

  // Loads the private parameters: (id, s_P_0, s_P_1)
  privateParamsInit(privateParamsFilePath.c_str());
}

IbasSigner::~IbasSigner() {
  pairing_clear(pairing);
}

Block IbasSigner::sign(const uint8_t* data, size_t dataLength) {
  // TODO: actual signing
  return Block(tlv::SignatureValue);
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
  while (infile >> param >> value)
  {
    if (param == "P") {
      // value.replace(value.find(","), 1, ", ");
      if (!element_set_str(P, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read P correctly");
      }
      element_printf("P: %B\n", P);
    } else if (param == "Q") {
      if (!element_set_str(Q, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read Q correctly");
      }
      element_printf("Q: %B\n", Q);
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
  // TODO
  element_init_G1(s_P_0, pairing);
  element_init_G1(s_P_1, pairing);
  std::cout << "Private params initialized" << std::endl;
}

} // namespace ndn
