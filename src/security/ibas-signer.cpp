#include <chrono>

#include "ibas-signer.hpp"

#include "../util/ibas-hash.hpp"
#include "../encoding/buffer-stream.hpp"

namespace ndn {

const static int DEFAULT_PARAMS_FILE_SIZE = 16384;
const static int PARAMS_STORE_BASE = 10; // The PBC library does not work properly otherwise
const static int W_LENGTH = 20;

/* Constructor and destructor */

IbasSigner::IbasSigner() {
  const static std::string publicParamsFilePath =
      std::string(getenv("HOME")) + std::string("/.ndn/ibas/params.conf");

  // Loads the public parameters: (G_1, G_2, e, P, Q)
  initializePublicParams(publicParamsFilePath);

  srand(std::time(NULL));
}

IbasSigner::~IbasSigner() {
  element_clear(P);
  element_clear(Q);

  if (m_canSign) {
    element_clear(s_P_0);
    element_clear(s_P_1);
  }

  pairing_clear(pairing);
}

/* Public methods */

// Loads the private parameters: (id, s_P_0, s_P_1)
void IbasSigner::setPrivateParams(const std::string& privateParamsFilePath) {
  // If it is first time, init the elements
  if (!m_canSign) {
    element_init_G1(s_P_0, pairing);
    element_init_G1(s_P_1, pairing);
    m_canSign = true;
  }

  std::ifstream infile(privateParamsFilePath);
  std::string param, value;
  while (infile >> param >> value) {
    if (param == "id") {
      identity = value;
      // std::cout << "Initialized private params with identity: " << identity << std::endl;
    } else if (param == "s_P_0") {
      if (!element_set_str(s_P_0, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read s_P_0 correctly");
      }
    } else if (param == "s_P_1") {
      if (!element_set_str(s_P_1, value.c_str(), PARAMS_STORE_BASE)) {
        pbc_die("Could not read s_P_1 correctly");
      }
    }
  }

  // //generate private keys, this code was used only once
  // util::generateSecretKeyForIdentit/y("Alice", pairing);
  // util::generateSecretKeyForIdentity("GovernmentOffice", pairing);
  // util::generateSecretKeyForIdentity("Bob", pairing);
}

bool IbasSigner::canSign() {
  return m_canSign;
}

Block IbasSigner::sign(const uint8_t* data, size_t dataLength) {
  element_t T, S;
  element_init_G1(T, pairing);
  element_init_G1(S, pairing);

  // Generate a new w
  const std::string w = generateW();

  // Compute T and S
  signInternal(T, S, data, dataLength, w);

  return signIntoBlock(T, S, w, true /* clear */);
}

Block IbasSigner::signAndAggregate(const uint8_t* data, size_t dataLength,
                                   const Signature& oldSignature) {
  // NOTE: This method just signs and aggregates without verifying the old signature

  // Load old signature parameters: w, T_old, S_old
  std::string w;
  element_t T_old, S_old;
  element_init_G1(T_old, pairing);
  element_init_G1(S_old, pairing);
  loadSignature(T_old, S_old, w, oldSignature);

  // Compute new signature parameters: T_new, S_new
  element_t T_new, S_new;
  element_init_G1(T_new, pairing);
  element_init_G1(S_new, pairing);
  signInternal(T_new, S_new, data, dataLength, w);

  // Aggregate the signatures
  element_add(T_new, T_new, T_old);
  element_add(S_new, S_new, S_old);

  element_clear(T_old);
  element_clear(S_old);

  return signIntoBlock(T_new, S_new, w, true /* clear */);
}

Block IbasSigner::sign(const Data& data) {
  // This way of signing ignores Name and Metainfo parts of the data
  return sign(data.getContent().value(), data.getContent().value_size());
}

Block IbasSigner::signAndAggregate(const Data& data, const Signature& oldSignature) {
  // This way of signing ignores Name and Metainfo parts of the data
  return signAndAggregate(data.getContent().value(), data.getContent().value_size(), oldSignature);
}

bool IbasSigner::verifySignatureSimple(element_t T, element_t S, element_t P_w,
                                       const std::string& w, const std::string& identity,
                                       const Data& data) {
  // Compute c_i = H_{3}(m_i, ID_i, w)
  element_t c_0;
  element_init_Zr(c_0, pairing);
  util::calculateH3(c_0, std::string(data.wireEncode().value(),
                                     data.wireEncode().value() + data.wireEncode().value_size() -
                                     data.getSignature().getValue().size())
                    + identity + w, pairing);

  // Calculate P_{i,j}s
  element_t P_0_0;
  element_t P_0_1;
  element_init_G1(P_0_0, pairing);
  element_init_G1(P_0_1, pairing);
  util::calculateH1(P_0_0, identity + "0", pairing);
  util::calculateH1(P_0_1, identity + "1", pairing);

  // Verify signature
  element_t gtTemp1;
  element_t gtTemp2;
  element_t g1Temp1;
  element_init_GT(gtTemp1, pairing);
  element_init_GT(gtTemp2, pairing);
  element_init_G1(g1Temp1, pairing);

  element_pairing(gtTemp1, T, P_w); // e(T_{n}, P_{w})
  element_mul_zn(g1Temp1, P_0_1, c_0); // c_{0}P_{0,1}
  element_add(g1Temp1, g1Temp1, P_0_0); // P_{0,0} + c_{0}P_{0,1}
  element_pairing(gtTemp2, Q, g1Temp1); // e(Q, P_{0,0} + c_{0}P_{0,1})
  element_mul(gtTemp1, gtTemp1, gtTemp2);

  element_pairing(gtTemp2, S, P); // e(S_{n}, P)

  bool verified;
  if (!element_cmp(gtTemp1, gtTemp2)) {
    verified = true;
  } else {
    verified = false;
  }

  element_clear(P_0_0);
  element_clear(P_0_1);
  element_clear(P_w);

  element_clear(c_0);

  element_clear(T);
  element_clear(S);

  element_clear(gtTemp1);
  element_clear(gtTemp2);
  element_clear(g1Temp1);

  return verified;
}

bool IbasSigner::verifySignature(const Data& data) {
  using std::string;

  // Load the aggregated signature
  const Signature signature = data.getSignature();
  string w;
  element_t T_n, S_n;
  element_init_G1(T_n, pairing);
  element_init_G1(S_n, pairing);
  if (!loadSignature(T_n, S_n, w, signature)) {
    // Could not load signature variables successfully
    element_clear(T_n);
    element_clear(S_n);
    return false;
  }

  // Compute P_w = H_{2}(w)
  element_t P_w;
  element_init_G1(P_w, pairing);
  util::calculateH2(P_w, w, pairing);

  // Get message parts and corresponding IDs
  const Block content = data.getContent();
  const string contentStr = string(content.value_begin(), content.value_end());

  const static string from = "From: ";
  size_t fromPos = contentStr.find(from);
  size_t identityEndPos = contentStr.find('\n', fromPos + from.size());
  string fromIdentity(contentStr,  fromPos + from.size(), identityEndPos - fromPos - from.size());

  if (fromPos == 0) {
    // This is a non-moderatod data
    // NOTE: element_t variables will be cleared inside following method
    return verifySignatureSimple(T_n, S_n, P_w, w, fromIdentity, data);
  }

  const static string moderator = "Moderator: ";
  size_t moderatorPos = contentStr.find(moderator);
  // assert(moderatorPos == 0);
  identityEndPos = contentStr.find('\n', moderatorPos + moderator.size());
  string moderatorIdentity(contentStr,  moderatorPos + moderator.size(),
                           identityEndPos - moderatorPos - moderator.size());

  // Rebuild previous (pre-moderation) data
  const Name name = data.getName();
  Name previousName = name.getSubName(3, 2).append(name.get(2)).append(name.get(5));
  Data previousData(previousName);
  previousData.setContent(reinterpret_cast<const uint8_t*>(contentStr.c_str() + fromPos),
                          contentStr.size() - fromPos);
  previousData.setSignature(data.getSignature()); // Just to make SignatureInfo same
  EncodingBuffer encoder;
  previousData.wireEncode(encoder, true);

  // Compute c_i = H_{3}(m_i, ID_i, w)
  element_t c_0, c_1;
  element_init_Zr(c_0, pairing);
  element_init_Zr(c_1, pairing);
  util::calculateH3(c_0, std::string(encoder.buf(), encoder.buf() + encoder.size())
                    + fromIdentity + w, pairing);
  util::calculateH3(c_1, string(data.wireEncode().value(),
                                data.wireEncode().value() + data.wireEncode().value_size() -
                                data.getSignature().getValue().size())
                    + moderatorIdentity + w, pairing);

  // Calculate P_{i,j}s
  element_t P_0_0;
  element_t P_0_1;
  element_t P_1_0;
  element_t P_1_1;
  element_init_G1(P_0_0, pairing);
  element_init_G1(P_0_1, pairing);
  element_init_G1(P_1_0, pairing);
  element_init_G1(P_1_1, pairing);
  util::calculateH1(P_0_0, fromIdentity + "0", pairing);
  util::calculateH1(P_0_1, fromIdentity + "1", pairing);
  util::calculateH1(P_1_0, moderatorIdentity + "0", pairing);
  util::calculateH1(P_1_1, moderatorIdentity + "1", pairing);

  // Verify signature
  element_t gtTemp1;
  element_t gtTemp2;
  element_t g1Temp1;
  element_t g1Temp2;
  element_init_GT(gtTemp1, pairing);
  element_init_GT(gtTemp2, pairing);
  element_init_G1(g1Temp1, pairing);
  element_init_G1(g1Temp2, pairing);

  element_pairing(gtTemp1, T_n, P_w); // e(T_{n}, P_{w})
  element_add(g1Temp1, P_0_0, P_1_0); // P_{0,0} + P_{1,0}
  element_mul_zn(g1Temp2, P_0_1, c_0); // c_{0}P_{0,1}
  element_add(g1Temp1, g1Temp1, g1Temp2); // P_{0,0} + P_{1,0} + c_{0}P_{0,1}
  element_mul_zn(g1Temp2, P_1_1, c_1); // c_{1}P_{1,1}s
  element_add(g1Temp1, g1Temp1, g1Temp2); // P_{0,0} + P_{1,0} + c_{0}P_{0,1} + c_{1}P_{1,1}
  element_pairing(gtTemp2, Q, g1Temp1); // e(Q, P_{0,0} + P_{1,0} + c_{0}P_{0,1} + c_{1}P_{1,1})
  element_mul(gtTemp1, gtTemp1, gtTemp2);

  element_pairing(gtTemp2, S_n, P); // e(S_{n}, P)

  bool verified;
  if (!element_cmp(gtTemp1, gtTemp2)) {
    verified = true;
  } else {
    verified = false;
  }

  element_clear(P_0_0);
  element_clear(P_0_1);
  element_clear(P_1_0);
  element_clear(P_1_1);
  element_clear(P_w);

  element_clear(c_0);
  element_clear(c_1);

  element_clear(T_n);
  element_clear(S_n);

  element_clear(gtTemp1);
  element_clear(gtTemp2);
  element_clear(g1Temp1);
  element_clear(g1Temp2);

  return verified;
}

/* Private methods */

void IbasSigner::initializePublicParams(const std::string& publicParamsFilePath) {
  // The following cast is used frequently in this class
  static_assert(std::is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");

  // Read pairing parameters
  char buffer[DEFAULT_PARAMS_FILE_SIZE];
  FILE *fp = fopen(publicParamsFilePath.c_str(), "r");
  if (!fp) pbc_die("error opening %s", publicParamsFilePath.c_str());

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

const std::string IbasSigner::generateW() {
  using namespace std::chrono;
  milliseconds ms = duration_cast<milliseconds>(high_resolution_clock::now().time_since_epoch());
  std::string res = std::to_string(ms.count());
  int filledSize = res.size();
  res.resize(W_LENGTH);
  for (int i = filledSize; i < W_LENGTH; i++) {
    res.at(i) = rand();
  }
  return res;
}

void IbasSigner::signInternal(element_t T, element_t S, const uint8_t* data, size_t dataLength,
                              const std::string& w) {
  element_t P_w;
  element_t c, r;
  element_t temp1;

  element_init_G1(P_w, pairing);
  element_init_Zr(c, pairing);
  element_init_Zr(r, pairing);
  element_init_G1(temp1, pairing);

  // Compute P_w = H_{2}(w)
  util::calculateH2(P_w, w, pairing);

  // Compute C_i = H_{3}(m_i, ID_i, w)
  util::calculateH3(c, std::string(data, data + dataLength) + identity + w, pairing);

  element_random(r);

  // Compute T_i = r_{i}P
  element_mul_zn(T, P, r); // T_i = r_{i}P

  // Compute S_i = r_{i}P_{w} + sP_{i,0} + c_{i}sP_{i,1}
  element_mul_zn(S, P_w, r); // r_{i}P_{w}
  element_mul_zn(temp1, s_P_1, c); // c_{i}sP_{i,1}
  element_add(S, S, s_P_0);
  element_add(S, S, temp1);

  element_clear(P_w);
  element_clear(c);
  element_clear(r);
  element_clear(temp1);
}

Block IbasSigner::signIntoBlock(element_t T, element_t S, const std::string& w, bool clear) {
  // Compress T_i and S_i into unsigned char arrays
  size_t element_size = element_length_in_bytes_compressed(T); // T and S have same size
  unsigned char T_compressed[element_size];
  unsigned char S_compressed[element_size];
  element_to_bytes_compressed(T_compressed, T);
  element_to_bytes_compressed(S_compressed, S);

  // Concatenate signature parts
  BufferPtr buf = std::make_shared<Buffer>();
  buf->insert(buf->end(), w.begin(), w.end());
  buf->insert(buf->end(), T_compressed, T_compressed + element_size);
  buf->insert(buf->end(), S_compressed, S_compressed + element_size);

  if (clear) {
    element_clear(T);
    element_clear(S);
  }

  return Block(tlv::SignatureValue, buf);
}

bool IbasSigner::loadSignature(element_t T, element_t S, std::string& w,
                               const Signature& signature) {
  if (signature.getType() != tlv::SignatureSha256Ibas) {
    return false;
  }

  const uint8_t* sig = signature.getValue().value();
  w = std::string(sig, sig + W_LENGTH);
  size_t signatureSize = signature.getValue().value_size();
  size_t element_size = (signatureSize - W_LENGTH) / 2;
  element_from_bytes_compressed(T, (unsigned char*) (sig + W_LENGTH));
  element_from_bytes_compressed(S, (unsigned char*) (sig + W_LENGTH + element_size));
  return true;
}

} // namespace ndn
