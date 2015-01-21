#include "signature-sha256-ibas.hpp"

namespace ndn {

SignatureSha256Ibas::SignatureSha256Ibas()
  : Signature(SignatureInfo(tlv::SignatureSha256Ibas))
{
}

SignatureSha256Ibas::SignatureSha256Ibas(const Signature& signature)
  : Signature(signature)
{
  if (getType() != tlv::SignatureSha256Ibas)
    throw Error("Incorrect signature type");

  if (hasKeyLocator()) {
    throw Error("KeyLocator should not be here");
  }
}

} // namespace ndn
