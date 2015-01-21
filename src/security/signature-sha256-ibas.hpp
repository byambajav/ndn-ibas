#ifndef NDN_SECURITY_SIGNATURE_SHA256_IBAS_HPP
#define NDN_SECURITY_SIGNATURE_SHA256_IBAS_HPP

#include "../signature.hpp"

namespace ndn {

/**
 * represents a Sha256Ibas signature.
 */
class SignatureSha256Ibas : public Signature
{
public:
  class Error : public Signature::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : Signature::Error(what)
    {
    }
  };

  explicit
  SignatureSha256Ibas();

  explicit
  SignatureSha256Ibas(const Signature& signature);
};

} // namespace ndn

#endif //NDN_SECURITY_SIGNATURE_SHA256_IBAS_HPP
