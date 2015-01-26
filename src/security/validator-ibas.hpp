#ifndef NDN_SECURITY_VALIDATOR_IBAS_HPP
#define NDN_SECURITY_VALIDATOR_IBAS_HPP

#include "validator.hpp"

namespace ndn {

class ValidatorIbas : public Validator
{
public:
  ValidatorIbas();

  virtual
  ~ValidatorIbas()
  {
  }

protected:
  void
  checkPolicy(const Data& data,
              int stepCount,
              const ndn::OnDataValidated& onValidated,
              const ndn::OnDataValidationFailed& onValidationFailed,
              std::vector<shared_ptr<ndn::ValidationRequest> >& nextSteps);

  void
  checkPolicy(const Interest& interest,
              int stepCount,
              const ndn::OnInterestValidated& onValidated,
              const ndn::OnInterestValidationFailed& onValidationFailed,
              std::vector<shared_ptr<ndn::ValidationRequest> >& nextSteps);

};

} // namespace ndn

#endif //NDN_SECURITY_VALIDATOR_IBAS_HPP
