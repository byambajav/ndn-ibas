#include "validator-ibas.hpp"

namespace ndn {


ValidatorIbas::ValidatorIbas() {
}

void
ValidatorIbas::checkPolicy (const Data& data,
                                  int stepCount,
                                  const OnDataValidated& onValidated,
                                  const OnDataValidationFailed& onValidationFailed,
                                  std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  onValidated(data.shared_from_this());
}

void
ValidatorIbas::checkPolicy (const Interest& interest,
                                  int stepCount,
                                  const OnInterestValidated& onValidated,
                                  const OnInterestValidationFailed& onValidationFailed,
                                  std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  onValidated(interest.shared_from_this());
}

} // namespace ndn
