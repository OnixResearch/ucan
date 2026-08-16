let Contracts = import "../../contracts.ncl" in
((import "../../profiles/base.ncl") & {
  id | force = "ucan.negative-unsupported-protocol-profile",
  protocol_profile = "ucan-wg-1.0.0",
}) | Contracts.IntegrationProfile
