# Non-consuming holder authorization recheck

## Why

A holder invocation spends its audience-scoped nonce once. An ongoing operation
must not repeat that admission to obtain current revocation and caveat facts.
Copying the original expiry or receipt also does not establish current authority.

## What Changes

Add a recheck API that requires the original live holder authorization and the
same compact token. Reuse the existing bounded token/proof verifier, profile
observer, and caveat authorization. Return a borrowed observation, not a new
holder authorization or dispatch permission. Expose no replay port in this API.

## Impact

UCAN owns this reusable contract. Basalt and Animus can adopt a published revision
later. The consumer still owns clocks, service authenticity, freshness, outage
policy, atomic effect authorization, custody, and resource release. No dependency
or token wire-format change is required.
