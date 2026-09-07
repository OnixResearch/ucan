# Selectable durable authority adapters

Basalt and Animus need UCAN verification without concrete durable-state adapter
dependencies. Those dependencies require a newer compiler than the consumer.

Make the durable-authority module and its two dependency edges feature-selectable.
Enable the feature by default to preserve existing callers. Explicit opt-out keeps
signature, holder, replay and revocation verification with caller-supplied services.
No cryptographic downgrade, dependency revision change or verification bypass.
