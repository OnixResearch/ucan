## Why

UCAN proves capability facts over supplied caveats, proof chains, revocation, replay, and time inputs. It does not yet provide a reusable, versioned, authenticated peer-message framing contract that binds a message body to a key, a clock bound, and a replay disposition.

Celld, the self-hosted Cloudflare Durable Objects daemon, authenticates node-to-node traffic with a peer HTTP protocol that is versioned, body-bound, HMAC-authenticated, clock-bounded, and replay-protected. That constraint set is a clean, transferable reference for the boundary between a transport and a verified message.

UCAN should own the deterministic authenticated-message framing and validation core. Transport, key custody, clock, and durable replay storage must remain consumer-owned.

## What Changes

- Add a typed, versioned authenticated-message framing contract to `ucan-core`.
- Verify HMAC, body-bound signature, protocol version, clock bound, and replay disposition over already-built message bytes.
- Keep validation deterministic and free of ambient effects.
- Produce an opaque authenticated-message verdict with bounded public fields.
- Add official-vector, positive, negative, timeout, replay, and version-drift coverage.
- Reference the reviewed Celld peer-protocol design as a bounded, non-parity input.

## Impact

The change gives consumers a typed proof that a message is body-bound, authenticated, fresh, and not replayed. It does not define a transport, terminate TLS, or prove key custody.

Authenticated-message identities and receipts remain BLAKE3.

## Dependencies

This change has no downstream prerequisite. Basalt consumes its reviewed output contract after this change stabilizes.

## Non-goals

- Do not add a transport, TLS, or an in-process network stack.
- Do not implement a clock or a durable replay store.
- Do not define a membership protocol or a control plane.
- Do not claim parity with, or equivalence to, the Celld peer protocol.
- Do not convert an authenticated message into a UCAN capability or authorization.
