## Goals

- Pin and document the byte-prefix resource containment semantics.
- Recommend delimited resource construction.
- Record the sibling-prefix behavior as fixtures.

## Package boundary

The change is documentation and test fixtures. No library behavior changes.

## Documentation

The authorization reference gains:

1. an explicit statement that containment is byte-prefix matching;
2. an example of the shared-prefix overmatch;
3. a recommended delimited resource grammar with a warning against
   delimiter-free concatenation.

## Fixtures

Add fixtures under the existing test surface:

- scope covers `resource/photos`;
- scope covers a longer string that shares the byte prefix;
- scope rejects a string that does not start with the scope bytes;
- these fixtures are marked as pins for the documented semantics.

## Verification plan

- Keep the audited-revision test baseline green.
- Add the fixtures and verify they pass.
- Confirm the documentation has no behavioral claims beyond the measured
  behavior.
