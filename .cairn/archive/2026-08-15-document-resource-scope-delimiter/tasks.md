# Tasks: Document the Resource Scope Delimiter Semantics

## Documentation

- [x] [serial] Document the byte-prefix containment rule and the shared-prefix overmatch in the authorization reference. r[ucan.scope.prefix]
- [x] [serial] Add the delimited resource-construction guidance and the delimiter-free warning. r[ucan.scope.delimiter]

## Pinned fixtures

- [x] [parallel] Add fixtures that record prefix admission for a scoped capability over a nested and a sibling resource. r[ucan.scope.fixtures]
- [x] [parallel] Add a negative fixture for a resource that does not share the scope prefix. r[ucan.scope.fixtures]
- [x] [parallel] Mark the fixtures as pins for the documented semantics. r[ucan.scope.fixtures]

## Closeout

- [x] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.scope.fixtures]
- [x] [serial] Record the fixture evidence and documentation revision. r[ucan.scope.prefix]
