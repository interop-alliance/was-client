# 0001: Cross-package error classification matches on `err.name`

- Status: accepted
- Date: 2026-09-05
- Driving work: the extraction design for the WAS replication driver for
  RxDB, approved 2026-09-05. Extracted at that design's approval, from the
  invariant it widened and the convention it asked to be signed off.
- Affects: `@interop/was-client` (`src/errors.ts`, `src/sync/index.ts`),
  `@interop/wallet-core` (`sync/types.ts`, `push.ts`, `remint.ts`,
  `descriptors`), `@interop/was-sync` (the RxDB driver's push and pull
  handlers and its controller core), freewallet, was-react, dcw.

## Context

was-client owns the errors the replication port throws:
`WasSyncConflictError` (412), `WasSyncNotFoundError` (404),
`WasSyncAuthError` (401, 403, and the masked 404), `UnknownEpochError`, and
`KeyUnwrapError`. Every consumer has to tell them apart. A 412 is a
conflict to reconcile, an unknown epoch is a descriptor to refresh, a
`KeyUnwrapError` is a row this reader was never a recipient of.

`instanceof` cannot carry that classification across a package boundary. A
consumer's tree can resolve two copies of was-client -- through a `link:`
reference, a caret range on a 0.x minor, or a peer a package declared as a
dependency -- and then the class the error was constructed from is not the
class the reader imported. The check returns false, quietly, and the caller
takes the wrong branch. The costs are not abstract. A missed
`KeyUnwrapError` puts another reader's real data in a purgeable bucket. A
missed 412 turns a conflict the push loop would settle into a fatal cycle
error.

The classification was also spread across two packages. wallet-core
defined three predicates over classes was-client owns, and freewallet
imported one predicate from wallet-core while importing the classes
themselves from was-client. The RxDB driver's merge base used raw
`instanceof` in three places, which was safe only while the driver and the
port sat inside one package with one resolved copy between them.

## Decision

was-client owns the sync error classes and the predicates that recognize
them. Every consumer package classifies through those predicates, which
match on `err.name` alone.

- `./sync` exports `isSyncConflictError`, `isSyncNotFoundError`,
  `isUnknownEpochError`, and `isSyncAuthError`. Each reads `name` off the
  value and compares it to one string. The three that lived in
  wallet-core's `sync/types.ts` move here beside the classes, with their
  suite; `isSyncAuthError` is new.
- No consumer uses `instanceof` on a was-client error class. That covers
  the base classes too, so a 412 is not recognized by catching
  `PreconditionFailedError` from another package.
- Any error class a package in this ecosystem owns assigns its `name`
  explicitly in the constructor, so it stays recognizable by name.
- Reading a property after the name match is fine. `isSyncAuthError(err)`
  followed by a check of `err.status` for the masked 404 is the intended
  shape.
- No consumer re-exports another package's predicates. wallet-core imports
  them and exports none.

A predicate that must walk a framework's error graph stays with that
framework's code. The driver's controller core keeps its RxDB-shaped
search for a wrapped auth error; at the leaf, it decides by name.

## Rejected Alternatives

- **Keep `instanceof` and guarantee one copy by discipline.** A lockfile
  audit does catch a duplicate copy, and the release train runs one. But
  the audit runs at install time and a missed check is silent at runtime,
  so the two failures are not comparable. The audit stays; it is a second
  guard rather than the contract.
- **Each consumer defines its own predicates.** That is where the three
  wallet-core predicates came from. Two owners of one classification drift,
  and a consumer that only holds one of them ends up importing the class
  from one package and the test for it from another.
- **A structural check on the error's shape (a status code plus a message
  pattern).** Statuses are not distinct enough: 404 is both the settled
  outcome of a delete and the masked refusal of an unauthorized read, and
  the port already needs the class to tell them apart. Messages are prose
  and change.
- **A code field on the wire instead of a class name.** Nothing here
  travels over the wire. The classification happens on thrown values inside
  one process, and the port is what turns an HTTP response into one of
  these classes in the first place.

## Consequences

- Each error's `name` string is part of was-client's public contract.
  Changing one is a breaking change for every consumer, whatever the
  TypeScript class is called.
- A consumer surviving a duplicate was-client copy is now a testable
  property: an error minted by one copy and classified by another still
  routes correctly. The extraction's suite asserts exactly that.
- The subtype relationships stay useful and stay local. A caller inside
  was-client, or one that knowingly resolves a single copy, may still catch
  `PreconditionFailedError` or `AuthRequiredError`. That is a convenience
  for one tree rather than the cross-package contract.
- Name matching survives boundaries that lose a prototype. An error passed
  through a structured clone keeps its own `name` property, so the same
  predicates work there.
- The rule binds how a consumer classifies rather than where every
  predicate has to live. `isKeyUnwrapError` stays in
  `@interop/wallet-core/descriptors`, even though `KeyUnwrapError` is
  defined in was-client's `errors.ts`, because it classifies a
  roster-membership failure the wallet layer's refresh policy owns and no
  replication driver dispatches on it. It matches by name like the rest.
- Predicates are boolean rather than type guards, so a caller wanting the
  typed shape narrows it itself. That is the price of not depending on the
  class identity, and it is accepted.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Two packages in the ecosystem need error classes that would carry the
   same `name`. Then the answer is a namespaced name value, decided here,
   rather than a return to `instanceof`.
2. Every consumer resolves was-client through an install-time single-copy
   guarantee the tooling enforces, and something arrives that names cannot
   express (a typed payload a caller must read off the class). Both halves
   have to hold; the first alone does not reopen it.
3. The sync errors stop being was-client's. If the classes move, the
   predicates move with them, and this record moves to the owning repo.
