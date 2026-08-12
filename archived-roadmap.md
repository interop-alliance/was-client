# WAS Client Roadmap Archive (completed items)

Completed WCL-N items move here **verbatim** (heading, field block, prose, with
their `done` date) from [ROADMAP.md](ROADMAP.md) as they land, append-only,
newest at the bottom -- so WCL-N references keep resolving. CHANGELOG.md remains
the record of what landed. Items completed before this archive existed
(everything through client 0.34.0) live only in git history of the
pre-conversion narrative roadmap.

---

### WCL-3: Client-driven bulk rewrap

- status: retired as obsolete 2026-08-12 (was todo)
- priority: low
- labels: encryption, key-epochs
- acceptance:
  - [ ] A bulk operation rewrites only the JWE `recipients` of each Resource to
        move it to a new epoch, never re-uploading ciphertext

A useful post-`removeRecipient` migration. Caveat: rewrap does not help against
a reader that cached the CEKs themselves.

Retirement note: written for a model where each Resource's JWE carried
per-reader recipient wraps; the landed key-epoch model forecloses both readings
of the acceptance criterion. Envelopes are roster-blind (exactly one JWE
recipient, the epoch key -- per-reader access rides the descriptor's
`epochs[].recipients[]` roster), so the useful rewrap shipped as the descriptor
roster operations (`addRecipient` every-epoch escrow, `removeRecipient`
rotate-then-revoke, `replaceRecipient` one-write rotation). And re-homing an
existing envelope to a new epoch without re-encrypting is cryptographically
impossible by design: `was.epoch` is AEAD-bound in the JWE protected header to
detect epoch swap/rollback, and the WAS-EC profile declares pushed envelopes
immutable. The re-encrypt-history variant is explicitly out of profile (WAS-EC
rotation-limitations) and a stated non-goal in freewallet (content-derived ids
would change) and wallet-core. Superseded by the "No client-driven bulk rewrap
of stored envelopes" recorded decision in ROADMAP.md.

---

### WCL-8: `Collection.meta()` / `Collection.setMeta()`

- status: done 2026-08-12
- priority: medium
- labels: api, metadata, encryption
- touches:
  - wallet-attached-storage-spec -- the endpoints must be specified first;
    tracked as WASS-9 in that repo's ROADMAP (done, WASS-9 moved to archive)
  - was-teaching-server -- resolved: WAS-55 shipped in was-teaching-server
    0.21.0, with conformance coverage in `@interop/was-conformance-suite` 0.5.0
  - was-client ARCHITECTURE.md + README.md -- resolved: the new handle surface
    is documented in both
- acceptance:
  - [x] `Collection.meta()` / `Collection.setMeta()` mirroring the Resource
        pair: full-replacement `custom` writes, an independent `metaVersion`
        ETag, `PreconditionFailedError` on a stale `ifMatch`, and the
        read-then-CAS patch sugar where it mirrors naturally
  - [x] On an encrypted collection, `custom` rides the codec's
        `encodeMeta`/`decodeMeta` envelope, exactly as at Resource level
  - [x] Node tests (stubbed transport) + integration tests against
        was-teaching-server (run green against a live 0.21.0 server)

discovered-from: WCL-1 (decision recorded 2026-08-12). The persisted
blinded-index schema needs a discoverable, conditionally-writable, encrypted
collection-level home; the Resource `/meta` model already provides the shape,
and mirroring it at Collection level also gives encrypted collections a
client-encrypted name/tags surface (today `name` rides the Collection
Description in plaintext, which encrypted collections refuse to populate). WCL-1
consumes this surface for its index schema and stays blocked on it (with WASS-9
/ WAS-55) for everything past key distribution.

### WCL-10: `was.collection` binding for the Collection Metadata envelope

- status: done
- done: 2026-08-12
- priority: medium
- labels: encryption, codec, metadata, breaking
- touches:
  - encrypted-collections-spec -- resolved: the rule shipped 2026-08-12 as ECS-1
    (see its archived-roadmap.md): a Collection Metadata envelope MUST bind
    `was.collection` (the Collection's `id`, no Space scoping) and MUST NOT bind
    `was.resource`; resource-slot envelopes MUST NOT bind `was.collection`
  - was-client CHANGELOG.md -- resolved: the 0.35.0 entry names the breaking
    change to the construction -- the interim collection-meta envelopes (which
    bind `v` + `epoch` only) are refused by the new verification
- acceptance:
  - [x] `encodeMeta` on the Collection-level path binds `was.collection` to the
        Collection's id and omits `resource` (the Resource-level path is
        unchanged)
  - [x] The Collection meta slot's verification requires a string
        `was.collection` equal to the Collection the read addressed
        (`IntegrityError` on mismatch or absence -- absence is no longer the
        accepted shape, it is some other slot's envelope), alongside the
        existing `forbidResourceBinding` refusal
  - [x] Resource-slot verification (content and resource metadata) refuses a
        present `was.collection` before any id comparison
  - [x] Node + integration coverage for the three refusals (resource envelope in
        the Collection slot, collection envelope in a resource slot, Collection
        X's meta served as Collection Y's)

discovered-from: ECS-1 (decision recorded 2026-08-12). Today `encodeMeta` binds
`v` + `epoch` only for the Collection slot and the reader distinguishes it
purely negatively (`forbidResourceBinding`), which cannot exclude a
content-derived content envelope (same member set) served in the Collection
Metadata slot, and leaves cross-collection swaps to key separation,
misclassified as `KeyUnwrapError`. Codec-only change: the binding lives inside
the AEAD, so no server or wire-type impact. Must land before WCL-1 resumes
persisting real index-schema envelopes, so schema envelopes are minted with the
final binding; blast radius of the break is otherwise nil (the slot is days
old).
