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

### WCL-9: key-epochs integration test drift (`UnknownEpochError` vs `KeyUnwrapError`)

- status: done
- done: 2026-08-12
- priority: medium
- labels: encryption, key-epochs, integration-test
- touches:
  - freewallet -- resolved: the decrypt-failure classification gained a third
    bucket -- a row failing with `KeyUnwrapError` is skipped, warned about
    honestly ("not a recipient of its key epoch"), and left uncached, but never
    joins the purgeable `undecryptableRowIds` bucket that feeds
    `purgeUndecryptableCredentials` (which deletes locally and, in remote-direct
    mode, server-side); `decryptEnvelope` never spends the one-shot descriptor
    refresh on it (a refresh cannot help). Unit coverage proves the row survives
    a purge in both backends. Dead code against the published was-client until
    the release carrying this item's split
  - was-react -- resolved (doc-only, behavior verified unaffected):
    `sharedCollectionReader`'s catch JSDoc and ARCHITECTURE.md now describe a
    mid-session revoke surfacing directly as `KeyUnwrapError` with no refresh
    spent; the refresh guards test for `UnknownEpochError` specifically and
    rethrow everything else, so no code change
  - wallet-core -- resolved (doc-only, behavior verified unaffected): the
    self-refreshing cipher's module JSDoc describes the split; its guard and the
    create-loss re-mint keep working (a lost epoch[0] is absent from the adopted
    descriptor by construction, so it still raises `UnknownEpochError`).
    Re-exporting `KeyUnwrapError` through wallet-core's `/sync` surface awaits
    the next published was-client, whose `/sync` subpath now carries it
- acceptance:
  - [x] The `test/integration/key-epochs.test.ts` suite is green against a live
        was-teaching-server >= 0.21.0, with expectations that assert the
        intended contract (not just whatever currently throws)
  - [x] The `KeyUnwrapError` / `UnknownEpochError` JSDoc contract matches the
        settled behavior

discovered-from: WCL-8 (found during its live verification run, 2026-08-12). The
"removes a reader: pull dies, new ciphertext is unreadable" test expects
`KeyUnwrapError` when the removed readerB decodes a post-rotation envelope, but
gets `UnknownEpochError` -- readerB holds no epoch-2 candidate key, so the
codec's fail-fast unroutable-envelope path (the stale-descriptor signal) fires
before any unwrap attempt. Reproduced from a clean HEAD worktree against
was-teaching-server 0.21.0, so it is not caused by the WCL-8 changes; but the
suite ran green live on 2026-07-31 (after the fail-fast landed), so the drift's
origin is unresolved. Note the test hands readerB the _rotated_ descriptor, for
which `UnknownEpochError` ("your descriptor may be stale") reads semantically
off -- readerB's descriptor is current, it is simply no longer a recipient; if
the investigation lands on distinguishing those cases, that is a codec
error-contract change and this item gains `touches:` entries for it.

The drift reproduced identically on the 2026-08-12 live verification runs for
WCL-1 Stage B and WCL-10 (same assertion, same errors), confirming it is
independent of those changes.

Resolution (2026-08-12). Git archaeology settled the "origin unresolved" note:
the assertion has been byte-identical since 2026-07-11, and the 2026-07-31 green
run was genuine -- the codec-level fail-fast only landed 2026-08-06 (shipped in
0.27.1) and threw `UnknownEpochError` for every unroutable envelope without
updating this test. (The "after the fail-fast landed" clause above conflated it
with the sync DocCipher routing signal from 2026-07-22, which this test never
exercises: it calls `codec.decode()` directly.) The investigation did land on
distinguishing the cases. Decrypt routing now raises `KeyUnwrapError` when the
envelope's epoch is on the descriptor but wraps to no key this reader holds
(readerB's case: its descriptor is current, it is simply not a recipient), and
reserves `UnknownEpochError` for an epoch the descriptor does not list
(genuinely stale; a re-read can help). `EdvCodec` gained the required `epochIds`
option to carry the descriptor's full epoch roster; the `/sync` subpath
re-exports `KeyUnwrapError` / `EncryptionError` so crypto-free consumers can
classify the membership signal; node coverage pins both halves of the split and
the integration suite ran green against a live was-teaching-server 0.21.0. A
downstream-consumer survey found no unbounded refresh loops anywhere (every
guard is one-shot and rethrows non-`UnknownEpoch` errors); the one real hazard
-- freewallet's purgeable bucket -- is fixed per its `touches:` entry.
