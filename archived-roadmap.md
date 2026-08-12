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
