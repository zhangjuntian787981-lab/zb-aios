# Formalize the P1 retrospective Reference Review decisions

- Status: Accepted
- Date: 2026-08-14
- Scope: C04, C06 and C07 P1 synthetic-only retrospective backfill

## Decision

The fixed retrospective source baseline is commit
`bc718bc1a069deaa388b9a00e0135c8e9427dd91`. The Reference Candidate
Catalog remains v1. The Profile-bound successor Policy remains on the existing
v1 Policy schema and binds the final Profile v2 raw digest and its execution
baseline without placing a Reference Review digest into either upstream
artifact. Those exact upstream bindings are
`sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5`
for the final Profile v2 raw bytes and
`sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec`
for the execution baseline.

The formal preproduction decisions are:

| Work package | Reference | Exact version | Decision |
| --- | --- | --- | --- |
| C04 | R09.KEYCLOAK | 26.7.0 | ADOPT |
| C06 | R11.OPENFGA | v1.18.1 | ADOPT |
| C07 | R12.PGVECTOR | 0.8.5 | ADOPT |
| C07 | R12.POSTGRESQL_RLS | 17.10 | ADOPT |

Each decision is limited to the already implemented P1 synthetic boundary and
uses the exact artifact digest, direct historical v1 implementation Evidence,
and source-file anchor recorded by the closed retrospective inputs. The
PostgreSQL 17.10 adopted digest is the official upstream source archive digest;
the Homebrew formula, bottle, and executable measurements are not substituted
for it.

C04, C06, and C07 each have one applicability report. C07 has one Bundle that
contains both R12 Receipts. O02 and O03 remain prospective and unproved.

## Hash order and cycle boundary

Low-level dependency locks, matrix slices, source indexes, and scan inputs are
raw-byte bound. Applicability reports remove `reportSha256` before project
canonical hashing. The successor Policy is hashed as its complete project
canonical JSON and does not embed its own digest. Receipts remove
`receiptSha256`, and Bundles remove `bundleSha256`, before project
canonical hashing. Bundle Receipt entries bind Receipt self-hashes; Bundle
implementation bindings bind raw conformance bytes.

This decision does not place the later evidence-freeze commit or tree into any
R1 artifact. No Freeze Attestation is issued in R1.

## Governance boundary

All artifacts have `governanceEffect=NONE` where the schema permits that
field. This decision does not approve the P2 Profile and does not append D1.
It does not decide a Gate, change a work package or Manifest, authorize
O02/O03, advance P3, admit real enterprise data or credentials, or authorize
production. Historical preparation and prospective O02/O03 records remain
unchanged.
