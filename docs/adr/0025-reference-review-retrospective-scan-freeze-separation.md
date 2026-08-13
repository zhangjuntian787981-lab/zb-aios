# Separate retrospective Reference Review source scans from their evidence freeze

- Status: Candidate
- Date: 2026-08-14
- Scope: C04, C06 and C07 P0/P1 retrospective Reference Review backfill

## Decision

ADR 0006 remains byte-identical and continues to define the historical v1
Reference Review contract. Its v1 dependency-lock and source-integration scan
inputs include `inventory.evidenceFreezeTree`; they remain valid only as
historical records and test fixtures. They cannot be used to construct a new
Git freeze when the input file itself is part of that tree, because doing so
would require a tree object to contain its own object ID.

The retrospective backfill therefore adds `reference-applicability-evidence.v2`
and v2 dependency-lock and source-integration inputs. These input files contain
only sorted, unique, closed-field path/hash inventories. The evidence freeze
commit and tree are proved separately by the outer Freeze Attestation and the
trusted build resolver. Neither v2 input may contain an evidence commit, tree,
or self-hash. v1 reports accept only v1 inputs; v2 reports require v2 dependency
and source scans while retaining v1 matrix and manual-supplement scans. Crossed
versions fail closed.

The marker-free source scan is narrower than ADR 0006's marker scan. It is
allowed only for `RETROSPECTIVE_BACKFILL` of the already frozen P0/P1 source
baseline. Each v2 index entry binds one Catalog name and official URI, one
source path and raw SHA-256, and one previously frozen implementation Evidence
artifact catalog. The trusted resolver reads that exact path both from the
declared source commit and from the later evidence freeze; the two byte strings
must be identical. The implementation Evidence identifies the same work
package, must already exist at the declared source commit, must remain
byte-identical at the evidence freeze, and contains exactly one matching
artifact path/hash. Its historical
`verified_source_commit` identifies the artifact catalog's own verification
lineage; it does not claim that the Evidence originally verified the later
Profile source commit.

For v2, each successor Policy must use exact source-file anchors as
`sourceRoots`: C04 has one Keycloak adapter, C06 has one OpenFGA adapter, and
C07 has the two PostgreSQL migrations. The trusted enumeration of those roots
must equal the index paths exactly. Broad roots such as `app`, `implementation`
or `lib` cannot be used to let an index select a convenient subset. The index
is therefore a closed retrospective association among Catalog identity,
historical Evidence, and exact unchanged source bytes; it is not an independent
semantic derivation from source code and does not invent a marker.

The retrospective source baseline is commit
`bc718bc1a069deaa388b9a00e0135c8e9427dd91`, tree
`2fa1d5a511215a78ce324b61c585a4d4bb9697e0`. Its only approved v2 source
anchors are:

| Work package / reference | Path | Mode | Bytes | Raw SHA-256 |
| --- | --- | --- | ---: | --- |
| C04 / R09.KEYCLOAK | `lib/keycloak-scim-provisioning-adapter.mjs` | `100644` | 14358 | `sha256:aa35e65310130d69337ef4de503803831cc73cd94ad5305b517c21e516fa3d15` |
| C06 / R11.OPENFGA | `lib/openfga-pdp.mjs` | `100644` | 14409 | `sha256:b9fed3071e397ad9e2a745300b42084b31493caee896652b4319c15db80ed37c` |
| C07 / R12.PGVECTOR | `implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql` | `100644` | 12355 | `sha256:06350029d5d99dd0b57681cd0c19ecfce87a4da7c61a74911ea2837c983e1f46` |
| C07 / R12.POSTGRESQL_RLS | `implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql` | `100644` | 5828 | `sha256:3ec52cc75571e863ffa01e6dddb256c174652375138cb1622baef798fbbfd41c` |

A successor Policy may enumerate only these exact file anchors for the three
retrospective work packages. Substitution of another artifact from the same
historical Evidence does not satisfy this decision.

Prospective Reference Review, including O02 and O03, continues to use v1 and
requires the canonical first-line `REFERENCE_INTEGRATION_MARKER_V1`. This ADR
does not authorize adding a marker to the historical source and then attributing
it to an earlier commit. The marker requirement remains mandatory, while the
v1 input's tree self-reference continues to fail closed for a newly constructed
freeze; this decision does not make prospective v1 freezes constructible.

## PostgreSQL 17.10 distribution lock

The C07 PostgreSQL lock records four separate typed observations: the official
upstream source archive, the local Homebrew formula snapshot, the exact
Homebrew bottle, and the installed executable. The future Receipt
`adoptedArtifactDigest` is the official upstream source archive SHA-256. The
bottle and installed executable hashes remain local build/runtime measurements
and are not interchangeable with that upstream digest. Capture is local-only
and fails with `POSTGRESQL_17_10_CAPTURE_INPUT_MISMATCH` if the fixed formula,
bottle, executable, version output, length, or digest differs. It performs no
network access and records no user or absolute cache path.

The historical preparation artifact keeps PostgreSQL `artifactDigest=null`.
The new lock is only an additive input for a later formally approved Receipt;
it does not rewrite the preparation artifact or create a Receipt, Bundle,
Policy successor, Freeze Attestation, or runtime activation.

## Governance boundary

This repair has `governanceEffect=NONE`. It does not approve a Profile, append
D1, decide a Gate, modify the Manifest or a work-package state, authorize or
start O02/O03, advance P3, or authorize production. A passing v2 scan is only a
closed engineering precondition for the separately approved R1/R2 evidence
chain.
