# Revise the P2 Worker Attestation pin without rewriting its history

ADR 0005 remains byte-identical and continues to describe the original
`48a4e4` Attestation and pin. Its source commit predates that Attestation, its
pin policy and ADR 0005 itself.

The superseding Profile baseline uses source commit
`bc718bc1a069deaa388b9a00e0135c8e9427dd91`. That commit necessarily contains
the historical builder, original pin policy and ADR 0005, but it predates the
new `bc718b` Attestation, the new active pin revision and this ADR. Historical
lineage therefore remains inside the source tree without entering the new
execution-baseline digest as a new subject and without creating a self-reference
cycle.

The pin module retains the original pin as
`P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY` and adds
`P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY` for the `bc718b` pin. The
established `P2_WORKER_ATTESTATION_PIN_POLICY` export aliases only the new
active revision, so the Worker composition interface remains unchanged. The
generic verifier can replay either exact historical pair, but an Attestation
from one revision can never be combined with the other revision's pin or start
policy.

This decision supersedes only ADR 0005's timing rule for pin revisions after
the original `48a4e4` chain. It does not rewrite ADR 0005, make the old pin
current, place either Attestation in its own execution baseline, or allow
working-tree bytes, ambient `PATH`, runtime Git, request headers, environment
variables or network state into the verification boundary.

Both revisions remain Git-frozen engineering evidence. Selecting an active pin
does not approve a Profile, append D1, authorize O02 or O03, decide a Gate,
change a Project Work Package, update the Manifest or create another governance
state store. It does not satisfy or alter the Reference Review hard gate, advance
P3 or authorize production.
