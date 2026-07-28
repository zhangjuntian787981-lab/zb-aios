# Let the Worker verify a build-time Git Attestation

The trusted local build reads the fixed source commit through `/usr/bin/git`, proves that the object is a commit with the expected tree, and hashes the Recipe and every required subject directly from the Git object database. It also recomputes the execution baseline digest and verifies that the Profile `recordedAt` does not follow the source-commit time. Working-tree files and ambient `PATH` are outside this evidence boundary.

The resulting closed Attestation records those build-time checks. Its source commit predates the Attestation, pin policy and this ADR, so those later artifacts do not enter the execution baseline and cannot create a self-reference cycle. The Attestation contains no self-hash. The Worker instead receives a server-frozen Attestation and independently frozen pin policy, canonicalizes the Attestation with `PROJECT_CANONICAL_JSON_V1_NOT_RFC8785`, recomputes its SHA-256 through Web Crypto, and compares all fixed fields before accepting the supplied execution-baseline binding.

Git freeze and code review are the trust boundary for this design. The Attestation has no external signature and is not a DSSE, external supply-chain attestation, or claim to any SLSA level. The Worker does not claim that it ran Git; its permitted conclusion is only: “已验证构建时冻结的 Git Attestation。”

The Worker does not execute `/usr/bin/git`, call the GitHub API, retain a GitHub token, access the network, or trust request headers or environment variables. Runtime Git and remote API checks would add unavailable binaries, long-lived credentials, network failure modes and a time-of-check/time-of-use gap without improving the frozen evidence already reviewed at build time.

Profile supersession requires a new source commit, Recipe, execution-baseline digest, Attestation and pin. The prior Attestation remains immutable for historical verification and is never overwritten. Whether an Attestation is current remains a decision projected from the existing online D1 append-only governance ledger.

This Attestation is Git-frozen engineering evidence only. It does not approve a Profile, authorize O02 or O03, decide a Gate, change a work package, update the Manifest, or create a second governance state store.
