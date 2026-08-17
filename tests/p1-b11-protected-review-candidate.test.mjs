import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertIndependentModelRequiredCheckContract } from "./independent-model-required-check.cases.mjs";

const codeowners = await readFile(
  new URL("../.github/CODEOWNERS", import.meta.url),
  "utf8",
);
const candidateV1Bytes = await readFile(
  new URL(
    "../implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
    import.meta.url,
  ),
);
const candidateV1GitBytes = execFileSync(
  "git",
  [
    "show",
    "HEAD:implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
  ],
  { encoding: "buffer" },
);
const candidate = JSON.parse(candidateV1Bytes);
const candidateV2Bytes = await readFile(
  new URL(
    "../implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v2.json",
    import.meta.url,
  ),
);
const candidateV2 = JSON.parse(candidateV2Bytes);
const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

assert.equal(candidateV1Bytes.byteLength, 3047);
assert.equal(
  sha256(candidateV1Bytes),
  "27ced7c34098bbd2f603aef3a4a11b84e1033f96b4d9fdc2cd1d3c608fefc27a",
);
assert.deepEqual(candidateV1Bytes, candidateV1GitBytes);
assert.match(
  execFileSync(
    "git",
    [
      "ls-tree",
      "HEAD",
      "--",
      "implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
    ],
    { encoding: "utf8" },
  ),
  /^100644 blob [a-f0-9]{40}\timplementation\/p1\/c13\/github\/c13-protected-review-ruleset\.candidate\.v1\.json\n$/u,
);
const adr = await readFile(
  new URL(
    "../docs/adr/0008-c13-protected-source-review.md",
    import.meta.url,
  ),
  "utf8",
);
const research = await readFile(
  new URL(
    "../implementation/p1/c13/p1-b11-official-reference-research.v1.md",
    import.meta.url,
  ),
  "utf8",
);

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

const requiredCheckContexts = [
  "protected-surface-gate",
  "contract-compatibility-gate",
  "c13-source-review-gate",
  "independent-model-review",
];

function assertCandidateV2Contract(value) {
  assertExactKeys(value, [
    "schemaVersion",
    "candidateId",
    "recordType",
    "workPackageId",
    "acceptanceCriterionId",
    "status",
    "recordedAt",
    "apiVersion",
    "apiEndpoint",
    "officialReference",
    "payload",
    "prerequisites",
    "validationPlan",
    "governanceBoundary",
  ]);
  assert.equal(value.schemaVersion, "c13-protected-review-ruleset-candidate.v2");
  assert.equal(value.candidateId, "c13-protected-review-ruleset-candidate-v2");
  assert.equal(value.recordType, "REMOTE_RULESET_CANDIDATE");
  assert.equal(value.workPackageId, "C13");
  assert.equal(value.acceptanceCriterionId, "C13-AC02");
  assert.equal(value.status, "CANDIDATE_NOT_APPLIED");
  assert.match(value.recordedAt, /^2026-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$/u);
  assert.equal(value.apiVersion, "2026-03-10");
  assert.equal(value.apiEndpoint, "POST /repos/{owner}/{repo}/rulesets");
  assert.deepEqual(value.officialReference, candidate.officialReference);

  assertExactKeys(value.payload, [
    "name",
    "target",
    "enforcement",
    "bypass_actors",
    "conditions",
    "rules",
  ]);
  assert.equal(value.payload.name, "main-governance");
  assert.equal(value.payload.target, "branch");
  assert.equal(value.payload.enforcement, "active");
  assert.deepEqual(value.payload.bypass_actors, []);
  assert.deepEqual(value.payload.conditions, {
    ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] },
  });
  assert.deepEqual(
    value.payload.rules.map((rule) => rule.type),
    ["deletion", "non_fast_forward", "pull_request", "required_status_checks"],
  );
  const rules = new Map(value.payload.rules.map((rule) => [rule.type, rule]));
  assert.equal(rules.size, 4);
  assert.deepEqual(rules.get("pull_request").parameters, {
    allowed_merge_methods: ["merge", "squash", "rebase"],
    dismiss_stale_reviews_on_push: false,
    require_code_owner_review: false,
    require_last_push_approval: false,
    required_approving_review_count: 0,
    required_review_thread_resolution: true,
  });
  assert.deepEqual(rules.get("required_status_checks").parameters, {
    do_not_enforce_on_create: false,
    strict_required_status_checks_policy: true,
    required_status_checks: requiredCheckContexts.map((context) => ({
      context,
      integration_id: 15368,
    })),
  });
  assert.deepEqual(value.prerequisites, {
    requiredCheckPublisherObservation: {
      context: "independent-model-review",
      publisher: "GitHub Actions",
      integrationId: 15368,
      runId: 31638907916,
      headSha: "a396bf32e2a7eff30b34fff70f86c2a46e773d9b",
      tree: "fab30e7e2abab4c4b561901fbc84e89602a31f2c",
      conclusion: "SUCCESS",
      purpose: "PUBLISHER_IDENTITY_DISCOVERY_ONLY",
      reusableForCandidateHead: false,
    },
    candidateHead: {
      freshIndependentModelReviewRequired: true,
      allRequiredChecksMustMatchHead: true,
    },
  });
  assert.deepEqual(value.validationPlan, {
    readBackRuleset: true,
    readBackEffectiveMainRules: true,
    requireMissingCheckRejection: true,
    requireFailedCheckRejection: true,
    requireInconclusiveModelReviewRejection: true,
    requireExactHeadRequiredChecks: true,
    requirePublisherIntegrationId: true,
    rejectCheckReplayAcrossHeads: true,
    requireDirectPushRejection: true,
    mergeRequiredForEvidence: false,
  });
  assert.deepEqual(value.governanceBoundary, {
    p1B11Closed: false,
    rulesetApplied: false,
    independentReviewProved: false,
    d1Written: false,
    profileApproved: false,
    o02Authorized: false,
    o03Authorized: false,
    governanceEffect: "NONE",
  });
}

test("C13 CODEOWNERS uses the repository owner and protects its own policy", () => {
  const activeLines = codeowners
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));

  assert.equal(activeLines.length, 14);
  for (const line of activeLines) {
    assert.match(line, / @zhangjuntian787981-lab$/);
    assert.doesNotMatch(line, /@tristian/);
  }
  assert.ok(
    activeLines.includes(
      "/.github/CODEOWNERS @zhangjuntian787981-lab",
    ),
  );
  assert.ok(
    activeLines.includes(
      "/.github/workflows/c13-source-review-gate.yml @zhangjuntian787981-lab",
    ),
  );
  for (const protectedTest of [
    "c13-hosted-source-review-workflow.test.mjs",
    "c13-skill-registry-evidence.test.mjs",
    "c13-synthetic-skill-catalog.test.mjs",
    "skill-registry-contract.test.mjs",
    "p1-b11-protected-review-candidate.test.mjs",
  ]) {
    assert.ok(
      activeLines.includes(
        `/tests/${protectedTest} @zhangjuntian787981-lab`,
      ),
      protectedTest,
    );
  }
  assert.equal(candidate.prerequisites.codeownersErrors, "PENDING_BRANCH_READBACK");
});

test("C13 ruleset candidate is closed, unapplied and has no bypass actors", () => {
  assertExactKeys(candidate, [
    "schemaVersion",
    "candidateId",
    "recordType",
    "workPackageId",
    "acceptanceCriterionId",
    "status",
    "recordedAt",
    "apiVersion",
    "apiEndpoint",
    "officialReference",
    "payload",
    "prerequisites",
    "validationPlan",
    "governanceBoundary",
  ]);
  assert.equal(
    candidate.schemaVersion,
    "c13-protected-review-ruleset-candidate.v1",
  );
  assert.equal(candidate.workPackageId, "C13");
  assert.equal(candidate.acceptanceCriterionId, "C13-AC02");
  assert.equal(candidate.status, "CANDIDATE_NOT_APPLIED");
  assert.equal(candidate.apiVersion, "2026-03-10");
  assert.equal(candidate.apiEndpoint, "POST /repos/{owner}/{repo}/rulesets");
  assert.equal(candidate.payload.target, "branch");
  assert.equal(candidate.payload.enforcement, "active");
  assert.deepEqual(candidate.payload.bypass_actors, []);
  assert.deepEqual(
    candidate.payload.conditions.ref_name.include,
    ["~DEFAULT_BRANCH"],
  );
  assert.deepEqual(candidate.payload.conditions.ref_name.exclude, []);
  assertCandidateV2Contract(candidateV2);
});

test("C13 ruleset requires independent review, exact hosted checks and destructive-change protection", async () => {
  await assertIndependentModelRequiredCheckContract();
  const rules = new Map(
    candidate.payload.rules.map((rule) => [rule.type, rule]),
  );
  assert.deepEqual(
    [...rules.keys()].sort(),
    [
      "deletion",
      "non_fast_forward",
      "pull_request",
      "required_status_checks",
    ].sort(),
  );

  assert.deepEqual(rules.get("pull_request").parameters, {
    allowed_merge_methods: ["merge", "squash", "rebase"],
    dismiss_stale_reviews_on_push: true,
    require_code_owner_review: true,
    require_last_push_approval: true,
    required_approving_review_count: 1,
    required_review_thread_resolution: true,
  });
  assert.deepEqual(
    rules.get("required_status_checks").parameters,
    {
      do_not_enforce_on_create: false,
      strict_required_status_checks_policy: true,
      required_status_checks: [
        {
          context: "protected-surface-gate",
          integration_id: 15368,
        },
        {
          context: "contract-compatibility-gate",
          integration_id: 15368,
        },
        {
          context: "c13-source-review-gate",
          integration_id: 15368,
        },
      ],
    },
  );

  assertCandidateV2Contract(candidateV2);
  const contractMutations = [
    (value) => value.payload.bypass_actors.push({ actor_id: 1 }),
    (value) => { value.payload.conditions.ref_name.include = ["refs/heads/main"]; },
    (value) => { value.payload.conditions.ref_name.exclude = ["refs/heads/dev"]; },
    (value) => { value.payload.rules.splice(0, 1); },
    (value) => { value.payload.rules[2].parameters.required_approving_review_count = 1; },
    (value) => { value.payload.rules[2].parameters.require_code_owner_review = true; },
    (value) => { value.payload.rules[2].parameters.require_last_push_approval = true; },
    (value) => { value.payload.rules[2].parameters.required_review_thread_resolution = false; },
    (value) => { value.payload.rules[3].parameters.strict_required_status_checks_policy = false; },
    (value) => { value.payload.rules[3].parameters.required_status_checks.pop(); },
    (value) => { value.payload.rules[3].parameters.required_status_checks.push(structuredClone(value.payload.rules[3].parameters.required_status_checks[0])); },
    (value) => { value.payload.rules[3].parameters.required_status_checks[3].integration_id = 1; },
  ];
  for (const mutate of contractMutations) {
    const changed = structuredClone(candidateV2);
    mutate(changed);
    assert.throws(() => assertCandidateV2Contract(changed));
  }

});

test("C13 candidate preserves external blockers and cannot claim governance effect", () => {
  assert.deepEqual(candidate.prerequisites, {
    privateRepositoryRulesCapability: "BLOCKED_BY_GITHUB_PLAN",
    codeownersErrors: "PENDING_BRANCH_READBACK",
    independentReviewer: "MISSING",
    requiredChecks: {
      observed: [
        "protected-surface-gate",
        "contract-compatibility-gate",
      ],
      pendingHostedObservation: ["c13-source-review-gate"],
    },
  });
  assert.equal(candidate.governanceBoundary.p1B11Closed, false);
  assert.equal(candidate.governanceBoundary.rulesetApplied, false);
  assert.equal(candidate.governanceBoundary.independentReviewProved, false);
  assert.equal(candidate.governanceBoundary.d1Written, false);
  assert.equal(candidate.governanceBoundary.profileApproved, false);
  assert.equal(candidate.governanceBoundary.o02Authorized, false);
  assert.equal(candidate.governanceBoundary.o03Authorized, false);

  assertCandidateV2Contract(candidateV2);
  for (const mutate of [
    (value) => { value.status = "ACTIVE"; },
    (value) => { value.governanceBoundary.rulesetApplied = true; },
    (value) => { value.governanceBoundary.p1B11Closed = true; },
    (value) => { value.governanceBoundary.governanceEffect = "RULESET_APPLIED"; },
    (value) => { value.prerequisites.requiredCheckPublisherObservation.reusableForCandidateHead = true; },
  ]) {
    const changed = structuredClone(candidateV2);
    mutate(changed);
    assert.throws(() => assertCandidateV2Contract(changed));
  }

  assert.match(adr, /状态：Candidate/);
  assert.match(adr, /第二名真实人类复核人/);
  assert.match(adr, /GitHub Pro/);
  assert.match(adr, /does not close P1-B11/i);
  assert.match(adr, /does not create D1, Gate, Profile, or start-authorization state/i);
});

test("P1-B11 research is official-source bounded and does not claim remote enforcement", () => {
  assert.match(research, /官方仓库：\[github\/docs\]/);
  assert.match(research, /固定快照 commit：.*6f69b5126a8616e7fab257af61999e8f9416250d/);
  assert.match(research, /固定 API 版本：`2026-03-10`/);
  assert.match(research, /`ADOPT`/);
  assert.match(research, /`DEFER`/);
  assert.match(research, /`REJECT`/);
  assert.match(research, /当前只有一名实施者/);
  assert.match(research, /结果必须保持 `INCONCLUSIVE`/);
  assert.match(research, /不证明任何控制已在远端启用/);
});
