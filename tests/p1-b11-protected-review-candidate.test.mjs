import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertIndependentModelRequiredCheckContract } from "./independent-model-required-check.cases.mjs";

const codeowners = await readFile(
  new URL("../.github/CODEOWNERS", import.meta.url),
  "utf8",
);
const candidate = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
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
