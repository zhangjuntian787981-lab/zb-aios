export function isC06DecisionBoundToRequest(decision, binding) {
  return (
    decision?.tenantId === binding?.tenantId &&
    decision?.surface === binding?.surface &&
    decision?.resourceId === binding?.resourceId &&
    decision?.workloadActorPrincipalId ===
      binding?.workloadActorPrincipalId &&
    decision?.leafDelegationId === binding?.delegationId &&
    Number.isSafeInteger(decision?.humanSecurityEpoch) &&
    decision.humanSecurityEpoch > 0 &&
    Number.isSafeInteger(decision?.workloadActorSecurityEpoch) &&
    decision.workloadActorSecurityEpoch > 0
  );
}
