import { createPepSdk } from "./authorization-facade.mjs";

const ADAPTERS = Object.freeze([
  ["c06.synthetic.read", "READ"],
  ["c06.synthetic.retrieve", "RETRIEVE"],
  ["c06.synthetic.download", "DOWNLOAD"],
  ["c06.synthetic.manage", "MANAGE"],
  ["c06.synthetic.tool-call", "TOOL_CALL"],
  ["c06.synthetic.sandbox-run", "SANDBOX_RUN"],
]);

function decisionRequest(request) {
  return Object.freeze({
    sessionToken: request?.sessionToken,
    delegationId: request?.delegationId,
    resourceId: request?.resourceId,
    correlationId: request?.correlationId,
  });
}

export function createSyntheticPepAdapters({
  authorizationFacade,
  tenantId,
  workloadActorPrincipalId,
}) {
  const pep = createPepSdk({ authorizationFacade });
  return Object.freeze(
    Object.fromEntries(
      ADAPTERS.map(([adapterId, surface]) => {
        const serverContext = Object.freeze({
          synthetic: true,
          routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
          tenantId,
          surface,
          workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
          workloadActorPrincipalId,
        });
        return [
          adapterId,
          Object.freeze({
            async enforce(request) {
              return pep.enforce(serverContext, decisionRequest(request));
            },
          }),
        ];
      }),
    ),
  );
}
