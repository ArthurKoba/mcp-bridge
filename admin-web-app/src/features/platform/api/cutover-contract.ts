import type { AccessProjection, PlatformPort } from "@/features/platform/model/contracts"
import { A11_ACCEPTED_SOURCE_ONLY } from "@/features/platform/api/a11-owner-bff-source"

/**
 * The cutover is intentionally NOT a runtime feature flag. It requires an
 * independently approved, actually mounted trusted server composition and
 * a verified current principal. The accepted A11/A12 source remains private
 * and unmounted; A12 normalized effects lack original Operation-UUID and
 * cannot satisfy the B17/B18 reviewed original-key confirmation contract.
 *
 * This is the future integration contract for the orchestrator/reviewer, not
 * a credential or permission check and not an authority users can supply.
 */
export type PlatformCutoverPrerequisite =
  | "independent-owner-schema-heads"
  | "verified-owner-service-attestations"
  | "cross-owner-effect-status"
  | "approved-public-api-contract"
  | "server-verified-active-principal"
  | "same-origin-https-trust-boundary"
  | "server-owned-permission-revisions"
  | "revocable-token-lifecycle"
  | "safe-command-status-reconciliation"
  | "authenticated-scoped-ws-revocation"
  | "independent-browser-runtime-acceptance"

export interface ReviewedPlatformRuntimeComposition {
  /** Future implementation must come from approved app composition, not UI. */
  readonly client: PlatformPort
  readonly publicContractVersion: string
  /** Accepted A11+ source, after all four owner schemas/roles are verified.
   * Historical A9 global Alembic never satisfies this contract. */
  readonly ownerTopology: "identity-access-control-catalog"
  /** Verified by a REAL authenticated server call; never a stored username. */
  verifyCurrentPrincipal(signal:AbortSignal):Promise<AccessProjection | null>
  /** The reviewed app owns cleanup on login/logout/service revocation. */
  destroy():void
}

export const platformCutoverReadiness: Readonly<{
  state:"blocked"
  acceptedSource:"A11 private four-owner BFF source (UNMOUNTED)"
  missing:readonly PlatformCutoverPrerequisite[]
}> = Object.freeze({
  state:"blocked",
  acceptedSource:"A11 private four-owner BFF source (UNMOUNTED)",
  missing:Object.freeze([
    "independent-owner-schema-heads",
    "verified-owner-service-attestations",
    "cross-owner-effect-status",
    "approved-public-api-contract",
    "server-verified-active-principal",
    "same-origin-https-trust-boundary",
    "server-owned-permission-revisions",
    "revocable-token-lifecycle",
    "safe-command-status-reconciliation",
    "authenticated-scoped-ws-revocation",
    "independent-browser-runtime-acceptance",
  ] as const),
})

/**
 * Future cutover must implement an independently reviewed installer that
 * consumes ReviewedPlatformRuntimeComposition after all public gates close.
 * There is intentionally no callable activate/enable path in B18.
 */
// A11_ACCEPTED_SOURCE_ONLY is a source-provenance marker and can NEVER be
// interpreted as permission to install public transport.
void A11_ACCEPTED_SOURCE_ONLY.publicMounted
export function cutoverBlocked():never {
  throw new Error("C1-B2-PUBLIC/C2 platform transport and verified runtime are not approved")
}
