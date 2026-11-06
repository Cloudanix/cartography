# IAM Access Signals

## Purpose

Cartography classifies who can assume an AWS IAM role. These signals describe
potential access granted by a role's trust policy; they do not prove that the
role was actually assumed.

## Terminology

The current names are ambiguous:

- `Internal` can mean the same account, the same AWS Organization, or a private
  network. It also overlaps with AWS IAM Access Analyzer's own "internal
  access" terminology.
- `CrossAccount` describes both trusted accounts and untrusted external
  accounts, so it does not distinguish the two risk boundaries.
- `ThirdParty` implies a known business relationship that cannot be inferred
  from an AWS principal.

Use these trust scopes instead:

| Trust scope | Meaning |
|---|---|
| `SameAccount` | The principal belongs to the account that owns the role. |
| `TrustedAccount` | The principal belongs to another account in the AWS Organization or the configured trusted-account allowlist. |
| `ExternalAccount` | The principal belongs to an account outside the trusted account set. |
| `Public` | The trust policy permits an unrestricted wildcard principal. |

Trust scope and principal type are separate concepts. Preserve the principal
type reported by the policy as `AWS`, `Service`, or `Federated`; do not label a
service or identity provider as an external account merely because it has no
AWS account ID.

Recommended data model:

```text
trust_scope:    SameAccount | TrustedAccount | ExternalAccount | Public
principal_type: AWS | Service | Federated
trust_basis:    current_account | organization | configured_allowlist | none
```

For backward compatibility, existing `CrossAccount` and `ThirdParty` values
can remain readable while downstream consumers migrate:

| Existing value | New value |
|---|---|
| same-account principal, currently stored without an access type | `SameAccount` |
| `CrossAccount` | `TrustedAccount` |
| `ThirdParty` with an AWS account principal | `ExternalAccount` |
| wildcard principal without an effective restriction | `Public` |

## Condition-aware classification

### Design principle

IAM Access Analyzer already evaluates IAM policy semantics and conditions when
it determines whether an external-access finding exists. Cartography should
not implement a second general-purpose IAM policy evaluator.

Instead, Cartography should use the exact details of each active Access
Analyzer finding. This fixes the current attribution problem where one finding
causes every principal in the role's trust policy to be classified, including
unrelated service and federated principals.

### Proposed flow

```text
list_findings_v2(ACTIVE IAM role findings)
  -> get_finding_v2(finding ID)
  -> externalAccessDetails
       principal
       condition
       isPublic
       action
  -> classify the reported principal
  -> attach normalized condition signals
  -> store the raw condition for audit/debugging
```

`get_finding_v2` may return paginated finding details. The implementation must
consume every details page before classifying the finding.

### Data source scope and fallback

Access Analyzer's external-access analyzer only emits findings for
cross-account, public, or otherwise external exposure — it does not emit a
finding for a role whose trust policy grants access exclusively within its
own account. Two consequences follow:

1. The `SameAccount` branch in classification rule 2 fires only when a
   finding's principal list mixes an external principal with a same-account
   one (e.g. one trust statement listing several principals). A role with
   *only* same-account trust will not appear in `list_findings_v2` at all.
2. Same-account and role-chaining edges, needed for lateral-movement
   graphing inside one account, must still be populated for every role, not
   only ones with an active finding. Cartography must keep parsing the role
   trust policy directly for this case; Access Analyzer findings extend that
   pipeline, they do not replace it for same-account edges.

Accounts without Access Analyzer enabled (or without an external-access
analyzer configured) return no findings at all. Cartography must fall back
to direct trust-policy parsing for `TrustedAccount`/`ExternalAccount`/`Public`
classification in that case too — the condition-aware enrichment in this
document is an enhancement over that baseline parser, not a replacement for
accounts where it is unavailable.

### Classification rules

1. Treat `isPublic` as authoritative: if it is `true`, classify the finding
   as `Public`. Do not re-implement Access Analyzer's own narrowing logic —
   store any accompanying condition as a qualifier (e.g.
   `external_id_required`) rather than reclassifying the trust scope.
2. For an AWS account principal, extract the account ID:
   - role owner account -> `SameAccount`
   - organization or configured allowlist -> `TrustedAccount`
   - otherwise -> `ExternalAccount`
3. For a wildcard constrained by `aws:PrincipalOrgID` or
   `aws:PrincipalOrgPaths`, classify it as trusted only when the condition
   matches the configured organization. Retain the organization restriction
   as a qualifier.
4. For a wildcard constrained by `aws:PrincipalAccount`, classify each listed
   account individually using the same account-ID rule as (2) — the
   condition enumerates concrete accounts, so it never yields a single trust
   scope for the finding as a whole.
5. Preserve service and federated principals as their own principal types.
   Conditions can constrain their access but do not turn them into AWS account
   principals.
6. Treat Access Analyzer as the authority on whether the complete condition is
   satisfiable by an external principal. Cartography only derives display and
   prioritization signals from supported condition keys.

### Condition signals

Conditions qualify access; most do not change the trust scope.

| Condition | Normalized signal | Effect |
|---|---|---|
| `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` | `principal_organization` | Can establish a trusted-organization boundary. |
| `aws:PrincipalAccount` | `principal_accounts` | Can establish the account trust scope. |
| `sts:ExternalId` | `external_id_required` | Mitigates confused-deputy risk; access remains external. |
| `aws:SourceAccount` | `source_accounts` | Constrains service-mediated access to source accounts. |
| `aws:SourceArn` | `source_arns` | Constrains service-mediated access to source resources. |
| `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceIp` | network constraint fields | Narrows the network origin; does not change ownership. |
| `aws:MultiFactorAuthPresent` | `mfa_required` | Adds an authentication requirement. |

Store the complete condition document as serialized JSON in addition to these
normalized fields. IAM supports negated operators, wildcard matching,
`ForAnyValue`, `ForAllValues`, and `IfExists`; retaining the source prevents a
lossy normalized signal from being mistaken for the full authorization logic.

### Configuration inputs

Classification needs three inputs that are not part of any Access Analyzer
finding and must come from Cartography's own configuration:

- `current_account`: the account ID owning the role (already available from
  the sync context).
- `organization`: the AWS Organization ID for the account, refreshed from
  `organizations:DescribeOrganization` on each sync so a role that changes
  organizations does not keep a stale trust scope.
- `trusted_account_allowlist`: an operator-maintained list of account IDs,
  scoped per Cartography config (not global), re-read on each sync run.

Cache invalidation follows the normal Cartography sync cadence — there is no
separate refresh schedule.

### Suggested graph properties

Named `AWSPrincipalTrust`, not `AWSExternalPrincipal` — the node stores
`SameAccount` trust as well (needed for role-chaining/lateral-movement
graphing), so an "external"-only name would misdescribe it.

```text
AWSPrincipalTrust {
  principal,
  principal_type,
  account_id,
  trust_scope,
  trust_basis,
  is_public,
  external_id_required,
  principal_organization,
  conditions_json
}
```

Additional condition fields should be added only when a downstream query uses
them. Until then, `conditions_json` preserves the source without expanding the
graph schema.

### Implementation outline

1. Enrich each active finding with all `get_finding_v2` detail pages, using
   the sync module's existing rate limiter/backoff — this is an added
   per-finding API call, not a per-account one, and a large organization can
   have thousands of active findings.
2. Add a small classifier that accepts one `externalAccessDetails` object plus
   the role owner, organization ID, and trusted-account set.
3. Emit one record per principal reported by the finding rather than walking
   every statement in the role trust policy. Keep the existing trust-policy
   parser running for roles with no active finding and for accounts without
   Access Analyzer enabled (see "Data source scope and fallback").
4. Persist `trust_scope`, principal type, trust basis, public status, and raw
   conditions on the `AWSPrincipalTrust` node.
5. Keep the existing `CrossAccount`/`ThirdParty` values for two Cartography
   minor releases after `trust_scope` ships, behind a changelog deprecation
   notice, then remove them and make `trust_scope` the only field.

### Minimum test matrix

- Same-account AWS principal.
- Account in the AWS Organization.
- Account in the configured trusted allowlist.
- External AWS account with and without `sts:ExternalId`.
- Wildcard restricted to the trusted organization.
- Unrestricted public wildcard.
- AWS service restricted by `aws:SourceAccount` and `aws:SourceArn`.
- Federated principal.
- Multiple detail pages for one finding.
- Negated or unsupported conditions preserved in `conditions_json` without
  being reinterpreted.
- Wildcard restricted to a specific account list via `aws:PrincipalAccount`.
- Role with no active finding (pure same-account trust) — classified via the
  trust-policy-parsing fallback, not Access Analyzer.
- Account with Access Analyzer disabled — same fallback path.
- Finding whose principal list mixes a same-account and an external
  principal in one statement.

