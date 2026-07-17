import logging
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from cartography.intel.aws.resources import RESOURCE_FUNCTIONS

logger = logging.getLogger(__name__)


def parse_and_validate_aws_requested_syncs(aws_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in aws_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS:
            validated_resources.append(resource)
        else:
            valid_syncs: str = ', '.join(RESOURCE_FUNCTIONS.keys())
            raise ValueError(
                f'Error parsing `aws-requested-syncs`. You specified "{aws_requested_syncs}". '
                f'Please check that your string is formatted properly. '
                f'Example valid input looks like "s3,iam,rds" or "s3, ec2:instance, dynamodb". '
                f'Our full list of valid values is: {valid_syncs}.',
            )
    return validated_resources


def get_default_vpc(ec2_client):
    try:
        response = ec2_client.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}],
        )
        vpcs = response.get('Vpcs', [])

        if not vpcs:
            logger.info("No default VPC found.")
            return {}

        return vpcs[0]

    except Exception as e:
        logger.error(f"Error fetching default VPC: {e}")
        return {}


def _normalize_account_id(value: str) -> str:
    """Normalize an AWS account ID by zero-padding to 12 digits if numeric."""
    if value.isdigit() and len(value) <= 12:
        return value.zfill(12)
    return value


def build_trusted_accounts(
    aws_ids_arns: List[str],
    internal_accounts: List[str],
    resource_arn: str = "",
    own_account: str = "",
) -> Set[str]:
    """
    Build a set of trusted account IDs from the provided lists.
    Normalizes account IDs and extracts them from ARNs.
    """
    if not own_account and resource_arn:
        parts = resource_arn.split(":")
        own_account = parts[4] if len(parts) > 4 else ""

    raw = set(aws_ids_arns) | set(internal_accounts) | {own_account}
    normalized: Set[str] = set()
    for entry in raw:
        if not entry:
            continue
        entry = str(entry)
        normalized.add(entry)
        normalized.add(_normalize_account_id(entry))
        parts = entry.split(":")
        if len(parts) > 4 and re.match(r"^\d+$", parts[4]):
            normalized.add(_normalize_account_id(parts[4]))
    return normalized


def is_cross_account_statement(
    statement: Dict[str, Any],
    trusted_accounts: Set[str],
    trusted_organisations: Optional[Set[str]] = None,
    iam_unique_ids: Optional[Set[str]] = None,
) -> bool:
    """
    Determine if a policy statement grants cross-account access.

    Args:
        statement: A single IAM policy statement dict.
        trusted_accounts: Set of account IDs considered trusted (own account + internal accounts).
        trusted_organisations: Optional set of trusted organization IDs.
        iam_unique_ids: Optional set of known IAM unique IDs (user/role/group IDs) for the account.

    Returns:
        True if the statement grants access to an account outside the trusted set.
    """
    if trusted_organisations is None:
        trusted_organisations = set()

    if iam_unique_ids is None:
        iam_unique_ids = set()

    if statement.get("Effect", "").upper() != "ALLOW":
        return False

    normalized_trusted: Set[str] = set()
    for acct in trusted_accounts:
        if acct:
            normalized_trusted.add(str(acct))
            normalized_trusted.add(_normalize_account_id(str(acct)))

    is_cross = False

    if "NotPrincipal" in statement:
        is_cross = True
    else:
        is_cross = _principal_is_cross_account(statement, normalized_trusted, iam_unique_ids)

    condition = statement.get("Condition", {})
    if condition and isinstance(condition, dict):
        cond_result = _evaluate_condition_accounts(condition, normalized_trusted, trusted_organisations)
        if cond_result == "restricted":
            return False
        elif cond_result == "cross_account":
            is_cross = True

    return is_cross


def _principal_is_cross_account(
    statement: Dict[str, Any],
    trusted_accounts: Set[str],
    iam_unique_ids: Optional[Set[str]] = None,
) -> bool:
    """Check if the Principal in a statement references a cross-account entity."""
    if iam_unique_ids is None:
        iam_unique_ids = set()

    principal = statement.get("Principal", "")

    if principal == "*":
        return True

    if isinstance(principal, dict):
        aws_val = principal.get("AWS", [])
        if aws_val == "*":
            return True

        if isinstance(aws_val, str):
            aws_principals = [aws_val]
        elif isinstance(aws_val, list):
            aws_principals = aws_val
        else:
            aws_principals = []

        federated_val = principal.get("Federated", [])
        if isinstance(federated_val, str):
            federated_principals = [federated_val]
        elif isinstance(federated_val, list):
            federated_principals = federated_val
        else:
            federated_principals = []

    else:
        aws_principals = [principal]
        federated_principals = []

    for v in aws_principals:
        if not isinstance(v, str) or not v:
            continue

        # AWS service principals are not cross-account
        if v.endswith(".amazonaws.com") or v.endswith(".amazonaws.com.cn"):
            continue

        # IAM unique ID format (e.g., AROA..., AIDA..., AGPA...)
        if re.match(r"^[A-Z0-9]{20,}$", v):
            if v in iam_unique_ids:
                continue
            if not iam_unique_ids:
                continue
            return True

        arr = v.split(":")

        if re.match(r"^\d+$", v) and len(v) <= 12:
            account = _normalize_account_id(v)
        elif len(arr) > 4:
            acct_field = arr[4]
            if acct_field == "*":
                return True
            if re.match(r"^\d+$", acct_field) and len(acct_field) <= 12:
                account = _normalize_account_id(acct_field)
            else:
                if v not in trusted_accounts:
                    return True
                continue
        else:
            if v not in trusted_accounts:
                return True
            continue

        if account not in trusted_accounts:
            return True

    for v in federated_principals:
        if not isinstance(v, str) or not v:
            continue

        # AWS service principals are not cross-account
        if v.endswith(".amazonaws.com") or v.endswith(".amazonaws.com.cn"):
            continue

        # External identity providers (e.g., accounts.google.com)
        if "." in v and not v.startswith("arn:"):
            return True

        arr = v.split(":")
        if len(arr) > 4 and re.match(r"^\d+$", arr[4]) and len(arr[4]) <= 12:
            account = _normalize_account_id(arr[4])
            if account not in trusted_accounts:
                return True

    return False


def _evaluate_condition_accounts(
    condition: Dict[str, Any],
    trusted_accounts: Set[str],
    trusted_organisations: Optional[Set[str]] = None,
) -> str:
    """
    Evaluate condition keys related to account restrictions.

    Returns:
        'restricted' - condition restricts access to trusted accounts/orgs only
        'cross_account' - condition explicitly references untrusted accounts
        'neutral' - no account-related conditions found
    """
    if trusted_organisations is None:
        trusted_organisations = set()

    account_condition_keys = {
        "aws:principalaccount",
        "aws:sourceaccount",
        "aws:sourceowner",
        "kms:calleraccount",
    }
    arn_condition_keys = {
        "aws:sourcearn",
        "aws:principalarn",
    }
    org_condition_keys = {
        "aws:principalorgid",
        "aws:principalorgpaths",
    }

    negated_operators = {
        "stringnotequals",
        "stringnotequalsignorecase",
        "stringnotlike",
        "arnnotequals",
        "arnnotlike",
        "stringnotequalsifexists",
        "stringnotequalsignorecaseifexists",
        "stringnotlikeifexists",
        "arnnotequalsifexists",
        "arnnotlikeifexists",
    }

    has_account_key = False
    has_untrusted = False
    has_negated = False
    has_trusted_account_key = False
    has_untrusted_account_key = False

    for operator, conditions_map in condition.items():
        if not isinstance(conditions_map, dict):
            continue

        operator_lower = operator.lower()
        is_negated = operator_lower in negated_operators

        for key, value in conditions_map.items():
            key_lower = key.lower()

            if key_lower in org_condition_keys:
                has_account_key = True
                if is_negated:
                    has_negated = True
                elif trusted_organisations:
                    orgs = value if isinstance(value, list) else [value]
                    all_trusted = True
                    for org in orgs:
                        if not isinstance(org, str) or org not in trusted_organisations:
                            has_untrusted = True
                            has_untrusted_account_key = True
                            all_trusted = False
                    if all_trusted:
                        has_trusted_account_key = True
                continue

            if key_lower in account_condition_keys:
                has_account_key = True
                if is_negated:
                    has_negated = True
                else:
                    accounts = value if isinstance(value, list) else [value]
                    all_trusted = True
                    for acct in accounts:
                        if not isinstance(acct, str):
                            has_untrusted = True
                            has_untrusted_account_key = True
                            all_trusted = False
                        elif _normalize_account_id(acct) not in trusted_accounts:
                            has_untrusted = True
                            has_untrusted_account_key = True
                            all_trusted = False
                    if all_trusted:
                        has_trusted_account_key = True

            if key_lower in arn_condition_keys:
                has_account_key = True
                if is_negated:
                    has_negated = True
                else:
                    arns = value if isinstance(value, list) else [value]
                    for arn in arns:
                        if not isinstance(arn, str):
                            has_untrusted = True
                            continue

                        arn_parts = arn.split(":")
                        if len(arn_parts) > 4 and arn_parts[4]:
                            acct_id = arn_parts[4]
                            if acct_id == "*":
                                has_untrusted = True
                            elif re.match(r"^\d+$", acct_id) and len(acct_id) <= 12:
                                if _normalize_account_id(acct_id) not in trusted_accounts:
                                    has_untrusted = True

    if not has_account_key:
        return "neutral"
    if has_negated:
        return "cross_account"
    if has_untrusted_account_key:
        return "cross_account"
    if has_trusted_account_key:
        return "restricted"
    return "cross_account" if has_untrusted else "restricted"
