from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
)
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class AWSPolicyStatementNodeProperties(CartographyNodeProperties):
    # Required unique identifier
    id: PropertyRef = PropertyRef("id")

    # Automatic fields (set by cartography)
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)

    # Business fields from AWS IAM policy statements
    effect: PropertyRef = PropertyRef("Effect")
    action: PropertyRef = PropertyRef("Action")
    notaction: PropertyRef = PropertyRef("NotAction")
    resource: PropertyRef = PropertyRef("Resource")
    notresource: PropertyRef = PropertyRef("NotResource")
    condition: PropertyRef = PropertyRef("Condition")
    sid: PropertyRef = PropertyRef("Sid")


@dataclass(frozen=True)
class AWSPolicyStatementToAWSPolicyRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AWSPolicyStatementToAWSPolicyRel(CartographyRelSchema):
    target_node_label: str = "AWSPolicy"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {
            "id": PropertyRef("POLICY_ID", set_in_kwargs=True),
        }
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "STATEMENT"
    properties: AWSPolicyStatementToAWSPolicyRelProperties = (
        AWSPolicyStatementToAWSPolicyRelProperties()
    )


@dataclass(frozen=True)
class AWSPolicyStatementSchema(CartographyNodeSchema):
    label: str = "AWSPolicyStatement"
    properties: AWSPolicyStatementNodeProperties = AWSPolicyStatementNodeProperties()
    sub_resource_relationship: AWSPolicyStatementToAWSPolicyRel = (
        AWSPolicyStatementToAWSPolicyRel()
    )
