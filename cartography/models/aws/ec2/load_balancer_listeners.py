from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
    ExtraNodeLabels,
)
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    OtherRelationships,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class ELBListenerNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    port: PropertyRef = PropertyRef("port")
    protocol: PropertyRef = PropertyRef("protocol")
    instance_port: PropertyRef = PropertyRef("instance_port")
    instance_protocol: PropertyRef = PropertyRef("instance_protocol")
    policy_names: PropertyRef = PropertyRef("policy_names")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class ELBListenerToLoadBalancerRelRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class ELBListenerToLoadBalancerRel(CartographyRelSchema):
    target_node_label: str = "AWSLoadBalancer"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("LoadBalancerId")},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "ELB_LISTENER"
    properties: ELBListenerToLoadBalancerRelRelProperties = (
        ELBListenerToLoadBalancerRelRelProperties()
    )


@dataclass(frozen=True)
class ELBListenerToAWSAccountRelRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class ELBListenerToAWSAccountRel(CartographyRelSchema):
    target_node_label: str = "AWSAccount"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("AWS_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: ELBListenerToAWSAccountRelRelProperties = (
        ELBListenerToAWSAccountRelRelProperties()
    )


@dataclass(frozen=True)
class ELBListenerSchema(CartographyNodeSchema):
    label: str = "ELBListener"
    properties: ELBListenerNodeProperties = ELBListenerNodeProperties()
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["Endpoint"])
    sub_resource_relationship: ELBListenerToAWSAccountRel = ELBListenerToAWSAccountRel()
    other_relationships: OtherRelationships = OtherRelationships(
        [
            ELBListenerToLoadBalancerRel(),
        ],
    )
