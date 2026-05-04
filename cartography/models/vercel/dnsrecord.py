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
class VercelDNSRecordNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    name: PropertyRef = PropertyRef("name", extra_index=True)
    type: PropertyRef = PropertyRef("type")
    value: PropertyRef = PropertyRef("value")
    ttl: PropertyRef = PropertyRef("ttl")
    priority: PropertyRef = PropertyRef("priority")
    created_at: PropertyRef = PropertyRef("createdAt")


@dataclass(frozen=True)
class VercelDNSRecordToTeamRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:VercelTeam)-[:RESOURCE]->(:VercelDNSRecord)
class VercelDNSRecordToTeamRel(CartographyRelSchema):
    target_node_label: str = "VercelTeam"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("TEAM_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: VercelDNSRecordToTeamRelProperties = (
        VercelDNSRecordToTeamRelProperties()
    )


@dataclass(frozen=True)
class VercelDNSRecordToDomainRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:VercelDomain)-[:HAS_DNS_RECORD]->(:VercelDNSRecord)
class VercelDNSRecordToDomainRel(CartographyRelSchema):
    target_node_label: str = "VercelDomain"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("domain_name", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "HAS_DNS_RECORD"
    properties: VercelDNSRecordToDomainRelProperties = (
        VercelDNSRecordToDomainRelProperties()
    )


@dataclass(frozen=True)
class VercelDNSRecordSchema(CartographyNodeSchema):
    label: str = "VercelDNSRecord"
    properties: VercelDNSRecordNodeProperties = VercelDNSRecordNodeProperties()
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["DNSRecord"])
    sub_resource_relationship: VercelDNSRecordToTeamRel = VercelDNSRecordToTeamRel()
    other_relationships: OtherRelationships = OtherRelationships(
        [VercelDNSRecordToDomainRel()],
    )
