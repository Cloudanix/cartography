from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties
from cartography.models.core.nodes import CartographyNodeSchema
from cartography.models.core.relationships import CartographyRelProperties
from cartography.models.core.relationships import CartographyRelSchema
from cartography.models.core.relationships import LinkDirection
from cartography.models.core.relationships import make_target_node_matcher
from cartography.models.core.relationships import TargetNodeMatcher


@dataclass(frozen=True)
class ElasticBeanstalkEnvironmentNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('Arn')
    arn: PropertyRef = PropertyRef('Arn')
    name: PropertyRef = PropertyRef('EnvironmentName')
    application_name: PropertyRef = PropertyRef('ApplicationName')
    environment_id: PropertyRef = PropertyRef('EnvironmentId')
    status: PropertyRef = PropertyRef('Status')
    consolelink: PropertyRef = PropertyRef('consolelink')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)
    # Listener protocols gathered from the environment's configuration option settings
    # (namespaces aws:elbv2:listener* / aws:elb:listener*, option Protocol / ListenerProtocol).
    # Stored as facts; the consumer decides HTTPS compliance — no rule logic in the sync.
    listener_protocols: PropertyRef = PropertyRef('ListenerProtocols')


@dataclass(frozen=True)
class ElasticBeanstalkEnvironmentToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:ElasticBeanstalkEnvironment)<-[:RESOURCE]-(:AWSAccount)
class ElasticBeanstalkEnvironmentToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: ElasticBeanstalkEnvironmentToAwsAccountRelProperties = (
        ElasticBeanstalkEnvironmentToAwsAccountRelProperties()
    )


@dataclass(frozen=True)
class ElasticBeanstalkEnvironmentSchema(CartographyNodeSchema):
    label: str = 'ElasticBeanstalkEnvironment'
    properties: ElasticBeanstalkEnvironmentNodeProperties = ElasticBeanstalkEnvironmentNodeProperties()
    sub_resource_relationship: ElasticBeanstalkEnvironmentToAWSAccount = ElasticBeanstalkEnvironmentToAWSAccount()
