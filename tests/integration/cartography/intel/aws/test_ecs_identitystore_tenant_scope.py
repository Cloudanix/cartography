"""ECS child links and Identity Center assignments / memberships stay inside the tenant."""
from cartography.intel.aws import ecs
from cartography.intel.aws import identitystore
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = '111100001111', '222200002222'


def _arn(account, kind, name):
    return f'arn:aws:ecs:{REGION}:{account}:{kind}/{name}'


def _seed_ecs(neo4j_session):
    create_test_org_account(neo4j_session, 'ecs-ws-own', 'ecs-org-own', OWN)
    create_test_org_account(neo4j_session, 'ecs-ws-other', 'ecs-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:ECSCluster{id: $own_cluster})
        MERGE (own)-[:RESOURCE]->(:ECSTaskDefinition{id: $own_td})
        MERGE (other)-[:RESOURCE]->(c:ECSCluster{id: $other_cluster})
        MERGE (other)-[:RESOURCE]->(:ECSTaskDefinition{id: $other_td})
        MERGE (c)-[:HAS_CONTAINER_INSTANCE]->(:ECSContainerInstance{id: $other_ci})
        MERGE (c)-[:HAS_TASK]->(:ECSTask{id: $other_task})
        """,
        own=OWN, other=OTHER,
        own_cluster=_arn(OWN, 'cluster', 'c'), own_td=_arn(OWN, 'task-definition', 'td:1'),
        other_cluster=_arn(OTHER, 'cluster', 'c'), other_td=_arn(OTHER, 'task-definition', 'td:1'),
        other_ci=_arn(OTHER, 'container-instance', 'c/ci'), other_task=_arn(OTHER, 'task', 'c/t'),
    )


def _degree(neo4j_session, node_id, rel):
    return neo4j_session.run(
        f"MATCH ({{id: $id}})-[r:{rel}]-() RETURN count(r) AS n", id=node_id,
    ).single()['n']


def test_ecs_children_link_only_to_the_accounts_cluster_and_task_definition(neo4j_session):
    _seed_ecs(neo4j_session)
    other_cluster, other_td = _arn(OTHER, 'cluster', 'c'), _arn(OTHER, 'task-definition', 'td:1')

    # rows naming another customer's cluster, task definition, container instance and task
    ecs.load_ecs_container_instances(
        neo4j_session, other_cluster, [{'containerInstanceArn': _arn(OWN, 'container-instance', 'c/ci')}],
        REGION, OWN, TAG,
    )
    ecs.load_ecs_services(
        neo4j_session, other_cluster,
        [{'serviceArn': _arn(OWN, 'service', 'c/s'), 'taskDefinition': other_td}], REGION, OWN, TAG,
    )
    ecs.load_ecs_tasks(
        neo4j_session, _arn(OWN, 'cluster', 'c'),
        [{
            'taskArn': _arn(OWN, 'task', 'c/t'), 'taskDefinitionArn': other_td,
            'containerInstanceArn': _arn(OTHER, 'container-instance', 'c/ci'), 'containers': [],
        }],
        REGION, OWN, TAG,
    )
    ecs.load_ecs_container_definitions(
        neo4j_session, [{'_taskDefinitionArn': other_td, 'name': 'web'}], REGION, OWN, TAG,
    )
    ecs.load_ecs_containers(
        neo4j_session,
        [{'containerArn': _arn(OWN, 'container', 'x'), 'taskArn': _arn(OTHER, 'task', 'c/t')}], REGION, OWN, TAG,
    )

    assert _degree(neo4j_session, other_cluster, 'HAS_CONTAINER_INSTANCE|HAS_SERVICE|HAS_TASK') == 2  # seeded
    assert _degree(neo4j_session, other_td, 'HAS_TASK_DEFINITION|HAS_CONTAINER_DEFINITION') == 0
    assert _degree(neo4j_session, _arn(OTHER, 'container-instance', 'c/ci'), 'HAS_TASK') == 0
    assert _degree(neo4j_session, _arn(OTHER, 'task', 'c/t'), 'HAS_CONTAINER') == 0
    # the own task still joins its own cluster
    assert _degree(neo4j_session, _arn(OWN, 'task', 'c/t'), 'HAS_TASK') == 1


def test_identity_center_links_stay_in_the_organization(neo4j_session):
    neo4j_session.run(
        """
        MERGE (own:AWSOrganization{id: 'ic-org-own'}) SET own.identity_store_arn = 'arn:sso-own'
        MERGE (other:AWSOrganization{id: 'ic-org-other'}) SET other.identity_store_arn = 'arn:sso-other'
        MERGE (own)-[:RESOURCE]->(:AWSUser:AWSPrincipal{id: 'u-own'})
        MERGE (own)-[:RESOURCE]->(:AWSGroup:AWSPrincipal{id: 'g-own'})
        MERGE (other)-[:RESOURCE]->(:AWSUser:AWSPrincipal{id: 'u-other'})
        MERGE (other)-[:RESOURCE]->(:AWSGroup:AWSPrincipal{id: 'g-other'})
        """,
    )

    identitystore.load_identity_center_group_memberships(
        neo4j_session,
        [
            {'GroupId': 'g-own', 'MemberId': {'UserId': 'u-own'}},
            {'GroupId': 'g-own', 'MemberId': {'UserId': 'u-other'}},
            {'GroupId': 'g-other', 'MemberId': {'UserId': 'u-own'}},
        ],
        TAG, 'arn:sso-own',
    )
    for principal in ('u-own', 'u-other'):
        neo4j_session.execute_write(
            identitystore._load_identity_center_account_assignments_tx,
            {'PrincipalId': principal, 'AccountId': 'ic-account'}, {'Name': 'ps'}, 'arn:sso-own', TAG,
        )

    members = neo4j_session.run("MATCH (u)-[:MEMBER_AWS_GROUP]->(g) RETURN u.id AS u, g.id AS g")
    assert {(r['u'], r['g']) for r in members} == {('u-own', 'g-own')}
    assigned = neo4j_session.run("MATCH (:AWSPermissionSet)-[:ASSIGNED_TO]->(p) RETURN p.id AS p")
    assert [r['p'] for r in assigned] == ['u-own']
