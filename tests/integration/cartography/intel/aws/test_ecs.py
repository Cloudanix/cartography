import copy

import cartography.intel.aws.ecs
import tests.data.aws.ecs
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters


TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
CLUSTER_ARN = 'arn:aws:ecs:us-east-1:000000000000:cluster/test_cluster'


def test_load_ecs_clusters(neo4j_session, *args):
    data = tests.data.aws.ecs.GET_ECS_CLUSTERS
    cartography.intel.aws.ecs.load_ecs_clusters(neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

    expected_nodes = {
        (
            CLUSTER_ARN,
            "test_cluster",
            "ACTIVE",
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSCluster)
        RETURN n.id, n.name, n.status
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.name'],
            n['n.status'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_load_ecs_container_instances(neo4j_session, *args):
    cartography.intel.aws.ecs.load_ecs_clusters(
        neo4j_session,
        tests.data.aws.ecs.GET_ECS_CLUSTERS,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.aws.ecs.GET_ECS_CONTAINER_INSTANCES
    cartography.intel.aws.ecs.load_ecs_container_instances(
        neo4j_session,
        CLUSTER_ARN,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:container-instance/test_instance/a0000000000000000000000000000000",
            "i-00000000000000000",
            "ACTIVE",
            100000,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSContainerInstance)
        RETURN n.id, n.ec2_instance_id, n.status, n.version
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.ec2_instance_id'],
            n['n.status'],
            n['n.version'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    nodes = neo4j_session.run(
        """
        MATCH (:ECSCluster)-[:HAS_CONTAINER_INSTANCE]->(n:ECSContainerInstance)
        RETURN count(n.id) AS c
        """,
    )
    for n in nodes:
        assert n["c"] == 1


def test_load_ecs_services(neo4j_session, *args):
    cartography.intel.aws.ecs.load_ecs_clusters(
        neo4j_session,
        tests.data.aws.ecs.GET_ECS_CLUSTERS,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.aws.ecs.GET_ECS_SERVICES
    cartography.intel.aws.ecs.load_ecs_services(
        neo4j_session,
        CLUSTER_ARN,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:service/test_instance/test_service",
            "test_service",
            "arn:aws:ecs:us-east-1:000000000000:cluster/test_cluster",
            "ACTIVE",
            1631096157,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSService)
        RETURN n.id, n.name, n.cluster_arn, n.status, n.created_at
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.name'],
            n['n.cluster_arn'],
            n['n.status'],
            n['n.created_at'],
        )
        for n in nodes
    }

    assert actual_nodes == expected_nodes

    nodes = neo4j_session.run(
        """
        MATCH (:ECSCluster)-[:HAS_SERVICE]->(n:ECSService)
        RETURN count(n.id) AS c
        """,
    )
    for n in nodes:
        assert n["c"] == 1


def test_load_ecs_tasks(neo4j_session, *args):
    data = tests.data.aws.ecs.GET_ECS_TASKS
    cartography.intel.aws.ecs.load_ecs_tasks(
        neo4j_session,
        CLUSTER_ARN,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:task/test_task/00000000000000000000000000000000",
            "arn:aws:ecs:us-east-1:000000000000:task-definition/test_definition:0",
            "arn:aws:ecs:us-east-1:000000000000:cluster/test_cluster",
            "service:test_service",
            1640673743,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSTask)
        RETURN n.id, n.task_definition_arn, n.cluster_arn, n.group, n.created_at
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.task_definition_arn'],
            n['n.cluster_arn'],
            n['n.group'],
            n['n.created_at'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:container/test_instance/00000000000000000000000000000000/00000000-0000-0000-0000-000000000000",  # noqa:E501
            "test-task_container",
            "000000000000.dkr.ecr.us-east-1.amazonaws.com/test-image:latest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSContainer)
        RETURN n.id, n.name, n.image, n.image_digest
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.name'],
            n['n.image'],
            n['n.image_digest'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    nodes = neo4j_session.run(
        """
        MATCH (:ECSTask)-[:HAS_CONTAINER]->(n:ECSContainer)
        RETURN count(n.id) AS c
        """,
    )
    for n in nodes:
        assert n["c"] == 1


def test_load_ecs_task_definitions(neo4j_session, *args):
    data = tests.data.aws.ecs.GET_ECS_TASK_DEFINITIONS
    cartography.intel.aws.ecs.load_ecs_task_definitions(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:task-definition/test_definition:0",
            "test_family",
            "ACTIVE",
            4,
            1626747090,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSTaskDefinition)
        RETURN n.id, n.family, n.status, n.revision, n.registered_at
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.family'],
            n['n.status'],
            n['n.revision'],
            n['n.registered_at'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    expected_nodes = {
        (
            "arn:aws:ecs:us-east-1:000000000000:task-definition/test_definition:0-test",
            "test",
            "test/test:latest",
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:ECSContainerDefinition)
        RETURN n.id, n.name, n.image
        """,
    )
    actual_nodes = {
        (
            n['n.id'],
            n['n.name'],
            n['n.image'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    nodes = neo4j_session.run(
        """
        MATCH (:ECSTaskDefinition)-[:HAS_CONTAINER_DEFINITION]->(n:ECSContainerDefinition)
        RETURN count(n.id) AS c
        """,
    )
    for n in nodes:
        assert n["c"] == 1

    nodes = neo4j_session.run(
        """
        MATCH (:ECSTaskDefinition)<-[:HAS_TASK_DEFINITION]-(n:ECSTask)
        RETURN n.id AS c
        """,
    )
    # TODO test later
    for n in nodes:
        assert n["c"] == 1


def _ecs_service(name, assign_public_ip):
    service = copy.deepcopy(tests.data.aws.ecs.GET_ECS_SERVICES[0])
    service['serviceArn'] = f'arn:aws:ecs:us-east-1:111111111111:service/exposure_cluster/{name}'
    service['serviceName'] = name
    # load_ecs_services converts createdAt in place, so the shared fixture may already hold an epoch int.
    service.pop('createdAt')
    if assign_public_ip is None:
        # EC2 launch type in bridge/host network mode: no awsvpc network configuration at all.
        del service['networkConfiguration']
    else:
        service['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] = assign_public_ip
    return service


def test_ecs_service_exposure_reads_awsvpc_assign_public_ip(neo4j_session):
    account_id = '111111111111'
    cluster_arn = 'arn:aws:ecs:us-east-1:111111111111:cluster/exposure_cluster'
    create_test_org_account(neo4j_session, 'ws-ecs', 'o-ecs', account_id)
    cartography.intel.aws.ecs.load_ecs_clusters(
        neo4j_session, [{'clusterArn': cluster_arn, 'clusterName': 'exposure_cluster'}], account_id, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.ecs.load_ecs_services(
        neo4j_session, cluster_arn, [
            _ecs_service('svc-public-ip', 'ENABLED'),
            _ecs_service('svc-private-ip', 'DISABLED'),
            _ecs_service('svc-bridge', None),
        ], TEST_REGION, account_id, TEST_UPDATE_TAG,
    )

    run_analysis_job(
        'aws_ecs_service_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-ecs', 'o-ecs', account_id, TEST_UPDATE_TAG + 1),
    )

    nodes = neo4j_session.run(
        """
        MATCH (:ECSCluster{id: $cluster_arn})-[:HAS_SERVICE]->(s:ECSService)
        RETURN s.name AS name, s.assign_public_ip AS assign_public_ip, s.exposed_internet AS exposed,
               s.exposed_internet_type AS types, s.publicContext IS NOT NULL AS has_context
        """,
        cluster_arn=cluster_arn,
    )
    assert {n['name']: (n['assign_public_ip'], n['exposed'], n['types'], n['has_context']) for n in nodes} == {
        'svc-public-ip': ('ENABLED', True, ['assign_public_ip'], True),
        'svc-private-ip': ('DISABLED', None, None, False),
        'svc-bridge': (None, None, None, False),
    }
