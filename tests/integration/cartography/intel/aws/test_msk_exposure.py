import functools
import json

import cartography.intel.aws.msk
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import create_test_security_group_rule
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777774'
OTHER_ACCOUNT_ID = '888888888884'


def _arn(account_id, name):
    return f'arn:aws:kafka:us-east-1:{account_id}:cluster/{name}/uuid'


def _load(neo4j_session, account_id, clusters):
    # Shape of ListClustersV2 output; name -> (cluster type, PublicAccess type, security groups).
    raw = []
    for name, (cluster_type, public_access, groups) in clusters.items():
        cluster = {'ClusterArn': _arn(account_id, name), 'ClusterName': name, 'ClusterType': cluster_type}
        if cluster_type == 'SERVERLESS':
            cluster['Serverless'] = {'VpcConfigs': [{'SecurityGroupIds': groups, 'SubnetIds': []}]}
        else:
            cluster['Provisioned'] = {
                'BrokerNodeGroupInfo': {
                    'SecurityGroups': groups, 'ConnectivityInfo': {'PublicAccess': {'Type': public_access}},
                },
            }
        raw.append(cluster)
    cartography.intel.aws.msk.load_msk_clusters(
        neo4j_session, cartography.intel.aws.msk.transform_msk_clusters(raw, 'us-east-1'), account_id, TEST_UPDATE_TAG,
    )


def test_msk_cluster_exposure(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mskx', 'o-mskx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-mskx-other', 'o-mskx-other', OTHER_ACCOUNT_ID)
    _group = functools.partial(create_test_security_group_rule, neo4j_session)
    _group('mskx-sg-open-iam', '0.0.0.0/0', 'tcp', 9198, 9198)
    _group('mskx-sg-open-v6-tls', '::/0', 'tcp', 20094, 20094)
    _group('mskx-sg-all-traffic', '0.0.0.0/0', '-1', None, None)
    _group('mskx-sg-open-private-ports', '0.0.0.0/0', 'tcp', 9092, 9098)
    _group('mskx-sg-office', '203.0.113.0/24', 'tcp', 9194, 9198)
    _load(
        neo4j_session, ACCOUNT_ID, {
            'mskx-public-open': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-open-iam']),
            'mskx-public-open-v6': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-open-v6-tls']),
            'mskx-public-all-traffic': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-all-traffic']),
            'mskx-public-private-ports-only': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-open-private-ports']),
            'mskx-public-office-only': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-office']),
            'mskx-public-unsynced-group': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-never-synced']),
            'mskx-private-open-group': ('PROVISIONED', 'DISABLED', ['mskx-sg-all-traffic']),
            'mskx-serverless-open-group': ('SERVERLESS', None, ['mskx-sg-all-traffic']),
            'mskx-stale': ('PROVISIONED', 'DISABLED', []),
        },
    )
    _load(
        neo4j_session, OTHER_ACCOUNT_ID,
        {'mskx-other-public': ('PROVISIONED', 'SERVICE_PROVIDED_EIPS', ['mskx-sg-all-traffic'])},
    )
    neo4j_session.run(
        "MATCH (c:MSKCluster{name: 'mskx-stale'}) "
        "SET c.exposed_internet = true, c.exposed_internet_type = ['direct_ipv4']",
    )

    run_analysis_job(
        'aws_msk_cluster_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-mskx', 'o-mskx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (c:MSKCluster) RETURN c.name AS name, c.exposed_internet AS exposed, "
        "c.exposed_internet_type AS types, c.publicContext AS context",
    )
    clusters = {r['name']: r for r in rows}
    assert {n: sorted(r['types']) for n, r in clusters.items() if r['exposed']} == {
        'mskx-public-open': ['direct_ipv4'],
        'mskx-public-open-v6': ['direct_ipv6'],
        'mskx-public-all-traffic': ['direct_ipv4'],
        'mskx-public-unsynced-group': ['public_access_unresolved_security_group'],
    }
    context = json.loads(clusters['mskx-public-open']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        _arn(ACCOUNT_ID, 'mskx-public-open'), 'aws-applicationintegration-msk-cluster',
    )
    assert context['context'][0]['securityRules'] == [{
        'securityGroupId': 'mskx-sg-open-iam', 'fromPort': 9198, 'toPort': 9198, 'protocol': 'tcp',
        'ipRange': '0.0.0.0/0',
    }]
    assert clusters['mskx-stale']['context'] is None
