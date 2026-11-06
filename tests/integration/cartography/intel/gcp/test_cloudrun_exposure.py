import json

import cartography.intel.gcp.cloudrun
from cartography.util import run_analysis_job

PROJECT = 'proj-run-exp'
TAG = 700
PARAMS = {
    'UPDATE_TAG': TAG, 'WORKSPACE_ID': 'ws-run-exp', 'GCP_ORGANIZATION_ID': 'org-run-exp', 'GCP_PROJECT_ID': PROJECT,
    'LIMIT_SIZE': 1000,
}
OTHER_WORKSPACE_PROJECT = 'proj-run-exp-other'


def _service(name, ingress='all', invokers=(), status='resolved', iam_disabled=False, region='us-central1'):
    return {
        'id': f'projects/{PROJECT}/locations/{region}/services/{name}', 'region': region,
        'url': f'https://{name}.a.run.app', 'metadata': {'name': name}, 'ingress': ingress,
        'invoker_iam_disabled': iam_disabled, 'public_invokers': list(invokers), 'iam_policy_status': status,
    }


SERVICES = [
    _service('all-users', invokers=['allUsers']),
    _service('all-authenticated', invokers=['allAuthenticatedUsers']),
    # No ingress annotation means all.
    _service('default-ingress', ingress=None, invokers=['allUsers']),
    _service('iam-check-off', iam_disabled=True, status='not_needed'),
    _service('iam-unknown', status='unresolved'),
    # A value this job does not know is treated like all (fail-safe).
    _service('future-ingress', ingress='something-new', invokers=['allUsers']),
    # Not public: nobody anonymous can invoke, or the run.app URL refuses internet traffic.
    _service('private-iam', invokers=[]),
    _service('internal', ingress='internal', iam_disabled=True, status='not_needed'),
    _service('lb-ingress-no-neg', ingress='internal-and-cloud-load-balancing', invokers=['allUsers']),
    _service('lb-ingress-internal-neg', ingress='internal-and-cloud-load-balancing', invokers=['allUsers']),
    _service('lb-ingress-private-iam', ingress='internal-and-cloud-load-balancing', invokers=[]),
    _service('internal-behind-lb', ingress='internal', invokers=['allUsers']),
    # Reachable through an external load balancer (serverless NEG of PR #506).
    _service('lb-ingress-public', ingress='internal-and-cloud-load-balancing', invokers=['allUsers']),
    _service('all-and-lb', invokers=['allUsers']),
    # Its serverless NEG is in another region than the service.
    _service(
        'lb-other-region', ingress='internal-and-cloud-load-balancing', invokers=['allUsers'], region='asia-east1',
    ),
]


def _seed(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(:GCPProject{id: $project})
        MERGE (:CloudanixWorkspace{id: 'ws-run-exp-other'})-[:OWNER]->(:GCPOrganization{id: 'org-run-exp-other'})
              -[:OWNER]->(:GCPProject{id: $other})
        """,
        ws=PARAMS['WORKSPACE_ID'], org=PARAMS['GCP_ORGANIZATION_ID'], project=PROJECT, other=OTHER_WORKSPACE_PROJECT,
    )
    cartography.intel.gcp.cloudrun.load_cloudrun_services(neo4j_session, SERVICES, PROJECT, TAG)
    other = _service('all-users', invokers=['allUsers'])
    other['id'] = f'projects/{OTHER_WORKSPACE_PROJECT}/locations/us-central1/services/all-users'
    cartography.intel.gcp.cloudrun.load_cloudrun_services(neo4j_session, [other], OTHER_WORKSPACE_PROJECT, TAG)
    # Stale flags from an earlier run must be cleared when the service is no longer public.
    neo4j_session.run(
        """
        MATCH (s:GCPCloudRunService{id: $id})
        SET s.exposed_internet = true, s.exposed_internet_type = ['allUsers'], s.publicContext = '[]'
        """,
        id=f'projects/{PROJECT}/locations/us-central1/services/private-iam',
    )
    # Serverless NEGs as gcp_load_balancer_exposure.json (with PR #506) leaves them: the NEG holds the Cloud Run
    # target as properties and is flagged when an external load balancer reaches it.
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        UNWIND $negs AS n
        MERGE (p)-[:RESOURCE]->(neg:GCPNetworkEndpointGroup{id: n.id})
        SET neg.network_endpoint_type = 'SERVERLESS', neg.region = n.region, neg.cloud_run_service = n.service,
            neg.exposed_internet = n.exposed, neg.exposed_internet_type = n.types
        """,
        project=PROJECT, negs=[
            {
                'id': 'neg-public', 'region': 'us-central1', 'service': 'lb-ingress-public', 'exposed': True,
                'types': ['external_load_balancer'],
            },
            {
                'id': 'neg-public-2', 'region': 'us-central1', 'service': 'lb-ingress-public', 'exposed': True,
                'types': ['external_load_balancer'],
            },
            {
                'id': 'neg-all', 'region': 'us-central1', 'service': 'all-and-lb', 'exposed': True,
                'types': ['external_load_balancer'],
            },
            {
                'id': 'neg-private-iam', 'region': 'us-central1', 'service': 'lb-ingress-private-iam', 'exposed': True,
                'types': ['external_load_balancer'],
            },
            {
                'id': 'neg-internal', 'region': 'us-central1', 'service': 'internal-behind-lb', 'exposed': True,
                'types': ['external_load_balancer'],
            },
            # Behind an internal load balancer only.
            {
                'id': 'neg-internal-lb', 'region': 'us-central1', 'service': 'lb-ingress-internal-neg',
                'exposed': None, 'types': None,
            },
            {
                'id': 'neg-wrong-region', 'region': 'us-central1', 'service': 'lb-other-region', 'exposed': True,
                'types': ['external_load_balancer'],
            },
        ],
    )


def _exposure(neo4j_session):
    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project})-[:RESOURCE]->(s:GCPCloudRunService)
        RETURN s.id AS id, s.exposed_internet AS exposed, s.exposed_internet_type AS types, s.publicContext AS ctx
        """,
        project=PROJECT,
    ).data()
    return {r['id'].split('/')[-1]: r for r in rows}


def test_cloudrun_service_exposure(neo4j_session):
    _seed(neo4j_session)

    run_analysis_job('gcp_cloudrun_service_exposure.json', neo4j_session, PARAMS)

    exposure = _exposure(neo4j_session)
    public = {name: sorted(r['types']) for name, r in exposure.items() if r['exposed']}
    assert public == {
        'all-users': ['allUsers'],
        'all-authenticated': ['allAuthenticatedUsers'],
        'default-ingress': ['allUsers'],
        'iam-check-off': ['invoker_iam_disabled'],
        'iam-unknown': ['iam_policy_unresolved'],
        'future-ingress': ['allUsers'],
        'lb-ingress-public': ['allUsers', 'external_load_balancer'],
        'all-and-lb': ['allUsers', 'external_load_balancer'],
    }
    not_public = {name: r for name, r in exposure.items() if name not in public}
    assert all(r['types'] is None and r['ctx'] is None for r in not_public.values())

    context = json.loads(exposure['lb-ingress-public']['ctx'])
    assert context[0]['resource'] == f'projects/{PROJECT}/locations/us-central1/services/lb-ingress-public'
    assert context[0]['resourceType'] == 'gcp-compute-cloudrun-service'
    assert context[0]['context'][0]['ingress'] == 'internal-and-cloud-load-balancing'
    assert context[0]['context'][0]['url'] == 'https://lb-ingress-public.a.run.app'
    assert sorted(context[0]['context'][0]['exposureTypes']) == ['allUsers', 'external_load_balancer']

    # Scoped to the workspace's project: the other workspace's public service is left alone.
    other = neo4j_session.run(
        "MATCH (s:GCPCloudRunService{id: $id}) RETURN s.exposed_internet AS exposed",
        id=f'projects/{OTHER_WORKSPACE_PROJECT}/locations/us-central1/services/all-users',
    ).single()
    assert other['exposed'] is None


def test_cloudrun_service_exposure_is_idempotent(neo4j_session):
    run_analysis_job('gcp_cloudrun_service_exposure.json', neo4j_session, PARAMS)
    first = _exposure(neo4j_session)

    run_analysis_job('gcp_cloudrun_service_exposure.json', neo4j_session, PARAMS)

    assert _exposure(neo4j_session) == first
