from cartography.intel.gcp import storage
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_policy_bindings_attach_only_to_buckets_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, bucket in ((OWN, 'gcs-a'), (FOREIGN, 'gcs-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPBucket', bucket)

    for bucket in ('gcs-a', 'gcs-b'):
        storage.load_bucket_iam_policy_bindings(
            neo4j_session, [{'id': f'{bucket}/binding', 'members': ['allUsers'], 'role': 'r'}], bucket, TAG, OWN,
        )

    assert sources(neo4j_session, 'ATTACHED_BINDING', 'gcs-a/binding') == {'gcs-a'}
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'gcs-b/binding') == set()
