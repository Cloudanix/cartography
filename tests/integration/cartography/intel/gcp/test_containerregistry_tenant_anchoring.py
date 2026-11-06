from cartography.intel.gcp import containerregistry
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_docker_images_land_only_in_a_repository_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, repo in ((OWN, 'cr-repo-a'), (FOREIGN, 'cr-repo-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPArtifactRegistryRepository', repo)

    for repo in ('cr-repo-a', 'cr-repo-b'):
        containerregistry.load_artifact_registry_docker_images(neo4j_session, [{'id': f'{repo}/img'}], repo, TAG, OWN)

    assert sources(neo4j_session, 'CONTAINS', 'cr-repo-a/img') == {'cr-repo-a'}
    assert sources(neo4j_session, 'CONTAINS', 'cr-repo-b/img') == set()
