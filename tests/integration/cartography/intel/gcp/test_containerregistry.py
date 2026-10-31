from typing import Dict
from typing import List
from typing import Optional

import cartography.intel.gcp.containerregistry
import tests.data.gcp.containerregistry
from cartography.intel.gcp import label

TEST_WORKSPACE_ID = 'ws-ar'
TEST_ORG_ID = 'organizations/ar'
TEST_PROJECT_ID = 'test-project'
OTHER_PROJECT_ID = 'ar-other-project'
TEST_UPDATE_TAG = 123456789


class _Request:
    def __init__(self, response: Dict):
        self.response = response

    def execute(self) -> Dict:
        return self.response


class _Collection:
    """One Artifact Registry collection: list() answers from `responder`, list_next() never pages."""

    def __init__(self, responder, calls: List, child: Optional['_Collection'] = None):
        self.responder = responder
        self.calls = calls
        self.child = child

    def list(self, **kwargs) -> _Request:
        self.calls.append(kwargs)
        return _Request(self.responder(**kwargs))

    def list_next(self, previous_request=None, previous_response=None) -> Optional[_Request]:
        return None

    # locations().repositories() and repositories().dockerImages()
    def repositories(self) -> Optional['_Collection']:
        return self.child

    def dockerImages(self) -> Optional['_Collection']:
        return self.child


class FakeArtifactRegistry:
    """Stands in for build('artifactregistry', 'v1'): projects().locations()[.repositories()[.dockerImages()]]."""

    def __init__(self, locations: List[Dict], repositories: List[Dict], images: Optional[Dict] = None):
        self.calls: Dict[str, List] = {'locations': [], 'repositories': [], 'dockerImages': []}
        self._images = images or {}
        docker_images = _Collection(self._list_images, self.calls['dockerImages'])
        repos = _Collection(
            lambda parent, **kw: {'repositories': [r for r in repositories if r['name'].startswith(parent + '/')]},
            self.calls['repositories'],
            docker_images,
        )
        self._locations = _Collection(lambda **kw: {'locations': locations}, self.calls['locations'], repos)

    def _list_images(self, parent, pageSize=None, orderBy=None, **kw) -> Dict:
        images = list(self._images.get(parent, []))
        if orderBy == 'update_time desc':
            images.sort(key=lambda i: i['updateTime'], reverse=True)
        if pageSize is not None and len(images) > pageSize:
            return {'dockerImages': images[:pageSize], 'nextPageToken': 'more'}
        return {'dockerImages': images}

    def projects(self):
        return self

    def locations(self):
        return self._locations


def _common_job_parameters(project_id: str = TEST_PROJECT_ID) -> Dict:
    return {
        'UPDATE_TAG': TEST_UPDATE_TAG,
        'WORKSPACE_ID': TEST_WORKSPACE_ID,
        'GCP_ORGANIZATION_ID': TEST_ORG_ID,
        'GCP_PROJECT_ID': project_id,
        'LIMIT_SIZE': 1000,
        'service_labels': [],
    }


def _seed_owner_chain(neo4j_session) -> None:
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: $ws})
        MERGE (o:GCPOrganization{id: $org})
        MERGE (w)-[:OWNER]->(o)
        WITH o
        UNWIND $projects AS pid
        MERGE (p:GCPProject{id: pid})
        MERGE (o)-[:OWNER]->(p)
        """,
        ws=TEST_WORKSPACE_ID, org=TEST_ORG_ID, projects=[TEST_PROJECT_ID, OTHER_PROJECT_ID],
    )


def _sync(neo4j_session, client: FakeArtifactRegistry, project_id: str = TEST_PROJECT_ID) -> Dict:
    params = _common_job_parameters(project_id)
    cartography.intel.gcp.containerregistry.sync(
        neo4j_session, client, project_id, TEST_UPDATE_TAG, params, ['us-central1'],
    )
    return params


def test_sync_loads_repositories_with_neo4j_safe_properties(neo4j_session):
    _seed_owner_chain(neo4j_session)
    client = FakeArtifactRegistry(
        tests.data.gcp.containerregistry.GCP_LOCATIONS,
        tests.data.gcp.containerregistry.ARTIFACT_REGISTRY_REPOSITORIES,
    )

    _sync(neo4j_session, client)

    # One repositories.list per Artifact Registry location (multi-region "us" included), at the max page size.
    assert [c['parent'] for c in client.calls['repositories']] == [
        'projects/test-project/locations/us',
        'projects/test-project/locations/us-central1',
        'projects/test-project/locations/europe-west1',
    ]
    assert {c['pageSize'] for c in client.calls['repositories']} == {1000}

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $pid})-[:RESOURCE]->(r:GCPArtifactRegistryRepository)
        RETURN r.id AS id, r.name AS name, r.region AS region, r.format AS format, r.size_bytes AS size,
               r.immutable_tags AS immutable, r.cleanup_policy_count AS policies,
               r.vulnerability_scanning_state AS scanning, r.consolelink AS link, r.labels AS labels
        """,
        pid=TEST_PROJECT_ID,
    ).data()
    by_id = {r['id']: r for r in rows}
    assert set(by_id) == {
        'projects/test-project/locations/us-central1/repositories/my-repo',
        'projects/test-project/locations/us/repositories/gcr.io',
        'projects/test-project/locations/europe-west1/repositories/python-repo',
    }
    docker = by_id['projects/test-project/locations/us-central1/repositories/my-repo']
    assert docker['name'] == 'my-repo'
    assert docker['region'] == 'us-central1'
    assert docker['size'] == 1048576
    assert docker['immutable'] is True
    assert docker['policies'] == 1
    assert docker['scanning'] == 'SCANNING_ACTIVE'
    assert docker['labels'] is None
    assert by_id['projects/test-project/locations/us/repositories/gcr.io']['region'] == 'us'

    # Labels land as GCPLabel nodes, like every other GCP resource.
    labels = neo4j_session.run(
        """
        MATCH (r:GCPArtifactRegistryRepository{name: 'my-repo'})-[:LABELED]->(l:GCPLabel)
        RETURN l.key AS key, l.value AS value
        """,
    ).data()
    assert {(lb['key'], lb['value']) for lb in labels} == {('env', 'production'), ('team', 'backend')}


def test_cleanup_is_scoped_to_the_synced_project(neo4j_session):
    _seed_owner_chain(neo4j_session)
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $other})
        MERGE (p)-[:RESOURCE]->(r:GCPArtifactRegistryRepository{id: $keep})
        SET r.lastupdated = 1
        WITH 1 AS x
        MATCH (p:GCPProject{id: $pid})
        MERGE (p)-[:RESOURCE]->(s:GCPArtifactRegistryRepository{id: $stale})
        SET s.lastupdated = 1
        """,
        other=OTHER_PROJECT_ID, pid=TEST_PROJECT_ID,
        keep='projects/ar-other-project/locations/us/repositories/keep',
        stale='projects/test-project/locations/us/repositories/stale',
    )
    client = FakeArtifactRegistry(
        tests.data.gcp.containerregistry.GCP_LOCATIONS,
        tests.data.gcp.containerregistry.ARTIFACT_REGISTRY_REPOSITORIES,
    )

    params = _sync(neo4j_session, client)
    for service_label in params['service_labels']:
        label.cleanup_labels(neo4j_session, params, service_label)

    ids = {
        r['id'] for r in neo4j_session.run('MATCH (r:GCPArtifactRegistryRepository) RETURN r.id AS id').data()
    }
    assert 'projects/ar-other-project/locations/us/repositories/keep' in ids
    assert 'projects/test-project/locations/us/repositories/stale' not in ids


def test_sync_loads_the_latest_docker_images_per_docker_repository(neo4j_session, monkeypatch, caplog):
    _seed_owner_chain(neo4j_session)
    monkeypatch.setattr(cartography.intel.gcp.containerregistry, 'MAX_IMAGES_PER_REPOSITORY', 2)
    data = tests.data.gcp.containerregistry
    client = FakeArtifactRegistry(data.GCP_LOCATIONS, data.ARTIFACT_REGISTRY_REPOSITORIES, data.DOCKER_IMAGES)

    _sync(neo4j_session, client)

    # One bounded call per DOCKER repository, newest first; the PYTHON repository is not crawled.
    assert sorted(c['parent'] for c in client.calls['dockerImages']) == sorted([data.GCR_REPO, data.MY_REPO])
    assert {(c['pageSize'], c['orderBy']) for c in client.calls['dockerImages']} == {(2, 'update_time desc')}

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $pid})-[:RESOURCE]->(r:GCPArtifactRegistryRepository)
              -[:CONTAINS]->(i:GCPArtifactRegistryDockerImage)
        RETURN r.id AS repo, i.id AS id, i.name AS name, i.image_name AS image_name, i.digest AS digest,
               i.uri AS uri, i.tags AS tags, i.image_size_bytes AS size, i.region AS region,
               i.repository_id AS repository_id, i.project_id AS project_id
        """,
        pid=TEST_PROJECT_ID,
    ).data()
    by_id = {r['id']: r for r in rows}
    # my-repo holds 3 images: only the 2 most recently updated are kept.
    assert set(by_id) == {
        f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:aaa1',
        f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:aaa2',
        f'{data.GCR_REPO}/dockerImages/nginx@sha256:bbb1',
    }
    latest = by_id[f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:aaa1']
    assert latest['repo'] == data.MY_REPO
    assert latest['name'] == 'team/api@sha256:aaa1'
    assert latest['image_name'] == 'team/api'
    assert latest['digest'] == 'sha256:aaa1'
    assert latest['uri'] == 'us-central1-docker.pkg.dev/test-project/my-repo/team/api@sha256:aaa1'
    assert latest['tags'] == ['v3', 'latest']
    assert latest['size'] == 52428800
    assert latest['region'] == 'us-central1'
    assert latest['repository_id'] == data.MY_REPO
    assert latest['project_id'] == TEST_PROJECT_ID
    assert by_id[f'{data.GCR_REPO}/dockerImages/nginx@sha256:bbb1']['region'] == 'us'

    truncated = [r for r in caplog.records if r.levelname == 'WARNING' and 'most recent' in r.getMessage()]
    assert len(truncated) == 1
    assert data.MY_REPO in truncated[0].getMessage()


def test_image_cleanup_drops_images_that_left_the_window_and_stays_in_the_project(neo4j_session):
    _seed_owner_chain(neo4j_session)
    data = tests.data.gcp.containerregistry
    other_image = 'projects/ar-other-project/locations/us/repositories/r/dockerImages/x@sha256:1'
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $other})
        MERGE (p)-[:RESOURCE]->(r:GCPArtifactRegistryRepository{id: $other_repo})
        SET r.lastupdated = 1
        MERGE (r)-[:CONTAINS]->(i:GCPArtifactRegistryDockerImage{id: $other_image})
        SET i.lastupdated = 1
        WITH 1 AS x
        MATCH (r:GCPArtifactRegistryRepository{id: $my_repo})
        MERGE (r)-[:CONTAINS]->(old:GCPArtifactRegistryDockerImage{id: $old_image})
        SET old.lastupdated = 1
        """,
        other=OTHER_PROJECT_ID, other_image=other_image, my_repo=data.MY_REPO,
        other_repo='projects/ar-other-project/locations/us/repositories/r',
        old_image=f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:old',
    )
    client = FakeArtifactRegistry(data.GCP_LOCATIONS, data.ARTIFACT_REGISTRY_REPOSITORIES, data.DOCKER_IMAGES)

    _sync(neo4j_session, client)

    ids = {r['id'] for r in neo4j_session.run('MATCH (i:GCPArtifactRegistryDockerImage) RETURN i.id AS id').data()}
    assert other_image in ids
    assert f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:old' not in ids
    assert f'{data.MY_REPO}/dockerImages/team%2Fapi@sha256:aaa3' in ids  # default window (50) keeps all 3
