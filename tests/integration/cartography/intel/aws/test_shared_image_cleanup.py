import pytest

from cartography.intel.aws import ecr
from cartography.intel.aws.ec2 import images
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

# Real-looking epoch seconds: the orphan sweeps only delete nodes untouched for ORPHAN_GRACE.
ORPHAN_GRACE = 86400
CLEANUP_TAG = 1_793_600_000
OWNER_TAG = CLEANUP_TAG - 3600
OLD_TAG = CLEANUP_TAG - 2 * ORPHAN_GRACE
ACCOUNT_ID = '777777777808'
OTHER_ACCOUNT_ID = '888888888808'


def _seed_accounts(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-shc', 'o-shc', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-shc-other', 'o-shc-other', OTHER_ACCOUNT_ID)


def _cleanup_params():
    # OTHER_ACCOUNT_ID syncs last and no longer has the shared images.
    return exposure_job_parameters('ws-shc-other', 'o-shc-other', OTHER_ACCOUNT_ID, CLEANUP_TAG)


def test_ec2_image_cleanup_keeps_a_node_another_tenant_still_holds(neo4j_session):
    _seed_accounts(neo4j_session)
    # Legacy shared node: last written by ACCOUNT_ID, still held by it; OTHER_ACCOUNT_ID's edge is stale.
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account}), (b:AWSAccount{id: $other})
        MERGE (img:EC2Image{id: 'ami-shc-shared|us-east-1'}) SET img.lastupdated = $owner_tag
        MERGE (a)-[:RESOURCE{lastupdated: $owner_tag}]->(img)
        MERGE (b)-[:RESOURCE{lastupdated: $old_tag}]->(img)
        MERGE (gone:EC2Image{id: 'ami-shc-gone|us-east-1'}) SET gone.lastupdated = $old_tag
        MERGE (b)-[:RESOURCE{lastupdated: $old_tag}]->(gone)
        """,
        account=ACCOUNT_ID, other=OTHER_ACCOUNT_ID, owner_tag=OWNER_TAG, old_tag=OLD_TAG,
    )

    images.cleanup_images(neo4j_session, _cleanup_params())

    held = {
        (row['account'], row['img']) for row in neo4j_session.run(
            """
            MATCH (a:AWSAccount)-[:RESOURCE]->(img:EC2Image) WHERE img.id STARTS WITH 'ami-shc-'
            RETURN a.id AS account, img.id AS img
            """,
        )
    }
    assert held == {(ACCOUNT_ID, 'ami-shc-shared|us-east-1')}
    orphans = neo4j_session.run("MATCH (img:EC2Image{id: 'ami-shc-gone|us-east-1'}) RETURN count(img) AS n")
    assert orphans.single()['n'] == 0


def test_ecr_cleanup_keeps_an_image_another_tenant_still_references(neo4j_session):
    _seed_accounts(neo4j_session)
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account}), (b:AWSAccount{id: $other})
        MERGE (img:ECRImage{id: 'sha256:shc-shared'}) SET img.lastupdated = $owner_tag
        MERGE (gone:ECRImage{id: 'sha256:shc-gone'}) SET gone.lastupdated = $old_tag
        MERGE (a)-[:RESOURCE{lastupdated: $owner_tag}]->(ra:ECRRepository{id: 'shc-repo-a'})
        SET ra.lastupdated = $owner_tag
        MERGE (ra)-[:REPO_IMAGE{lastupdated: $owner_tag}]->(ria:ECRRepositoryImage{id: 'shc-repo-a:1'})
        SET ria.lastupdated = $owner_tag
        MERGE (ria)-[:IMAGE{lastupdated: $owner_tag}]->(img)
        MERGE (b)-[:RESOURCE{lastupdated: $cleanup_tag}]->(rb:ECRRepository{id: 'shc-repo-b'})
        SET rb.lastupdated = $cleanup_tag
        MERGE (rb)-[:REPO_IMAGE{lastupdated: $old_tag}]->(rib:ECRRepositoryImage{id: 'shc-repo-b:1'})
        SET rib.lastupdated = $old_tag
        MERGE (rib)-[:IMAGE{lastupdated: $old_tag}]->(img)
        MERGE (rb)-[:REPO_IMAGE{lastupdated: $old_tag}]->(rib2:ECRRepositoryImage{id: 'shc-repo-b:2'})
        SET rib2.lastupdated = $old_tag
        MERGE (rib2)-[:IMAGE{lastupdated: $old_tag}]->(gone)
        """,
        account=ACCOUNT_ID, other=OTHER_ACCOUNT_ID, owner_tag=OWNER_TAG, old_tag=OLD_TAG, cleanup_tag=CLEANUP_TAG,
    )

    ecr.cleanup(neo4j_session, _cleanup_params())

    links = {
        (row['ri'], row['img']) for row in neo4j_session.run(
            """
            MATCH (ri:ECRRepositoryImage)-[:IMAGE]->(img:ECRImage) WHERE img.id STARTS WITH 'sha256:shc-'
            RETURN ri.id AS ri, img.id AS img
            """,
        )
    }
    assert links == {('shc-repo-a:1', 'sha256:shc-shared')}
    orphans = neo4j_session.run("MATCH (img:ECRImage{id: 'sha256:shc-gone'}) RETURN count(img) AS n")
    assert orphans.single()['n'] == 0


@pytest.mark.parametrize(
    'label, job', [
        ('EC2Image', 'aws_ec2_image_orphan_cleanup.json'),
        ('ECRImage', 'aws_ecr_image_orphan_cleanup.json'),
    ],
)
def test_orphan_sweep_spares_a_node_another_worker_just_wrote(neo4j_session, label, job):
    # 'fresh' stands for a node another worker's sync has written but not linked yet; the sweep must
    # leave it alone. 'stale' has had no edge and no write for longer than the grace window.
    neo4j_session.run(
        f"""
        MERGE (fresh:{label}{{id: 'shc-sweep-fresh'}}) SET fresh.lastupdated = $fresh_tag
        MERGE (edge:{label}{{id: 'shc-sweep-edge'}}) SET edge.lastupdated = $old_tag
        MERGE (stale:{label}{{id: 'shc-sweep-stale'}}) SET stale.lastupdated = $old_tag
        MERGE (holder:ShcSweepHolder{{id: 'shc-sweep-holder'}})-[:HOLDS]->(edge)
        """,
        fresh_tag=CLEANUP_TAG - 60, old_tag=OLD_TAG,
    )

    run_cleanup_job(job, neo4j_session, {'UPDATE_TAG': CLEANUP_TAG})

    left = {
        row['id'] for row in neo4j_session.run(
            f"MATCH (n:{label}) WHERE n.id STARTS WITH 'shc-sweep-' RETURN n.id AS id",
        )
    }
    assert left == {'shc-sweep-fresh', 'shc-sweep-edge'}
