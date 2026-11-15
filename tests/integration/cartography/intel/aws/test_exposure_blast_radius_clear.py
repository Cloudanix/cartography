"""
blast_radius.clear removes one account's L5 output (CAN_NETWORK_REACH edges and reach summaries) and
leaves every other account's untouched, including another workspace's.
"""
from cartography.intel.aws.exposure_layers import blast_radius
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TAG = 1700000000
WS, ORG, ACCOUNT = 'ws-clear', 'o-clear', '121212121212'
OTHER_WS, OTHER_ORG, OTHER_ACCOUNT = 'ws-clear-other', 'o-clear-other', '343434343434'
SUMMARY_PROPS = (
    'network_reachable_data_stores', 'network_reachable_data_store_count',
    'network_reachable_from_count', 'network_reachable_from_internet_exposed_count',
)


def _seed_l5(session, account, prefix):
    """One instance reaching one RDS instance and one Redshift cluster, with the summaries L5 writes."""
    session.run(
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (a)-[:RESOURCE]->(i:EC2Instance{id: $prefix + '-i'})
        SET i.network_reachable_data_stores = '[]', i.network_reachable_data_store_count = 2
        MERGE (a)-[:RESOURCE]->(db:RDSInstance{id: $prefix + '-db'})
        MERGE (a)-[:RESOURCE]->(rs:RedshiftCluster{id: $prefix + '-rs'})
        WITH i, db, rs
        UNWIND [db, rs] AS store
            SET store.network_reachable_from_count = 1, store.network_reachable_from_internet_exposed_count = 0
            MERGE (i)-[r:CAN_NETWORK_REACH]->(store) SET r.lastupdated = $tag
        """,
        account=account, prefix=prefix, tag=TAG,
    ).consume()


def _edges(session, prefix):
    return session.run(
        "MATCH (i:EC2Instance{id: $id})-[r:CAN_NETWORK_REACH]->() RETURN count(r) AS n", id=prefix + '-i',
    ).single()['n']


def _summary_props(session, prefix):
    rows = session.run(
        "MATCH (n) WHERE n.id STARTS WITH $prefix RETURN keys(n) AS keys", prefix=prefix + '-',
    )
    return {k for row in rows for k in row['keys'] if k in SUMMARY_PROPS}


def test_clear_removes_only_this_accounts_l5_output(neo4j_session):
    create_test_org_account(neo4j_session, WS, ORG, ACCOUNT)
    create_test_org_account(neo4j_session, OTHER_WS, OTHER_ORG, OTHER_ACCOUNT)
    _seed_l5(neo4j_session, ACCOUNT, 'mine')
    _seed_l5(neo4j_session, OTHER_ACCOUNT, 'other')

    blast_radius.clear(neo4j_session, exposure_job_parameters(WS, ORG, ACCOUNT, TAG + 1))

    assert _edges(neo4j_session, 'mine') == 0
    assert _summary_props(neo4j_session, 'mine') == set()
    # Another workspace's account keeps its edges and summaries.
    assert _edges(neo4j_session, 'other') == 2
    assert _summary_props(neo4j_session, 'other') == set(SUMMARY_PROPS)
    # The nodes themselves stay.
    assert neo4j_session.run(
        "MATCH (n) WHERE n.id IN ['mine-i', 'mine-db', 'mine-rs'] RETURN count(n) AS n",
    ).single()['n'] == 3
