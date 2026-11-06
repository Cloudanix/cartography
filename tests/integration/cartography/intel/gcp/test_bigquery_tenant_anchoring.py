from cartography.intel.gcp import bigquery
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_tables_and_acls_link_only_datasets_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, dataset in ((OWN, 'bq-ds-a'), (FOREIGN, 'bq-ds-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPBigqueryDataset', dataset)

    bigquery.load_bigquery_tables(
        neo4j_session, [{'id': f'{d}/t', 'datasetId': d, 'details': {}} for d in ('bq-ds-a', 'bq-ds-b')], OWN, TAG,
    )
    for dataset in ('bq-ds-a', 'bq-ds-b'):
        bigquery.attach_dataset_to_accesses(
            neo4j_session, dataset, [{'id': f'{dataset}/acl', 'role': 'READER'}], TAG, OWN,
        )

    assert sources(neo4j_session, 'HAS_TABLE', 'bq-ds-a/t') == {'bq-ds-a'}
    assert sources(neo4j_session, 'APPLIES_TO', 'bq-ds-a') == {'bq-ds-a/acl'}
    assert sources(neo4j_session, 'HAS_TABLE', 'bq-ds-b/t') == set()
    assert sources(neo4j_session, 'APPLIES_TO', 'bq-ds-b') == set()
