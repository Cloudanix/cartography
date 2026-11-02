from cartography.intel.gcp import sql
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import targets


def test_users_databases_and_addresses_link_only_instances_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, instance in ((OWN, 'sql-a'), (FOREIGN, 'sql-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPSQLInstance', instance)

    for instance, address in (('sql-a', '34.9.0.1'), ('sql-b', '34.9.0.2')):
        sql.load_sql_users(neo4j_session, [{'id': f'{instance}/user', 'instance_id': instance}], OWN, TAG)
        sql.load_sql_databases(neo4j_session, [{'id': f'{instance}/db', 'instance_id': instance}], OWN, TAG)
        sql.load_public_ip_address(
            neo4j_session, {'id': instance, 'ipAddresses': [{'type': 'PRIMARY', 'ipAddress': address}]}, OWN, TAG,
        )

    def links(instance):
        return {
            rel: targets(neo4j_session, instance, rel)
            for rel in ('USED_BY', 'HAS_DATABASE', 'MEMBER_OF_PUBLIC_IP_ADDRESS')
        }

    assert links('sql-a') == {
        'USED_BY': {'sql-a/user'}, 'HAS_DATABASE': {'sql-a/db'}, 'MEMBER_OF_PUBLIC_IP_ADDRESS': {'34.9.0.1'},
    }
    assert links('sql-b') == {'USED_BY': set(), 'HAS_DATABASE': set(), 'MEMBER_OF_PUBLIC_IP_ADDRESS': set()}
