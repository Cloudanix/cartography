from cartography.intel.gcp import dns
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_records_and_keys_link_only_zones_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, zone in ((OWN, 'dns-zone-a'), (FOREIGN, 'dns-zone-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPDNSZone', zone)

    zones = ('dns-zone-a', 'dns-zone-b')
    dns.load_rrs(neo4j_session, [{'id': f'{z}/rrs', 'zone': z} for z in zones], OWN, TAG)
    dns.load_dns_keys(neo4j_session, [{'id': f'{z}/key', 'zone': z} for z in zones], OWN, TAG)

    assert sources(neo4j_session, 'HAS_RECORD', 'dns-zone-a/rrs') == {'dns-zone-a'}
    assert sources(neo4j_session, 'HAS_KEY', 'dns-zone-a/key') == {'dns-zone-a'}
    assert sources(neo4j_session, 'HAS_RECORD', 'dns-zone-b/rrs') == set()
    assert sources(neo4j_session, 'HAS_KEY', 'dns-zone-b/key') == set()
