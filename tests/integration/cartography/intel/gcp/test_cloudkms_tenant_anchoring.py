from cartography.intel.gcp import cloudkms
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import put_principal
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params


def test_kms_links_stay_in_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    put_principal(neo4j_session, 'a', 'kms@a.test')
    for project, t in ((OWN, 'a'), (FOREIGN, 'b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPLocation', f'kms-loc-{t}')
        put(neo4j_session, 'GCPLocation', f'kms-loc-{t}', 'RESOURCE', 'GCPKMSKeyRing', f'kms-ring-{t}')
        put(neo4j_session, 'GCPKMSKeyRing', f'kms-ring-{t}', 'RESOURCE', 'GCPKMSCryptoKey', f'kms-key-{t}')

    cloudkms.load_kms_key_rings(
        neo4j_session, [{'id': f'{loc}/new-ring', 'loc_id': loc} for loc in ('kms-loc-a', 'kms-loc-b')], OWN, TAG,
    )
    cloudkms.load_kms_crypto_keys(
        neo4j_session, [{'id': f'{r}/new-key', 'keyring_id': r} for r in ('kms-ring-a', 'kms-ring-b')], OWN, TAG,
    )
    for t in 'ab':
        cloudkms.attach_keyring_to_binding(neo4j_session, f'kms-ring-{t}', [{'id': f'ring-{t}/b'}], TAG, OWN)
        cloudkms.attach_crypto_key_to_bindings(neo4j_session, f'kms-key-{t}', [{'id': f'key-{t}/b'}], TAG, OWN)
        cloudkms.load_keyring_entity_relation(
            neo4j_session, {'id': f'kms-ring-{t}', 'entities': [{'email': 'kms@a.test'}]}, TAG, tenant_params(),
        )

    assert sources(neo4j_session, 'RESOURCE', 'kms-loc-a/new-ring') == {'kms-loc-a'}
    assert sources(neo4j_session, 'RESOURCE', 'kms-ring-a/new-key') == {'kms-ring-a'}
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'ring-a/b') == {'kms-ring-a'}
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'key-a/b') == {'kms-key-a'}
    assert sources(neo4j_session, 'USES', 'kms-ring-a') == {'kms@a.test'}
    assert sources(neo4j_session, 'RESOURCE', 'kms-loc-b/new-ring') == set()
    assert sources(neo4j_session, 'RESOURCE', 'kms-ring-b/new-key') == set()
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'ring-b/b') == set()
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'key-b/b') == set()
    assert sources(neo4j_session, 'USES', 'kms-ring-b') == set()
