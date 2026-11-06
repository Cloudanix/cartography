"""
Compute lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
Tenancy B already holds the compartment / instance / image / attachment an id in tenancy A's API data
points at; A's sync must not link to it or write to it.
"""
import pytest

from cartography.intel.oci import compute
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


def _tenancy_with_instance(neo4j_session, prefix):
    ids = seed_tenancy(neo4j_session, prefix)
    tenancy, compartment = ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID']
    compute.load_instances(
        neo4j_session, [{'id': f'{prefix}-inst', 'compartment-id': compartment, 'image-id': f'{prefix}-image'}],
        tenancy, compartment, REGION, TAG,
    )
    compute.load_images(
        neo4j_session, [{'id': f'{prefix}-image', 'operating-system': f'{prefix}-os'}], tenancy, compartment, TAG,
    )
    # Each tenancy's instance has attachments naming the same boot and block volume.
    compute.load_boot_volume_attachments(
        neo4j_session, [{'instance-id': f'{prefix}-inst', 'boot-volume-id': 'shared-bv'}], tenancy, TAG,
    )
    compute.load_volume_attachments(
        neo4j_session, [{'id': f'{prefix}-va', 'instance-id': f'{prefix}-inst', 'volume-id': 'shared-vol'}],
        tenancy, TAG,
    )
    return ids


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    return _tenancy_with_instance(neo4j_session, 'cmp-a'), _tenancy_with_instance(neo4j_session, 'cmp-b')


def test_instances_and_images_attach_only_to_the_syncing_tenancys_compartment(neo4j_session, tenants):
    a, b = tenants
    args = (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'])
    compute.load_instances(
        neo4j_session, [{'id': 'a-inst-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}], *args, REGION, TAG,
    )
    compute.load_images(neo4j_session, [{'id': 'a-image-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}], *args, TAG)
    compute.load_boot_volumes(
        neo4j_session, [{'id': 'a-bv-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}], *args, REGION, TAG,
    )
    compute.load_block_volumes(
        neo4j_session, [{'id': 'a-vol-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}], *args, REGION, TAG,
    )
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'cmp-a-inst')
    for node_id in ('a-inst-2', 'a-image-2', 'a-bv-2', 'a-vol-2'):
        assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', node_id), node_id


def test_attachments_link_only_to_the_syncing_tenancys_instance(neo4j_session, tenants):
    a, _ = tenants
    tenancy = a['OCI_TENANCY_ID']
    foreign = {'instance-id': 'cmp-b-inst'}
    compute.load_vnic_attachments(neo4j_session, [{'id': 'a-vnicatt', 'vnic-id': 'v', **foreign}], tenancy, TAG)
    compute.load_boot_volume_attachments(neo4j_session, [{'boot-volume-id': 'a-bv', **foreign}], tenancy, TAG)
    compute.load_volume_attachments(neo4j_session, [{'id': 'a-va-2', 'volume-id': 'a-vol', **foreign}], tenancy, TAG)
    assert linked(neo4j_session, 'cmp-a-inst', 'OCI_BOOT_VOLUME_ATTACHMENT', 'cmp-a-inst::shared-bv')
    assert linked(neo4j_session, 'cmp-a-inst', 'OCI_VOLUME_ATTACHMENT', 'cmp-a-va')
    assert not linked(neo4j_session, 'cmp-b-inst', 'OCI_VNIC_ATTACHMENT', 'a-vnicatt')
    assert not linked(neo4j_session, 'cmp-b-inst', 'OCI_BOOT_VOLUME_ATTACHMENT', 'cmp-b-inst::a-bv')
    assert not linked(neo4j_session, 'cmp-b-inst', 'OCI_VOLUME_ATTACHMENT', 'a-va-2')


def test_volumes_link_only_to_the_syncing_tenancys_attached_instance(neo4j_session, tenants):
    a, _ = tenants
    args = (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG)
    compute.load_boot_volumes(neo4j_session, [{'id': 'shared-bv'}], *args)
    compute.load_block_volumes(neo4j_session, [{'id': 'shared-vol'}], *args)
    assert linked(neo4j_session, 'cmp-a-inst', 'OCI_BOOT_VOLUME', 'shared-bv')
    assert linked(neo4j_session, 'shared-vol', 'ATTACHED_TO', 'cmp-a-inst')
    assert not linked(neo4j_session, 'cmp-b-inst', 'OCI_BOOT_VOLUME', 'shared-bv')
    assert not linked(neo4j_session, 'shared-vol', 'ATTACHED_TO', 'cmp-b-inst')


def test_ip_addresses_and_os_are_written_only_inside_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    compute.load_instance_ip_addresses(
        neo4j_session, {'cmp-b-inst': {'public_ip': '203.0.113.9'}}, a['OCI_TENANCY_ID'], TAG,
    )
    # Tenancy A's instance boots from tenancy B's image id.
    neo4j_session.run("MATCH (i:OCIInstance{id: 'cmp-a-inst'}) SET i.image_id = 'cmp-b-image'")
    neo4j_session.run(
        "MERGE (i:OCIInstance{id: 'cmp-a-inst-2'}) SET i.image_id = 'cmp-a-image', i.lastupdated = $t", t=TAG,
    )
    neo4j_session.run(
        "MATCH (c:OCICompartment{id: $c}), (i:OCIInstance{id: 'cmp-a-inst-2'}) MERGE (c)-[:RESOURCE]->(i)",
        c=a['OCI_COMPARTMENT_ID'],
    )
    compute._enrich_instances_with_image_os(neo4j_session, a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG)

    rows = neo4j_session.run(
        "MATCH (i:OCIInstance) WHERE i.id STARTS WITH 'cmp-' RETURN i.id AS id, i.public_ip AS ip, i.vm_os AS os",
    )
    found = {row['id']: (row['ip'], row['os']) for row in rows}
    assert found['cmp-b-inst'][0] is None
    assert found['cmp-a-inst'][1] is None
    assert found['cmp-a-inst-2'][1] == 'cmp-a-os'
