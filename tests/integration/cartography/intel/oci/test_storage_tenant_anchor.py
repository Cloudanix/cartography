"""
Storage lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
Tenancy B already holds the compartment / instance / volume / mount target / file system an id in
tenancy A's API data points at; A's sync must not link to it.
"""
import pytest

from cartography.intel.oci import storage
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

TAG = 7


def _tenancy_with_storage(neo4j_session, prefix):
    ids = seed_tenancy(neo4j_session, prefix)
    tenancy, compartment = ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID']
    # The instance has attachments naming the same block and boot volume in both tenancies, and a
    # VNIC on the shared subnet id.
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment})
        MERGE (c)-[:RESOURCE]->(i:OCIInstance{id: $prefix + '-inst'})
        MERGE (i)-[:OCI_VOLUME_ATTACHMENT]->(:OCIVolumeAttachment{
            id: $prefix + '-va', volume_id: 'shared-vol', lifecycle_state: 'ATTACHED'})
        MERGE (i)-[:OCI_BOOT_VOLUME_ATTACHMENT]->(:OCIBootVolumeAttachment{
            id: $prefix + '-bva', boot_volume_id: 'shared-bv', lifecycle_state: 'ATTACHED'})
        MERGE (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment{id: $prefix + '-vnicatt', subnet_id: 'shared-subnet'})
        """,
        compartment=compartment, prefix=prefix,
    )
    args = (tenancy, compartment, TAG)
    storage.load_block_volumes(neo4j_session, [{'id': f'{prefix}-vol', 'ocid': f'{prefix}-vol'}], *args)
    storage.load_file_systems(neo4j_session, [{'id': f'{prefix}-fs'}], *args)
    storage.load_mount_targets(
        neo4j_session, [{'id': f'{prefix}-mt', 'export_set_id': f'{prefix}-es', 'subnet_id': 'shared-subnet'}], *args,
    )
    return ids


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    return _tenancy_with_storage(neo4j_session, 'st-a'), _tenancy_with_storage(neo4j_session, 'st-b')


@pytest.mark.parametrize(
    'loader', [
        storage.load_buckets, storage.load_block_volumes, storage.load_boot_volumes,
        storage.load_file_systems, storage.load_mount_targets,
    ],
)
def test_storage_resources_attach_only_to_the_syncing_tenancys_compartment(neo4j_session, tenants, loader):
    a, b = tenants
    # A compartment that is not in the syncing tenancy (a mismatched job parameter) finds nothing.
    loader(neo4j_session, [{'id': 'a-own'}], a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG)
    loader(neo4j_session, [{'id': 'a-misplaced'}], a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], TAG)
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-own')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-misplaced')


def test_volumes_link_only_to_the_syncing_tenancys_instances(neo4j_session, tenants):
    a, _ = tenants
    args = (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG)
    storage.load_block_volumes(neo4j_session, [{'id': 'shared-vol', 'ocid': 'shared-vol'}], *args)
    storage.load_boot_volumes(neo4j_session, [{'id': 'shared-bv', 'ocid': 'shared-bv'}], *args)
    assert linked(neo4j_session, 'st-a-inst', 'OCI_VOLUME_ATTACHMENT', 'shared-vol')
    assert linked(neo4j_session, 'st-a-inst', 'OCI_BOOT_VOLUME_ATTACHMENT', 'shared-bv')
    assert not linked(neo4j_session, 'st-b-inst', 'OCI_VOLUME_ATTACHMENT', 'shared-vol')
    assert not linked(neo4j_session, 'st-b-inst', 'OCI_BOOT_VOLUME_ATTACHMENT', 'shared-bv')


def test_backups_link_only_to_the_syncing_tenancys_volume(neo4j_session, tenants):
    a, _ = tenants
    backups = [
        {'id': 'a-backup', 'source_kind': 'BLOCK', 'parent_volume_id': 'st-a-vol'},
        {'id': 'a-backup-foreign', 'source_kind': 'BLOCK', 'parent_volume_id': 'st-b-vol'},
    ]
    storage.load_volume_backups(neo4j_session, backups, a['OCI_TENANCY_ID'], TAG)
    assert linked(neo4j_session, 'st-a-vol', 'OCI_VOLUME_BACKUP', 'a-backup')
    assert not linked(neo4j_session, 'st-b-vol', 'OCI_VOLUME_BACKUP', 'a-backup-foreign')


def test_exports_and_mounts_stay_in_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    exports = [
        {'ocid': 'a-export', 'export_set_id': 'st-a-es', 'file_system_id': 'st-a-fs'},
        {'ocid': 'a-export-foreign-mt', 'export_set_id': 'st-b-es', 'file_system_id': 'st-a-fs'},
        {'ocid': 'a-export-foreign-fs', 'export_set_id': 'st-a-es', 'file_system_id': 'st-b-fs'},
    ]
    storage.load_exports(neo4j_session, exports, a['OCI_TENANCY_ID'], TAG)
    assert linked(neo4j_session, 'st-a-mt', 'OCI_EXPORT', 'st-a-fs')
    assert not linked(neo4j_session, 'st-b-mt', 'OCI_EXPORT', 'st-a-fs')
    assert not linked(neo4j_session, 'st-a-mt', 'OCI_EXPORT', 'st-b-fs')

    # Tenancy B's instance sits on the same subnet id as A's mount target.
    storage.link_instances_to_file_systems(neo4j_session, a['OCI_TENANCY_ID'], TAG)
    assert linked(neo4j_session, 'st-a-inst', 'MOUNTS', 'st-a-fs')
    assert not linked(neo4j_session, 'st-b-inst', 'MOUNTS', 'st-a-fs')
