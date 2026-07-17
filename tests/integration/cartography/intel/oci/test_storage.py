# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.storage as test_data
from cartography.intel.oci import storage
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_UPDATE_TAG = 123456789


def _seed_compartment(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )


def test_load_buckets_batches_across_chunk_boundary(neo4j_session):
    # 600 > the 500-row load_graph_data batch size: proves batching loads all rows.
    _seed_compartment(neo4j_session)
    buckets = test_data.bucket_list(600)

    storage.load_buckets(neo4j_session, buckets, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG)

    count = neo4j_session.run("MATCH (b:OCIStorageBucket) RETURN count(b) AS c").single()["c"]
    assert count == 600
    # spot-check the compartment RESOURCE edge on a row from each batch
    rels = check_rels(
        neo4j_session, "OCICompartment", "id", "OCIStorageBucket", "id", "RESOURCE",
    )
    assert (TEST_COMPARTMENT_ID, "oci.bucket.0") in rels
    assert (TEST_COMPARTMENT_ID, "oci.bucket.599") in rels


def test_load_block_volumes(neo4j_session):
    _seed_compartment(neo4j_session)
    storage.load_block_volumes(
        neo4j_session, test_data.BLOCK_VOLUMES, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIBlockVolume", ["id"]) == {("oci.blockvol.0",)}
    assert (TEST_COMPARTMENT_ID, "oci.blockvol.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIBlockVolume", "id", "RESOURCE",
    )


def test_load_boot_volumes(neo4j_session):
    _seed_compartment(neo4j_session)
    storage.load_boot_volumes(
        neo4j_session, test_data.BOOT_VOLUMES, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIBootVolume", ["id"]) == {("oci.bootvol.0",)}


def test_load_volume_backups_links_both_parent_kinds(neo4j_session):
    _seed_compartment(neo4j_session)
    storage.load_block_volumes(
        neo4j_session, test_data.BLOCK_VOLUMES, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    storage.load_boot_volumes(
        neo4j_session, test_data.BOOT_VOLUMES, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    storage.load_volume_backups(neo4j_session, test_data.VOLUME_BACKUPS, TEST_UPDATE_TAG)

    assert check_nodes(neo4j_session, "OCIVolumeBackup", ["id"]) == {
        ("oci.backup.block.0",), ("oci.backup.boot.0",),
    }
    assert ("oci.blockvol.0", "oci.backup.block.0") in check_rels(
        neo4j_session, "OCIBlockVolume", "id", "OCIVolumeBackup", "id", "OCI_VOLUME_BACKUP",
    )
    assert ("oci.bootvol.0", "oci.backup.boot.0") in check_rels(
        neo4j_session, "OCIBootVolume", "id", "OCIVolumeBackup", "id", "OCI_VOLUME_BACKUP",
    )


def test_load_file_storage(neo4j_session):
    _seed_compartment(neo4j_session)
    storage.load_file_systems(
        neo4j_session, test_data.FILE_SYSTEMS, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    storage.load_mount_targets(
        neo4j_session, test_data.MOUNT_TARGETS, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    storage.load_exports(neo4j_session, test_data.EXPORTS, TEST_UPDATE_TAG)

    assert check_nodes(neo4j_session, "OCIFileSystem", ["id"]) == {("oci.fs.0",)}
    assert check_nodes(neo4j_session, "OCIMountTarget", ["id"]) == {("oci.mt.0",)}
    # export wires mount target -> file system
    assert ("oci.mt.0", "oci.fs.0") in check_rels(
        neo4j_session, "OCIMountTarget", "id", "OCIFileSystem", "id", "OCI_EXPORT",
    )
