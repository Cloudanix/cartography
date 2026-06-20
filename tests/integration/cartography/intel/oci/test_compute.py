# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.compute as test_data
from cartography.intel.oci import compute
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_TENANCY_ID = test_data.TEST_TENANCY_ID
TEST_REGION = test_data.TEST_REGION
TEST_UPDATE_TAG = 123456789


def _seed_compartment(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )


def test_load_instances(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIInstance", ["id", "display_name"]) == {
        ("oci.instance.0", "instance-0"),
    }
    assert (TEST_COMPARTMENT_ID, "oci.instance.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIInstance", "id", "RESOURCE",
    )


def test_load_vnic_attachments(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    compute.load_vnic_attachments(
        neo4j_session, test_data.VNIC_ATTACHMENTS, TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIVnicAttachment", ["id"]) == {("oci.vnicatt.0",)}
    assert ("oci.instance.0", "oci.vnicatt.0") in check_rels(
        neo4j_session, "OCIInstance", "id", "OCIVnicAttachment", "id", "OCI_VNIC_ATTACHMENT",
    )


def test_load_images(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_images(
        neo4j_session, test_data.IMAGES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIImage", ["id"]) == {("oci.image.0",)}
    assert (TEST_COMPARTMENT_ID, "oci.image.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIImage", "id", "RESOURCE",
    )


def test_load_boot_volume_attachments(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    compute.load_boot_volume_attachments(
        neo4j_session, test_data.BOOT_VOLUME_ATTACHMENTS, TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    assert ("oci.instance.0", "oci.bva.0") in check_rels(
        neo4j_session, "OCIInstance", "id", "OCIBootVolumeAttachment", "id",
        "OCI_BOOT_VOLUME_ATTACHMENT",
    )


def test_load_volume_attachments(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    compute.load_volume_attachments(
        neo4j_session, test_data.VOLUME_ATTACHMENTS, TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    assert ("oci.instance.0", "oci.va.0") in check_rels(
        neo4j_session, "OCIInstance", "id", "OCIVolumeAttachment", "id",
        "OCI_VOLUME_ATTACHMENT",
    )


def test_load_boot_volumes_links_instance(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    compute.load_boot_volume_attachments(
        neo4j_session, test_data.BOOT_VOLUME_ATTACHMENTS, TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    compute.load_boot_volumes(
        neo4j_session, test_data.BOOT_VOLUMES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIBootVolume", ["id"]) == {("oci.bootvol.0",)}
    # instance -> boot volume, resolved via the attachment
    assert ("oci.instance.0", "oci.bootvol.0") in check_rels(
        neo4j_session, "OCIInstance", "id", "OCIBootVolume", "id", "OCI_BOOT_VOLUME",
    )


def test_load_block_volumes_links_instance(neo4j_session):
    _seed_compartment(neo4j_session)
    compute.load_instances(
        neo4j_session, test_data.INSTANCES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    compute.load_volume_attachments(
        neo4j_session, test_data.VOLUME_ATTACHMENTS, TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    compute.load_block_volumes(
        neo4j_session, test_data.BLOCK_VOLUMES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIBlockVolume", ["id"]) == {("oci.blockvol.0",)}
    # block volume -> instance (ATTACHED_TO), resolved via the volume attachment
    assert ("oci.blockvol.0", "oci.instance.0") in check_rels(
        neo4j_session, "OCIBlockVolume", "id", "OCIInstance", "id", "ATTACHED_TO",
    )
