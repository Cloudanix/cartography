"""
Unit tests for uniform neo4j interactions in the oci intel modules
(perf plan Phase 3 items 5+6).
"""
from unittest.mock import MagicMock

from cartography.intel.oci import containerregistry
from cartography.intel.oci import database
from cartography.intel.oci import utils

TEST_UPDATE_TAG = 123456789
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaa"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..bbbb"


def assert_batched(call, rows):
    assert "UNWIND $DictList" in call.args[1]
    assert call.kwargs["DictList"] == rows


class TestDatabaseBatchedLoaders:
    def test_autonomous_databases_batched(self):
        session = MagicMock()
        adbs = [{"id": "ocid1.autonomousdatabase.oc1..cccc", "compartment-id": TEST_COMPARTMENT_ID}]

        database.load_autonomous_databases(session, adbs, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args_list[0], adbs)

    def test_db_systems_batched(self):
        session = MagicMock()
        systems = [{"id": "ocid1.dbsystem.oc1..dddd", "compartment-id": TEST_COMPARTMENT_ID}]

        database.load_db_systems(session, systems, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args_list[0], systems)


class TestManagedScalarWrites:
    def test_container_repository_write_is_managed(self):
        session = MagicMock()
        repos = [{"id": "ocid1.containerrepo.oc1..eeee", "display-name": "repo"}]

        containerregistry.load_container_repositories(
            session, repos, TEST_TENANCY_ID, TEST_COMPARTMENT_ID, "us-ashburn-1", TEST_UPDATE_TAG,
        )

        session.run.assert_not_called()
        assert session.execute_write.call_count >= 1


class TestReads:
    def test_tenancy_lookups_use_managed_reads(self):
        session = MagicMock()
        session.execute_read.return_value = [{"compartment.ocid": TEST_COMPARTMENT_ID}]

        result = utils.get_compartments_in_tenancy(session, TEST_TENANCY_ID)

        session.run.assert_not_called()
        session.execute_read.assert_called_once()
        assert result == [{"compartment.ocid": TEST_COMPARTMENT_ID}]
