import pytest

from cartography import util


def test_no_deadline_never_raises():
    util.check_sync_deadline("anything")
    with util.sync_deadline(None):
        util.check_sync_deadline("anything")


def test_spent_budget_raises_and_names_the_place(mocker):
    clock = mocker.patch("cartography.util.time.monotonic", return_value=1000.0)
    with util.sync_deadline(420):
        clock.return_value = 1419.0
        util.check_sync_deadline("bigquery tables")
        clock.return_value = 1421.0
        with pytest.raises(util.SyncDeadlineExceeded, match="bigquery tables"):
            util.check_sync_deadline("bigquery tables")


def test_deadline_ends_with_its_block(mocker):
    clock = mocker.patch("cartography.util.time.monotonic", return_value=1000.0)
    with util.sync_deadline(1):
        pass
    clock.return_value = 5000.0
    util.check_sync_deadline("after the block")


def test_withheld_services_are_collected_once_and_only_inside_the_block():
    util.record_withheld_service("bigquery")
    with util.collect_withheld_services() as withheld:
        util.record_withheld_service("bigquery")
        util.record_withheld_service("bigquery")
        assert util.withheld_services() == ["bigquery"]
    assert withheld == ["bigquery"]
    assert util.withheld_services() == []
