import logging

from cartography.intel.oci.util import common


def test_known_syncs_and_exposure_layers_pass_through():
    assert common.parse_and_validate_oci_requested_syncs(' compute, network ,exposure_layers') == [
        'compute', 'network', 'exposure_layers',
    ]


def test_unknown_syncs_are_skipped_with_a_warning_naming_them(caplog):
    # cloudanix-web sent "networking" and "containers" for months; dropping them without a word meant
    # OCI network and container registry data silently never synced.
    with caplog.at_level(logging.WARNING, logger=common.__name__):
        synced = common.parse_and_validate_oci_requested_syncs('compute,networking,containers')

    assert synced == ['compute']
    assert "['networking', 'containers']" in caplog.text


def test_no_warning_when_every_sync_is_known(caplog):
    with caplog.at_level(logging.WARNING, logger=common.__name__):
        common.parse_and_validate_oci_requested_syncs('compute,network')

    assert caplog.text == ''
