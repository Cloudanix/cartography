"""
The OCI analysis subrun (services == ["analysis"]) must run only the post-sync jobs. Every sync or cleanup it ran
carried its newer update tag; tags.cleanup_tags is tenancy-wide and no sync_tags runs on that subrun, so it deleted
every TAGGED edge in the tenancy and the inventory export that followed shipped the assets without their tags.
"""
import base64
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import cartography.intel.oci

OCI = 'cartography.intel.oci'
TENANCY = 'ocid1.tenancy.oc1..t1'
COMPARTMENT = 'ocid1.compartment.oc1..c1'
OCI_CONFIG = base64.b64encode(json.dumps({'fingerprint': 'fp', 'private_key_content': 'key'}).encode()).decode()
SYNC_NAMES = (
    '_initialize_resources', 'organizations.load_oci_accounts', 'compartment.get_current_oci_compartment',
    'compartment.sync', '_sync_multiple_compartments', 'tags.cleanup_tags',
)


def _start(requested):
    """Run start_oci_ingestion for the given services; return (analysis job calls, sync/cleanup mocks)."""
    config = SimpleNamespace(
        update_tag=7, oci_tenancy_id=TENANCY, oci_compartment_id=COMPARTMENT,
        oci_requested_syncs=[{'name': name} for name in requested],
        params={'workspace': {'id_string': 'ws-1'}, 'ociConfig': OCI_CONFIG, 'userOcid': 'u1', 'defaultRegion': 'PHX'},
    )
    with ExitStack() as stack:
        stack.enter_context(patch(f'{OCI}.oci.config.validate_config'))
        stack.enter_context(patch(f'{OCI}.exposure_layers.run'))
        syncs = {name: stack.enter_context(patch(f'{OCI}.{name}')) for name in SYNC_NAMES}
        run_analysis_job = stack.enter_context(patch('cartography.intel.post_sync.run_analysis_job'))
        cartography.intel.oci.start_oci_ingestion(None, config)
    return run_analysis_job.call_args_list, syncs


def test_analysis_only_runs_the_jobs_and_no_sync_or_cleanup():
    calls, syncs = _start(['analysis'])

    assert {name for name, mock in syncs.items() if mock.called} == set()
    assert 'oci_subnet_asset_exposure.json' in {call.args[0] for call in calls}
    assert {(call.args[2]['OCI_TENANCY_ID'], call.args[2]['OCI_COMPARTMENT_ID']) for call in calls} == {
        (TENANCY, COMPARTMENT),
    }


def test_resource_syncs_with_analysis_take_the_full_path():
    _, syncs = _start(['compute', 'analysis'])

    syncs['_sync_multiple_compartments'].assert_called_once()
    assert syncs['_sync_multiple_compartments'].call_args.args[4] == ['compute', 'analysis']
