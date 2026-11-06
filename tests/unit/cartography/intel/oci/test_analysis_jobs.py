import inspect
import re
from importlib.resources import read_text

import cartography.intel.oci as oci_intel
from cartography.intel.oci import iam
from cartography.intel.oci import utils
from cartography.intel.oci.exposure_layers import network as layers_network
from cartography.intel.oci.exposure_layers import software as layers_software

# The tenancy node is keyed by its OCID alone, so it is reachable from every workspace that onboarded
# that tenancy. A tenancy match is only scoped to the syncing workspace when it is chained to it.
_TENANCY = re.compile(r"\(\s*\w*\s*:OCITenancy\s*\{\{?\s*id:\s*\$OCI_TENANCY_ID\s*\}\}?\s*\)")
_WORKSPACE_BEFORE = re.compile(
    r"\(\s*:CloudanixWorkspace\s*\{\{?\s*id:\s*\$WORKSPACE_ID\s*\}\}?\s*\)\s*-\s*\[\s*:OWNER\s*\]\s*->\s*$",
)
_WORKSPACE_AFTER = re.compile(
    r"^\s*<-\s*\[\s*:OWNER\s*\]\s*-\s*\(\s*:CloudanixWorkspace\s*\{\{?\s*id:\s*\$WORKSPACE_ID",
)


def _unanchored_tenancy_matches(text):
    return [
        text[max(0, m.start() - 60): m.end()]
        for m in _TENANCY.finditer(text)
        if not _WORKSPACE_BEFORE.search(text[:m.start()]) and not _WORKSPACE_AFTER.search(text[m.end():])
    ]


def test_oci_analysis_jobs_exist():
    for job_file in oci_intel.OCI_ANALYSIS_JOBS:
        assert read_text('cartography.data.jobs.analysis', job_file)


def test_oci_autonomous_database_exposure_job_is_wired():
    assert 'oci_autonomous_database_asset_exposure.json' in oci_intel.OCI_ANALYSIS_JOBS


def test_oci_security_list_exposure_runs_after_subnet_exposure():
    # The security list job reads the exposed_internet flag the subnet job writes.
    jobs = oci_intel.OCI_ANALYSIS_JOBS
    assert jobs.index('oci_subnet_asset_exposure.json') < jobs.index('oci_security_list_asset_exposure.json')


def test_oci_boot_volume_exposure_runs_after_instance_exposure():
    # The boot volume job reads the exposed_internet flag the instance job writes.
    jobs = oci_intel.OCI_ANALYSIS_JOBS
    assert jobs.index('oci_instance_asset_exposure.json') < jobs.index('oci_boot_volume_asset_exposure.json')


def test_oci_db_system_exposure_is_wired():
    assert 'oci_db_system_asset_exposure.json' in oci_intel.OCI_ANALYSIS_JOBS


def test_oci_load_balancer_exposure_runs_before_instance_exposure():
    # The instance job reads the load balancer job's exposed_internet to flag LB backends.
    jobs = oci_intel.OCI_ANALYSIS_JOBS
    assert jobs.index('oci_load_balancer_asset_exposure.json') < jobs.index('oci_instance_asset_exposure.json')


def test_oci_api_gateway_exposure_is_wired():
    assert 'oci_api_gateway_asset_exposure.json' in oci_intel.OCI_ANALYSIS_JOBS


def test_oci_oke_cluster_exposure_is_wired():
    assert 'oci_oke_cluster_asset_exposure.json' in oci_intel.OCI_ANALYSIS_JOBS


def test_unanchored_tenancy_matcher_flags_only_unchained_tenancy():
    workspace = "(:CloudanixWorkspace{id: $WORKSPACE_ID})"
    tenancy = "(:OCITenancy{id: $OCI_TENANCY_ID})"
    anchored = f"MATCH {workspace}-[:OWNER]->{tenancy}-[:OWNER]->(c)"
    anchored_reverse = f"MATCH (c)<-[:OWNER]-{tenancy}<-[:OWNER]-{workspace}"
    bare = "MATCH (:OCITenancy{id: $OCI_TENANCY_ID})-[:OWNER]->(c)"
    assert _unanchored_tenancy_matches(anchored) == []
    assert _unanchored_tenancy_matches(anchored_reverse) == []
    assert len(_unanchored_tenancy_matches(bare)) == 1


def test_oci_analysis_jobs_chain_every_tenancy_match_to_the_workspace():
    # Exposure jobs read network objects across compartments of the tenancy; those reads must
    # still stay inside the syncing workspace.
    offenders = {
        job_file: hits
        for job_file in oci_intel.OCI_ANALYSIS_JOBS
        if (hits := _unanchored_tenancy_matches(read_text('cartography.data.jobs.analysis', job_file)))
    }
    assert offenders == {}


def test_oci_exposure_layer_queries_chain_every_tenancy_match_to_the_workspace():
    for module in (layers_network, layers_software):
        assert _unanchored_tenancy_matches(inspect.getsource(module)) == [], module.__name__


def test_oci_iam_and_tenancy_lookup_queries_chain_every_tenancy_match_to_the_workspace():
    # IAM loaders attach users, groups, policies, compartments and regions to the tenancy, and the
    # utils lookups read them back; both must reach the tenancy through the syncing workspace.
    for module in (iam, utils):
        assert _unanchored_tenancy_matches(inspect.getsource(module)) == [], module.__name__


def test_oci_iam_loaders_require_the_workspace():
    # Keyword-only with no default: a caller cannot forget it and silently write nothing.
    loaders = (
        iam.load_compartments, iam.load_users, iam.load_groups, iam.load_group_memberships, iam.load_policies,
        iam.load_oci_policy_group_reference, iam.load_oci_policy_compartment_reference,
        iam.load_oci_external_principal, iam.load_region_subscriptions,
    )
    for loader in loaders:
        param = inspect.signature(loader).parameters['workspace_id']
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, loader.__name__
        assert param.default is inspect.Parameter.empty, loader.__name__
