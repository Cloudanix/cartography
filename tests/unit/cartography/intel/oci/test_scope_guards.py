"""
Scope guards for OCI graph queries, checked on the query text.

- Workspace: the tenancy node is keyed by its OCID alone, so it is reachable from every workspace
  that onboarded that tenancy. A tenancy match is only scoped to the syncing workspace when it is
  chained to it.
- Compartment: one compartment is one Cloudanix entity, synced on its own schedule, so exposure
  reads stay in the compartment being analysed, never another compartment of the same tenancy.

Jobs are listed from the package, not from the run order, so the guards cover every OCI job file.
"""
import inspect
import re
from importlib.resources import files
from importlib.resources import read_text

from cartography.intel.oci import iam
from cartography.intel.oci import utils
from cartography.intel.oci.exposure_layers import access as layers_access
from cartography.intel.oci.exposure_layers import blast_radius as layers_blast_radius
from cartography.intel.oci.exposure_layers import network as layers_network
from cartography.intel.oci.exposure_layers import reach as layers_reach
from cartography.intel.oci.exposure_layers import software as layers_software

JOBS_PACKAGE = 'cartography.data.jobs.analysis'
OCI_JOBS = sorted(
    p.name for p in files(JOBS_PACKAGE).iterdir() if p.name.startswith('oci_') and p.name.endswith('.json')
)
EXPOSURE_JOBS = [job for job in OCI_JOBS if job.endswith('_asset_exposure.json')]
LAYER_MODULES = (layers_access, layers_blast_radius, layers_network, layers_reach, layers_software)

_TENANCY = re.compile(r"\(\s*\w*\s*:OCITenancy\s*\{\{?\s*id:\s*\$OCI_TENANCY_ID\s*\}\}?\s*\)")
_WORKSPACE_BEFORE = re.compile(
    r"\(\s*:CloudanixWorkspace\s*\{\{?\s*id:\s*\$WORKSPACE_ID\s*\}\}?\s*\)\s*-\s*\[\s*:OWNER\s*\]\s*->\s*$",
)
_WORKSPACE_AFTER = re.compile(
    r"^\s*<-\s*\[\s*:OWNER\s*\]\s*-\s*\(\s*:CloudanixWorkspace\s*\{\{?\s*id:\s*\$WORKSPACE_ID",
)
_OTHER_COMPARTMENT = re.compile(r":OCICompartment(?!\s*\{\{?\s*id:\s*\$OCI_COMPARTMENT_ID\s*\}\}?\s*\))")


def _unanchored_tenancy_matches(text):
    return [
        text[max(0, m.start() - 60): m.end()]
        for m in _TENANCY.finditer(text)
        if not _WORKSPACE_BEFORE.search(text[:m.start()]) and not _WORKSPACE_AFTER.search(text[m.end():])
    ]


def test_oci_job_list_is_not_empty():
    assert 'oci_instance_asset_exposure.json' in EXPOSURE_JOBS


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
    offenders = {
        job: hits
        for job in OCI_JOBS
        if (hits := _unanchored_tenancy_matches(read_text(JOBS_PACKAGE, job)))
    }
    assert offenders == {}


def test_oci_exposure_layer_queries_chain_every_tenancy_match_to_the_workspace():
    for module in LAYER_MODULES:
        assert _unanchored_tenancy_matches(inspect.getsource(module)) == [], module.__name__


def test_compartment_matcher_flags_any_compartment_but_the_analysed_one():
    assert not _OTHER_COMPARTMENT.search("(:OCICompartment{id: $OCI_COMPARTMENT_ID})-[:RESOURCE]->(n)")
    assert not _OTHER_COMPARTMENT.search("(c:OCICompartment{{id: $OCI_COMPARTMENT_ID}})")
    assert _OTHER_COMPARTMENT.search("(:OCICompartment)-[:RESOURCE]->(n)")
    assert _OTHER_COMPARTMENT.search("(c:OCICompartment)-[:RESOURCE]->(n) WHERE c.id = $OCI_COMPARTMENT_ID")


def test_oci_exposure_jobs_read_only_the_analysed_compartment():
    offenders = {
        job: hits
        for job in EXPOSURE_JOBS
        if (hits := _OTHER_COMPARTMENT.findall(read_text(JOBS_PACKAGE, job)))
    }
    assert offenders == {}


def test_oci_exposure_layers_read_only_the_analysed_compartment():
    for module in LAYER_MODULES:
        assert not _OTHER_COMPARTMENT.search(inspect.getsource(module)), module.__name__


def test_oci_iam_and_tenancy_lookup_queries_chain_every_tenancy_match_to_the_workspace():
    # IAM loaders attach users, groups, policies, compartments and regions to the tenancy, and
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
