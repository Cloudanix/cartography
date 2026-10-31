from importlib.resources import read_text

import cartography.intel.oci as oci_intel


def test_oci_analysis_jobs_exist():
    for job_file in oci_intel.OCI_ANALYSIS_JOBS:
        assert read_text('cartography.data.jobs.analysis', job_file)


def test_oci_autonomous_database_exposure_job_is_wired():
    assert 'oci_autonomous_database_asset_exposure.json' in oci_intel.OCI_ANALYSIS_JOBS
