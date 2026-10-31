from importlib.resources import read_text

import cartography.intel.oci as oci_intel


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
