"""
Console links built by the GCP transforms: right cloudconsolelink resource_name and arguments,
and never an exception for a missing optional field.
"""
from unittest.mock import MagicMock

from cartography.intel.gcp import bigquery
from cartography.intel.gcp import cloudtasks
from cartography.intel.gcp import compute
from cartography.intel.gcp import containerregistry
from cartography.intel.gcp import dataflow
from cartography.intel.gcp import dns
from cartography.intel.gcp import gke
from cartography.intel.gcp import loadbalancer
from cartography.intel.gcp import spanner
from tests.unit.cartography.intel.gcp.test_compute_vm_os import _make_instance

CONSOLE = "https://console.cloud.google.com"
ZONE = {"id": "123", "name": "my-zone"}


def test_record_set_link_includes_type():
    rrs = dns.transform_rrs([{"name": "www.example.com.", "type": "A"}], ZONE, "p")
    assert rrs[0]["consolelink"] == f"{CONSOLE}/net-services/dns/zones/my-zone/rrsets/www.example.com./A/view?project=p"


def test_record_set_without_type_falls_back_to_zone():
    rrs = dns.transform_rrs([{"name": "www.example.com."}], ZONE, "p")
    assert rrs[0]["consolelink"] == f"{CONSOLE}/net-services/dns/zones/my-zone/details?project=p"


def test_dns_key_links_to_its_zone():
    keys = dns.transform_dns_keys([{"id": "1"}], "p", ZONE)
    assert keys[0]["consolelink"] == f"{CONSOLE}/net-services/dns/zones/my-zone/details?project=p"


def test_instance_nic_uses_network_name_and_image_link():
    instance = _make_instance(source_image="projects/debian-cloud/global/images/debian-12-v20240101")
    result = compute.transform_gcp_instances([instance], MagicMock())[0]
    assert result["networkInterfaces"][0]["consolelink"].startswith(
        f"{CONSOLE}/networking/networks/details/default?",
    )
    assert result["source_image_consolelink"] == (
        f"{CONSOLE}/compute/imagesDetail/projects/debian-cloud/global/images/debian-12-v20240101?project=my-project"
    )


def test_image_family_reference_gets_no_link():
    assert compute._image_consolelink("projects/debian-cloud/global/images/family/debian-12", "p") is None
    assert compute._image_consolelink(None, "p") is None


def test_https_proxy_deep_link():
    proxies = compute.transform_https_proxies([{"name": "px"}], "p")
    assert proxies[0]["consolelink"] == (
        f"{CONSOLE}/net-services/loadbalancing/advanced/targetHttpsProxies/details/px?project=p"
    )


def test_regional_instance_group_uses_region():
    groups = loadbalancer.transform_regional_instance_groups([{"name": "ig"}], "p", "us-east1")
    assert "/us-east1/ig?" in groups[0]["consolelink"]


def test_cloud_tasks_queue_link():
    queues = cloudtasks.transform_cloudtasks_queues(
        [{"name": "projects/p/locations/us-central1/queues/q1"}], "p",
    )
    assert queues[0]["consolelink"] == f"{CONSOLE}/cloudtasks/queue/us-central1/q1?project=p"


def test_spanner_database_link():
    dbs = spanner.transform_instances_databases([{"name": "projects/p/instances/i1/databases/d1"}], "p")
    assert dbs[0]["consolelink"] == f"{CONSOLE}/spanner/instances/i1/databases/d1/details?project=p"


def test_dataflow_job_without_location_gets_no_link():
    jobs = dataflow.transform_jobs([{"id": "j1"}], "p")
    assert jobs[0]["consolelink"] is None


def test_bigquery_table_link():
    bq = MagicMock()
    tables = bigquery.transform_bigquery_tables(bq, {"id": "ds"}, [{"tableReference": {"tableId": "t"}}], "p")
    assert tables[0]["consolelink"] == f"{CONSOLE}/bigquery?project=p&p=p&d=ds&t=t&page=table"


def test_artifact_registry_repository_link_uses_format():
    client = MagicMock()
    client.projects().locations().repositories().list().execute.return_value = {
        "repositories": [{"name": "projects/p/locations/us-central1/repositories/r1", "format": "NPM"}],
    }
    client.projects().locations().repositories().list_next.return_value = None
    repos = containerregistry.get_artifact_registry_repositories(client, "p", ["us-central1"], {})
    assert repos[0]["consolelink"] == f"{CONSOLE}/artifacts/npm/p/us-central1/r1?project=p"
    assert repos[0]["console_link"] == repos[0]["consolelink"]


def test_gke_node_pool_link():
    session = MagicMock()
    cluster = {"id": "projects/p/locations/us-central1/clusters/c1", "name": "c1", "location": "us-central1"}
    cluster["nodePools"] = [{"name": "pool-1"}]
    gke.load_gke_node_pools(session, [cluster], "p", 1)
    records = session.execute_write.call_args.args[1]
    assert records[0]["consolelink"] == f"{CONSOLE}/kubernetes/nodepool/us-central1/c1/pool-1?project=p"
