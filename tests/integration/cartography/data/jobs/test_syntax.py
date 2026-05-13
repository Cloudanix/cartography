from importlib.resources import files

import pytest

import cartography.util


def test_analysis_jobs_cypher_syntax(neo4j_session):
    parameters = {
        "AWS_ID": "my_aws_account_id",
        "OCI_TENANCY_ID": "my_oci_tenant_id",
        "UPDATE_TAG": "my_update_tag",
        "OKTA_ORG_ID": "my_okta_org_id",
        "DEPLOYMENT_ID": "my_deployment_id",
        "CLUSTER_ID": "my_cluster_id",
        "AZURE_SUBSCRIPTION_ID": "my_azure_subscription_id",
        "AZURE_TENANT_ID": "my_azure_tenant_id",
        "PROJECT_ID": "my_gcp_project_id",
        "TENANT_ID": "my_tenant_id",
        # Cloudanix-specific parameters
        "WORKSPACE_ID": "my_workspace_id",
        "ORGANIZATION_ID": "my_org_id",
        "GCP_PROJECT_ID": "my_gcp_project_id",
        "GCP_ORGANIZATION_ID": "my_gcp_org_id",
        "LIMIT_SIZE": 100,
        "DEFAULT_DATETIME": "2020-01-01T00:00:00",
        "NULL_STRINGS": [],
        "PUBLIC_PORTS": [80, 443],
    }

    for resource in files("cartography.data.jobs.analysis").iterdir():
        if not resource.name.endswith(".json"):
            continue
        try:
            cartography.util.run_analysis_job(resource.name, neo4j_session, parameters)
        except Exception as e:
            pytest.fail(
                f"run_analysis_job failed for analysis job '{resource.name}' with exception: {e}",
            )

    for resource in files("cartography.data.jobs.scoped_analysis").iterdir():
        if not resource.name.endswith(".json"):
            continue
        try:
            cartography.util.run_scoped_analysis_job(
                resource.name,
                neo4j_session,
                parameters,
            )
        except Exception as e:
            pytest.fail(
                f"run_analysis_job failed for analysis job '{resource.name}' with exception: {e}",
            )


def test_cleanup_jobs_cypher_syntax(neo4j_session):
    parameters = {
        "AWS_ID": None,
        "OCI_TENANCY_ID": None,
        "UPDATE_TAG": None,
        "OKTA_ORG_ID": None,
        "DO_ACCOUNT_ID": None,
        "AZURE_SUBSCRIPTION_ID": None,
        "AZURE_TENANT_ID": None,
        "GITLAB_URL": None,
        # Cloudanix-specific parameters
        "WORKSPACE_ID": None,
        "ORGANIZATION_ID": None,
        "GCP_PROJECT_ID": None,
        "GCP_ORGANIZATION_ID": None,
        "LIMIT_SIZE": None,
        "WORKSPACE_UUID": None,
        "GITLAB_GROUP_ID": None,
    }

    for resource in files("cartography.data.jobs.cleanup").iterdir():
        if not resource.name.endswith(".json"):
            continue
        try:
            cartography.util.run_cleanup_job(resource.name, neo4j_session, parameters)
        except Exception as e:
            pytest.fail(
                f"run_cleanup_job failed for cleanup job '{resource.name}' with exception: {e}",
            )
