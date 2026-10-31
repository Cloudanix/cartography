def create_test_account(neo4j_session, test_account_id, test_update_tag):
    # Create Test AWSAccount
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=test_account_id,
        aws_update_tag=test_update_tag,
    )


def create_test_org_account(neo4j_session, workspace_id, org_id, account_id):
    # Production shape: CloudanixWorkspace-[:OWNER]->AWSOrganization-[:OWNER]->AWSAccount.
    # There is no direct Workspace->Account edge, so exposure jobs must match through the Organization.
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: $workspace_id})
        MERGE (w)-[:OWNER]->(o:AWSOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(:AWSAccount{id: $account_id})
        """,
        workspace_id=workspace_id, org_id=org_id, account_id=account_id,
    )


def exposure_job_parameters(workspace_id, org_id, account_id, update_tag):
    return {
        'UPDATE_TAG': update_tag,
        'AWS_ID': account_id,
        'ORGANIZATION_ID': org_id,
        'WORKSPACE_ID': workspace_id,
        'LIMIT_SIZE': 100,
    }
