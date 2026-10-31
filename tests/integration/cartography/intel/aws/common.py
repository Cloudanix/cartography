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


def create_exposure_test_account(neo4j_session, workspace_id, org_id, account_id):
    # The asset exposure jobs match the full CloudanixWorkspace -> AWSOrganization -> AWSAccount chain.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:AWSOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(:AWSAccount{id: $account_id})
        """,
        workspace_id=workspace_id, org_id=org_id, account_id=account_id,
    )
