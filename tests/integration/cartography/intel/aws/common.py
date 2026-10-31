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


def create_test_security_group_rule(neo4j_session, group_id, cidr, protocol, from_port, to_port):
    # A security group as the EC2 sync leaves it (it has a name) with one inbound rule from cidr.
    label = 'Ipv6Range' if ':' in cidr else 'IpRange'
    neo4j_session.run(
        f"""
        MERGE (sg:EC2SecurityGroup{{id: $group_id}}) SET sg.name = $group_id
        MERGE (sg)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:IpPermissionInbound:IpRule{{ruleid: $group_id + '-rule'}})
        SET rule.protocol = $protocol, rule.fromport = $from_port, rule.toport = $to_port
        MERGE (rule)<-[:MEMBER_OF_IP_RULE]-(:{label}{{id: $group_id + '-range', range: $cidr}})
        """,
        group_id=group_id, cidr=cidr, protocol=protocol, from_port=from_port, to_port=to_port,
    )


def exposure_job_parameters(workspace_id, org_id, account_id, update_tag):
    return {
        'UPDATE_TAG': update_tag,
        'AWS_ID': account_id,
        'ORGANIZATION_ID': org_id,
        'WORKSPACE_ID': workspace_id,
        'LIMIT_SIZE': 100,
    }
