from cartography.util import run_analysis_job

TEST_UPDATE_TAG = 123456789


def test_lambda_ecr_links_through_the_organization(neo4j_session):
    # Accounts hang off the workspace through an organization, as organizations.sync builds
    # them. The other workspace's Lambda runs the same image but must not be linked by this
    # account's run, and only this account's stale edge may be removed.
    neo4j_session.run(
        """
        MERGE (w1:CloudanixWorkspace{id: 'lecr-w1'})-[:OWNER]->(o1:AWSOrganization{id: 'lecr-w1/o-1'})
        MERGE (o1)-[:OWNER]->(a1:AWSAccount{id: 'lecr-a1'})
        MERGE (w2:CloudanixWorkspace{id: 'lecr-w2'})-[:OWNER]->(o2:AWSOrganization{id: 'lecr-w2/o-2'})
        MERGE (o2)-[:OWNER]->(a2:AWSAccount{id: 'lecr-a2'})
        MERGE (img:ECRImage{id: 'sha256:lecr-abc', digest: 'sha256:lecr-abc'})
        MERGE (old:ECRImage{id: 'sha256:lecr-old', digest: 'sha256:lecr-old'})
        MERGE (a1)-[:RESOURCE]->(:AWSLambda{id: 'lecr-l1', codesha256: 'lecr-abc'})
        MERGE (a1)-[:RESOURCE]->(:AWSLambda{id: 'lecr-l2', codesha256: 'lecr-zip'})
        MERGE (a1)-[:RESOURCE]->(l3:AWSLambda{id: 'lecr-l3', codesha256: 'lecr-new'})
        MERGE (l3)-[:HAS{lastupdated: 1}]->(old)
        MERGE (a2)-[:RESOURCE]->(l4:AWSLambda{id: 'lecr-l4', codesha256: 'lecr-abc'})
        MERGE (l4)-[:HAS{lastupdated: 1}]->(old)
        """,
    )

    run_analysis_job(
        'aws_lambda_ecr.json',
        neo4j_session,
        {
            'WORKSPACE_ID': 'lecr-w1', 'ORGANIZATION_ID': 'lecr-w1/o-1', 'AWS_ID': 'lecr-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG,
        },
    )

    links = {
        (r['l'], r['e']) for r in neo4j_session.run(
            """
            MATCH (l:AWSLambda)-[:HAS]->(e:ECRImage) WHERE l.id STARTS WITH 'lecr-'
            RETURN l.id AS l, e.id AS e
            """,
        )
    }
    assert links == {('lecr-l1', 'sha256:lecr-abc'), ('lecr-l4', 'sha256:lecr-old')}
