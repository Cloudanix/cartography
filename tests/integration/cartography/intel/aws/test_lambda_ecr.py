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
        MERGE (a1)-[:RESOURCE]->(:ECRRepository{id: 'lecr-repo1'})-[:REPO_IMAGE]->
            (:ECRRepositoryImage{id: 'lecr-repo1:abc'})-[:IMAGE]->(img)
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


def test_lambda_ecr_links_only_images_in_the_account_repositories(neo4j_session):
    # ECRImage is one node per digest for every tenant. The digest 'only-b' is in the other
    # tenant's repository only, so this account's Lambda with that code hash must not link to it;
    # 'both' is in a repository of each tenant and links through this account's own repository.
    neo4j_session.run(
        """
        MERGE (w1:CloudanixWorkspace{id: 'lecr2-w1'})-[:OWNER]->(o1:AWSOrganization{id: 'lecr2-o-1'})
        MERGE (o1)-[:OWNER]->(a1:AWSAccount{id: 'lecr2-a1'})
        MERGE (w2:CloudanixWorkspace{id: 'lecr2-w2'})-[:OWNER]->(o2:AWSOrganization{id: 'lecr2-o-2'})
        MERGE (o2)-[:OWNER]->(a2:AWSAccount{id: 'lecr2-a2'})
        MERGE (only_b:ECRImage{id: 'sha256:lecr2-only-b'})
        MERGE (both:ECRImage{id: 'sha256:lecr2-both'})
        MERGE (a1)-[:RESOURCE]->(:ECRRepository{id: 'lecr2-repo-a1'})-[:REPO_IMAGE]->
            (:ECRRepositoryImage{id: 'lecr2-repo-a1:both'})-[:IMAGE]->(both)
        MERGE (a2)-[:RESOURCE]->(repo_b:ECRRepository{id: 'lecr2-repo-a2'})
        MERGE (repo_b)-[:REPO_IMAGE]->(:ECRRepositoryImage{id: 'lecr2-repo-a2:only-b'})-[:IMAGE]->(only_b)
        MERGE (repo_b)-[:REPO_IMAGE]->(:ECRRepositoryImage{id: 'lecr2-repo-a2:both'})-[:IMAGE]->(both)
        MERGE (a1)-[:RESOURCE]->(:AWSLambda{id: 'lecr2-l-foreign', codesha256: 'lecr2-only-b'})
        MERGE (a1)-[:RESOURCE]->(:AWSLambda{id: 'lecr2-l-own', codesha256: 'lecr2-both'})
        """,
    )

    run_analysis_job(
        'aws_lambda_ecr.json',
        neo4j_session,
        {
            'WORKSPACE_ID': 'lecr2-w1', 'ORGANIZATION_ID': 'lecr2-o-1', 'AWS_ID': 'lecr2-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG,
        },
    )

    links = {
        (r['l'], r['e']) for r in neo4j_session.run(
            """
            MATCH (l:AWSLambda)-[:HAS]->(e:ECRImage) WHERE l.id STARTS WITH 'lecr2-'
            RETURN l.id AS l, e.id AS e
            """,
        )
    }
    assert links == {('lecr2-l-own', 'sha256:lecr2-both')}
