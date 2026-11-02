import datetime

from cartography.intel.aws import ecr
from cartography.intel.aws import inspector
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777807'
OTHER_ACCOUNT_ID = '888888888807'
DIGEST = 'sha256:' + 'e' * 64
REGIONS = {ACCOUNT_ID: 'us-east-1', OTHER_ACCOUNT_ID: 'eu-west-1'}


def _repo(account_id):
    region = REGIONS[account_id]
    return {
        'repositoryArn': f'arn:aws:ecr:{region}:{account_id}:repository/app',
        'repositoryName': 'app',
        'repositoryUri': f'{account_id}.dkr.ecr.{region}.amazonaws.com/app',
        'region': region,
        'createdAt': datetime.datetime(2026, 1, 1),
    }


def _finding(account_id):
    repo = _repo(account_id)
    return {
        'findingArn': f'arn:aws:inspector2:{repo["region"]}:{account_id}:finding/f-{account_id}',
        'severity': 'HIGH', 'title': 'CVE-2026-0001 - openssl', 'description': 'd',
        'firstObservedAt': datetime.datetime(2026, 1, 1), 'updatedAt': datetime.datetime(2026, 1, 1),
        'awsAccountId': account_id, 'type': 'PACKAGE_VULNERABILITY', 'status': 'ACTIVE',
        'resources': [{'type': 'AWS_ECR_CONTAINER_IMAGE', 'id': f'{repo["repositoryArn"]}/{DIGEST}'}],
        'packageVulnerabilityDetails': {
            'vulnerabilityId': 'CVE-2026-0001',
            'vulnerablePackages': [{'name': 'openssl', 'version': '3.0.0', 'filePath': f'/{account_id}'}],
        },
    }


def _sync_account(neo4j_session, account_id):
    # Both tenants pushed the same image (same digest) to their own "app" repository.
    repo = _repo(account_id)
    ecr.load_ecr_repositories(neo4j_session, [repo], account_id, TEST_UPDATE_TAG)
    ecr.load_ecr_repository_images(
        neo4j_session,
        ecr.transform_ecr_repository_images(
            {repo['repositoryUri']: [{'imageDigest': DIGEST, 'imageTag': 'latest', 'region': repo['region']}]},
        ),
        TEST_UPDATE_TAG,
    )
    findings, packages = inspector.transform_inspector_findings([_finding(account_id)])
    inspector.load_inspector_findings(neo4j_session, findings, repo['region'], TEST_UPDATE_TAG, account_id)
    inspector.load_inspector_packages(neo4j_session, packages, repo['region'], TEST_UPDATE_TAG, account_id)


def test_ecr_image_and_inspector_findings_stay_in_their_tenant(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-ecr', 'o-ecr', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-ecr-other', 'o-ecr-other', OTHER_ACCOUNT_ID)
    _sync_account(neo4j_session, ACCOUNT_ID)
    _sync_account(neo4j_session, OTHER_ACCOUNT_ID)

    # One shared image node, holding no tenant's region or console link.
    images = neo4j_session.run(
        "MATCH (img:ECRImage{id: $digest}) RETURN img.region AS region, img.consolelink AS link", digest=DIGEST,
    ).data()
    assert images == [{'region': None, 'link': None}]

    # Walking out of a tenant's repositories never reaches the other tenant's findings.
    for account_id in (ACCOUNT_ID, OTHER_ACCOUNT_ID):
        reached = neo4j_session.run(
            """
            MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(:ECRRepository)-[*1..3]-(f:AWSInspectorFinding)
            RETURN DISTINCT f.awsaccount AS account
            """,
            account_id=account_id,
        ).data()
        assert reached == [{'account': account_id}]

    # The same package version found in both tenants is one node per account.
    packages = {
        (row['account'], row['id']) for row in neo4j_session.run(
            """
            MATCH (a:AWSAccount)-[:RESOURCE]->(p:AWSInspectorPackage) WHERE p.name = 'openssl'
            RETURN a.id AS account, p.id AS id
            """,
        )
    }
    assert packages == {
        (ACCOUNT_ID, f'{ACCOUNT_ID}|openssl||3.0.0||'),
        (OTHER_ACCOUNT_ID, f'{OTHER_ACCOUNT_ID}|openssl||3.0.0||'),
    }
