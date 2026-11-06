from cartography.intel.aws.ec2 import images
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
OWNER_ID = '777777777806'
USER_ID = '888888888806'
AMAZON_ID = '137112412989'
REGION = 'us-east-1'
OTHER_REGION = 'us-west-2'


def _image(image_id, owner_id, cross_account=None):
    return {
        'ImageId': image_id, 'OwnerId': owner_id, 'Name': image_id, 'region': REGION,
        'consolelink': f'link-{image_id}', 'has_cross_account_access': cross_account,
    }


def _seed(neo4j_session):
    # OWNER_ID shares its AMI with USER_ID; both run Amazon's public AMI. The images are in
    # describe_images of both accounts, so before the fix both MERGEd the same "ami|region" node.
    create_test_org_account(neo4j_session, 'ws-img-owner', 'o-img-owner', OWNER_ID)
    create_test_org_account(neo4j_session, 'ws-img-user', 'o-img-user', USER_ID)
    neo4j_session.run(
        """
        MATCH (owner:AWSAccount{id: $owner}), (user:AWSAccount{id: $user})
        MERGE (owner)-[:RESOURCE]->(:EC2Instance{id: 'i-img-owner', imageid: 'ami-img-public', region: $region})
        MERGE (user)-[:RESOURCE]->(:EC2Instance{id: 'i-img-user-public', imageid: 'ami-img-public', region: $region})
        MERGE (user)-[:RESOURCE]->(:EC2Instance{id: 'i-img-user-shared', imageid: 'ami-img-shared', region: $region})
        MERGE (user)-[:RESOURCE]->(:EC2Instance{id: 'i-img-user-west', imageid: 'ami-img-public', region: $west})
        """,
        owner=OWNER_ID, user=USER_ID, region=REGION, west=OTHER_REGION,
    )
    images.load_images(
        neo4j_session,
        [_image('ami-img-shared', OWNER_ID, cross_account=True), _image('ami-img-public', AMAZON_ID)],
        OWNER_ID, TEST_UPDATE_TAG,
    )
    images.load_images(
        neo4j_session,
        [_image('ami-img-shared', OWNER_ID), _image('ami-img-public', AMAZON_ID)],
        USER_ID, TEST_UPDATE_TAG,
    )


def _account_images(neo4j_session, account_id):
    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(img:EC2Image)
        RETURN img.id AS id, img.arn AS arn, img.has_cross_account_access AS cross
        """,
        account_id=account_id,
    )
    return {row['id']: (row['arn'], row['cross']) for row in rows}


def test_each_account_writes_its_own_image_node(neo4j_session):
    _seed(neo4j_session)

    assert _account_images(neo4j_session, OWNER_ID) == {
        f'ami-img-shared|{REGION}': (f'arn:aws:ec2:{REGION}:{OWNER_ID}:image/ami-img-shared', True),
        f'ami-img-public|{REGION}|{OWNER_ID}': (f'arn:aws:ec2:{REGION}:{OWNER_ID}:image/ami-img-public', None),
    }
    assert _account_images(neo4j_session, USER_ID) == {
        f'ami-img-shared|{REGION}|{USER_ID}': (f'arn:aws:ec2:{REGION}:{USER_ID}:image/ami-img-shared', None),
        f'ami-img-public|{REGION}|{USER_ID}': (f'arn:aws:ec2:{REGION}:{USER_ID}:image/ami-img-public', None),
    }
    shared = neo4j_session.run(
        """
        MATCH (a:AWSAccount)-[:RESOURCE]->(img:EC2Image) WHERE img.imageid STARTS WITH 'ami-img-'
        WITH img, count(DISTINCT a) AS accounts WHERE accounts > 1 RETURN img.id AS id
        """,
    )
    assert [row['id'] for row in shared] == []


def test_instances_link_to_their_account_image_only(neo4j_session):
    _seed(neo4j_session)
    # Left by the old graph-wide link: the user's instance pointed at the owner's node.
    neo4j_session.run(
        """
        MATCH (i:EC2Instance{id: 'i-img-user-shared'}), (img:EC2Image{id: $legacy})
        MERGE (i)-[:CHILDREN{lastupdated: 1}]->(img)
        """,
        legacy=f'ami-img-shared|{REGION}',
    )

    images.link_ec2_instances_to_images(neo4j_session, OWNER_ID, TEST_UPDATE_TAG)
    images.link_ec2_instances_to_images(neo4j_session, USER_ID, TEST_UPDATE_TAG)

    links = {
        (row['i'], row['img']) for row in neo4j_session.run(
            """
            MATCH (i:EC2Instance)-[:CHILDREN]->(img:EC2Image) WHERE i.id STARTS WITH 'i-img-'
            RETURN i.id AS i, img.id AS img
            """,
        )
    }
    assert links == {
        ('i-img-owner', f'ami-img-public|{REGION}|{OWNER_ID}'),
        ('i-img-user-public', f'ami-img-public|{REGION}|{USER_ID}'),
        ('i-img-user-shared', f'ami-img-shared|{REGION}|{USER_ID}'),
    }
