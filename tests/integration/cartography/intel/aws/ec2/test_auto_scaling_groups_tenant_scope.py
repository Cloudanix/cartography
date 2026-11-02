import datetime

from cartography.intel.aws.ec2 import auto_scaling_groups
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777802'
OTHER_ACCOUNT_ID = '888888888802'
REGION = 'us-east-1'
OTHER_REGION = 'us-west-2'
LC_NAME = 'web-lc'


def _lc_arn(account_id, region):
    return (
        f'arn:aws:autoscaling:{region}:{account_id}:launchConfiguration:'
        f'00000000-0000-0000-0000-{account_id}:launchConfigurationName/{LC_NAME}'
    )


def _launch_configuration(account_id, region):
    return {
        'LaunchConfigurationName': LC_NAME,
        'LaunchConfigurationARN': _lc_arn(account_id, region),
        'CreatedTime': datetime.datetime(2021, 9, 21, 10, 55, 34),
        'ImageId': 'ami-1',
        'InstanceMonitoring': {'Enabled': False},
    }


def test_asg_launch_configuration_is_resolved_in_its_own_account_and_region(neo4j_session):
    # Launch configuration names are unique only per account and region: the same name in a second
    # tenant, and in a second region of the same account, must not be linked.
    create_test_org_account(neo4j_session, 'ws-asg', 'o-asg', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-asg-other', 'o-asg-other', OTHER_ACCOUNT_ID)
    for account_id, region in ((ACCOUNT_ID, REGION), (ACCOUNT_ID, OTHER_REGION), (OTHER_ACCOUNT_ID, REGION)):
        auto_scaling_groups.load_launch_configurations(
            neo4j_session, [_launch_configuration(account_id, region)], region, account_id, TEST_UPDATE_TAG,
        )
    group_arn = f'arn:aws:autoscaling:{REGION}:{ACCOUNT_ID}:autoScalingGroup:1:autoScalingGroupName/web'
    group = {
        'AutoScalingGroupARN': group_arn,
        'AutoScalingGroupName': 'web',
        'LaunchConfigurationName': LC_NAME,
        'CreatedTime': datetime.datetime(2021, 9, 21, 10, 55, 34),
        'MaxSize': 1, 'MinSize': 1,
    }

    auto_scaling_groups.load_ec2_auto_scaling_groups(neo4j_session, [group], REGION, ACCOUNT_ID, TEST_UPDATE_TAG)

    configs = {
        r['id'] for r in neo4j_session.run(
            "MATCH (:AutoScalingGroup{arn: $arn})-[:HAS_LAUNCH_CONFIG]->(c) RETURN c.id AS id", arn=group_arn,
        )
    }
    assert configs == {_lc_arn(ACCOUNT_ID, REGION)}


def test_asg_launch_template_is_resolved_in_its_own_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-asg', 'o-asg', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-asg-other', 'o-asg-other', OTHER_ACCOUNT_ID)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:LaunchTemplate{id: 'lt-own'})
        MERGE (other)-[:RESOURCE]->(:LaunchTemplate{id: 'lt-other'})
        """,
        own=ACCOUNT_ID, other=OTHER_ACCOUNT_ID,
    )
    groups = [
        {
            'AutoScalingGroupARN': f'arn:aws:autoscaling:{REGION}:{ACCOUNT_ID}:autoScalingGroup:2:autoScalingGroupName/{lt}',
            'AutoScalingGroupName': lt, 'LaunchTemplate': {'LaunchTemplateId': lt},
            'CreatedTime': datetime.datetime(2021, 9, 21, 10, 55, 34), 'MaxSize': 1, 'MinSize': 1,
        }
        for lt in ('lt-own', 'lt-other')
    ]

    auto_scaling_groups.load_ec2_auto_scaling_groups(neo4j_session, groups, REGION, ACCOUNT_ID, TEST_UPDATE_TAG)

    templates = neo4j_session.run(
        "MATCH (g:AutoScalingGroup)-[:HAS_LAUNCH_TEMPLATE]->(t:LaunchTemplate) RETURN g.name AS g, t.id AS t",
    )
    assert {(r['g'], r['t']) for r in templates} == {('lt-own', 'lt-own')}
