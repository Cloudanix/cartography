"""
Unit tests for the batched EC2 security group loaders (perf plan Phase 3.3).
"""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2 import security_groups

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"

GROUP = {
    "GroupId": "sg-1",
    "GroupName": "web",
    "Description": "web sg",
    "VpcId": "vpc-1",
    "region": "us-east-1",
    "isDefault": False,
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        },
        {
            "IpProtocol": "-1",
            "IpRanges": [],
            "Ipv6Ranges": [],
        },
    ],
    "IpPermissionsEgress": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            "Ipv6Ranges": [],
        },
    ],
}


class TestBuildRuleAndRangeRows:
    def test_partitions_and_ids(self):
        rule_rows, range_rows = security_groups._build_rule_and_range_rows([GROUP])

        assert len(rule_rows["IpPermissionInbound"]) == 2
        assert len(rule_rows["IpPermissionEgress"]) == 1
        all_protocol_rule = rule_rows["IpPermissionInbound"][1]
        # "-1" protocol expands to the full port range, exactly as before
        assert all_protocol_rule["from_port"] == 0
        assert all_protocol_rule["to_port"] == 65535
        assert all_protocol_rule["ruleid"] == "sg-1/IpPermissions/065535-1"

        assert range_rows["IpRange"] == [
            {
                "range_id": "IpRule/sg-1/IpPermissions/8080tcp/ipRange/0.0.0.0/0",
                "range": "0.0.0.0/0",
                "range_name": "0.0.0.0",
                "ruleid": "sg-1/IpPermissions/8080tcp",
            },
            {
                "range_id": "IpRule/sg-1/IpPermissionsEgress/443443tcp/ipRange/10.0.0.0/8",
                "range": "10.0.0.0/8",
                "range_name": "10.0.0.0",
                "ruleid": "sg-1/IpPermissionsEgress/443443tcp",
            },
        ]
        assert len(range_rows["Ipv6Range"]) == 1

    def test_empty_groups(self):
        rule_rows, range_rows = security_groups._build_rule_and_range_rows([])
        assert all(not rows for rows in rule_rows.values())
        assert all(not rows for rows in range_rows.values())


class TestLoadEc2SecurityGroupInfo:
    def test_batched_writes(self):
        session = MagicMock()

        security_groups.load_ec2_security_groupinfo(session, [GROUP], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        # 1 group batch + 2 rule-label batches + 1 rule-group-pair batch +
        # 2 range-label batches = 6 writes, independent of group count.
        assert session.execute_write.call_count == 6
        group_call = session.execute_write.call_args_list[0]
        assert group_call.kwargs["DictList"][0]["group_arn"] == \
            "arn:aws:ec2:us-east-1:1234:security-group/sg-1"
        assert group_call.kwargs["AWS_ACCOUNT_ID"] == TEST_ACCOUNT_ID
        queries = [c.args[1] for c in session.execute_write.call_args_list]
        assert all("UNWIND $DictList" in q for q in queries)

    def test_empty_data_writes_nothing(self):
        session = MagicMock()
        security_groups.load_ec2_security_groupinfo(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()
