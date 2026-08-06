"""
Unit tests for the batched classic ELB loaders (perf plan Phase 3.4).
"""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2 import load_balancers

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"

ELB = {
    "DNSName": "web-elb.us-east-1.elb.amazonaws.com",
    "LoadBalancerName": "web-elb",
    "CreatedTime": "2024-01-01",
    "CanonicalHostedZoneName": "web-elb.us-east-1.elb.amazonaws.com",
    "CanonicalHostedZoneNameID": "Z123",
    "Scheme": "internet-facing",
    "region": "us-east-1",
    "Subnets": ["subnet-1", "subnet-2"],
    "SecurityGroups": ["sg-1"],
    "SourceSecurityGroup": {"GroupName": "default"},
    "Instances": [{"InstanceId": "i-1"}, {"InstanceId": "i-2"}],
    "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 80, "Protocol": "HTTP"}}],
}


class TestLoadLoadBalancers:
    def test_batched_writes(self):
        session = MagicMock()

        load_balancers.load_load_balancers(session, [ELB, ELB], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        # lbs + subnets + security groups + source security groups + instances +
        # listeners = 6 writes total (was ~7+ writes PER load balancer).
        assert session.execute_write.call_count == 6
        lb_call, subnet_call, sg_call, source_sg_call, instance_call, listener_call = \
            session.execute_write.call_args_list

        assert len(lb_call.kwargs["DictList"]) == 2
        assert lb_call.kwargs["DictList"][0]["arn"].endswith(f"loadbalancer/{ELB['DNSName']}")
        assert len(subnet_call.kwargs["DictList"]) == 4  # 2 subnets x 2 lbs
        assert len(sg_call.kwargs["DictList"]) == 2
        assert source_sg_call.kwargs["DictList"][0]["group_name"] == "default"
        assert len(instance_call.kwargs["DictList"]) == 4
        listener_rows = listener_call.kwargs["DictList"]
        assert listener_rows[0]["listeners"] == ELB["ListenerDescriptions"]
        assert all("UNWIND $DictList" in c.args[1] for c in session.execute_write.call_args_list)

    def test_empty_data_writes_nothing(self):
        session = MagicMock()
        load_balancers.load_load_balancers(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()

    def test_missing_optional_fields_produce_no_rows(self):
        session = MagicMock()
        bare = {
            **ELB,
            "Subnets": [],
            "SecurityGroups": [],
            "SourceSecurityGroup": None,
            "Instances": [],
            "ListenerDescriptions": [],
        }

        load_balancers.load_load_balancers(session, [bare], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        # only the lb node batch writes; empty row lists short-circuit
        assert session.execute_write.call_count == 1
