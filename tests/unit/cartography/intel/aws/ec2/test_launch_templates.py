from cartography.intel.aws.ec2.launch_templates import LAUNCH_TEMPLATE_VERSIONS


def test_launch_template_versions_request_latest_and_default():
    assert LAUNCH_TEMPLATE_VERSIONS == ['$Latest', '$Default']
