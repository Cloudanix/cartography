from cartography.intel.aws.ec2.images import EC2_IMAGE_FILTERS


def test_ec2_image_filters_request_available_only():
    assert EC2_IMAGE_FILTERS == [{
        'Name': 'state',
        'Values': ['available'],
    }]
