from cartography.intel.aws.ec2.images import filter_available_ec2_images


def test_filter_available_ec2_images_keeps_available_only():
    images = [
        {'ImageId': 'ami-ok', 'State': 'available'},
        {'ImageId': 'ami-pending', 'State': 'pending'},
        {'ImageId': 'ami-failed', 'State': 'failed'},
        {'ImageId': 'ami-missing'},
    ]
    filtered = filter_available_ec2_images(images)
    assert [i['ImageId'] for i in filtered] == ['ami-ok']


def test_filter_available_ec2_images_empty():
    assert filter_available_ec2_images([]) == []
