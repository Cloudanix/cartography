from cartography.intel.aws.ec2.launch_templates import filter_current_launch_template_versions


def test_filter_current_launch_template_versions_keeps_default_and_latest():
    versions = [
        {'VersionNumber': 1, 'DefaultVersion': False},
        {'VersionNumber': 2, 'DefaultVersion': True},
        {'VersionNumber': 3, 'DefaultVersion': False},
        {'VersionNumber': 4, 'DefaultVersion': False},
    ]
    filtered = filter_current_launch_template_versions(versions)
    assert sorted(v['VersionNumber'] for v in filtered) == [2, 4]


def test_filter_current_launch_template_versions_same_default_and_latest():
    versions = [{'VersionNumber': 1, 'DefaultVersion': True}]
    filtered = filter_current_launch_template_versions(versions)
    assert len(filtered) == 1
    assert filtered[0]['VersionNumber'] == 1


def test_filter_current_launch_template_versions_empty():
    assert filter_current_launch_template_versions([]) == []
