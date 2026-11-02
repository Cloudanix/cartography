from datetime import datetime
from unittest.mock import MagicMock

from cartography.intel.aws.inspector import get_inspector_findings
from cartography.intel.aws.inspector import transform_inspector_findings
from tests.data.aws.inspector import LIST_FINDINGS_EC2_PACKAGE
from tests.data.aws.inspector import LIST_FINDINGS_NETWORK


TEST_UPDATE_TAG = 123456789


def test_transform_inspector_findings_network():
    findings, _packages = transform_inspector_findings(LIST_FINDINGS_NETWORK)
    assert findings == [
        {
            'id': 'arn:aws:test123',
            'arn': 'arn:aws:test123',
            'instanceid': 'i-instanceid',
            'severity': 'INFORMATIONAL',
            'name': 'string',
            'firstobservedat': datetime(2015, 1, 1, 0, 0),
            'updatedat': datetime(2015, 1, 1, 0, 0),
            'awsaccount': '123456789011',
            'description': 'string',
            'cvssscore': 123.0,
            'protocol': 'TCP',
            'portrange': '123-124',
            'portrangeend': 124,
            'portrangebegin': 123,
            'type': 'NETWORK_REACHABILITY',
            'status': 'ACTIVE',
        },
    ]


def test_transform_inspector_findings_package():
    findings, packages = transform_inspector_findings(LIST_FINDINGS_EC2_PACKAGE)
    assert findings == [
        {
            'id': 'arn:aws:test456',
            'arn': 'arn:aws:test456',
            'vulnerabilityid': 'CVE-2017-9059',
            'instanceid': 'i-88503981029833100',
            'severity': 'MEDIUM',
            'name': 'CVE-2017-9059 - kernel-tools, kernel',
            'firstobservedat': datetime(2022, 5, 4, 16, 23, 3, 692000),
            'updatedat': datetime(2022, 5, 4, 16, 23, 3, 692000),
            'awsaccount': '123456789012',
            'description': 'The NFSv4 implementation in the Linux kernel through '
            '4.11.1 allows local users to cause a denial of service '
            '(resource consumption) by leveraging improper channel '
            'callback shutdown when unmounting an NFSv4 filesystem, aka '
            'a "module reference and kernel daemon" leak.',
            'cvssscore': 5.5,
            'type': 'PACKAGE_VULNERABILITY',
            'vulnerabilityid': 'CVE-2017-9059',
            'referenceurls': [],
            'relatedvulnerabilities': [],
            'source': 'REDHAT_CVE',
            'vendorcreatedat': datetime(2017, 4, 25, 17, 0),
            'vendorupdatedat': None,
            'vendorseverity': 'Moderate',
            'sourceurl': 'https://access.redhat.com/security/cve/CVE-2017-9059',
            'status': 'ACTIVE',

            'vulnerablepackageids': [
                '123456789012|kernel-tools|X86_64|4.9.17|6.29.amzn1|0',
                '123456789012|kernel|X86_64|4.9.17|6.29.amzn1|0',
            ],
        },
    ]
    assert packages == [
        {
            'arch': 'X86_64',
            'awsaccount': '123456789012',
            'epoch': 0,
            'filepath': None,
            'findingarn': 'arn:aws:test456',
            'fixedinversion': None,
            'id': '123456789012|kernel-tools|X86_64|4.9.17|6.29.amzn1|0',
            'manager': 'OS',
            'name': 'kernel-tools',
            'release': '6.29.amzn1',
            'sourcelayerhash': None,
            'version': '4.9.17',
        },
        {
            'arch': 'X86_64',
            'awsaccount': '123456789012',
            'epoch': 0,
            'filepath': None,
            'findingarn': 'arn:aws:test456',
            'fixedinversion': None,
            'id': '123456789012|kernel|X86_64|4.9.17|6.29.amzn1|0',
            'manager': 'OS',
            'name': 'kernel',
            'release': '6.29.amzn1',
            'sourcelayerhash': None,
            'version': '4.9.17',
        },
    ]


def test_get_findings_only_for_the_syncing_account_not_delegated_members():
    # A delegated administrator could list its members' findings; those belong to the members' own syncs.
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{'findings': [{'findingArn': 'arn:own'}]}]

    findings = get_inspector_findings(session, 'us-east-1', '111111111111')

    assert findings == [{'findingArn': 'arn:own'}]
    client.get_paginator.assert_called_once_with('list_findings')
    criteria = client.get_paginator.return_value.paginate.call_args.kwargs['filterCriteria']
    assert criteria['awsAccountId'] == [{'comparison': 'EQUALS', 'value': '111111111111'}]
