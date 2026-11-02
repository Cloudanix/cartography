import pytest

from cartography.intel.aws.ec2.network_interfaces import _parse_elb_description

ACCOUNT = '123456789012'
REGION = 'us-east-1'
PREFIX = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer'


@pytest.mark.parametrize(
    'description, expected',
    [
        ('ELB my-classic-lb', ('my-classic-lb', None)),
        ('ELB app/my-alb/50dc6c495c0c9188', (None, f'{PREFIX}/app/my-alb/50dc6c495c0c9188')),
        ('ELB net/my-nlb/0123456789abcdef', (None, f'{PREFIX}/net/my-nlb/0123456789abcdef')),
        ('ELB gwy/my-gwlb/0123456789abcdef', (None, f'{PREFIX}/gwy/my-gwlb/0123456789abcdef')),
        # Not an ELB ENI, or not a well-formed one: no link.
        ('', (None, None)),
        ('Interface for NAT Gateway nat-0123', (None, None)),
        ('ELB ', (None, None)),
        ('ELB app/my-alb', (None, None)),
        ('ELB app/my-alb/abc/extra', (None, None)),
        ('ELB two words', (None, None)),
    ],
)
def test_parse_elb_description(description, expected):
    assert _parse_elb_description(description, REGION, ACCOUNT, 'aws') == expected


def test_parse_elb_description_uses_the_partition():
    _, arn = _parse_elb_description('ELB app/my-alb/abc', 'cn-north-1', ACCOUNT, 'aws-cn')
    assert arn == f'arn:aws-cn:elasticloadbalancing:cn-north-1:{ACCOUNT}:loadbalancer/app/my-alb/abc'
