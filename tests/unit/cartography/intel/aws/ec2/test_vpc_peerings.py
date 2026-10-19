import re
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws.ec2 import vpc_peerings


@patch.object(vpc_peerings, 'load_graph_data')
def test_peering_arn_read_from_row(load_graph_data):
    data = [{'VpcPeeringConnectionId': 'pcx-1'}]
    vpc_peerings.load_vpc_peerings(MagicMock(), data, 'us-east-1', '123456789012', 1)

    query, rows = load_graph_data.call_args.args[1:3]
    row_var = re.search(r"UNWIND \$DictList AS (\w+)", query, re.IGNORECASE).group(1)
    var, field = re.search(r"\bpcx\.arn = (\w+)\.(\w+)", query).groups()
    assert var == row_var
    assert rows[0][field] == 'arn:aws:ec2:us-east-1:123456789012:vpc-peering-connection/pcx-1'
