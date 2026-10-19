import datetime
import re
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws.ec2 import reserved_instances


def _arn_source(query: str, node_var: str) -> tuple:
    """(UNWIND row variable, (variable, field) that `<node_var>.arn` is set from)."""
    row_var = re.search(r"UNWIND \$DictList AS (\w+)", query, re.IGNORECASE).group(1)
    source = re.search(rf"\b{node_var}\.arn = (\w+)\.(\w+)", query).groups()
    return row_var, source


@patch.object(reserved_instances, 'load_graph_data')
def test_reserved_instance_arn_read_from_row(load_graph_data):
    now = datetime.datetime(2024, 1, 1)
    data = [{'ReservedInstancesId': 'ri-1', 'Start': now, 'End': now}]
    reserved_instances.load_reserved_instances(MagicMock(), data, 'us-east-1', '123456789012', 1)

    query, rows = load_graph_data.call_args.args[1:3]
    row_var, (var, field) = _arn_source(query, 'ri')
    assert var == row_var
    assert rows[0][field] == 'arn:aws:ec2:us-east-1:123456789012:reserved-instances/ri-1'
