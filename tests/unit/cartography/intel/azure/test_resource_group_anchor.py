import re
from pathlib import Path

import pytest

import cartography.intel.azure
from cartography.util import get_azure_subscription_id

AZURE_INTEL = Path(cartography.intel.azure.__file__).parent
RG_BY_NAME = re.compile(r"\(\s*\w*\s*:\s*AzureResourceGroup\s*\{\s*name\s*:")
SUBSCRIPTION = "MATCH (rg_sub:AzureSubscription{id: $resource_group_subscription_id})"
ANCHORED = "MATCH (rg_sub)-[:RESOURCE]->("


@pytest.mark.parametrize(
    'arm_id,expected', [
        ('/subscriptions/AAAA-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v', 'aaaa-1'),
        ('/subscriptions/aaaa-1', 'aaaa-1'),
        ('/providers/Microsoft.Management/managementGroups/mg', ''),
        ('/subscriptions', ''),
        ('', ''),
        (None, ''),
    ],
)
def test_get_azure_subscription_id(arm_id, expected):
    assert get_azure_subscription_id(arm_id) == expected


def test_resource_groups_are_matched_by_name_only_under_a_subscription():
    # Resource group names (NetworkWatcherRG, DefaultResourceGroup-EUS, ...) repeat in every
    # subscription of every tenant: a name-only MATCH links one customer's resources to all of them.
    unanchored = []
    for path in sorted(AZURE_INTEL.rglob('*.py')):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if not RG_BY_NAME.search(line):
                continue
            if ANCHORED not in line or SUBSCRIPTION not in lines[number - 2]:
                unanchored.append(f'{path.name}:{number}: {line.strip()}')
    assert unanchored == []
