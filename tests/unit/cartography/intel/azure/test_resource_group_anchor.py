import re
from pathlib import Path

import cartography.intel.azure

AZURE_INTEL = Path(cartography.intel.azure.__file__).parent
RG_BY_NAME = re.compile(r"\(\s*\w*\s*:\s*AzureResourceGroup\s*\{\s*name\s*:")
# The group is reached from a variable bound to the subscription the sync is loading.
ANCHORED = re.compile(r"MATCH \((\w+)\)-\[:RESOURCE\]->\(\w+:AzureResourceGroup\{name:")
SYNC_PARAMETER = r"(subscription_id|SUBSCRIPTION_ID|AZURE_SUBSCRIPTION_ID)"
SYNCING_SUBSCRIPTION = r"\({var}:AzureSubscription\{{id: \$" + SYNC_PARAMETER + r"\}}\)"


def test_resource_groups_are_matched_by_name_only_under_the_syncing_subscription():
    # Resource group names (NetworkWatcherRG, DefaultResourceGroup-EUS, ...) repeat in every subscription of
    # every tenant: a name-only MATCH links one customer's resources to all of them. The subscription inside
    # the resource's ARM id is API data, not an anchor: every resource a sync lists belongs to the syncing one.
    unanchored = []
    for path in sorted(AZURE_INTEL.rglob('*.py')):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if not RG_BY_NAME.search(line):
                continue
            anchored = ANCHORED.search(line)
            before = '\n'.join(lines[max(0, number - 4):number])
            if not anchored or not re.search(SYNCING_SUBSCRIPTION.format(var=anchored.group(1)), before):
                unanchored.append(f'{path.name}:{number}: {line.strip()}')
    assert unanchored == []
