from unittest.mock import MagicMock

from cartography.intel.azure import compute


def test_load_vm_scale_sets_writes_consolelink_on_every_run():
    tx = MagicMock()
    scale_set = {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/x/vmss-1", "consolelink": "https://x"}

    compute._load_vm_scale_sets_tx(tx, "sub-1", [scale_set], 42)

    query = tx.run.call_args_list[0].args[0]
    # The key was misspelled 'consolelinke' and only set on create, so exports never saw it.
    assert "REMOVE a.consolelinke" in query
    set_clause = query.split("SET a.lastupdated", 1)[1]
    assert "a.consolelink = set.consolelink" in set_clause
