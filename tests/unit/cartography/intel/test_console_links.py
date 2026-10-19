import pathlib
import re

import cartography.intel

INTEL_DIR = pathlib.Path(cartography.intel.__file__).parent
# A block ends at the next clause or at the end of the query string literal.
ON_CREATE_BLOCK = re.compile(r'ON CREATE SET(.*?)(?=^\s*(?:SET|ON MATCH SET|WITH|MERGE|MATCH)\b|""")', re.S | re.M)


def test_no_consolelink_is_written_only_on_create():
    # ON CREATE SET never runs again for an existing node, so link fixes would never reach it.
    # Scans every provider and subpackage, not just cartography/intel/azure/*.py.
    offenders = [
        str(path.relative_to(INTEL_DIR))
        for path in INTEL_DIR.rglob("*.py")
        for block in ON_CREATE_BLOCK.findall(path.read_text(encoding="utf-8"))
        if "consolelink" in block or "console_link" in block
    ]
    assert offenders == []
