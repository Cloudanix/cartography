"""
L4 input: normalized `<product>@<version>` identities.

Cartography only states what runs; cloudanix-web joins identities to CVEs. Keep products
lowercase and versions as the provider reports them so the web side owns the mapping.
"""
import re
from typing import List
from typing import Optional
from typing import Pattern
from typing import Tuple


def identity(product: Optional[str], version: Optional[str]) -> Optional[str]:
    if not product or not version:
        return None
    return f"{str(product).strip().lower()}@{str(version).strip()}"


# (pattern, product, version-group joiner). Ordered: first match wins.
# ponytail: name-based OS guess; says nothing about in-place patching (source=image_name, low confidence).
_OS_PATTERNS: List[Tuple[Pattern, str, str]] = [
    (re.compile(r"ubuntu\D*?(\d{2})[._]?(\d{2})"), "ubuntu", "."),
    (re.compile(r"\bal(2023)-ami"), "amazon-linux", ""),
    (re.compile(r"amzn(2)-ami"), "amazon-linux", ""),
    (re.compile(r"amzn-ami"), "amazon-linux", "1"),
    (re.compile(r"windows[_ -]?server[_ -]?(\d{4})"), "windows-server", ""),
    (re.compile(r"debian[_ -]?(\d+)"), "debian", ""),
    (re.compile(r"\brhel[_ -]?(\d+(?:\.\d+)?)"), "rhel", ""),
    (re.compile(r"centos[_ -]?(?:stream[_ -]?)?(\d+)"), "centos", ""),
    (re.compile(r"rocky[_ -]?(?:linux[_ -]?)?(\d+(?:\.\d+)?)"), "rocky-linux", ""),
    (re.compile(r"alma[_ -]?linux[_ -]?(\d+(?:\.\d+)?)"), "almalinux", ""),
    (re.compile(r"oracle[_ -]?linux[_ -]?(\d+(?:\.\d+)?)"), "oracle-linux", ""),
    (re.compile(r"sles[_ -]?(\d+)"), "sles", ""),
    (re.compile(r"\bcos[_ -](\d+)"), "cos", ""),
]


def os_from_image_name(*names: Optional[str]) -> Optional[str]:
    """
    Best-effort OS identity from image names / descriptions / marketplace offer+sku.

    >>> os_from_image_name("ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240207")
    'ubuntu@22.04'
    """
    text = " ".join(n for n in names if n).lower()
    if not text:
        return None
    for pattern, product, joiner in _OS_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        version = joiner.join(match.groups()) if match.groups() else joiner
        return identity(product, version)
    return None
