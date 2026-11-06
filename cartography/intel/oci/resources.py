from typing import Dict

from . import audit_logging
from . import compute
from . import database
from . import containerregistry
from . import encryption
from . import iam
from . import monitoring
from . import network
from . import oke
from . import storage


RESOURCE_FUNCTIONS: Dict = {
    "iam": iam.sync,
    "compute": compute.sync,
    "network": network.sync,
    "encryption": encryption.sync,
    "monitoring": monitoring.sync,
    "storage": storage.sync,
    "oke": oke.sync,
    "containerregistry": containerregistry.sync,
    "logging": audit_logging.sync,
    "database": database.sync,
}
