from typing import Dict

from . import members
from . import projects
from . import repos


RESOURCE_FUNCTIONS: Dict = {
    'projects': projects.sync,
    'repos': repos.sync,
    'members': members.sync,
}
