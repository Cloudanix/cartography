from typing import Dict

from . import projects
from . import repos
from . import members


RESOURCE_FUNCTIONS: Dict = {
    'projects': projects.sync,
    'repos': repos.sync,
    'members': members.sync,
} 