from typing import List
from typing import Dict

from cartography.intel.gcp.resources import RESOURCE_FUNCTIONS


def parse_and_validate_gcp_requested_syncs(gcp_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in gcp_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS:
            validated_resources.append(resource)
        else:
            valid_syncs: str = ', '.join(RESOURCE_FUNCTIONS.keys())
            raise ValueError(
                f'Error parsing `gcp-requested-syncs`. You specified "{gcp_requested_syncs}". '
                f'Please check that your string is formatted properly. '
                f'Example valid input looks like "compute,storage,gke". '
                f'Our full list of valid values is: {valid_syncs}.',
            )
    return validated_resources

def transform_iam_bindings(bindings: Dict, project_id: str) -> tuple:
    users = []
    groups = []
    domains = []
    service_account = []
    entity_list = []
    public_access = False
    if len(bindings) != 0:
        for binding in bindings:
            for member in binding['members']:
                if member.startswith('allUsers') or member.startswith('allAuthenticatedUsers'):
                    public_access = True
                else:
                    if member.startswith('user:'):
                        usr = member[len('user:'):]
                        users.append({
                            "id": f'projects/{project_id}/users/{usr}',
                            "email": usr,
                            "name": usr.split("@")[0],
                        })

                    elif member.startswith('group:'):
                        grp = member[len('group:'):]
                        groups.append({
                            "id": f'projects/{project_id}/groups/{grp}',
                            "email": grp,
                            "name": grp.split('@')[0],
                        })

                    elif member.startswith('domain:'):
                        dmn = member[len('domain:'):]
                        domains.append({
                            "id": f'projects/{project_id}/domains/{dmn}',
                            "email": dmn,
                            "name": dmn,
                        })

                    elif member.startswith('serviceAccount:'):
                        sac = member[len('serviceAccount:'):]
                        service_account.append({
                            "id": f'projects/{project_id}/serviceAccounts/{sac}',
                            "email": sac,
                            "name": sac,
                        })
                    elif member.startswith('deleted:'):
                        pass
    else:
        public_access = None  

    entity_list.extend(users)
    entity_list.extend(groups)
    entity_list.extend(domains)
    entity_list.extend(service_account)
   
    return entity_list, public_access