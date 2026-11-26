"""
GCPInstance properties read by the VM auto-install dry-run checks (doc: "Auto Install Dry Run Checks GCP").

    os_short_name / os_long_name / os_version   os.family        VM Manager OS Inventory
    iap_ssh_ingress_allowed                     platform.access  firewall rules already in the graph
    iap_tunnel_access_granted                   platform.access  testIamPermissions iap.tunnelInstances.accessViaIAP
    os_login_admin_granted                      platform.access  testIamPermissions compute.instances.osAdminLogin
    service_account_user_granted                platform.access  testIamPermissions iam.serviceAccounts.actAs

architecture and os_login_enabled are set by the instance sync (compute.py). vm_os and vm_os_version
are set there from the boot-disk license, then overwritten here from VM Manager inventory when that
inventory names a known OS. Same order as EC2: AMI first, SSM PlatformName second.

The *_granted checks test the identity this sync runs as (config.credentials["account_email"]): the Cloudanix
service account in the customer's project, which the dry-run and auto-install use to reach the VM. Each is
tested once on the project (covers grants inherited from folders / the organization and group membership);
only when the project does not grant it is it tested per VM or per service account.

Runs after the project's syncs, as compute.sync_gke_node_links does. A value that cannot be determined (API
error, data not visible) is written as null, never as a guess.
"""
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import from_cidr
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import levels_open
from cartography.intel.gcp.exposure_layers.network import NON_INTERNET
from cartography.intel.gcp.exposure_layers.network import read_instances
from cartography.intel.gcp.exposure_layers.network import read_vpcs
from cartography.intel.gcp.exposure_layers.network import VpcFacts
from cartography.util import timeit

logger = logging.getLogger(__name__)

# IAP TCP forwarding source range. https://cloud.google.com/iap/docs/using-tcp-forwarding
IAP_RANGE = "35.235.240.0/20"
SSH = PortSet.of(TCP, 22, 22)
# IAP TCP forwarding traffic is in the non-internet network context.
# https://cloud.google.com/firewall/docs/understand-network-contexts
_IAP_CONTEXTS = frozenset({NON_INTERNET})

PERM_IAP_TUNNEL = "iap.tunnelInstances.accessViaIAP"
PERM_OS_ADMIN_LOGIN = "compute.instances.osAdminLogin"
PERM_ACT_AS = "iam.serviceAccounts.actAs"

_INSTANCES_QUERY = """
MATCH (p:GCPProject{id: $GCP_PROJECT_ID})-[:RESOURCE]->(i:GCPInstance)
WHERE i.lastupdated = $UPDATE_TAG
OPTIONAL MATCH (i)-[:USES]->(sa:GCPServiceAccount)
RETURN i.id AS id, i.instancename AS name, i.zone_name AS zone, i.instance_id AS instance_id,
    p.projectnumber AS project_number, collect(DISTINCT sa.email) AS service_accounts
"""

_WRITE_QUERY = """
UNWIND $rows AS row
MATCH (:GCPProject{id: $GCP_PROJECT_ID})-[:RESOURCE]->(i:GCPInstance{id: row.id})
SET i += row.props
"""

_WRITE_BATCH = 500


def _inventory_instance(name: str) -> Optional[str]:
    """
    Instance segment of an inventory name: projects/{p}/locations/{zone}/instances/{instance}/inventory.
    >>> _inventory_instance("projects/123/locations/us-central1-a/instances/456/inventory")
    '456'
    """
    parts = name.split("/")
    if "instances" not in parts:
        return None
    i = parts.index("instances")
    return parts[i + 1] if i + 1 < len(parts) else None


@timeit
def get_os_inventories(osconfig: Resource, project_id: str, zones: Set[str]) -> Dict[str, Dict]:
    """
    osInfo of every VM that VM Manager reports in these zones, keyed by the instance segment of the inventory
    name (the numeric instance id). A zone whose call fails is skipped: its VMs get no OS fields.
    https://cloud.google.com/compute/vm-manager/docs/os-inventory/view-os-details
    """
    found: Dict[str, Dict] = {}
    for zone in sorted(zones):
        try:
            req = osconfig.projects().locations().instances().inventories().list(
                parent=f"projects/{project_id}/locations/{zone}/instances/-", view="BASIC",
            )
            while req is not None:
                res = req.execute()
                for inventory in res.get("inventories", []):
                    instance = _inventory_instance(inventory.get("name", ""))
                    if instance:
                        found[instance] = inventory.get("osInfo") or {}
                req = osconfig.projects().locations().instances().inventories().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            # VM Manager / the OS Config API off on the project is the common case: the VMs fall back to vm_os.
            logger.info(f"Could not get OS inventory of project {project_id} zone {zone} - {e}")
    return found


def _vm_os_from_inventory(info: Dict) -> Dict[str, str]:
    """
    vm_os / vm_os_version from VM Manager osInfo, using the same matcher as the boot-disk license.

    Returned only when a known OS is named. An empty dict leaves the license-derived values in place:
    SET += {vm_os: null} would delete them.
    """
    # Imported here: compute is heavy, and importing it at module load cycles through the GCP package.
    from cartography.intel.gcp.compute import _match_operating_system
    from cartography.intel.gcp.compute import _numeric_os_version

    short_name = info.get("shortName") or ""
    long_name = info.get("longName") or ""
    vm_os = _match_operating_system(f"{short_name} {long_name}")
    if not vm_os:
        return {}
    # Skip a version we could not parse. Writing "Unknown" would erase a version the boot-disk license already stored.
    fields = {"vm_os": vm_os}
    version = _numeric_os_version(vm_os, info.get("version") or "", long_name, short_name)
    if version != "Unknown":
        fields["vm_os_version"] = version
    return fields


def os_fields(row: Dict, inventories: Dict[str, Dict]) -> Dict[str, Optional[str]]:
    info = inventories.get(str(row.get("instance_id") or "")) or inventories.get(row.get("name") or "") or {}
    fields: Dict[str, Optional[str]] = {
        "os_short_name": info.get("shortName"),
        "os_long_name": info.get("longName"),
        "os_version": info.get("version"),
    }
    fields.update(_vm_os_from_inventory(info))
    return fields


def _iap_source(fw: Firewall) -> bool:
    # A VPC rule with no source defaults to 0.0.0.0/0, which covers the IAP range; from_cidr only
    # applies that default to a 0.0.0.0/0 source.
    if not fw.in_policy and not fw.has_source:
        return True
    return from_cidr(IAP_RANGE, _IAP_CONTEXTS)(fw)


def iap_ssh_ingress_allowed(inst: Optional[Instance], vpcs: Dict[str, VpcFacts]) -> Optional[bool]:
    """
    Firewall rules and policies of the instance's networks let tcp:22 in from the IAP range. None when the
    instance has no network or some network's firewalls are not visible to this workspace.
    ponytail: any NIC counts, though IAP uses nic0 by default; regional network firewall policies and host
    firewalls are not evaluated (as in the exposure layers).
    """
    if inst is None or not inst.vpcs:
        return None
    if any(v not in vpcs or not vpcs[v].visible for v in inst.vpcs):
        return None
    return any(
        not levels_open(vpcs[v].levels, inst.tags, inst.sas, _iap_source).intersect(SSH).is_empty()
        for v in inst.vpcs
    )


def _granted(request: object, permission: str, what: str) -> Optional[bool]:
    """Run a testIamPermissions request: True / False, or None when the call fails."""
    try:
        res = request.execute()  # type: ignore[attr-defined]
    except HttpError as e:
        logger.info(f"testIamPermissions {permission} on {what} failed - {e}")
        return None
    return permission in (res.get("permissions") or [])


def project_grants(crm_v1: Resource, project_id: str, permission: str) -> Optional[bool]:
    """
    The sync identity holds `permission` on the project, directly or inherited (folder, organization, groups).
    One call per permission, so a permission the project resource rejects cannot fail the others.
    """
    request = crm_v1.projects().testIamPermissions(resource=project_id, body={"permissions": [permission]})
    return _granted(request, permission, f"project {project_id}")


def _either(project_level: Optional[bool], resource_level: Optional[bool]) -> Optional[bool]:
    """Granted when either level grants it; unknown when neither grants it and one is unknown."""
    if project_level or resource_level:
        return True
    if project_level is None or resource_level is None:
        return None
    return False


class PermissionChecker:
    """Per-VM / per-account permission tests, skipped when the project already grants the permission."""

    def __init__(self, resources: Resource, project_id: str) -> None:
        self.compute = resources.compute
        self.iam = resources.iam
        self.iap = resources.iap
        self.project_id = project_id
        self.on_project = {
            p: project_grants(resources.crm_v1, project_id, p)
            for p in (PERM_IAP_TUNNEL, PERM_OS_ADMIN_LOGIN, PERM_ACT_AS)
        }
        self._act_as: Dict[str, Optional[bool]] = {}

    def iap_tunnel(self, row: Dict) -> Optional[bool]:
        if self.on_project[PERM_IAP_TUNNEL]:
            return True
        project = row.get("project_number") or self.project_id
        resource = f"projects/{project}/iap_tunnel/zones/{row['zone']}/instances/{row['name']}"
        request = self.iap.v1().testIamPermissions(resource=resource, body={"permissions": [PERM_IAP_TUNNEL]})
        return _either(self.on_project[PERM_IAP_TUNNEL], _granted(request, PERM_IAP_TUNNEL, resource))

    def os_admin_login(self, row: Dict) -> Optional[bool]:
        if self.on_project[PERM_OS_ADMIN_LOGIN]:
            return True
        request = self.compute.instances().testIamPermissions(
            project=self.project_id, zone=row["zone"], resource=row["name"],
            body={"permissions": [PERM_OS_ADMIN_LOGIN]},
        )
        return _either(self.on_project[PERM_OS_ADMIN_LOGIN], _granted(request, PERM_OS_ADMIN_LOGIN, row["id"]))

    def _act_as_account(self, email: str) -> Optional[bool]:
        if email not in self._act_as:
            request = self.iam.projects().serviceAccounts().testIamPermissions(
                resource=f"projects/-/serviceAccounts/{email}", body={"permissions": [PERM_ACT_AS]},
            )
            self._act_as[email] = _either(self.on_project[PERM_ACT_AS], _granted(request, PERM_ACT_AS, email))
        return self._act_as[email]

    def service_account_user(self, row: Dict) -> Optional[bool]:
        """
        The sync identity can act as every service account the VM runs as. True for a VM without one: OS Login
        then needs no roles/iam.serviceAccountUser.
        ponytail: accounts are read from the instance's USES edges; an account of another customer gets no
        edge (compute._attach_instance_service_account) and is not tested.
        """
        if self.on_project[PERM_ACT_AS]:
            return True
        results = [self._act_as_account(email) for email in row.get("service_accounts") or []]
        if any(r is False for r in results):
            return False
        if any(r is None for r in results):
            return None
        return True


def read_precheck_instances(neo4j_session: neo4j.Session, project_id: str, update_tag: int) -> List[Dict]:
    """This sync's instances of the project (its own RESOURCE edges only)."""
    return [
        dict(r) for r in neo4j_session.run(_INSTANCES_QUERY, GCP_PROJECT_ID=project_id, UPDATE_TAG=update_tag)
    ]


def _exposure_view(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> tuple:
    """Instances and networks as the exposure layers read them; empty when the parameters are missing."""
    try:
        params = {
            k: common_job_parameters[k] for k in ("WORKSPACE_ID", "GCP_ORGANIZATION_ID", "GCP_PROJECT_ID", "UPDATE_TAG")
        }
        return read_instances(neo4j_session, params), read_vpcs(neo4j_session, params)
    except KeyError as e:
        logger.warning(f"iap_ssh_ingress_allowed not evaluated, missing job parameter {e}")
        return {}, {}


def load_precheck_fields(neo4j_session: neo4j.Session, rows: List[Dict], project_id: str) -> None:
    for i in range(0, len(rows), _WRITE_BATCH):
        neo4j_session.run(_WRITE_QUERY, rows=rows[i:i + _WRITE_BATCH], GCP_PROJECT_ID=project_id).consume()


@timeit
def sync(neo4j_session: neo4j.Session, resources: Resource, project_id: str, common_job_parameters: Dict) -> None:
    """
    Set the dry-run properties on the project's instances synced in this run.
    :param resources: the GCP Resources namedtuple (compute, crm_v1, iam, iap, osconfig)
    :param common_job_parameters: needs UPDATE_TAG; WORKSPACE_ID and GCP_ORGANIZATION_ID for the firewall check
    """
    rows = read_precheck_instances(neo4j_session, project_id, common_job_parameters["UPDATE_TAG"])
    if not rows:
        return
    inventories = get_os_inventories(resources.osconfig, project_id, {r["zone"] for r in rows if r.get("zone")})
    exposure_instances, vpcs = _exposure_view(neo4j_session, common_job_parameters)
    checker = PermissionChecker(resources, project_id)
    out = []
    for row in rows:
        props: Dict[str, Optional[object]] = dict(os_fields(row, inventories))
        props["iap_ssh_ingress_allowed"] = iap_ssh_ingress_allowed(exposure_instances.get(row["id"]), vpcs)
        if row.get("zone") and row.get("name"):
            props["iap_tunnel_access_granted"] = checker.iap_tunnel(row)
            props["os_login_admin_granted"] = checker.os_admin_login(row)
        else:
            props["iap_tunnel_access_granted"] = props["os_login_admin_granted"] = None
        props["service_account_user_granted"] = checker.service_account_user(row)
        out.append({"id": row["id"], "props": props})
    load_precheck_fields(neo4j_session, out, project_id)
    logger.info(f"vm precheck fields set on {len(out)} instances of project {project_id}")
