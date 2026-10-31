import json
import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

import neo4j
from cloudconsolelink.clouds.gcp import GCPLinker
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from . import compute
from . import label
from cartography.client.core.tx import read_list_of_values_tx
from cartography.client.core.tx import run_write_query
from cartography.intel.gcp.util.errors import is_permission_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


@timeit
def get_compute_zones(compute: Resource, project_id: str) -> List[Dict]:
    compute_zones = []
    try:
        req = compute.zones().list(project=project_id)
        while req is not None:
            res = req.execute()
            if res.get('items'):
                for zone in res['items']:
                    compute_zones.append(zone)
            req = compute.zones().list_next(previous_request=req, previous_response=res)

        return compute_zones
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve zones on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_global_health_checks(compute: Resource, project_id: str, common_job_parameters) -> List[Dict]:
    global_health_checks = []
    try:
        req = compute.healthChecks().list(project=project_id)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                global_health_checks.extend(res['items'])
            req = compute.healthChecks().list_next(previous_request=req, previous_response=res)

        return global_health_checks
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve global health checks on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_global_health_checks(health_checks: List, project_id: str):
    list_health_checks = []

    for health_check in health_checks:
        health_check['id'] = f"projects/{project_id}/global/healthChecks/{health_check['name']}"
        health_check['region'] = 'global'
        health_check['type'] = 'global'
        health_check['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id,
            health_check_name=health_check['name'], resource_name='global_health_check',
        )
        list_health_checks.append(health_check)

    return list_health_checks


@timeit
def get_regional_health_checks(compute: Resource, project_id: str, region: str, common_job_parameters) -> List[Dict]:
    regional_health_checks = []
    try:
        req = compute.regionHealthChecks().list(project=project_id, region=region)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                regional_health_checks.extend(res['items'])
            req = compute.regionHealthChecks().list_next(previous_request=req, previous_response=res)

        return regional_health_checks
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err) or err.get('code') == 400:
            logger.warning(
                (
                    "Could not retrieve regional health checks on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_regional_health_checks(health_checks: List, project_id: str, region: str):
    list_health_checks = []

    for health_check in health_checks:
        health_check['id'] = f"projects/{project_id}/regions/{region}/healthChecks/{health_check['name']}"
        health_check['region'] = region
        health_check['type'] = 'regional'
        health_check['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id, health_check_name=health_check['name'],
            region=health_check['region'], resource_name='regional_health_check',
        )
        list_health_checks.append(health_check)

    return list_health_checks


@timeit
def load_health_checks(session: neo4j.Session, health_checks: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(load_health_checks_tx, health_checks, project_id, update_tag)


@timeit
def load_health_checks_tx(
    tx: neo4j.Transaction, health_checks: List[Dict],
    project_id: str, gcp_update_tag: int,
) -> None:

    query = """
    UNWIND $HealthChecks as hc
    MERGE (healthcheck:GCPHealthCheck{id:hc.id})
    ON CREATE SET
        healthcheck.firstseen = timestamp()
    SET
        healthcheck.uniqueId = hc.id,
        healthcheck.region = hc.region,
        healthcheck.type = hc.type,
        healthcheck.consolelink = hc.consolelink,
        healthcheck.checkIntervalSec = hc.checkIntervalSec,
        healthcheck.timeoutSec = hc.timeoutSec,
        healthcheck.lastupdated = $gcp_update_tag
    WITH healthcheck
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(healthcheck)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """

    tx.run(
        query,
        HealthChecks=health_checks,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_health_checks(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_health_checks_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_global_health_checks(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    health_checks = get_global_health_checks(compute, project_id, common_job_parameters)
    global_health_checks = transform_global_health_checks(health_checks, project_id)

    load_health_checks(neo4j_session, global_health_checks, project_id, gcp_update_tag)
    cleanup_health_checks(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, global_health_checks, gcp_update_tag, common_job_parameters, 'health_check', 'GCPHealthCheck')


@timeit
def sync_regional_health_checks(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str, regions: List,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    if regions:
        for region in regions:
            health_checks = get_regional_health_checks(compute, project_id, region, common_job_parameters)
            regional_health_checks = transform_regional_health_checks(health_checks, project_id, region)

            load_health_checks(neo4j_session, regional_health_checks, project_id, gcp_update_tag)
            cleanup_health_checks(neo4j_session, common_job_parameters)
            label.sync_labels(neo4j_session, regional_health_checks, gcp_update_tag, common_job_parameters, 'health_check', 'GCPHealthCheck')


@timeit
def get_global_instance_groups(compute: Resource, project_id: str, zone: Dict, common_job_parameters) -> List[Dict]:
    global_instance_groups = []
    try:
        req = compute.instanceGroups().list(project=project_id, zone=zone['name'])
        while req is not None:
            res = req.execute()
            if 'items' in res:
                global_instance_groups.extend(res['items'])
            req = compute.instanceGroups().list_next(previous_request=req, previous_response=res)

        return global_instance_groups
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve global instance groups on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_global_instance_groups(instance_groups: List, project_id: str, zone: dict):
    list_instance_groups = []

    for instancegroup in instance_groups:
        instancegroup['id'] = f"projects/{project_id}/zones/{zone['name']}/instanceGroups/{instancegroup['name']}"
        instancegroup['type'] = 'global'
        instancegroup['region'] = 'global'
        instancegroup['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id, instance_group_name=instancegroup['name'],
            zone=zone['name'], resource_name='global_instance_group',
        )
        list_instance_groups.append(instancegroup)

    return list_instance_groups


@timeit
def get_regional_instance_groups(compute: Resource, project_id: str, region: str, common_job_parameters) -> List[Resource]:
    regional_instance_groups = []
    try:
        req = compute.regionInstanceGroups().list(project=project_id, region=region)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                regional_instance_groups.extend(res['items'])
            req = compute.regionInstanceGroups().list_next(previous_request=req, previous_response=res)

        return regional_instance_groups
    except HttpError as e:
        if e.status_code == 404:
            logger.warning(
                (
                    "Could not retrieve regional instance groups on project %s due to 404. Code: %s, Message: %s"
                ), project_id, e.status_code, e.reason,
            )
            return []

        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve regional instance groups on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_regional_instance_groups(instance_groups: List, project_id: str, region: str):
    list_instance_groups = []

    for instancegroup in instance_groups:
        instancegroup['id'] = f"projects/{project_id}/regions/{region}/instanceGroups/{instancegroup['name']}"
        instancegroup['type'] = 'regional'
        instancegroup['region'] = region
        instancegroup['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id, instance_group_name=instancegroup['name'],
            region=region, resource_name='regional_instance_group',
        )
        list_instance_groups.append(instancegroup)

    return list_instance_groups


@timeit
def load_instance_groups(session: neo4j.Session, instance_groups: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(load_instance_groups_tx, instance_groups, project_id, update_tag)


@timeit
def load_instance_groups_tx(
    tx: neo4j.Transaction, instance_groups: List[Dict],
    project_id: str, gcp_update_tag: int,
) -> None:

    query = """
    UNWIND $InstanceGroups as ig
    MERGE (instancegroup:GCPInstanceGroup{id:ig.id})
    ON CREATE SET
        instancegroup.firstseen = timestamp()
    SET
        instancegroup.uniqueId = ig.id,
        instancegroup.type = ig.type,
        instancegroup.region = ig.region,
        instancegroup.size = ig.size,
        instancegroup.consolelink = ig.consolelink,
        instancegroup.network = ig.network,
        instancegroup.subnetwork = ig.subnetwork,
        instancegroup.lastupdated = $gcp_update_tag
    WITH instancegroup
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(instancegroup)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """

    tx.run(
        query,
        InstanceGroups=instance_groups,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_instance_groups(neo4j_session: neo4j.Session, common_job_parameters) -> None:
    run_cleanup_job('gcp_instance_groups_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_global_instance_groups(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    zones = get_compute_zones(compute, project_id)
    for zone in zones:
        instance_groups = get_global_instance_groups(compute, project_id, zone, common_job_parameters)
        global_instance_groups = transform_global_instance_groups(instance_groups, project_id, zone)
        load_instance_groups(neo4j_session, global_instance_groups, project_id, gcp_update_tag)
        label.sync_labels(neo4j_session, global_instance_groups, gcp_update_tag, common_job_parameters, 'instance_group', 'GCPInstanceGroup')
    cleanup_instance_groups(neo4j_session, common_job_parameters)


@timeit
def sync_regional_instance_groups(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str, regions: List,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    if regions:
        for region in regions:
            instance_groups = get_regional_instance_groups(compute, project_id, region, common_job_parameters)
            regional_instance_groups = transform_regional_instance_groups(instance_groups, project_id, region)
            load_instance_groups(neo4j_session, regional_instance_groups, project_id, gcp_update_tag)
            cleanup_instance_groups(neo4j_session, common_job_parameters)
            label.sync_labels(neo4j_session, regional_instance_groups, gcp_update_tag, common_job_parameters, 'instance_group', 'GCPInstanceGroup')


@timeit
def get_global_url_maps(compute: Resource, project_id: str, common_job_parameters) -> List[Dict]:
    global_url_maps = []
    try:
        req = compute.urlMaps().list(project=project_id)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                global_url_maps.extend(res['items'])
            req = compute.urlMaps().list_next(previous_request=req, previous_response=res)

        return global_url_maps
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve global url maps on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_global_url_maps(url_maps: List, project_id: str):
    list_url_maps = []

    for url_map in url_maps:
        url_map['region'] = 'global'
        url_map['type'] = 'global'
        url_map['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id, resource_name='url_map', instance_name=url_map['name'],
        )
        url_map['id'] = f"projects/{project_id}/global/urlmaps/{url_map['name']}"
        list_url_maps.append(url_map)

    return list_url_maps


@timeit
def get_regional_url_maps(compute: Resource, project_id: str, region: str, common_job_parameters) -> List[Dict]:
    regional_url_maps = []
    try:
        req = compute.regionUrlMaps().list(project=project_id, region=region)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                regional_url_maps.extend(res['items'])
            req = compute.regionUrlMaps().list_next(previous_request=req, previous_response=res)

        return regional_url_maps
    except HttpError as e:
        if e.status_code == 404:
            logger.warning(
                (
                    "Could not retrieve regional url maps on project %s due to 404. Code: %s, Message: %s"
                ), project_id, e.status_code, e.reason,
            )
            return []

        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve regional url maps on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_regional_url_maps(maps: List, region: str, project_id: str):
    list_url_maps = []

    for url_map in maps:
        url_map['region'] = region
        url_map['type'] = 'regional'
        url_map['consolelink'] = gcp_console_link.get_console_link(project_id=project_id, resource_name='load_balancer_home')
        url_map['id'] = f"projects/{project_id}/regions/{region}/urlmaps/{url_map['name']}"
        list_url_maps.append(url_map)

    return list_url_maps


@timeit
def load_url_maps(session: neo4j.Session, url_maps: List[Dict], project_id: str, update_tag: int) -> None:
    for url_map in url_maps:
        # The node id spells 'urlmaps'; forwarding rules reference the map by its self-link ('urlMaps').
        url_map['partial_uri'] = compute._parse_compute_full_uri_to_partial_uri(url_map.get('selfLink', ''))
        url_map['services'] = compute.url_map_backend_refs(url_map)
    session.execute_write(load_url_maps_tx, url_maps, project_id, update_tag)


@timeit
def load_url_maps_tx(
    tx: neo4j.Transaction, url_maps: List[Dict],
    project_id: str, gcp_update_tag: int,
) -> None:

    query = """
    UNWIND $Maps as mp
    MERGE (map:GCPUrlMap{id:mp.id})
    ON CREATE SET
        map.firstseen = timestamp()
    SET
        map.lastupdated = $gcp_update_tag,
        map.region = mp.region,
        map.type = mp.type,
        map.consolelink = mp.consolelink,
        map.uniqueId = mp.id,
        map.name = mp.name,
        map.defaultService = mp.defaultService,
        map.partial_uri = mp.partial_uri,
        map.services = mp.services
    WITH map
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(map)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """

    tx.run(
        query,
        Maps=url_maps,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_url_maps(neo4j_session: neo4j.Session, common_job_parameters) -> None:
    run_cleanup_job('gcp_url_maps_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_global_url_maps(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    maps = get_global_url_maps(compute, project_id, common_job_parameters)
    global_maps = transform_global_url_maps(maps, project_id)
    load_url_maps(neo4j_session, global_maps, project_id, gcp_update_tag)
    cleanup_url_maps(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, global_maps, gcp_update_tag, common_job_parameters, 'url_map', 'GCPUrlMap')


@timeit
def sync_regional_url_maps(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str, regions: List,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    if regions:
        for region in regions:
            maps = get_regional_url_maps(compute, project_id, region, common_job_parameters)
            regional_maps = transform_regional_url_maps(maps, region, project_id)
            load_url_maps(neo4j_session, regional_maps, project_id, gcp_update_tag)
            cleanup_url_maps(neo4j_session, common_job_parameters)
            label.sync_labels(neo4j_session, regional_maps, gcp_update_tag, common_job_parameters, 'url_map', 'GCPUrlMap')


@timeit
def get_ssl_policies(compute: Resource, project_id: str, common_job_parameters) -> List[Dict]:
    ssl_policies = []
    try:
        req = compute.sslPolicies().list(project=project_id)
        while req is not None:
            res = req.execute()
            if 'items' in res:
                ssl_policies.extend(res['items'])
            req = compute.sslPolicies().list_next(previous_request=req, previous_response=res)

        return ssl_policies
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if is_permission_error(e, err):
            logger.warning(
                (
                    "Could not retrieve ssl policies on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_ssl_policies(ssl_policies: List, project_id: str):
    list_ssl_policies = []

    for policy in ssl_policies:
        policy['id'] = f"projects/{project_id}/global/sslPolicies/{policy['name']}"
        policy['region'] = 'global'
        policy['consolelink'] = gcp_console_link.get_console_link(
            project_id=project_id,
            ssl_policy_name=policy['name'], resource_name='ssl_policy',
        )
        list_ssl_policies.append(policy)

    return list_ssl_policies


@timeit
def load_ssl_policies(session: neo4j.Session, ssl_policies: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(load_ssl_policies_tx, ssl_policies, project_id, update_tag)


@timeit
def load_ssl_policies_tx(
    tx: neo4j.Transaction, ssl_policies: List[Dict],
    project_id: str, gcp_update_tag: int,
) -> None:

    query = """
    UNWIND $SSLPolicies as pol
    MERGE (policy:GCPSSLPolicy{id:pol.id})
    ON CREATE SET
        policy.firstseen = timestamp()
    SET
        policy.uniqueId = pol.id,
        policy.region = pol.region,
        policy.name = pol.name,
        policy.consolelink = pol.consolelink,
        policy.minTlsVersion = pol.minTlsVersion,
        policy.lastupdated = $gcp_update_tag
    WITH policy
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(policy)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """

    tx.run(
        query,
        SSLPolicies=ssl_policies,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_ssl_policies(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_ssl_policies_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_ssl_policies(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    policies = get_ssl_policies(compute, project_id, common_job_parameters)
    ssl_policies = transform_ssl_policies(policies, project_id)
    load_ssl_policies(neo4j_session, ssl_policies, project_id, gcp_update_tag)
    cleanup_ssl_policies(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, ssl_policies, gcp_update_tag, common_job_parameters, 'ssl_policy', 'GCPSSLPolicy')


# Zonal NEG types whose endpoints are VMs (GCE_VM_IP_PORT: container-native GKE NEGs and VM ports; GCE_VM_IP:
# passthrough load balancers). The other types point at serverless apps, the internet, on-prem or PSC.
VM_NEG_TYPES = ('GCE_VM_IP_PORT', 'GCE_VM_IP')


def _list_pages(collection: Resource, method: str, **kwargs: Any) -> List[Dict]:
    """Every response page of collection.<method>(**kwargs), following <method>_next."""
    pages = []
    req = getattr(collection, method)(**kwargs)
    while req is not None:
        res = req.execute()
        pages.append(res)
        req = getattr(collection, f'{method}_next')(previous_request=req, previous_response=res)
    return pages


@timeit
def get_network_endpoint_groups(compute_client: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    """
    Every network endpoint group of the project: zonal ones from one aggregatedList, regional ones (serverless,
    internet, PSC) from regionNetworkEndpointGroups.list per region, global ones (internet) from one
    globalNetworkEndpointGroups.list. Deduplicated by selfLink in case the aggregated list also returns regional or
    global scopes. A scope that can't be read is skipped with a warning.
    """
    calls: List[Tuple[Resource, str, Dict[str, Any]]] = [
        (compute_client.networkEndpointGroups(), 'aggregatedList', {'returnPartialSuccess': True}),
    ]
    calls.append((compute_client.globalNetworkEndpointGroups(), 'list', {}))
    calls.extend((compute_client.regionNetworkEndpointGroups(), 'list', {'region': r}) for r in regions)
    negs: Dict[str, Dict] = {}
    for collection, method, kwargs in calls:
        try:
            pages = _list_pages(collection, method, project=project_id, **kwargs)
        except HttpError as e:
            logger.warning(f"Could not list network endpoint groups ({method} {kwargs}) on project {project_id} - {e}")
            continue
        for page in pages:
            items = page.get('items', [])
            if method == 'aggregatedList':
                items = [neg for scoped in items.values() for neg in scoped.get('networkEndpointGroups', [])]
            negs.update({neg['selfLink']: neg for neg in items if neg.get('selfLink')})
    return list(negs.values())


def transform_network_endpoint_groups(negs: List[Dict], project_id: str) -> List[Dict]:
    result = []
    for neg in negs:
        neg_id = compute._parse_compute_full_uri_to_partial_uri(neg['selfLink'])
        zone = neg['zone'].split('/')[-1] if neg.get('zone') else None
        region = neg['region'].split('/')[-1] if neg.get('region') else None
        cloud_run, function = neg.get('cloudRun', {}), neg.get('cloudFunction', {})
        app_engine = neg.get('appEngine', {})
        result.append({
            'id': neg_id,
            'name': neg.get('name'),
            'network_endpoint_type': neg.get('networkEndpointType'),
            'zone': zone,
            'region': region or ('-'.join(zone.split('-')[:2]) if zone else 'global'),
            'network': compute._parse_compute_full_uri_to_partial_uri(neg['network']) if neg.get('network') else None,
            'subnetwork': (
                compute._parse_compute_full_uri_to_partial_uri(neg['subnetwork']) if neg.get('subnetwork') else None
            ),
            'size': neg.get('size'),
            'default_port': neg.get('defaultPort'),
            # Serverless target: the app the load balancer sends traffic to (a URL mask routes to several).
            'cloud_run_service': cloud_run.get('service'),
            'cloud_run_tag': cloud_run.get('tag'),
            'cloud_function': function.get('function'),
            'app_engine_service': app_engine.get('service'),
            'app_engine_version': app_engine.get('version'),
            'url_mask': cloud_run.get('urlMask') or function.get('urlMask') or app_engine.get('urlMask'),
            'psc_target_service': neg.get('pscTargetService'),
            'consolelink': gcp_console_link.get_console_link(
                resource_name='network_endpoint_group', project_id=project_id, zone=zone, instance_name=neg.get('name'),
            ) if zone else None,
        })
    return result


@timeit
def load_network_endpoint_groups(
    neo4j_session: neo4j.Session, negs: List[Dict], project_id: str, update_tag: int,
) -> None:
    query = """
    UNWIND $Negs AS n
    MERGE (neg:GCPNetworkEndpointGroup{id: n.id})
    ON CREATE SET neg.firstseen = timestamp()
    SET neg.uniqueId = n.id,
        neg.name = n.name,
        neg.network_endpoint_type = n.network_endpoint_type,
        neg.zone = n.zone,
        neg.region = n.region,
        neg.network = n.network,
        neg.subnetwork = n.subnetwork,
        neg.size = n.size,
        neg.default_port = n.default_port,
        neg.cloud_run_service = n.cloud_run_service,
        neg.cloud_run_tag = n.cloud_run_tag,
        neg.cloud_function = n.cloud_function,
        neg.app_engine_service = n.app_engine_service,
        neg.app_engine_version = n.app_engine_version,
        neg.url_mask = n.url_mask,
        neg.psc_target_service = n.psc_target_service,
        neg.consolelink = n.consolelink,
        neg.lastupdated = $UpdateTag
    WITH neg
    MATCH (p:GCPProject{id: $ProjectId})
    MERGE (p)-[r:RESOURCE]->(neg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """
    run_write_query(neo4j_session, query, Negs=negs, ProjectId=project_id, UpdateTag=update_tag)


@timeit
def sync_network_endpoint_groups(
    neo4j_session: neo4j.Session, compute_client: Resource, project_id: str, regions: List[str],
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:
    negs = transform_network_endpoint_groups(
        get_network_endpoint_groups(compute_client, project_id, regions or []), project_id,
    )
    load_network_endpoint_groups(neo4j_session, negs, project_id, gcp_update_tag)
    run_cleanup_job('gcp_network_endpoint_groups_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def get_external_backend_groups(neo4j_session: neo4j.Session, project_id: str) -> List[str]:
    """
    Partial URIs of the backend groups (instance groups, NEGs) of the project's EXTERNAL / EXTERNAL_MANAGED backend
    services.
    """
    query = """
    MATCH (:GCPProject{id: $ProjectId})-[:RESOURCE]->(bs:GCPBackendService)
    WHERE bs.loadBalancingScheme IN $Schemes
    UNWIND coalesce(bs.backend_groups, []) AS group
    RETURN DISTINCT group
    """
    return neo4j_session.execute_read(
        read_list_of_values_tx, query, ProjectId=project_id, Schemes=list(compute.EXTERNAL_LB_SCHEMES),
    )


def _zonal_groups(groups: List[str], project_id: str, kind: str) -> List[Tuple[str, str]]:
    """(zone, name) of each projects/{project_id}/zones/{zone}/{kind}/{name} reference; other scopes are skipped."""
    zonal = []
    for group in groups:
        parts = group.split('/')
        if len(parts) == 6 and parts[:3] == ['projects', project_id, 'zones'] and parts[4] == kind:
            zonal.append((parts[3], parts[5]))
    return zonal


@timeit
def get_instance_group_members(compute_client: Resource, project_id: str, zone: str, name: str) -> List[str]:
    """
    Partial URIs of every instance in a zonal instance group, managed or unmanaged, whatever its state (the analysis
    job checks the instance status). [] when the group can't be read (e.g. missing compute.instanceGroups.get).
    """
    members: List[str] = []
    try:
        req = compute_client.instanceGroups().listInstances(
            project=project_id, zone=zone, instanceGroup=name, body={'instanceState': 'ALL'},
        )
        while req is not None:
            res = req.execute()
            members.extend(
                compute._parse_compute_full_uri_to_partial_uri(item['instance'])
                for item in res.get('items', []) if item.get('instance')
            )
            req = compute_client.instanceGroups().listInstances_next(previous_request=req, previous_response=res)
    except HttpError as e:
        logger.warning(f"Could not list instances of instance group {name} in {zone}; members stay unresolved - {e}")
        return []
    return members


@timeit
def load_instance_group_members(
    neo4j_session: neo4j.Session, members: List[Dict], project_id: str, update_tag: int,
) -> None:
    query = """
    UNWIND $Members AS m
    MATCH (p:GCPProject{id: $ProjectId})-[:RESOURCE]->(ig:GCPInstanceGroup{id: m.group})
    MATCH (p)-[:RESOURCE]->(i:GCPInstance{id: m.instance})
    MERGE (i)-[r:MEMBER_OF_INSTANCE_GROUP]->(ig)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """
    run_write_query(neo4j_session, query, Members=members, ProjectId=project_id, UpdateTag=update_tag)


@timeit
def get_external_vm_negs(neo4j_session: neo4j.Session, project_id: str, groups: List[str]) -> List[str]:
    """Ids of this project's zonal VM NEGs among the given backend groups."""
    query = """
    MATCH (:GCPProject{id: $ProjectId})-[:RESOURCE]->(neg:GCPNetworkEndpointGroup)
    WHERE neg.id IN $Groups AND neg.zone IS NOT NULL AND neg.network_endpoint_type IN $Types
    RETURN neg.id
    """
    return neo4j_session.execute_read(
        read_list_of_values_tx, query, ProjectId=project_id, Groups=groups, Types=list(VM_NEG_TYPES),
    )


@timeit
def get_neg_vm_endpoints(compute_client: Resource, project_id: str, zone: str, name: str) -> List[Dict]:
    """
    One row per VM of a zonal VM NEG: instance partial URI, its endpoint IP addresses and ports (a container-native
    GKE NEG has one endpoint per pod, all on the node VM). [] when the NEG can't be read (e.g. missing
    compute.networkEndpointGroups.get).
    """
    neg_id = f'projects/{project_id}/zones/{zone}/networkEndpointGroups/{name}'
    endpoints: Dict[str, Dict] = {}
    try:
        pages = _list_pages(
            compute_client.networkEndpointGroups(), 'listNetworkEndpoints',
            project=project_id, zone=zone, networkEndpointGroup=name, body={},
        )
    except HttpError as e:
        logger.warning(f"Could not list endpoints of network endpoint group {neg_id}; they stay unresolved - {e}")
        return []
    for page in pages:
        for item in page.get('items', []):
            endpoint = item.get('networkEndpoint', {})
            instance = endpoint.get('instance')
            if not instance:
                continue
            # The instance is given by name or URL; a NEG's VMs are in its own zone.
            if '/' not in instance:
                instance = f'projects/{project_id}/zones/{zone}/instances/{instance}'
            row = endpoints.setdefault(
                compute._parse_compute_full_uri_to_partial_uri(instance),
                {'neg': neg_id, 'ip_addresses': [], 'ports': []},
            )
            if endpoint.get('ipAddress') and endpoint['ipAddress'] not in row['ip_addresses']:
                row['ip_addresses'].append(endpoint['ipAddress'])
            if endpoint.get('port') is not None and endpoint['port'] not in row['ports']:
                row['ports'].append(endpoint['port'])
    return [{'instance': instance, **row} for instance, row in endpoints.items()]


@timeit
def load_neg_vm_endpoints(
    neo4j_session: neo4j.Session, endpoints: List[Dict], project_id: str, update_tag: int,
) -> None:
    query = """
    UNWIND $Endpoints AS e
    MATCH (p:GCPProject{id: $ProjectId})-[:RESOURCE]->(neg:GCPNetworkEndpointGroup{id: e.neg})
    MATCH (p)-[:RESOURCE]->(i:GCPInstance{id: e.instance})
    MERGE (i)-[r:MEMBER_OF_NETWORK_ENDPOINT_GROUP]->(neg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.ip_addresses = e.ip_addresses,
        r.ports = e.ports,
        r.lastupdated = $UpdateTag
    """
    run_write_query(neo4j_session, query, Endpoints=endpoints, ProjectId=project_id, UpdateTag=update_tag)


@timeit
def link_backend_services_to_negs(neo4j_session: neo4j.Session, project_id: str, update_tag: int) -> None:
    """
    Graph only: (GCPBackendService)-[:HAS_BACKEND]->(GCPNetworkEndpointGroup) from backend_groups, and
    (GCPNetworkEndpointGroup)-[:SERVERLESS_TARGET]->(GCPFunction) for a serverless NEG naming a function of the same
    project and region. Cloud Run and App Engine targets stay as properties on the NEG (cloud_run_service,
    app_engine_service): no Cloud Run service or App Engine node is ingested to link to.
    """
    query = """
    MATCH (p:GCPProject{id: $ProjectId})-[:RESOURCE]->(bs:GCPBackendService)
    UNWIND coalesce(bs.backend_groups, []) AS group
    MATCH (p)-[:RESOURCE]->(neg:GCPNetworkEndpointGroup{id: group})
    MERGE (bs)-[r:HAS_BACKEND]->(neg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    WITH DISTINCT p, neg
    WHERE neg.cloud_function IS NOT NULL
    MATCH (p)-[:RESOURCE]->(fn:GCPFunction{
        id: 'projects/' + p.id + '/locations/' + neg.region + '/functions/' + neg.cloud_function
    })
    MERGE (neg)-[t:SERVERLESS_TARGET]->(fn)
    ON CREATE SET t.firstseen = timestamp()
    SET t.lastupdated = $UpdateTag
    """
    run_write_query(neo4j_session, query, ProjectId=project_id, UpdateTag=update_tag)


@timeit
def sync_external_backend_members(
    neo4j_session: neo4j.Session, compute_client: Resource, project_id: str, common_job_parameters: Dict,
) -> None:
    """
    Post-sync step: backend services (cloudcdn), instance groups and NEGs (loadbalancer), instances (compute) and
    functions (cloudfunction) sync in parallel, so the project orchestrator calls this after all of them.

    For the backend groups of this project's EXTERNAL / EXTERNAL_MANAGED backend services only, links each instance
    to the zonal instance groups it is a member of (MEMBER_OF_INSTANCE_GROUP; unmanaged groups such as GKE Ingress's
    k8s-ig--* have no other membership source) and to the zonal VM NEGs it is an endpoint of
    (MEMBER_OF_NETWORK_ENDPOINT_GROUP; e.g. GKE container-native NEGs). API calls: one instanceGroups.listInstances
    per such instance group and one networkEndpointGroups.listNetworkEndpoints per such NEG (each paged by 500);
    groups behind internal backend services, or behind no backend service, cost nothing. Then links backend
    services to NEGs and serverless NEGs to functions (graph only).
    """
    update_tag = common_job_parameters['UPDATE_TAG']
    groups = get_external_backend_groups(neo4j_session, project_id)
    members = [
        {'group': f'projects/{project_id}/zones/{zone}/instanceGroups/{name}', 'instance': instance}
        for zone, name in _zonal_groups(groups, project_id, 'instanceGroups')
        for instance in get_instance_group_members(compute_client, project_id, zone, name)
    ]
    load_instance_group_members(neo4j_session, members, project_id, update_tag)
    endpoints = [
        endpoint
        for zone, name in _zonal_groups(
            get_external_vm_negs(neo4j_session, project_id, groups), project_id, 'networkEndpointGroups',
        )
        for endpoint in get_neg_vm_endpoints(compute_client, project_id, zone, name)
    ]
    load_neg_vm_endpoints(neo4j_session, endpoints, project_id, update_tag)
    link_backend_services_to_negs(neo4j_session, project_id, update_tag)
    run_cleanup_job('gcp_lb_backend_members_cleanup.json', neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session, compute: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict, regions: List,
) -> None:
    tic = time.perf_counter()

    logger.info(f"Syncing load balancer for project {project_id}, at {tic}")

    sync_global_health_checks(neo4j_session, compute, project_id, gcp_update_tag, common_job_parameters)
    sync_regional_health_checks(neo4j_session, compute, project_id, regions, gcp_update_tag, common_job_parameters)
    sync_global_instance_groups(neo4j_session, compute, project_id, gcp_update_tag, common_job_parameters)
    sync_regional_instance_groups(neo4j_session, compute, project_id, regions, gcp_update_tag, common_job_parameters)
    sync_global_url_maps(neo4j_session, compute, project_id, gcp_update_tag, common_job_parameters)
    sync_regional_url_maps(neo4j_session, compute, project_id, regions, gcp_update_tag, common_job_parameters)
    sync_ssl_policies(neo4j_session, compute, project_id, gcp_update_tag, common_job_parameters)
    sync_network_endpoint_groups(neo4j_session, compute, project_id, regions, gcp_update_tag, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process load balancer: {toc - tic:0.4f} seconds")
