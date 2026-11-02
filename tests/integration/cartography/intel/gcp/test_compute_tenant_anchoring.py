from cartography.intel.gcp import compute
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import OWN_OTHER
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import put_principal
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import targets
from tests.integration.cartography.intel.gcp.common import tenant_params


def _vm(project):
    return f'projects/{project}/zones/z-a/instances/vm'


def _vpc(project):
    return f'projects/{project}/global/networks/net'


def _sa(project):
    return f'svc@{project}.iam.gserviceaccount.com'


def _fw(project):
    return f'projects/{project}/global/firewalls/fw'


def _seed(neo4j_session):
    # Every project holds an instance, a VPC with a firewall, and a service account, as its syncs leave them.
    seed_tenants(neo4j_session)
    for project in (OWN, OWN_OTHER, FOREIGN):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPInstance', _vm(project))
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPVpc', _vpc(project))
        put(neo4j_session, 'GCPVpc', _vpc(project), 'RESOURCE', 'GCPFirewall', _fw(project))
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPServiceAccount', _sa(project), email=_sa(project))
        put(
            neo4j_session, 'GCPInstance', _vm(project), 'NETWORK_INTERFACE', 'GCPNetworkInterface',
            f'{_vm(project)}/networkinterfaces/nic0',
        )


def _instance(vm_project, vpc_project, sa_project, nic='nic0'):
    return {
        'partial_uri': _vm(vm_project),
        'tags': {'items': ['web']},
        'networkInterfaces': [{
            'name': nic, 'network': _vpc(vpc_project), 'vpc_partial_uri': _vpc(vpc_project),
            'subnet_partial_uri': f'projects/{vpc_project}/regions/r/subnetworks/s',
            'accessConfigs': [{'type': 'ONE_TO_ONE_NAT', 'name': 'nat'}],
        }],
        'serviceAccounts': [{'email': _sa(sa_project)}],
        'image_partial_uri': 'projects/debian-cloud/global/images/debian',
    }


def _load_instance_links(neo4j_session, instances):
    params = tenant_params()
    compute._attach_instance_tags(neo4j_session, instances, TAG, params)
    compute._attach_gcp_nics(neo4j_session, instances, TAG, params)
    compute._attach_gcp_nic_access_configs(neo4j_session, instances, TAG, params)
    compute._attach_gcp_vpc(neo4j_session, instances, TAG, params)
    compute._attach_instance_service_account(neo4j_session, instances, TAG, params)
    compute.load_gcp_instance_image_relations(neo4j_session, instances, TAG, OWN)
    compute.attach_compute_disks_to_instances(
        neo4j_session, [{'id': f"{i['partial_uri']}/disk", 'instance_id': i['partial_uri']} for i in instances],
        TAG, OWN,
    )


def test_instance_links_start_from_the_syncing_project(neo4j_session):
    _seed(neo4j_session)
    # Tenant a's sync handed an id of tenant b's instance: a new NIC (nic1) and an access config on b's nic0.
    _load_instance_links(neo4j_session, [_instance(FOREIGN, FOREIGN, FOREIGN, nic='nic1')])
    compute._attach_gcp_nic_access_configs(neo4j_session, [_instance(FOREIGN, FOREIGN, FOREIGN)], TAG, tenant_params())
    put_principal(neo4j_session, 'a', 'vm@a.test')
    compute.load_compute_entity_relation(
        neo4j_session, {'name': _vm(FOREIGN), 'entities': [{'email': 'vm@a.test'}]}, TAG, tenant_params(),
    )

    nic = f'{_vm(FOREIGN)}/networkinterfaces/nic0'
    leaks = {
        rel: targets(neo4j_session, _vm(FOREIGN), rel) - {nic}
        for rel in ('TAGGED', 'NETWORK_INTERFACE', 'MEMBER_OF_GCP_VPC', 'USES', 'HAS')
    }
    leaks['access config'] = targets(neo4j_session, nic, 'RESOURCE')
    leaks['principal'] = sources(neo4j_session, 'USES', _vm(FOREIGN))
    assert not any(leaks.values()), leaks


def test_instance_tags_and_service_accounts_link_only_inside_the_workspace(neo4j_session):
    _seed(neo4j_session)
    # Shared VPC host and service account in another project of the same workspace and org: linked.
    _load_instance_links(neo4j_session, [_instance(OWN, OWN_OTHER, OWN_OTHER)])
    tag = compute._create_gcp_network_tag_id(_vpc(OWN_OTHER), 'web')
    assert targets(neo4j_session, tag, 'DEFINED_IN') == {_vpc(OWN_OTHER)}
    assert _sa(OWN_OTHER) in targets(neo4j_session, _vm(OWN), 'USES')
    assert f'{_vm(OWN)}/disk' in targets(neo4j_session, _vm(OWN), 'USES')
    assert targets(neo4j_session, _vm(OWN), 'HAS') == {'projects/debian-cloud/global/images/debian'}
    assert targets(neo4j_session, f'{_vm(OWN)}/networkinterfaces/nic0', 'RESOURCE') == {
        f'{_vm(OWN)}/networkinterfaces/nic0/accessconfigs/ONE_TO_ONE_NAT',
    }

    # The same references into another customer's project: no edge.
    _load_instance_links(neo4j_session, [_instance(OWN, FOREIGN, FOREIGN)])
    tag = compute._create_gcp_network_tag_id(_vpc(FOREIGN), 'web')
    assert targets(neo4j_session, tag, 'DEFINED_IN') == set()
    assert sources(neo4j_session, 'USES', _sa(FOREIGN)) == set()


def test_forwarding_rules_hang_off_the_syncing_project_only(neo4j_session):
    _seed(neo4j_session)
    put(neo4j_session, 'GCPProject', FOREIGN, 'RESOURCE', 'GCPForwardingRule', 'fr-b')
    put(neo4j_session, 'GCPProject', OWN, 'RESOURCE', 'GCPVpc', 'fr-net-a')
    rule = {'partial_uri': 'fr-a', 'project_id': FOREIGN, 'network': 'n', 'network_partial_uri': 'fr-net-a'}
    # project_id in the row is API data: the rule belongs to the project the sync passes in.
    compute.load_gcp_forwarding_rules(neo4j_session, [rule], TAG, OWN)
    assert sources(neo4j_session, 'RESOURCE', 'fr-a') == {OWN, 'fr-net-a'}

    compute._attach_fwd_rules_to_subnets(
        neo4j_session, [{'partial_uri': 'fr-b', 'subnetwork_partial_uri': 'fr-subnet'}], TAG, OWN,
    )
    compute._attach_fwd_rules_to_vpcs(
        neo4j_session, [{'partial_uri': 'fr-b', 'network_partial_uri': 'fr-net'}], TAG, OWN,
    )
    assert sources(neo4j_session, 'RESOURCE', 'fr-b') == {FOREIGN}


def test_firewall_links_start_from_the_syncing_project(neo4j_session):
    _seed(neo4j_session)

    def firewall(project):
        return {
            'id': _fw(project), 'vpc_partial_uri': _vpc(project), 'targetTags': ['web'],
            'sourceRanges': ['8.8.8.0/24'],
            'transformed_allow_list': [
                {'ruleid': f'{_fw(project)}/allow', 'protocol': 'tcp', 'fromport': 1, 'toport': 2},
            ],
        }
    for project in (OWN, FOREIGN):
        compute._attach_firewall_rules(neo4j_session, [firewall(project)], TAG, OWN)
        compute._attach_target_tags(neo4j_session, [firewall(project)], TAG, OWN)
        compute._attach_firewall_public_ip_address(neo4j_session, [firewall(project)], TAG, OWN)
    compute.load_gcp_firewall_policy_rules(
        neo4j_session, [{'id': f'{_vpc(p)}/policy-rule', 'vpc_partial_uri': _vpc(p)} for p in (OWN, FOREIGN)], TAG, OWN,
    )

    assert sources(neo4j_session, 'ALLOWED_BY', _fw(OWN)) == {f'{_fw(OWN)}/allow'}
    assert targets(neo4j_session, _fw(OWN), 'TARGET_TAG') != set()
    assert targets(neo4j_session, _fw(OWN), 'MEMBER_OF_PUBLIC_IP_ADDRESS') == {'8.8.8.0/24'}
    assert sources(neo4j_session, 'RESOURCE', f'{_vpc(OWN)}/policy-rule') == {_vpc(OWN)}
    assert sources(neo4j_session, 'ALLOWED_BY', _fw(FOREIGN)) == set()
    assert targets(neo4j_session, _fw(FOREIGN), 'TARGET_TAG') == set()
    assert targets(neo4j_session, _fw(FOREIGN), 'MEMBER_OF_PUBLIC_IP_ADDRESS') == set()
    assert sources(neo4j_session, 'RESOURCE', f'{_vpc(FOREIGN)}/policy-rule') == set()
