import json
from types import SimpleNamespace
from unittest.mock import patch

import cartography.intel.gcp.compute
import tests.data.gcp.compute
from cartography.util import run_analysis_job
from cartography.util import run_cleanup_job

TEST_WORKSPACE_ID = '1223344'
TEST_PROJECT_ID = 'project-abc'
TEST_UPDATE_TAG = 123456789

common_job_parameters = {
    "UPDATE_TAG": TEST_UPDATE_TAG,
    "WORKSPACE_ID": '1223344',
    "GCP_PROJECT_ID": TEST_PROJECT_ID,
}


def _ensure_local_neo4j_has_test_instance_data(neo4j_session):
    cartography.intel.gcp.compute.load_gcp_instances(
        neo4j_session,
        tests.data.gcp.compute.TRANSFORMED_GCP_INSTANCES,
        TEST_UPDATE_TAG,
    )


def cloudanix_workspace_to_gcp_project(neo4j_session):
    query = """
    MERGE (w:CloudanixWorkspace{id: $WorkspaceId})
    MERGE (project:GCPProject{id: $ProjectId})
    MERGE (w)-[:OWNER]->(project)
    """
    nodes = neo4j_session.run(
        query,
        WorkspaceId=TEST_WORKSPACE_ID,
        ProjectId=TEST_PROJECT_ID,
    )


def _ensure_local_neo4j_has_test_vpc_data(neo4j_session):
    cartography.intel.gcp.compute.load_gcp_vpcs(
        neo4j_session,
        tests.data.gcp.compute.TRANSFORMED_GCP_VPCS,
        TEST_UPDATE_TAG,
    )


def _ensure_local_neo4j_has_test_subnet_data(neo4j_session):
    cartography.intel.gcp.compute.load_gcp_subnets(
        neo4j_session,
        tests.data.gcp.compute.TRANSFORMED_GCP_SUBNETS,
        TEST_UPDATE_TAG,
    )


def _ensure_local_neo4j_has_test_firewall_data(neo4j_session):
    cartography.intel.gcp.compute.load_gcp_ingress_firewalls(
        neo4j_session,
        tests.data.gcp.compute.TRANSFORMED_FW_LIST,
        TEST_UPDATE_TAG,
    )


def test_transform_and_load_vpcs(neo4j_session):
    """
    Test that we can correctly transform and load VPC nodes to Neo4j.
    """
    vpc_res = tests.data.gcp.compute.VPC_RESPONSE
    vpc_list = cartography.intel.gcp.compute.transform_gcp_vpcs(vpc_res)
    cartography.intel.gcp.compute.load_gcp_vpcs(neo4j_session, vpc_list, TEST_UPDATE_TAG)

    query = """
    MATCH(vpc:GCPVpc{id:$VpcId})
    RETURN vpc.id, vpc.partial_uri, vpc.auto_create_subnetworks
    """
    expected_vpc_id = 'projects/project-abc/global/networks/default'
    nodes = neo4j_session.run(
        query,
        VpcId=expected_vpc_id,
    )
    actual_nodes = {(n['vpc.id'], n['vpc.partial_uri'], n['vpc.auto_create_subnetworks']) for n in nodes}
    expected_nodes = {
        (expected_vpc_id, expected_vpc_id, True),
    }
    assert actual_nodes == expected_nodes


def test_transform_and_load_subnets(neo4j_session):
    """
    Ensure we can transform and load subnets.
    """
    subnet_res = tests.data.gcp.compute.VPC_SUBNET_RESPONSE
    subnet_list = cartography.intel.gcp.compute.transform_gcp_subnets(subnet_res)
    cartography.intel.gcp.compute.load_gcp_subnets(neo4j_session, subnet_list, TEST_UPDATE_TAG)

    query = """
    MATCH(subnet:GCPSubnet)
    RETURN subnet.id, subnet.region, subnet.gateway_address, subnet.ip_cidr_range, subnet.private_ip_google_access,
    subnet.vpc_partial_uri
    """
    nodes = neo4j_session.run(query)
    actual_nodes = {
        (
            n['subnet.id'],
            n['subnet.region'],
            n['subnet.gateway_address'],
            n['subnet.ip_cidr_range'],
            n['subnet.private_ip_google_access'],
            n['subnet.vpc_partial_uri'],
        ) for n in nodes
    }

    expected_nodes = {
        (
            'projects/project-abc/locations/europe-west2/subnetworks/default',
            'europe-west2',
            '10.0.0.1',
            '10.0.0.0/20',
            False,
            'projects/project-abc/global/networks/default',
        ),
    }
    assert actual_nodes == expected_nodes


def test_transform_and_load_gcp_forwarding_rules(neo4j_session):
    """
    Ensure that we can correctly transform and load GCP Forwarding Rules
    """
    fwd_res = tests.data.gcp.compute.LIST_FORWARDING_RULES_RESPONSE
    fwd_list = cartography.intel.gcp.compute.transform_gcp_forwarding_rules(fwd_res)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(neo4j_session, fwd_list, TEST_UPDATE_TAG)

    fwd_query = """
    MATCH(f:GCPForwardingRule)
    RETURN f.id, f.partial_uri, f.ip_address, f.ip_protocol, f.load_balancing_scheme, f.name, f.network, f.port_range,
    f.ports, f.project_id, f.region, f.self_link, f.subnetwork, f.target
    """
    objects = neo4j_session.run(fwd_query)
    actual_nodes = {
        (
            o['f.id'],
            o['f.ip_address'],
            o['f.ip_protocol'],
            o['f.load_balancing_scheme'],
            o['f.name'],
            o.get('f.port_range', None),
            ','.join(o.get('f.ports', None)) if o.get('f.ports', None) else None,
            o['f.project_id'],
            o['f.region'],
            o['f.target'],
        ) for o in objects
    }

    expected_nodes = {
        (
            'projects/project-abc/locations/europe-west2/forwardingRules/internal-service-1111',
            '10.0.0.10',
            'TCP',
            'INTERNAL',
            'internal-service-1111',
            None,
            '80',
            'project-abc',
            'europe-west2',
            'projects/project-abc/regions/europe-west2/targetPools/node-pool-12345',
        ),
        (
            'projects/project-abc/locations/europe-west2/forwardingRules/public-ingress-controller-1234567',
            '1.2.3.11',
            'TCP',
            'EXTERNAL',
            'public-ingress-controller-1234567',
            '80-443',
            None,
            'project-abc',
            'europe-west2',
            'projects/project-abc/regions/europe-west2/targetVpnGateways/vpn-12345',
        ),
        (
            'projects/project-abc/locations/europe-west2/forwardingRules/shard-server-22222',
            '10.0.0.20',
            'TCP',
            'INTERNAL',
            'shard-server-22222',
            None,
            '10203',
            'project-abc',
            'europe-west2',
            'projects/project-abc/regions/europe-west2/targetPools/node-pool-234567',
        ),
    }
    assert actual_nodes == expected_nodes


def test_transform_and_load_gcp_instances_and_nics(neo4j_session):
    """
    Ensure that we can correctly transform and load GCP instances.
    """
    instance_responses = tests.data.gcp.compute.GCP_LIST_INSTANCES_RESPONSE
    instance_list = cartography.intel.gcp.compute.transform_gcp_instances(instance_responses.get("items", []), compute=None)
    cartography.intel.gcp.compute.load_gcp_instances(neo4j_session, instance_list, TEST_UPDATE_TAG)

    instance_id1 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1-test'
    instance_id2 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1'

    nic_query = """
    MATCH(i:GCPInstance)-[r:NETWORK_INTERFACE]->(nic:GCPNetworkInterface)
    OPTIONAL MATCH (i)-[:TAGGED]->(t:GCPNetworkTag)
    RETURN i.id, i.zone_name, i.project_id, i.hostname, t.value, r.lastupdated, nic.nic_id, nic.private_ip
    """
    objects = neo4j_session.run(nic_query)
    actual_nodes = {
        (
            o['i.id'],
            o['i.zone_name'],
            o['i.project_id'],
            o['nic.nic_id'],
            o['nic.private_ip'],
            o['t.value'],
            o['r.lastupdated'],
        ) for o in objects
    }

    expected_nodes = {
        (
            instance_id1,
            'europe-west2-b',
            'project-abc',
            'projects/project-abc/zones/europe-west2-b/instances/instance-1-test/networkinterfaces/nic0',
            '10.0.0.3',
            None,
            TEST_UPDATE_TAG,
        ),
        (
            instance_id2,
            'europe-west2-b',
            'project-abc',
            'projects/project-abc/zones/europe-west2-b/instances/instance-1/networkinterfaces/nic0',
            '10.0.0.2',
            'test',
            TEST_UPDATE_TAG,
        ),
    }

    # assert actual_nodes == expected_nodes


def test_transform_and_load_firewalls(neo4j_session):
    """
    Ensure we can correctly transform and load GCP firewalls
    :param neo4j_session:
    :return:
    """
    fw_list = cartography.intel.gcp.compute.transform_gcp_firewall(tests.data.gcp.compute.LIST_FIREWALLS_RESPONSE)
    cartography.intel.gcp.compute.load_gcp_ingress_firewalls(neo4j_session, fw_list, TEST_UPDATE_TAG)

    query = """
    MATCH (vpc:GCPVpc)-[r:RESOURCE]->(fw:GCPFirewall)
    return vpc.id, fw.id, fw.has_target_service_accounts
    """

    nodes = neo4j_session.run(query)
    actual_nodes = {
        (
            (
                n['vpc.id'],
                n['fw.id'],
                n['fw.has_target_service_accounts'],
            )
        ) for n in nodes
    }
    expected_nodes = {
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/global/firewalls/default-allow-icmp',
            False,
        ),
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/global/firewalls/default-allow-internal',
            False,
        ),
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/global/firewalls/default-allow-rdp',
            False,
        ),
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/global/firewalls/default-allow-ssh',
            False,
        ),
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/global/firewalls/custom-port-incoming',
            False,
        ),
    }
    assert actual_nodes == expected_nodes


def test_vpc_to_subnets(neo4j_session):
    """
    Ensure that subnets are connected to VPCs.
    """
    _ensure_local_neo4j_has_test_vpc_data(neo4j_session)
    _ensure_local_neo4j_has_test_subnet_data(neo4j_session)
    query = """
    MATCH(vpc:GCPVpc{id:$VpcId})-[:RESOURCE]->(subnet:GCPSubnet)
    RETURN vpc.id, subnet.id, subnet.region, subnet.gateway_address, subnet.ip_cidr_range,
    subnet.private_ip_google_access
    """
    expected_vpc_id = 'projects/project-abc/global/networks/default'
    nodes = neo4j_session.run(
        query,
        VpcId=expected_vpc_id,
    )
    actual_nodes = {
        (
            n['vpc.id'],
            n['subnet.id'],
            n['subnet.region'],
            n['subnet.gateway_address'],
            n['subnet.ip_cidr_range'],
            n['subnet.private_ip_google_access'],
        ) for n in nodes
    }
    expected_nodes = {
        (
            'projects/project-abc/global/networks/default',
            'projects/project-abc/regions/europe-west2/subnetworks/default',
            'europe-west2',
            '10.0.0.1',
            '10.0.0.0/20',
            False,
        ),
    }

    assert actual_nodes == expected_nodes


def test_nics_to_access_configs(neo4j_session):
    """
    Ensure that network interfaces and access configs are attached
    """
    _ensure_local_neo4j_has_test_instance_data(neo4j_session)
    ac_query = """
    MATCH (nic:GCPNetworkInterface)-[r:RESOURCE]->(ac:GCPNicAccessConfig)
    return nic.nic_id, ac.access_config_id, ac.public_ip
    """
    nodes = neo4j_session.run(ac_query)

    nic_id1 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1-test/networkinterfaces/nic0'
    ac_id1 = f"{nic_id1}/accessconfigs/ONE_TO_ONE_NAT"
    nic_id2 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1/networkinterfaces/nic0'
    ac_id2 = f"{nic_id2}/accessconfigs/ONE_TO_ONE_NAT"

    actual_nodes = {(n['nic.nic_id'], n['ac.access_config_id'], n['ac.public_ip']) for n in nodes}
    expected_nodes = {
        (nic_id1, ac_id1, '1.3.4.5'),
        (nic_id2, ac_id2, '1.2.3.4'),
    }

    assert actual_nodes == expected_nodes


def test_nic_to_subnets(neo4j_session):
    """
    Ensure that network interfaces are attached to subnets
    """
    _ensure_local_neo4j_has_test_subnet_data(neo4j_session)
    _ensure_local_neo4j_has_test_instance_data(neo4j_session)
    subnet_query = """
    MATCH (nic:GCPNetworkInterface{id:$NicId})-[:PART_OF_SUBNET]->(subnet:GCPSubnet)
    return nic.nic_id, nic.private_ip, subnet.id, subnet.gateway_address, subnet.ip_cidr_range
    """
    nodes = neo4j_session.run(
        subnet_query,
        NicId='projects/project-abc/zones/europe-west2-b/instances/instance-1-test/networkinterfaces/nic0',
    )
    actual_nodes = {
        (
            n['nic.nic_id'],
            n['nic.private_ip'],
            n['subnet.id'],
            n['subnet.gateway_address'],
            n['subnet.ip_cidr_range'],
        ) for n in nodes
    }
    expected_nodes = {(
        'projects/project-abc/zones/europe-west2-b/instances/instance-1-test/networkinterfaces/nic0',
        '10.0.0.3',
        'projects/project-abc/regions/europe-west2/subnetworks/default',
        '10.0.0.1',
        '10.0.0.0/20',
    )}
    assert actual_nodes == expected_nodes


def test_instance_to_vpc(neo4j_session):
    _ensure_local_neo4j_has_test_vpc_data(neo4j_session)
    _ensure_local_neo4j_has_test_subnet_data(neo4j_session)
    _ensure_local_neo4j_has_test_instance_data(neo4j_session)
    instance_id1 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1-test'
    query = """
    MATCH (i:GCPInstance{id:$InstanceId})-[r:MEMBER_OF_GCP_VPC]->(v:GCPVpc)
    RETURN i.id, v.id
    """
    nodes = neo4j_session.run(
        query,
        InstanceId=instance_id1,
    )
    actual_nodes = {
        (
            n['i.id'],
            n['v.id'],
        ) for n in nodes
    }
    expected_nodes = {(
        instance_id1,
        'projects/project-abc/global/networks/default',
    )}
    assert actual_nodes == expected_nodes


def test_vpc_to_firewall_to_iprule_to_iprange(neo4j_session):
    _ensure_local_neo4j_has_test_vpc_data(neo4j_session)
    _ensure_local_neo4j_has_test_firewall_data(neo4j_session)
    query = """
    MATCH (rng:IpRange{id:'0.0.0.0/0'})-[m:MEMBER_OF_IP_RULE]->(rule:IpRule{fromport:22})
           -[a:ALLOWED_BY]->(fw:GCPFirewall)<-[r:RESOURCE]-(vpc:GCPVpc)
    RETURN rng.id, rule.id, fw.id, fw.priority, vpc.id
    """
    nodes = neo4j_session.run(query)
    actual_nodes = {
        (
            n['rng.id'],
            n['rule.id'],
            n['fw.id'],
            n['vpc.id'],
        ) for n in nodes
    }
    expected_nodes = {(
        '0.0.0.0/0',
        'projects/project-abc/global/firewalls/default-allow-ssh/allow/22tcp',
        'projects/project-abc/global/firewalls/default-allow-ssh',
        'projects/project-abc/global/networks/default',
    )}
    assert actual_nodes == expected_nodes


def test_compute_disks(neo4j_session):
    data = tests.data.gcp.compute.TEST_DISKS
    cartography.intel.gcp.compute.load_compute_disks(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'projects/project123/disks/disk123',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPComputeDisk) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def test_proxies(neo4j_session):
    data = tests.data.gcp.compute.TEST_PROXIES
    cartography.intel.gcp.compute.load_proxies(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'projects/project123/global/targetHttpsProxies/httpsproxy123',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPProxy) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_compute_network_interfaces(neo4j_session):

    instance_responses = tests.data.gcp.compute.GCP_LIST_INSTANCES_RESPONSE
    instance_list = cartography.intel.gcp.compute.transform_gcp_instances(instance_responses.get("items", []), compute=None)
    cartography.intel.gcp.compute.load_gcp_instances(neo4j_session, instance_list, TEST_UPDATE_TAG)
    instance_id1 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1'
    instance_id2 = 'projects/project-abc/zones/europe-west2-b/instances/instance-1-test'

    nat_ip_query = """
    MATCH (i:Instance:GCPInstance)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID}) \nWHERE i.nat_ip IS NOT NULL AND i.ipv6_nat_ip IS NOT NULL \n
    RETURN i.id, i.zone_name, i.project_id, i.nat_ip, i.ipv6_nat_ip
    """

    objects = neo4j_session.run(nat_ip_query, GCP_PROJECT_ID=TEST_PROJECT_ID)
    actual_nodes = {
        (
            o['i.id'],
            o['i.zone_name'],
            o['i.project_id'],
            o['i.nat_ip'],
            o['i.ipv6_nat_ip'],
        ) for o in objects
    }

    expected_nodes = {
        (
            instance_id1,
            'europe-west2-b',
            'project-abc',
            '1.2.3.4',
            '6.7.8.9',
        ),
        (
            instance_id2,
            'europe-west2-b',
            'project-abc',
            '1.3.4.5',
            '6.7.8.9',
        ),
    }

    assert actual_nodes == expected_nodes


def test_compute_firewalls(neo4j_session):

    cloudanix_workspace_to_gcp_project(neo4j_session)
    fw_responses = tests.data.gcp.compute.LIST_FIREWALLS_RESPONSE
    fw_list = cartography.intel.gcp.compute.transform_gcp_firewall(fw_responses)
    cartography.intel.gcp.compute.load_gcp_ingress_firewalls(neo4j_session, fw_list, TEST_UPDATE_TAG)
    instance_responses = tests.data.gcp.compute.GCP_LIST_INSTANCES_RESPONSE
    instance_list = cartography.intel.gcp.compute.transform_gcp_instances(instance_responses.get("items", []), compute=None)
    cartography.intel.gcp.compute.load_gcp_instances(neo4j_session, instance_list, TEST_UPDATE_TAG)

    firewall_query = """
    MATCH (rng:IpRange)-[m:MEMBER_OF_IP_RULE]->(rule:IpRule:IpPermissionInbound:GCPIpRule)-[r:ALLOWED_BY]->(fw:GCPFirewall)<-[:RESOURCE]-(vpc:GCPVpc)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE fw.direction='INGRESS' AND fw.disabled=FALSE AND rng.id='0.0.0.0/0' AND rule.protocol IN ['tcp','udp'] AND rule.fromport IN [80,443,23,3389,25,465,587,3306,5432,1521,1433,135,137,138,139,445,0,53,20,21,22] AND rule.toport IN [80,443,23,3389,25,465,587,3306,5432,1521,1433,135,137,138,139,445,53,20,21,22,65535]
    RETURN fw.id
    """
    query1 = """
    MATCH (i:Instance:GCPInstance)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE i.exposed_internet=true
    RETURN i.id,i.exposed_internet_type
    """

    query2 = """
    MATCH (fw:GCPFirewall)-[:CONNECTION]->(network:GCPNetwork)<-[:CONNECTION]-(i:Instance:GCPInstance)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID})
    RETURN fw.id,fw.unrestricted_access
    """
    run_analysis_job('gcp_compute_firewall_analysis.json', neo4j_session, common_job_parameters)
    run_analysis_job('gcp_compute_instance_analysis.json', neo4j_session, common_job_parameters)

    objects1 = neo4j_session.run(query1, GCP_PROJECT_ID=TEST_PROJECT_ID, WORKSPACE_ID=TEST_WORKSPACE_ID)
    # checked the query1 output by printing the output due to unhashable type list error

    actual_nodes = {
        (
            o['i.id'],
            ",".join(o['i.exposed_internet_type']),

        ) for o in objects1

    }

    expected_nodes = {

        (
            'projects/project-abc/zones/europe-west2-b/instances/instance-1',
            'nat_ip,ipv6_nat_ip,unrestricted_access_from_firewall',
        ),
        (
            'projects/project-abc/zones/europe-west2-b/instances/instance-1-test',
            'nat_ip,ipv6_nat_ip,unrestricted_access_from_firewall',
        ),

    }

    assert actual_nodes == expected_nodes


CLEANUP_PROJECT_ID = 'proj-fw-cleanup'
CLEANUP_OLD_TAG = 100
CLEANUP_NEW_TAG = 200
CLEANUP_JOB_PARAMETERS = {
    'UPDATE_TAG': CLEANUP_NEW_TAG,
    'WORKSPACE_ID': 'ws-fw-cleanup',
    'GCP_ORGANIZATION_ID': 'org-fw-cleanup',
    'GCP_PROJECT_ID': CLEANUP_PROJECT_ID,
}
CLEANUP_VPC_ID = f'projects/{CLEANUP_PROJECT_ID}/global/networks/default'
CLEANUP_FW_ID = f'projects/{CLEANUP_PROJECT_ID}/global/firewalls/allow-ssh'


def _seed_cleanup_project(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:GCPOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project_id})
        MERGE (p)-[:RESOURCE]->(:GCPVpc{id: $vpc_id})
        """,
        workspace_id=CLEANUP_JOB_PARAMETERS['WORKSPACE_ID'], org_id=CLEANUP_JOB_PARAMETERS['GCP_ORGANIZATION_ID'],
        project_id=CLEANUP_PROJECT_ID, vpc_id=CLEANUP_VPC_ID,
    )


def _load_firewall(neo4j_session, source_ranges, ports, target_tags, update_tag):
    response = {
        'id': f'projects/{CLEANUP_PROJECT_ID}/global/firewalls',
        'items': [{
            'name': 'allow-ssh', 'direction': 'INGRESS', 'disabled': False, 'priority': 1000,
            'network': f'https://www.googleapis.com/compute/v1/{CLEANUP_VPC_ID}',
            'selfLink': f'https://www.googleapis.com/compute/v1/{CLEANUP_FW_ID}',
            'allowed': [{'IPProtocol': 'tcp', 'ports': ports}],
            'sourceRanges': source_ranges, 'targetTags': target_tags,
        }],
    }
    fw_list = cartography.intel.gcp.compute.transform_gcp_firewall(response)
    cartography.intel.gcp.compute.load_gcp_ingress_firewalls(neo4j_session, fw_list, update_tag)


def test_firewall_cleanup_removes_stale_rules_ranges_and_target_tags(neo4j_session):
    _seed_cleanup_project(neo4j_session)
    # Last sync: SSH open to the internet on instances tagged "web". The customer then narrowed it.
    _load_firewall(neo4j_session, ['0.0.0.0/0'], ['22'], ['web'], CLEANUP_OLD_TAG)
    _load_firewall(neo4j_session, ['10.0.0.0/8'], ['443'], ['db'], CLEANUP_NEW_TAG)

    run_cleanup_job('gcp_compute_firewall_cleanup.json', neo4j_session, CLEANUP_JOB_PARAMETERS)

    ranges = neo4j_session.run(
        """
        MATCH (rng)-[:MEMBER_OF_IP_RULE]->(rule:GCPIpRule)-[:ALLOWED_BY]->(:GCPFirewall{id: $fw_id})
        RETURN rule.id AS rule, rng.id AS rng
        """,
        fw_id=CLEANUP_FW_ID,
    )
    assert {(r['rule'], r['rng']) for r in ranges} == {(f'{CLEANUP_FW_ID}/allow/443tcp', '10.0.0.0/8')}
    stale_rules = neo4j_session.run(
        "MATCH (rule:GCPIpRule) WHERE rule.id STARTS WITH $fw_id AND rule.lastupdated <> $tag RETURN rule.id",
        fw_id=CLEANUP_FW_ID, tag=CLEANUP_NEW_TAG,
    )
    assert [r['rule.id'] for r in stale_rules] == []
    tags = neo4j_session.run(
        "MATCH (:GCPFirewall{id: $fw_id})-[:TARGET_TAG]->(t:GCPNetworkTag) RETURN t.value AS value",
        fw_id=CLEANUP_FW_ID,
    )
    assert {t['value'] for t in tags} == {'db'}
    # IpRange nodes are shared by every tenant's rules: only this firewall's edge goes, never the node.
    assert neo4j_session.run("MATCH (r:IpRange{id: '0.0.0.0/0'}) RETURN count(r) AS n").single()['n'] == 1


def test_instance_cleanup_removes_stale_network_tags(neo4j_session):
    _seed_cleanup_project(neo4j_session)
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project_id})
        MERGE (p)-[pr:RESOURCE]->(i:GCPInstance{id: 'cleanup-vm'})
        SET i.lastupdated = $new, pr.lastupdated = $new
        MERGE (i)-[old:TAGGED]->(:GCPNetworkTag{id: 'cleanup-web', value: 'web'})
        SET old.lastupdated = $old
        MERGE (i)-[cur:TAGGED]->(:GCPNetworkTag{id: 'cleanup-db', value: 'db'})
        SET cur.lastupdated = $new
        """,
        project_id=CLEANUP_PROJECT_ID, old=CLEANUP_OLD_TAG, new=CLEANUP_NEW_TAG,
    )

    run_cleanup_job('gcp_compute_instance_cleanup.json', neo4j_session, CLEANUP_JOB_PARAMETERS)

    tags = neo4j_session.run(
        "MATCH (:GCPInstance{id: 'cleanup-vm'})-[:TAGGED]->(t:GCPNetworkTag) RETURN t.value AS value",
    )
    assert {t['value'] for t in tags} == {'db'}


VM_PROJECT_ID = 'proj-vm-exposure'
VM_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG,
    'WORKSPACE_ID': 'ws-vm-exposure',
    'GCP_ORGANIZATION_ID': 'org-vm-exposure',
    'GCP_PROJECT_ID': VM_PROJECT_ID,
}


def _seed_vm_firewalls(neo4j_session, firewalls):
    # Shapes as load_gcp_ingress_firewalls writes them: (range)-[:MEMBER_OF_IP_RULE]->(rule)-[:ALLOWED_BY]->(fw).
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:GCPOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project_id})
        WITH p
        UNWIND $firewalls AS f
        MERGE (p)-[:RESOURCE]->(vpc:GCPVpc{id: f.vpc})
        MERGE (vpc)-[:RESOURCE]->(fw:GCPFirewall{id: f.id})
        SET fw.direction = 'INGRESS', fw.disabled = coalesce(f.disabled, false),
            fw.has_target_service_accounts = coalesce(f.target_sa, false)
        MERGE (rule:GCPIpRule:IpRule:IpPermissionInbound{id: f.id + '/rule'})
        SET rule.protocol = f.protocol, rule.fromport = f.fromport, rule.toport = f.toport
        MERGE (rule)-[:ALLOWED_BY]->(fw)
        MERGE (rng:IpRange{id: f.source})
        MERGE (rng)-[:MEMBER_OF_IP_RULE]->(rule)
        FOREACH (tag IN coalesce(f.tags, []) | MERGE (fw)-[:TARGET_TAG]->(:GCPNetworkTag{id: f.vpc + '/' + tag}))
        """,
        workspace_id=VM_JOB_PARAMETERS['WORKSPACE_ID'], org_id=VM_JOB_PARAMETERS['GCP_ORGANIZATION_ID'],
        project_id=VM_PROJECT_ID, firewalls=firewalls,
    )


def _seed_vms(neo4j_session, vms):
    # Shapes as load_gcp_instances writes them (natIP, status, MEMBER_OF_GCP_VPC, TAGGED).
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project_id})
        UNWIND $vms AS v
        MERGE (p)-[:RESOURCE]->(i:GCPInstance:Instance{id: v.id})
        SET i.natIP = v.nat_ip, i.status = coalesce(v.status, 'RUNNING'), i.exposed_internet = v.exposed_before,
            i.exposed_internet_type = CASE WHEN v.exposed_before THEN ['nat_ip'] END
        MERGE (vpc:GCPVpc{id: coalesce(v.vpc, 'vpc-none')})
        MERGE (i)-[:MEMBER_OF_GCP_VPC]->(vpc)
        FOREACH (tag IN coalesce(v.tags, []) | MERGE (t:GCPNetworkTag{id: v.vpc + '/' + tag}) MERGE (i)-[:TAGGED]->(t))
        """,
        project_id=VM_PROJECT_ID, vms=vms,
    )


def test_instance_exposure_firewall_paths(neo4j_session):
    anywhere = '0.0.0.0/0'
    _seed_vm_firewalls(
        neo4j_session, [
            # No target tags or service accounts: applies to every instance in the network.
            {
                'id': 'fw-default-ssh', 'vpc': 'vpc-a', 'protocol': 'tcp', 'fromport': 22, 'toport': 22,
                'source': anywhere,
            },
            {
                'id': 'fw-sa-target', 'vpc': 'vpc-c', 'protocol': 'tcp', 'fromport': 22, 'toport': 22,
                'source': anywhere, 'target_sa': True,
            },
            {
                'id': 'fw-disabled', 'vpc': 'vpc-d', 'protocol': 'tcp', 'fromport': 22, 'toport': 22,
                'source': anywhere, 'disabled': True,
            },
            {
                'id': 'fw-internal', 'vpc': 'vpc-e', 'protocol': 'tcp', 'fromport': 22, 'toport': 22,
                'source': '10.0.0.0/8',
            },
            # Target-tagged firewalls; port ranges that contain a sensitive port, protocol all, and none.
            {
                'id': 'fw-web-range', 'vpc': 'vpc-f', 'protocol': 'tcp', 'fromport': 1, 'toport': 1000,
                'source': anywhere, 'tags': ['web'],
            },
            {'id': 'fw-all', 'vpc': 'vpc-f', 'protocol': 'all', 'source': anywhere, 'tags': ['any']},
            {
                'id': 'fw-high', 'vpc': 'vpc-f', 'protocol': 'tcp', 'fromport': 8080, 'toport': 8090,
                'source': anywhere, 'tags': ['app'],
            },
            {
                'id': 'fw-ssh-tag', 'vpc': 'vpc-f', 'protocol': 'tcp', 'fromport': 22, 'toport': 22,
                'source': anywhere, 'tags': ['ssh'],
            },
        ],
    )
    ext = '34.1.1.1'
    _seed_vms(
        neo4j_session, [
            {'id': 'vm-default-ssh', 'nat_ip': ext, 'vpc': 'vpc-a'},
            {'id': 'vm-no-ext-ip', 'vpc': 'vpc-a'},
            {'id': 'vm-stopped', 'nat_ip': ext, 'vpc': 'vpc-a', 'status': 'TERMINATED'},
            # An external IP alone is not reachable: GCP denies ingress unless a firewall allows it.
            {'id': 'vm-no-firewall', 'nat_ip': ext, 'vpc': 'vpc-b'},
            {'id': 'vm-sa-target', 'nat_ip': ext, 'vpc': 'vpc-c'},
            {'id': 'vm-disabled-fw', 'nat_ip': ext, 'vpc': 'vpc-d'},
            {'id': 'vm-internal-src', 'nat_ip': ext, 'vpc': 'vpc-e'},
            {'id': 'vm-tag-range', 'nat_ip': ext, 'vpc': 'vpc-f', 'tags': ['web']},
            {'id': 'vm-tag-all', 'nat_ip': ext, 'vpc': 'vpc-f', 'tags': ['any']},
            {'id': 'vm-tag-high', 'nat_ip': ext, 'vpc': 'vpc-f', 'tags': ['app']},
            {'id': 'vm-tag-ssh', 'nat_ip': ext, 'vpc': 'vpc-f', 'tags': ['ssh']},
            {'id': 'vm-untagged', 'nat_ip': ext, 'vpc': 'vpc-f'},
        ],
    )
    # Flagged by an earlier run, nothing exposes them now. One sits at each end of a project with more
    # instances than one reset batch (1000), so it falls outside the first batch whichever way it is scanned.
    _seed_vms(neo4j_session, [{'id': 'reset-first', 'exposed_before': True}])
    _seed_vms(neo4j_session, [{'id': f'reset-clean-{n}'} for n in range(1200)])
    _seed_vms(neo4j_session, [{'id': 'reset-last', 'exposed_before': True}])

    run_analysis_job('gcp_compute_instance_analysis.json', neo4j_session, VM_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project_id})-[:RESOURCE]->(i:GCPInstance)
        WHERE i.exposed_internet IS NOT NULL OR i.exposed_internet_type IS NOT NULL
        RETURN i.id AS id, i.exposed_internet_type AS types
        """,
        project_id=VM_PROJECT_ID,
    )
    assert {n['id']: n['types'] for n in nodes} == {
        'vm-default-ssh': ['unrestricted_access_from_firewall'],
        'vm-tag-range': ['unrestricted_access_from_firewall'],
        'vm-tag-all': ['unrestricted_access_from_firewall'],
        'vm-tag-ssh': ['unrestricted_access_from_firewall'],
    }


SYNC_WORKSPACE_ID = 'ws-vm-sync'
SYNC_ORG_ID = 'org-vm-sync'
SYNC_PROJECT_ID = 'proj-vm-sync'
SYNC_OLD_TAG = 100
SYNC_TAG = 200


def _seed_sync_project(neo4j_session):
    # Shapes as compute ingestion writes them, plus state a previous sync's analysis left behind.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project})
        MERGE (p)-[:RESOURCE]->(vpc:GCPVpc{id: 'sync-vpc'})
        MERGE (vpc)-[:RESOURCE]->(fw_ssh:GCPFirewall{id: 'sync-fw-ssh'})
        SET fw_ssh.name = 'allow-ssh', fw_ssh.direction = 'INGRESS', fw_ssh.disabled = false,
            fw_ssh.has_target_service_accounts = false, fw_ssh.priority = 1000
        MERGE (fw_ssh)-[:TARGET_TAG]->(ssh:GCPNetworkTag{id: 'sync-vpc/ssh'})
        MERGE (r_ssh:GCPIpRule:IpRule:IpPermissionInbound{id: 'sync-r-ssh'})
        MERGE (:IpRange{id: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->(r_ssh)
        SET r_ssh.protocol = 'tcp', r_ssh.fromport = 22, r_ssh.toport = 22
        MERGE (r_ssh)-[:ALLOWED_BY]->(fw_ssh)
        MERGE (vpc)-[:RESOURCE]->(fw_office:GCPFirewall{id: 'sync-fw-office'})
        SET fw_office.name = 'allow-office', fw_office.direction = 'INGRESS', fw_office.disabled = false,
            fw_office.has_target_service_accounts = false, fw_office.priority = 1000
        MERGE (fw_office)-[:TARGET_TAG]->(office:GCPNetworkTag{id: 'sync-vpc/office'})
        MERGE (r_office:GCPIpRule:IpRule:IpPermissionInbound{id: 'sync-r-office'})
        MERGE (:IpRange{id: '203.0.113.0/24'})-[:MEMBER_OF_IP_RULE]->(r_office)
        SET r_office.protocol = 'tcp', r_office.fromport = 22, r_office.toport = 22
        MERGE (r_office)-[:ALLOWED_BY]->(fw_office)
        WITH p, vpc, ssh, office, fw_ssh
        UNWIND [
            {id: 'sync-vm-open', ip: '34.1.1.1', tag: 'ssh'},
            {id: 'sync-vm-remediated', ip: '34.1.1.2', tag: 'office'}
        ] AS v
        MERGE (p)-[:RESOURCE]->(i:GCPInstance:Instance{id: v.id})
        SET i.name = v.id, i.natIP = v.ip, i.status = 'RUNNING', i.zone_name = 'us-central1-a',
            i.machine_type = 'e2-small', i.networkIP = '10.0.0.' + right(v.ip, 1)
        MERGE (i)-[:MEMBER_OF_GCP_VPC]->(vpc)
        MERGE (i)-[:NETWORK_INTERFACE]->(nic:GCPNetworkInterface{id: v.id + '/nic0'})
        MERGE (nic)-[:RESOURCE]->(:GCPNicAccessConfig{id: v.id + '/nic0/ac', public_ip: v.ip})
        FOREACH (_ IN CASE WHEN v.tag = 'ssh' THEN [1] ELSE [] END | MERGE (i)-[:TAGGED]->(ssh))
        FOREACH (_ IN CASE WHEN v.tag = 'office' THEN [1] ELSE [] END |
            MERGE (i)-[:TAGGED]->(office)
            // Flagged by the previous sync, when it was still tagged ssh.
            SET i.exposed_internet = true, i.exposed_internet_type = ['unrestricted_access_from_firewall'],
                i.publicContext = '[{"resource": "stale"}]'
            MERGE (fw_ssh)-[stale:FIREWALL_INGRESS]->(i) SET stale.lastupdated = $old)
        """,
        ws=SYNC_WORKSPACE_ID, org=SYNC_ORG_ID, project=SYNC_PROJECT_ID, old=SYNC_OLD_TAG,
    )


def _run_gcp_sync_analysis(neo4j_session):
    """Run start_gcp_ingestion with every API call stubbed, so all GCP analysis jobs run in production order."""
    config = SimpleNamespace(
        update_tag=SYNC_TAG, refresh_entitlements=False, gcp_requested_syncs=None,
        params={'workspace': {'id_string': SYNC_WORKSPACE_ID, 'account_id': SYNC_PROJECT_ID}},
        credentials={'token_uri': 'uri', 'account_email': 'sa@example.com'},
    )

    def _set_org(session, crm_v1, update_tag, common_job_parameters):
        common_job_parameters['GCP_ORGANIZATION_ID'] = SYNC_ORG_ID

    gcp = 'cartography.intel.gcp'
    with patch(f'{gcp}.AuthHelper'), patch(f'{gcp}._initialize_resources'), \
            patch(f'{gcp}.crm.sync_gcp_organizations', side_effect=_set_org), \
            patch(f'{gcp}.crm.sync_gcp_folders'), patch(f'{gcp}.crm.sync_gcp_projects'), \
            patch(f'{gcp}.crm.get_gcp_projects', return_value=[{'projectId': SYNC_PROJECT_ID}]), \
            patch(f'{gcp}._sync_single_project'):
        cartography.intel.gcp.start_gcp_ingestion(neo4j_session, config)


def test_instance_flags_and_public_context_agree_after_a_full_sync(neo4j_session):
    _seed_sync_project(neo4j_session)

    _run_gcp_sync_analysis(neo4j_session)

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project})-[:RESOURCE]->(i:GCPInstance)
        WHERE i.exposed_internet IS NOT NULL OR i.publicContext IS NOT NULL
        RETURN i.id AS id, i.exposed_internet AS exposed, i.exposed_internet_type AS types, i.publicContext AS ctx
        """,
        project=SYNC_PROJECT_ID,
    ).data()
    # The remediated VM keeps neither the flag nor the context the previous sync wrote.
    assert [r['id'] for r in rows] == ['sync-vm-open']
    row = rows[0]
    assert row['exposed'] is True
    assert row['types'] == ['unrestricted_access_from_firewall']
    context = json.loads(row['ctx'])[0]['context'][0]
    assert context['exposureTypes'] == row['types']
    assert context['publicIp'] == '34.1.1.1'
    assert context['privateIp'] == '10.0.0.1'
    assert context['zone'] == 'us-central1-a'
    assert [(r['firewallId'], r['fromPort']) for r in context['firewallRules']] == [('sync-fw-ssh', 22)]
    # FIREWALL_INGRESS edges from an earlier sync are removed once the firewall no longer applies.
    stale = neo4j_session.run(
        "MATCH (:GCPFirewall)-[r:FIREWALL_INGRESS]->(:GCPInstance{id: 'sync-vm-remediated'}) "
        "WHERE r.lastupdated <> $tag RETURN count(r) AS n",
        tag=SYNC_TAG,
    ).single()['n']
    assert stale == 0


SHARED_WORKSPACE_ID = 'ws-shared-vpc'
SHARED_ORG_ID = 'org-shared-vpc'
SHARED_HOST_PROJECT = 'proj-host'
SHARED_SVC_PROJECT = 'proj-svc'
SHARED_VPC_ID = f'projects/{SHARED_HOST_PROJECT}/global/networks/shared'
SHARED_OWN_VPC_ID = f'projects/{SHARED_SVC_PROJECT}/global/networks/own'


def _shared_vpc_params(project_id, update_tag):
    return {
        'UPDATE_TAG': update_tag, 'WORKSPACE_ID': SHARED_WORKSPACE_ID,
        'GCP_ORGANIZATION_ID': SHARED_ORG_ID, 'GCP_PROJECT_ID': project_id, 'LIMIT_SIZE': 1000,
    }


def _transformed_instance(project_id, name, vpc_id, region='us-central1'):
    """The fields load_gcp_instances reads, shaped as transform_gcp_instances returns them."""
    network = f'https://www.googleapis.com/compute/v1/{vpc_id}'
    subnet = f'projects/{vpc_id.split("/")[1]}/regions/{region}/subnetworks/default'
    return {
        'name': name, 'status': 'RUNNING', 'natIP': '34.9.9.9', 'project_id': project_id,
        'partial_uri': f'projects/{project_id}/zones/{region}-a/instances/{name}',
        'networkInterfaces': [{
            'name': 'nic0', 'network': network, 'vpc_partial_uri': vpc_id,
            'subnet_partial_uri': subnet, 'accessConfigs': [],
        }],
    }


def test_instances_join_the_vpc_of_their_nic_network(neo4j_session):
    # The host project's sync wrote the shared VPC and its firewall at an earlier tag. Subnets are
    # stored as projects/<p>/locations/<r>/subnetworks/<s>, which a NIC's .../regions/... subnet never matches.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(host:GCPProject{id: $host})
        MERGE (o)-[:OWNER]->(svc:GCPProject{id: $svc})
        MERGE (host)-[:RESOURCE]->(vpc:GCPVpc{id: $vpc}) SET vpc.lastupdated = $old
        MERGE (vpc)-[:RESOURCE]->(:GCPFirewall{id: $vpc + '/fw'})
        MERGE (svc)-[:RESOURCE]->(own:GCPVpc{id: $own})
        MERGE (own)-[:RESOURCE]->(:GCPSubnet{id: 'projects/proj-svc/locations/us-central1/subnetworks/default'})
        """,
        ws=SHARED_WORKSPACE_ID, org=SHARED_ORG_ID, host=SHARED_HOST_PROJECT, svc=SHARED_SVC_PROJECT,
        vpc=SHARED_VPC_ID, own=SHARED_OWN_VPC_ID, old=100,
    )
    instances = [
        _transformed_instance(SHARED_SVC_PROJECT, 'svc-vm-shared', SHARED_VPC_ID),
        _transformed_instance(SHARED_SVC_PROJECT, 'svc-vm-own', SHARED_OWN_VPC_ID),
    ]
    cartography.intel.gcp.compute.load_gcp_instances(neo4j_session, instances, 200)
    # The next service-project sync cleans VPCs before it reloads instances.
    run_cleanup_job('gcp_compute_vpc_cleanup.json', neo4j_session, _shared_vpc_params(SHARED_SVC_PROJECT, 300))
    cartography.intel.gcp.compute.load_gcp_instances(neo4j_session, instances, 300)

    members = neo4j_session.run(
        "MATCH (i:GCPInstance)-[:MEMBER_OF_GCP_VPC]->(v:GCPVpc) WHERE i.project_id = $svc "
        "RETURN i.instancename AS vm, v.id AS vpc",
        svc=SHARED_SVC_PROJECT,
    ).data()
    assert sorted((m['vm'], m['vpc']) for m in members) == [
        ('svc-vm-own', SHARED_OWN_VPC_ID), ('svc-vm-shared', SHARED_VPC_ID),
    ]
    # The service project's cleanup must not delete the host project's VPC or cut it from its firewalls.
    owned = neo4j_session.run(
        "MATCH (:GCPProject{id: $host})-[:RESOURCE]->(v:GCPVpc{id: $vpc})-[:RESOURCE]->(fw:GCPFirewall) "
        "RETURN count(fw) AS n",
        host=SHARED_HOST_PROJECT, vpc=SHARED_VPC_ID,
    ).single()['n']
    assert owned == 1
