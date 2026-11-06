from cartography.intel.gcp import instance_groups
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import TAG


def _seed(neo4j_session, project, tenant):
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        MERGE (p)-[:RESOURCE]->(:GCPInstanceGroup{id: 'mig-' + $tenant})
        MERGE (p)-[:RESOURCE]->(vm:GCPInstance:GCPComputeInstance{id: 'vm-' + $tenant})
        SET vm.self_link = 'link/vm-' + $tenant
        """,
        project=project, tenant=tenant,
    )


def _part_of(neo4j_session):
    rows = neo4j_session.run("MATCH (vm:GCPComputeInstance)-[:PART_OF]->(mig) RETURN vm.id AS vm, mig.id AS mig")
    return {(r['vm'], r['mig']) for r in rows}


def test_vms_join_only_instance_groups_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    _seed(neo4j_session, OWN, 'a')
    _seed(neo4j_session, FOREIGN, 'b')

    instance_groups._load_vm_to_mig_part_of_relationships(
        neo4j_session,
        [
            {'vm_self_link': 'link/vm-a', 'mig_id': 'mig-a'},
            {'vm_self_link': 'link/vm-a', 'mig_id': 'mig-b'},
            {'vm_self_link': 'link/vm-b', 'mig_id': 'mig-a'},
        ],
        TAG, OWN,
    )

    assert _part_of(neo4j_session) == {('vm-a', 'mig-a')}
