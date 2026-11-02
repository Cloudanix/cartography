"""
Compute links stay inside the syncing tenant (AGENTS.md "Tenant isolation", rule 7).

Customer B holds VMs, scale sets, NICs, NSGs and disks whose ids customer A's API data names. Loading customer A must
never link to, or set properties on, customer B's nodes. A snapshot's source disk may sit in another subscription
of customer A's own workspace, so that one link is anchored on the workspace.
"""
from cartography.intel.azure import compute
from cartography.intel.azure import subscription
from cartography.intel.azure import vmss
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import CUSTOMERS
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

WORKSPACE_A, TENANT_A = CUSTOMERS[SUB_A]
# A second subscription of customer A (same workspace and tenant).
SUB_A2 = 'aaaaaaaa-0000-0000-0000-0000000000a2'

VM = 'AzureVirtualMachine'
VMSS = 'AzureVirtualMachineScaleSet'
VM_A = arm_id(SUB_A, 'Microsoft.Compute/virtualMachines/vm')
VM_B = arm_id(SUB_B, 'Microsoft.Compute/virtualMachines/vm')
# An id the API returned while syncing SUB_A that names SUB_B: its subscription segment is not an anchor.
VM_FOREIGN = arm_id(SUB_B, 'Microsoft.Compute/virtualMachines/vm-foreign')
NIC_A = arm_id(SUB_A, 'Microsoft.Network/networkInterfaces/nic')
NIC_B = arm_id(SUB_B, 'Microsoft.Network/networkInterfaces/nic')
NSG_A = arm_id(SUB_A, 'Microsoft.Network/networkSecurityGroups/nsg')
NSG_B = arm_id(SUB_B, 'Microsoft.Network/networkSecurityGroups/nsg')
VMSS_A = arm_id(SUB_A, 'Microsoft.Compute/virtualMachineScaleSets/ss')
VMSS_B = arm_id(SUB_B, 'Microsoft.Compute/virtualMachineScaleSets/ss')
DISK_A = arm_id(SUB_A, 'Microsoft.Compute/disks/d')
DISK_A2 = arm_id(SUB_A2, 'Microsoft.Compute/disks/d')
DISK_B = arm_id(SUB_B, 'Microsoft.Compute/disks/d')
SNAP_A = arm_id(SUB_A, 'Microsoft.Compute/snapshots/s')
SNAP_B = arm_id(SUB_B, 'Microsoft.Compute/snapshots/s')


def _seed(neo4j_session):
    seed_customers(neo4j_session)
    subscription.load_azure_subscriptions(
        neo4j_session, TENANT_A, [{'id': f'/subscriptions/{SUB_A2}', 'subscriptionId': SUB_A2}], UPDATE_TAG,
    )
    for sub, label, node_id in [
        (SUB_A, 'AzureNetworkInterface', NIC_A), (SUB_B, 'AzureNetworkInterface', NIC_B),
        (SUB_A, 'AzureNetworkSecurityGroup', NSG_A), (SUB_B, 'AzureNetworkSecurityGroup', NSG_B),
        (SUB_B, VM, VM_B), (SUB_B, VMSS, VMSS_B), (SUB_A2, 'AzureDisk', DISK_A2), (SUB_B, 'AzureDisk', DISK_B),
        (SUB_B, 'AzureSnapshot', SNAP_B),
    ]:
        seed_node(neo4j_session, sub, label, node_id)
    # Customer B's VM has a public IP behind its NIC: customer A's sync must not copy it onto the VM.
    neo4j_session.run(
        "MATCH (vm:AzureVirtualMachine{id: $vm}), (nic:AzureNetworkInterface{id: $nic}) "
        "MERGE (vm)-[:MEMBER_NETWORK_INTERFACE]->(nic) "
        "MERGE (nic)-[:MEMBER_PUBLIC_IP_ADDRESS]->(:AzurePublicIPAddress{id: 'pip-b', ipAddress: '203.0.113.9'}) "
        "MERGE (nic)-[:CONTAINS]->(:AzureNetworkInterfaceIPConfiguration{id: 'ipc-b', private_ip_address: '10.9.9.9'})",
        vm=VM_B, nic=NIC_B,
    )


def _vm(vm_id, name):
    return {
        'id': vm_id, 'name': name, 'image_reference_id': 'pub:offer:sku:1',
        'network_interfaces': [{'id': NIC_A}, {'id': NIC_B}],
        'network_security_group': [{'id': NSG_A}, {'id': NSG_B}],
        'user_assigned_identities': [f'/subscriptions/{SUB_A}/providers/mi/{name}'],
        'storage_profile': {
            'os_disk': {'name': f'{name}-os', 'managed_disk': {'id': f'{vm_id}/os'}},
            'data_disks': [{'name': f'{name}-data', 'managed_disk': {'id': f'{vm_id}/data'}}],
        },
    }


def _property(neo4j_session, label, node_id, prop):
    return neo4j_session.run(
        f"MATCH (n:{label}{{id: $id}}) RETURN n[$prop] AS value", id=node_id, prop=prop,
    ).single()['value']


def test_vm_links_stay_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)

    compute.load_vms(neo4j_session, SUB_A, [_vm(VM_A, 'vm'), _vm(VM_FOREIGN, 'vm-foreign')], UPDATE_TAG)
    # Customer B's VM id handed to every VM-keyed loader while syncing customer A.
    compute.load_vm_os_disk(neo4j_session, SUB_A, VM_B, {'name': 'x', 'managed_disk': {'id': f'{VM_B}/os'}}, 1)
    compute.load_vm_data_disks(neo4j_session, SUB_A, VM_B, [{'name': 'x', 'managed_disk': {'id': f'{VM_B}/dd'}}], 1)
    compute.load_vm_managed_identities(neo4j_session, SUB_A, VM_B, ['mi-b'], UPDATE_TAG)
    compute.load_vm_image_relations(neo4j_session, SUB_A, [{'id': VM_B, 'image_reference_id': 'p:o:s:1'}], 1)
    compute.load_vm_network_interfaces_relationship(neo4j_session, SUB_A, VM_B, [{'id': NIC_A}], UPDATE_TAG)
    compute.load_vm_security_groups_relationship(neo4j_session, SUB_A, VM_B, [{'id': NSG_A}], UPDATE_TAG)
    compute._attach_vm_properties_public_ip(neo4j_session, SUB_A, VM_B, UPDATE_TAG)
    compute._attach_vm_properties_private_ip(neo4j_session, SUB_A, VM_B, UPDATE_TAG)

    for vm_id in (VM_A, VM_FOREIGN):
        assert resource_group_of(neo4j_session, VM, vm_id) == {rg_id(SUB_A)}
        assert linked_ids(neo4j_session, VM, vm_id, 'MEMBER_NETWORK_INTERFACE', 'AzureNetworkInterface') == {NIC_A}
        assert linked_ids(neo4j_session, VM, vm_id, 'MEMBER_NETWORK_SECURITY_GROUP', 'AzureNetworkSecurityGroup') == {
            NSG_A,
        }
        assert linked_ids(neo4j_session, VM, vm_id, 'ATTACHED_TO', 'AzureDisk') == {f'{vm_id}/os', f'{vm_id}/data'}
        assert len(linked_ids(neo4j_session, VM, vm_id, 'HAS', 'AzureManagedIdentity')) == 1
        assert linked_ids(neo4j_session, VM, vm_id, 'HAS', 'AzureImage') == {'pub:offer:sku:1'}

    assert resource_group_of(neo4j_session, VM, VM_B) == set()
    assert linked_ids(neo4j_session, VM, VM_B, 'MEMBER_NETWORK_INTERFACE', 'AzureNetworkInterface') == {NIC_B}
    for rel, label in [
        ('MEMBER_NETWORK_SECURITY_GROUP', 'AzureNetworkSecurityGroup'), ('ATTACHED_TO', 'AzureDisk'),
        ('HAS', 'AzureManagedIdentity'), ('HAS', 'AzureImage'),
    ]:
        assert linked_ids(neo4j_session, VM, VM_B, rel, label) == set(), rel
    assert _property(neo4j_session, VM, VM_B, 'public_ip') is None
    assert _property(neo4j_session, VM, VM_B, 'private_ip') is None
    assert linked_ids(neo4j_session, 'AzureNetworkInterface', NIC_B, 'MEMBER_NETWORK_INTERFACE', VM) == {VM_B}


def test_vm_children_stay_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)
    compute.load_vms(neo4j_session, SUB_A, [{'id': VM_A, 'name': 'vm'}], UPDATE_TAG)

    compute.load_vm_extensions(
        neo4j_session, SUB_A,
        [{'id': f'{VM_A}/extensions/own', 'vm_id': VM_A}, {'id': f'{VM_B}/extensions/x', 'vm_id': VM_B}],
        UPDATE_TAG,
    )
    compute.load_vm_available_sizes(
        neo4j_session, SUB_A,
        [{'id': f'{VM_A}/Size/own', 'vm_id': VM_A}, {'id': f'{VM_B}/Size/x', 'vm_id': VM_B}],
        UPDATE_TAG,
    )

    for label in ('AzureVirtualMachineExtension', 'AzureVirtualMachineAvailableSize'):
        own = f'{VM_A}/extensions/own' if label.endswith('Extension') else f'{VM_A}/Size/own'
        assert linked_ids(neo4j_session, VM, VM_A, 'CONTAIN', label) == {own}
        assert linked_ids(neo4j_session, VM, VM_B, 'CONTAIN', label) == set()
        assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}


def test_scale_set_links_stay_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)
    foreign_set = arm_id(SUB_B, 'Microsoft.Compute/virtualMachineScaleSets/ss-foreign')
    compute.load_vms(neo4j_session, SUB_A, [{'id': VM_A, 'name': 'vm'}], UPDATE_TAG)
    compute.load_vm_scale_sets(neo4j_session, SUB_A, [{'id': VMSS_A}, {'id': foreign_set}], UPDATE_TAG)

    compute.load_vm_scale_sets_extensions(
        neo4j_session, SUB_A,
        [{'id': f'{VMSS_A}/extensions/own', 'set_id': VMSS_A}, {'id': f'{VMSS_B}/extensions/x', 'set_id': VMSS_B}],
        UPDATE_TAG,
    )
    neo4j_session.execute_write(
        vmss._load_vm_scale_set_vms_part_of_relationships_tx, SUB_A,
        [
            {'vm_id': VM_A, 'vmss_id': VMSS_A},
            {'vm_id': VM_B, 'vmss_id': VMSS_A},
            {'vm_id': VM_A, 'vmss_id': VMSS_B},
        ],
        UPDATE_TAG,
    )

    assert resource_group_of(neo4j_session, VMSS, VMSS_A) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, VMSS, foreign_set) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, VMSS, VMSS_B) == set()
    ext = 'AzureVirtualMachineScaleSetExtension'
    assert linked_ids(neo4j_session, VMSS, VMSS_A, 'CONTAIN', ext) == {f'{VMSS_A}/extensions/own'}
    assert linked_ids(neo4j_session, VMSS, VMSS_B, 'CONTAIN', ext) == set()
    assert resource_group_of(neo4j_session, ext, f'{VMSS_A}/extensions/own') == {rg_id(SUB_A)}
    assert linked_ids(neo4j_session, VMSS, VMSS_A, 'PART_OF', VM) == {VM_A}
    assert linked_ids(neo4j_session, VMSS, VMSS_B, 'PART_OF', VM) == set()


def test_disk_and_snapshot_links_stay_in_the_tenant(neo4j_session):
    _seed(neo4j_session)
    foreign_disk = arm_id(SUB_B, 'Microsoft.Compute/disks/d-foreign')
    foreign_snap = arm_id(SUB_B, 'Microsoft.Compute/snapshots/s-foreign')
    snap_copy = arm_id(SUB_A, 'Microsoft.Compute/snapshots/s-copy')
    compute.load_disks(neo4j_session, SUB_A, [{'id': DISK_A}, {'id': foreign_disk}], UPDATE_TAG)
    compute.load_snapshots(
        neo4j_session, SUB_A, [{'id': SNAP_A}, {'id': snap_copy}, {'id': foreign_snap}], UPDATE_TAG,
    )

    # Source disk in another subscription of customer A's workspace: linked.
    compute._attach_snapshot_disk(neo4j_session, SUB_A, WORKSPACE_A, snap_copy, DISK_A2, UPDATE_TAG)
    compute._attach_snapshot_disk(neo4j_session, SUB_A, WORKSPACE_A, SNAP_A, DISK_A, UPDATE_TAG)
    # Source disk owned by customer B, and customer B's snapshot: never linked.
    compute._attach_snapshot_disk(neo4j_session, SUB_A, WORKSPACE_A, SNAP_A, DISK_B, UPDATE_TAG)
    compute._attach_snapshot_disk(neo4j_session, SUB_A, WORKSPACE_A, SNAP_B, DISK_A, UPDATE_TAG)

    for disk_id in (DISK_A, foreign_disk):
        assert resource_group_of(neo4j_session, 'AzureDisk', disk_id) == {rg_id(SUB_A)}
    for snap_id in (SNAP_A, snap_copy, foreign_snap):
        assert resource_group_of(neo4j_session, 'AzureSnapshot', snap_id) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureDisk', DISK_B) == set()
    assert resource_group_of(neo4j_session, 'AzureSnapshot', SNAP_B) == set()

    assert linked_ids(neo4j_session, 'AzureDisk', DISK_A, 'HAS', 'AzureSnapshot') == {SNAP_A}
    assert linked_ids(neo4j_session, 'AzureDisk', DISK_A2, 'HAS', 'AzureSnapshot') == {snap_copy}
    assert linked_ids(neo4j_session, 'AzureDisk', DISK_B, 'HAS', 'AzureSnapshot') == set()
    assert linked_ids(neo4j_session, 'AzureSnapshot', SNAP_B, 'HAS', 'AzureDisk') == set()
