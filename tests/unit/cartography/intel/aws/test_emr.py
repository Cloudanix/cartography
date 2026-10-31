from cartography.intel.aws import emr
from cartography.models.aws.emr import EMRClusterNodeProperties


def test_get_master_security_group_ids_reads_managed_and_additional_groups():
    # Shape of describe_cluster()['Cluster'].
    cluster = {
        'Ec2InstanceAttributes': {
            'EmrManagedMasterSecurityGroup': 'sg-master',
            'AdditionalMasterSecurityGroups': ['sg-extra-1', 'sg-extra-2'],
            'EmrManagedSlaveSecurityGroup': 'sg-core',
            'ServiceAccessSecurityGroup': 'sg-service',
        },
    }

    assert emr.get_master_security_group_ids(cluster) == ['sg-master', 'sg-extra-1', 'sg-extra-2']


def test_get_master_security_group_ids_without_ec2_attributes():
    assert emr.get_master_security_group_ids({}) == []


def test_emr_cluster_schema_stores_master_security_group_ids():
    assert EMRClusterNodeProperties().master_security_group_ids.name == 'MasterSecurityGroupIds'
