import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import botocore.exceptions

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


def _summary(cluster_id):
    return {'Id': cluster_id, 'Name': cluster_id, 'Status': {'State': 'RUNNING'}}


def _emr_session(pages, block_public=True, describe_error_for=()):
    """boto3 session stub: list_clusters pages, the regional BPA setting, describe_cluster per id."""
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = pages
    client.get_block_public_access_configuration.return_value = {
        'BlockPublicAccessConfiguration': {'BlockPublicSecurityGroupRules': block_public},
    }

    def describe(ClusterId):
        if ClusterId in describe_error_for:
            raise botocore.exceptions.ClientError({'Error': {'Code': 'InvalidRequestException', 'Message': 'x'}}, 'D')
        return {'Cluster': {'Id': ClusterId, 'ClusterArn': f'arn:aws:elasticmapreduce:us-east-1:1:cluster/{ClusterId}'}}

    client.describe_cluster.side_effect = describe
    session = MagicMock()
    session.client.return_value = client
    return session, client


def test_get_emr_clusters_lists_live_states_only_and_stops_at_cap():
    session, client = _emr_session([{'Clusters': [_summary('j-1'), _summary('j-2')]}])

    assert [c['Id'] for c in emr.get_emr_clusters(session, 'us-east-1')] == ['j-1', 'j-2']

    client.get_paginator.assert_called_once_with('list_clusters')
    kwargs = client.get_paginator.return_value.paginate.call_args.kwargs
    # Terminated clusters stay listable for ~2 months; listing them is what made the sync run forever.
    assert kwargs['ClusterStates'] == ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING']
    assert kwargs['PaginationConfig'] == {'MaxItems': emr.MAX_CLUSTERS_PER_REGION + 1}


def test_cap_clusters_truncates_and_warns(caplog):
    clusters = [_summary(f'j-{i}') for i in range(3)]
    with patch.object(emr, 'MAX_CLUSTERS_PER_REGION', 2), caplog.at_level(logging.WARNING):
        capped = emr.cap_clusters(clusters, '123456789012', 'us-east-1')

    assert [c['Id'] for c in capped] == ['j-0', 'j-1']
    assert '123456789012' in caplog.text and 'us-east-1' in caplog.text


def test_cap_clusters_under_cap_is_unchanged(caplog):
    clusters = [_summary('j-1')]
    with caplog.at_level(logging.WARNING):
        assert emr.cap_clusters(clusters, '123456789012', 'us-east-1') == clusters
    assert caplog.text == ''


def test_get_cluster_details_reads_bpa_once_per_region_and_never_sleeps():
    session, client = _emr_session([], block_public=False, describe_error_for={'j-bad'})
    clusters = [_summary('j-1'), _summary('j-bad'), _summary('j-2')]

    with patch.object(emr.time, 'sleep') as sleep:
        details = emr.get_cluster_details(session, 'us-east-1', clusters)

    assert [d['Id'] for d in details] == ['j-1', 'j-2']  # a failed describe skips only that cluster
    assert all(d['public_access_configuration'] is False for d in details)
    client.get_block_public_access_configuration.assert_called_once_with()
    assert client.describe_cluster.call_count == 3
    session.client.assert_called_once()  # one client per region, not per cluster
    sleep.assert_not_called()


def test_get_cluster_details_bpa_missing_key_defaults_to_blocked():
    session, client = _emr_session([])
    client.get_block_public_access_configuration.return_value = {}

    details = emr.get_cluster_details(session, 'us-east-1', [_summary('j-1')])

    assert details[0]['public_access_configuration'] is True


def test_get_cluster_details_without_clusters_makes_no_calls():
    session, client = _emr_session([])

    assert emr.get_cluster_details(session, 'us-east-1', []) == []
    session.client.assert_not_called()


def test_sync_is_enabled_and_cleans_up():
    with patch.object(emr, 'get_emr_clusters', return_value=[_summary('j-1')]) as get_clusters, \
            patch.object(emr, 'get_cluster_details', return_value=[{'Id': 'j-1'}]) as details, \
            patch.object(emr, 'load_emr_clusters') as load, patch.object(emr, 'cleanup') as cleanup:
        emr.sync(MagicMock(), MagicMock(), ['us-east-1', 'eu-west-1'], '123456789012', 1, {'UPDATE_TAG': 1})

    assert get_clusters.call_count == 2
    assert details.call_count == 2
    assert load.call_count == 2
    cleanup.assert_called_once()
