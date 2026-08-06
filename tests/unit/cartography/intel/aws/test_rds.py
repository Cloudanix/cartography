from cartography.intel.aws.rds import filter_active_rds_reserved_db_instances


def test_filter_active_rds_reserved_db_instances_keeps_active_only():
    instances = [
        {'ReservedDBInstanceId': 'ri-active', 'State': 'active'},
        {'ReservedDBInstanceId': 'ri-retired', 'State': 'retired'},
        {'ReservedDBInstanceId': 'ri-payment-failed', 'State': 'payment-failed'},
        {'ReservedDBInstanceId': 'ri-payment-pending', 'State': 'payment-pending'},
        {'ReservedDBInstanceId': 'ri-missing-state'},
    ]

    filtered = filter_active_rds_reserved_db_instances(instances)

    assert [i['ReservedDBInstanceId'] for i in filtered] == ['ri-active']


def test_filter_active_rds_reserved_db_instances_empty():
    assert filter_active_rds_reserved_db_instances([]) == []
