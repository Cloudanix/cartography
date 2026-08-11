from cartography.intel.gcp import label
from cartography.intel.gcp.sql import transform_sql_instances
from tests.data.gcp.sql import CLOUD_SQL_INSTANCES


def test_transform_sql_instances_lifts_user_labels():
    # Cloud SQL keeps labels at settings.userLabels; label.sync_labels reads
    # 'labels', so the transform must lift them or they are silently dropped
    instances = transform_sql_instances(CLOUD_SQL_INSTANCES)

    assert len(instances) == 2
    labeled = next(i for i in instances if i['id'] == 'instance123')
    unlabeled = next(i for i in instances if i['id'] == 'instance456')

    assert labeled['labels'] == {'env': 'prod', 'team': 'data'}
    assert unlabeled['labels'] == {}

    labels = label.get_labels_list(instances)
    assert {(lbl['key'], lbl['value']) for lbl in labels} == {
        ('env', 'prod'),
        ('team', 'data'),
    }
    for lbl in labels:
        assert lbl['resource_id'] == 'instance123'
        assert lbl['id'] == f"instance123/label/{lbl['key']}"


def test_transform_sql_instances_psc_disabled_by_default():
    instances = transform_sql_instances(CLOUD_SQL_INSTANCES)
    assert all(i['pscEnabled'] is False for i in instances)
