from cartography.intel.oci import storage


def test_transform_buckets_console_link_uses_namespace_and_name():
    # Buckets without an OCID get a synthetic id; the console link must still use namespace + name.
    buckets = storage.transform_buckets([{"name": "logs"}], {}, "ns1", "us-phoenix-1")
    assert buckets[0]["id"] == "oci.bucket.ns1.logs"
    assert buckets[0]["consolelink"] == "https://cloud.oracle.com/object-storage/buckets/ns1/logs?region=us-phoenix-1"


def test_transform_buckets_leaves_public_access_type_unknown_when_get_bucket_failed():
    # ListBuckets carries no public-access-type; without GetBucket details we must not
    # claim "NoPublicAccess" and overwrite the last value GetBucket returned.
    buckets = storage.transform_buckets([{"name": "logs"}], {}, "ns1", "us-phoenix-1")
    assert buckets[0]["public_access_type"] is None


def test_transform_buckets_uses_get_bucket_public_access_type():
    buckets = storage.transform_buckets(
        [{"name": "pub"}, {"name": "priv"}, {"name": "unset"}],
        {
            "pub": {"public-access-type": "ObjectRead"},
            "priv": {"public-access-type": "NoPublicAccess"},
            "unset": {"versioning": "Enabled"},
        },
        "ns1",
        "us-phoenix-1",
    )
    assert [b["public_access_type"] for b in buckets] == ["ObjectRead", "NoPublicAccess", "NoPublicAccess"]


def test_transform_volume_backups_console_link_per_source_kind():
    backups = storage.transform_volume_backups(
        [{"id": "ocid1.volumebackup.oc1..a"}],
        [{"id": "ocid1.bootvolumebackup.oc1..b"}],
        "us-phoenix-1",
    )
    links = {b["source_kind"]: b["consolelink"] for b in backups}
    assert links["BLOCK"] == "https://cloud.oracle.com/block-storage/backups/ocid1.volumebackup.oc1..a?region=us-phoenix-1"
    assert links["BOOT"] == (
        "https://cloud.oracle.com/block-storage/boot-volume-backups/ocid1.bootvolumebackup.oc1..b?region=us-phoenix-1"
    )
