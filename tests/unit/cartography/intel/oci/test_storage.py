from unittest.mock import MagicMock

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


def test_transform_buckets_summarises_read_pre_authenticated_requests():
    pars = {
        "shared": [
            {"access-type": "AnyObjectRead", "time-expires": "2027-01-01T00:00:00+00:00"},
            {"access-type": "ObjectRead", "time-expires": "2027-06-01T00:00:00.500000+00:00"},
            # Write-only PARs let anyone upload but not read.
            {"access-type": "AnyObjectWrite", "time-expires": "2030-01-01T00:00:00+00:00"},
        ],
        "none": [],
        "write-only": [{"access-type": "ObjectWrite", "time-expires": "2030-01-01T00:00:00+00:00"}],
        # ListPreauthenticatedRequests failed: unknown, so load_buckets keeps the last value.
        "failed": None,
    }
    buckets = storage.transform_buckets(
        [{"name": name} for name in pars], {}, "ns1", "us-phoenix-1", pars,
    )
    summary = {b["name"]: (b["read_par_expires_at"], b["read_par_access_types"]) for b in buckets}
    assert summary == {
        "shared": (1811808000500, ["AnyObjectRead", "ObjectRead"]),
        "none": (0, []),
        "write-only": (0, []),
        "failed": (None, None),
    }


def test_get_bucket_pre_authenticated_requests_returns_none_on_error(monkeypatch):
    list_all = MagicMock(side_effect=storage.oci.exceptions.ServiceError(404, "NotAuthorizedOrNotFound", {}, "x"))
    monkeypatch.setattr(storage.oci.pagination, "list_call_get_all_results", list_all)

    assert storage.get_bucket_pre_authenticated_requests(MagicMock(), "ns1", "logs") is None
    assert list_all.call_args.kwargs == {"namespace_name": "ns1", "bucket_name": "logs"}


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
