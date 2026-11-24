"""
Unit tests for ECR image selection: inventory keeps the newest images per repository plus any image
pulled recently, instead of every tag CI ever pushed.
"""
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import MagicMock

from cartography.intel.aws.ecr import ECR_KEEP_LATEST_IMAGES_PER_REPO
from cartography.intel.aws.ecr import ECR_KEEP_PULLED_WITHIN_DAYS
from cartography.intel.aws.ecr import get_ecr_repository_images
from cartography.intel.aws.ecr import select_images_to_keep
from cartography.intel.aws.ecr import to_image_ids

NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def _image(index, pulled_days_ago=None, tags=None):
    """Image pushed `index` days before NOW, optionally pulled `pulled_days_ago` days before NOW."""
    detail = {
        "imageDigest": f"sha256:{index:04d}",
        "imagePushedAt": NOW - timedelta(days=index),
        "imageTags": tags if tags is not None else [f"build-{index}"],
    }
    if pulled_days_ago is not None:
        detail["lastRecordedPullTime"] = NOW - timedelta(days=pulled_days_ago)
    return detail


class TestSelectImagesToKeep:
    def test_keeps_only_newest_n_when_none_pulled(self):
        images = [_image(i) for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO + 15)]

        kept = select_images_to_keep(list(reversed(images)), NOW)

        expected = {f"sha256:{i:04d}" for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO)}
        assert {d["imageDigest"] for d in kept} == expected

    def test_keeps_old_image_pulled_recently(self):
        old_in_use = _image(400, pulled_days_ago=1)
        images = [_image(i) for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO)] + [old_in_use]

        kept = select_images_to_keep(images, NOW)

        assert old_in_use in kept
        assert len(kept) == ECR_KEEP_LATEST_IMAGES_PER_REPO + 1

    def test_drops_old_image_pulled_before_window(self):
        stale = _image(400, pulled_days_ago=ECR_KEEP_PULLED_WITHIN_DAYS + 1)
        images = [_image(i) for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO)] + [stale]

        assert stale not in select_images_to_keep(images, NOW)

    def test_small_repo_keeps_everything(self):
        images = [_image(i) for i in range(3)]

        assert len(select_images_to_keep(images, NOW)) == 3

    def test_missing_push_time_sorts_last(self):
        no_push_time = {"imageDigest": "sha256:none", "imageTags": ["x"]}
        images = [_image(i) for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO)] + [no_push_time]

        assert no_push_time not in select_images_to_keep(images, NOW)


class TestToImageIds:
    def test_one_entry_per_tag_and_tagless_for_untagged(self):
        details = [_image(1, tags=["a", "b"]), _image(2, tags=[])]

        image_ids = to_image_ids(details, "us-east-1")

        assert image_ids == [
            {"imageDigest": "sha256:0001", "region": "us-east-1", "imageTag": "a"},
            {"imageDigest": "sha256:0001", "region": "us-east-1", "imageTag": "b"},
            {"imageDigest": "sha256:0002", "region": "us-east-1"},
        ]


class TestGetEcrRepositoryImages:
    def test_uses_describe_images_and_caps_result(self):
        session = MagicMock()
        client = session.client.return_value
        pages = [{"imageDetails": [_image(i) for i in range(ECR_KEEP_LATEST_IMAGES_PER_REPO + 5)]}]
        client.get_paginator.return_value.paginate.return_value = pages

        image_ids = get_ecr_repository_images(session, "us-east-1", "example-repo", "123456789012")

        client.get_paginator.assert_called_once_with("describe_images")
        assert client.get_paginator.return_value.paginate.call_args.kwargs["repositoryName"] == "example-repo"
        assert len(image_ids) == ECR_KEEP_LATEST_IMAGES_PER_REPO
        assert all(i["region"] == "us-east-1" for i in image_ids)
