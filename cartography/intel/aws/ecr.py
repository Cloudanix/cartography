import logging
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import batch
from cartography.util import run_cleanup_job
from cartography.util import timeit
from cartography.util import to_asynchronous
from cartography.util import to_synchronous

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# See select_images_to_keep. Raise N if older tags are needed; drop the cap if per-image
# inventory is ever needed in full.
ECR_KEEP_LATEST_IMAGES_PER_REPO = 10
ECR_KEEP_PULLED_WITHIN_DAYS = 30
_EPOCH = datetime.fromtimestamp(0, tz=timezone.utc)


@timeit
@aws_handle_regions
def get_ecr_repositories(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    logger.info("Getting ECR repositories for region '%s'.", region)
    client = boto3_session.client("ecr", region_name=region, config=get_botocore_config())
    paginator = client.get_paginator("describe_repositories")
    ecr_repositories: List[Dict] = []
    for page in paginator.paginate():
        ecr_repositories.extend(page["repositories"])

    return ecr_repositories


@timeit
def transform_repositories(repositories: List[Dict], region: str) -> List[Dict]:
    ecr_repositories = []
    for repo in repositories:
        repo["region"] = region
        repo["consolelink"] = aws_console_link.get_console_link(arn=repo["repositoryArn"])
        ecr_repositories.append(repo)

    return ecr_repositories


@timeit
@aws_handle_regions
def get_ecr_repository_images(
    boto3_session: boto3.session.Session,
    region: str,
    repository_name: str,
    current_aws_account_id: str,
) -> List[Dict]:
    logger.debug("Getting ECR images in repository '%s' for region '%s'.", repository_name, region)
    client = boto3_session.client("ecr", region_name=region, config=get_botocore_config())
    paginator = client.get_paginator("describe_images")
    image_details: List[Dict] = []
    for page in paginator.paginate(repositoryName=repository_name, PaginationConfig={"PageSize": 1000}):
        image_details.extend(page["imageDetails"])

    kept = select_images_to_keep(image_details, datetime.now(timezone.utc))
    logger.debug("Keeping %d of %d ECR images in repository '%s'.", len(kept), len(image_details), repository_name)
    return to_image_ids(kept, region)


def select_images_to_keep(image_details: List[Dict], now: datetime) -> List[Dict]:
    """
    CI pipelines push an image per build and rarely expire them (a single repository can hold
    tens of thousands of tags), and every tag became an inventory asset. Keep the images that
    matter for posture: the newest ECR_KEEP_LATEST_IMAGES_PER_REPO by push time, plus any image
    pulled in the last ECR_KEEP_PULLED_WITHIN_DAYS days (in use, however old). AWS updates
    lastRecordedPullTime with up to ~24h lag.
    """
    newest_first = sorted(image_details, key=lambda d: d.get("imagePushedAt") or _EPOCH, reverse=True)
    pulled_since = now - timedelta(days=ECR_KEEP_PULLED_WITHIN_DAYS)
    return [
        detail for index, detail in enumerate(newest_first)
        if index < ECR_KEEP_LATEST_IMAGES_PER_REPO or (detail.get("lastRecordedPullTime") or _EPOCH) >= pulled_since
    ]


def to_image_ids(image_details: List[Dict], region: str) -> List[Dict]:
    """
    Flatten DescribeImages details to the ListImages imageIds shape the loader expects: one entry
    per (digest, tag), and one tagless entry for an untagged image.
    """
    image_ids: List[Dict] = []
    for detail in image_details:
        for tag in detail.get("imageTags") or [None]:
            image_id = {"imageDigest": detail.get("imageDigest"), "region": region}
            if tag:
                image_id["imageTag"] = tag
            image_ids.append(image_id)
    return image_ids


@timeit
def load_ecr_repositories(
    neo4j_session: neo4j.Session,
    repos: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    query = """
    UNWIND $DictList as ecr_repo
        MERGE (repo:ECRRepository{id: ecr_repo.repositoryArn})
        ON CREATE SET repo.firstseen = timestamp(),
            repo.arn = ecr_repo.repositoryArn,
            repo.name = ecr_repo.repositoryName,
            repo.region = ecr_repo.region,
            repo.created_at = ecr_repo.createdAt
        SET repo.lastupdated = $aws_update_tag,
            repo.consolelink = ecr_repo.consolelink,
            repo.uri = ecr_repo.repositoryUri
        WITH repo

        MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
        MERGE (owner)-[r:RESOURCE]->(repo)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    load_graph_data(
        neo4j_session,
        query,
        repos,
        aws_update_tag=aws_update_tag,
        AWS_ACCOUNT_ID=current_aws_account_id,
    )


@timeit
def transform_ecr_repository_images(repo_data: Dict) -> List[Dict]:
    """
    Ensure that we only load ECRImage nodes to the graph if they have a defined imageDigest field.
    """
    repo_images_list = []
    for repo_uri, repo_images in repo_data.items():
        for img in repo_images:
            if "imageDigest" in img and img["imageDigest"]:
                img["repo_uri"] = repo_uri
                repo_images_list.append(img)
            else:
                logger.warning(
                    "Repo %s has an image that has no imageDigest. Its tag is %s. Continuing on.",
                    repo_uri,
                    img.get("imageTag"),
                )

    return repo_images_list


def _load_ecr_repo_img_tx(
    tx: neo4j.Transaction,
    repo_images_list: List[Dict],
    aws_update_tag: int,
    current_aws_account_id: str,
) -> None:
    query = """
    UNWIND $RepoList as repo_img
        MERGE (ri:ECRRepositoryImage{id: repo_img.repo_uri + COALESCE(":" + repo_img.imageTag, '')})
        ON CREATE SET ri.firstseen = timestamp()
        SET ri.lastupdated = $aws_update_tag,
            ri.tag = repo_img.imageTag,
            ri.uri = repo_img.repo_uri + COALESCE(":" + repo_img.imageTag, ''),
            ri.digest = repo_img.imageDigest,
            ri.region = repo_img.region,
            ri.consolelink = repo_img.consolelink
        WITH ri, repo_img

        // ECRImage is keyed by digest alone: every account that pushed the same image shares it,
        // so only the digest goes on the node; region and console link stay on ri (this account's).
        MERGE (img:ECRImage{id: repo_img.imageDigest})
        ON CREATE SET img.firstseen = timestamp(),
            img.digest = repo_img.imageDigest
        SET img.lastupdated = $aws_update_tag
        WITH ri, img, repo_img

        MERGE (ri)-[r1:IMAGE]->(img)
        ON CREATE SET r1.firstseen = timestamp()
        SET r1.lastupdated = $aws_update_tag
        WITH ri, repo_img

        MATCH (:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->(repo:ECRRepository{uri: repo_img.repo_uri})
        MERGE (repo)-[r2:REPO_IMAGE]->(ri)
        ON CREATE SET r2.firstseen = timestamp()
        SET r2.lastupdated = $aws_update_tag
    """
    tx.run(
        query, RepoList=repo_images_list, aws_update_tag=aws_update_tag, AWS_ACCOUNT_ID=current_aws_account_id,
    )


@timeit
def load_ecr_repository_images(
    neo4j_session: neo4j.Session,
    repo_images_list: List[Dict],
    aws_update_tag: int,
    current_aws_account_id: str,
) -> None:
    logger.info(f"Loading {len(repo_images_list)} ECR repository images into graph.")
    for repo_image_batch in batch(repo_images_list, size=500):
        neo4j_session.execute_write(_load_ecr_repo_img_tx, repo_image_batch, aws_update_tag, current_aws_account_id)


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    logger.debug("Running ECR cleanup job.")
    run_cleanup_job("aws_import_ecr_cleanup.json", neo4j_session, common_job_parameters)
    # ECRImage is shared across tenants: the account cleanup only drops its edges, this drops orphans.
    run_cleanup_job("aws_ecr_image_orphan_cleanup.json", neo4j_session, common_job_parameters)


def _get_image_data(
    boto3_session: boto3.session.Session,
    region: str,
    repositories: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Given a list of repositories, get the image data for each repository,
    return as a mapping from repositoryUri to image object
    """
    image_data = {}

    async def async_get_images(repo: Dict[str, Any]) -> None:
        repo_image_obj = await to_asynchronous(get_ecr_repository_images, boto3_session, region, repo["repositoryName"])
        image_data[repo["repositoryUri"]] = repo_image_obj

    to_synchronous(*[async_get_images(repo) for repo in repositories])

    return image_data


@timeit
def sync(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing ECR for account '%s', at %s.", current_aws_account_id, tic)

    repositories = []
    for region in regions:
        logger.info("Syncing ECR for region '%s' in account '%s'.", region, current_aws_account_id)
        repos = get_ecr_repositories(boto3_session, region)
        repositories.extend(transform_repositories(repos, region))

    logger.info(f"Total ECR Repositories: {len(repositories)}")

    load_ecr_repositories(neo4j_session, repositories, current_aws_account_id, update_tag)

    image_data = {}
    for repo in repositories:
        repo_image_obj = get_ecr_repository_images(
            boto3_session,
            repo["region"],
            repo["repositoryName"],
            current_aws_account_id,
        )
        image_data[repo["repositoryUri"]] = repo_image_obj

    repo_images_list = transform_ecr_repository_images(image_data)
    load_ecr_repository_images(neo4j_session, repo_images_list, update_tag, current_aws_account_id)
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process ECR: {toc - tic:0.4f} seconds")
