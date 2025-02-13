import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j
from clouduniqueid.clouds.bitbucket import BitbucketUniqueId

from .common import cleanse_string
from cartography.util import make_requests_url
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

bitbucket_linker = BitbucketUniqueId()


@timeit
def get_repos(access_token: str, workspace: str) -> List[Dict]:
    # https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/#api-repositories-workspace-get
    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}?pagelen=100"

    response = make_requests_url(url, access_token)
    repositories = response.get("values", [])

    while "next" in response:
        response = make_requests_url(response.get("next"), access_token)
        repositories.extend(response.get("values", []))

    return repositories


def _transform_repo_languages(repo_url: str, repo: Dict, repo_languages: List[Dict]) -> None:
    """
    Helper function to transform the languages in a Bitbucket repo.
    :param repo_url: The URL of the repo.
    :param repo: The repo object from Bitbucket API.
    :param repo_languages: Output array to append transformed results to.
    """
    if repo.get("language"):
        repo_languages.append(
            {
                "repo_id": repo["uuid"],
                "language_name": repo["language"],
            },
        )


def transform_repos(workspace_repos: List[Dict], workspace: str) -> Dict:
    """
    Transform the repos data including languages
    """
    transformed_repo_list = []
    transformed_repo_languages = []

    for repo in workspace_repos:
        # Existing transformations
        repo["workspace"]["uuid"] = repo["workspace"]["uuid"].replace("{", "").replace("}", "")
        repo["project"]["uuid"] = repo["project"]["uuid"].replace("{", "").replace("}", "")
        repo["uuid"] = repo["uuid"].replace("{", "").replace("}", "")

        if repo is not None and repo.get("mainbranch") is not None:
            repo["default_branch"] = repo.get("mainbranch", {}).get("name", None)

         # Transform languages
        _transform_repo_languages(repo["url"], repo, transformed_repo_languages)

        data = {
            "workspace": workspace,
            "project": cleanse_string(repo["project"]["name"]),
            "repository": cleanse_string(repo["name"]),
        }

        repo["uniqueId"] = bitbucket_linker.get_unique_id(service="bitbucket", data=data, resource_type="repository")
        transformed_repo_list.append(repo)

    return {
        "repos": transformed_repo_list,
        "repo_languages": transformed_repo_languages,
    }


def load_repositories_data(session: neo4j.Session, repos_data: List[Dict], common_job_parameters: Dict) -> None:
    session.write_transaction(_load_repositories_data, repos_data, common_job_parameters)


@timeit
def load_languages(neo4j_session: neo4j.Session, update_tag: int, repo_languages: List[Dict]) -> None:
    """
    Ingest the relationships for repo languages
    :param neo4j_session: Neo4J session object for server communication
    :param update_tag: Timestamp used to determine data freshness
    :param repo_languages: list of language to repo mappings
    """
    ingest_languages = """
        UNWIND $Languages as lang

        MERGE (pl:ProgrammingLanguage{id: lang.language_name})
        ON CREATE SET pl.firstseen = timestamp(),
        pl.name = lang.language_name
        SET pl.lastupdated = $UpdateTag
        WITH pl, lang

        MATCH (repo:BitbucketRepository{id: lang.repo_id})
        MERGE (repo)-[r:LANGUAGE]->(pl)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $UpdateTag
    """

    neo4j_session.run(
        ingest_languages,
        Languages=repo_languages,
        UpdateTag=update_tag,
    )


def _load_repositories_data(tx: neo4j.Transaction, repos_data: List[Dict], common_job_parameters: Dict) -> None:
    ingest_repositories = """
    UNWIND $reposData as repo
    MERGE (re:BitbucketRepository{id:repo.uuid})
    ON CREATE SET re.firstseen = timestamp(),
    re.created_on = repo.created_on

    SET re.slug = repo.slug,
    re.type = repo.type,
    re.unique_id = repo.uniqueId,
    re.name = repo.name,
    re.is_private = repo.is_private,
    re.description = repo.description,
    re.full_name = repo.full_name,
    re.has_issues = repo.has_issues,
    re.language = repo.language,
    re.owner = repo.owner,
    re.default_branch = repo.default_branch,
    re.lastupdated = $UpdateTag


    WITH re,repo
    WHERE repo.language IS NOT NULL
    MERGE (pl:ProgrammingLanguage{id: repo.language})
    ON CREATE SET pl.firstseen = timestamp(),
    pl.name = repo.language
    SET pl.lastupdated = $UpdateTag
    MERGE (re)-[lang:PRIMARY_LANGUAGE]->(pl)
    ON CREATE SET lang.firstseen = timestamp()
    SET lang.lastupdated = $UpdateTag

    WITH re,repo
    MATCH (project:BitbucketProject{id:repo.project_uuid})
    MERGE (project)<-[o:RESOURCE]-(re)
    ON CREATE SET o.firstseen = timestamp()
    SET o.lastupdated = $UpdateTag
    """

    tx.run(
        ingest_repositories,
        reposData=repos_data,
        UpdateTag=common_job_parameters["UPDATE_TAG"],
    )


def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("bitbucket_workspace_repositories_cleanup.json", neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session,
    workspace_name: str,
    bitbucket_access_token: str,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync bitbucket data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """
    tic = time.perf_counter()
    logger.info(
        "BEGIN Syncing Bitbucket Repositories",
        extra={"workspace": common_job_parameters["WORKSPACE_ID"], "slug": workspace_name, "start": tic},
    )

    logger.info("Syncing Bitbucket All Repositories")
    workspace_repos = get_repos(bitbucket_access_token, workspace_name)
    transformed_data = transform_repos(workspace_repos, workspace_name)

    # Load repositories
    load_repositories_data(neo4j_session, transformed_data["repos"], common_job_parameters)

    # Load languages
    load_languages(neo4j_session, common_job_parameters["UPDATE_TAG"], transformed_data["repo_languages"])

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(
        "END Syncing Bitbucket Repositories",
        extra={
            "workspace": common_job_parameters["WORKSPACE_ID"],
            "slug": workspace_name,
            "end": toc,
            "duration": f"{toc - tic:0.4f}",
        },
    )
