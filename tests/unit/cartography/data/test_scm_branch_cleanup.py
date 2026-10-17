from pathlib import Path

CLEANUP_DIR = Path(__file__).resolve().parents[4] / 'cartography' / 'data' / 'jobs' / 'cleanup'


def _queries(filename: str) -> str:
    return (CLEANUP_DIR / filename).read_text()


def test_github_branch_cleanup_follows_the_loaded_edge_direction():
    # load_github_repos / load_github_branches write (repo)-[:BRANCH]->(branch). A reversed
    # pattern never matches, so stale branches and edges were never removed.
    text = _queries('github_repos_cleanup.json')
    assert '(:GitHubRepository)-[:BRANCH]->(n:GitHubBranch)' in text
    assert '(:GitHubBranch)<-[r:BRANCH]-(:GitHubRepository)' in text
    assert '(:GitHubRepository)<-[:BRANCH]-' not in text
    assert '(:GitHubBranch)-[r:BRANCH]->' not in text


def test_gitlab_branch_cleanup_follows_the_loaded_edge_direction():
    # _load_branches_data writes (project)-[:BRANCH]->(branch).
    text = _queries('gitlab_group_project_cleanup.json')
    assert '(:GitLabProject)-[:BRANCH]->(n:GitLabBranch)' in text
    assert '(:GitLabProject)-[r:BRANCH]->(:GitLabBranch) WHERE r.lastupdated' in text
    assert '(:GitLabProject)<-[:BRANCH]-' not in text
