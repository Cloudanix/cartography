import logging
import os
import time

import neo4j
import neo4j.exceptions
import pytest
from testcontainers.core.container import DockerContainer

from tests.integration import settings

logging.basicConfig(level=logging.INFO)
logging.getLogger("neo4j").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def _neo4j_auth() -> neo4j.Auth | None:
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")
    if user and password:
        return neo4j.basic_auth(user, password)
    return None


def _make_driver(uri: str) -> neo4j.Driver:
    auth = _neo4j_auth()
    return neo4j.GraphDatabase.driver(uri, auth=auth)


def _wait_for_neo4j(uri: str, timeout_seconds: int = 60) -> None:
    """Block until Neo4j accepts Bolt connections."""
    deadline = time.monotonic() + timeout_seconds
    last_error = None

    while time.monotonic() < deadline:
        driver = _make_driver(uri)
        try:
            driver.verify_connectivity()
            return
        except neo4j.exceptions.AuthError as exc:
            raise RuntimeError(
                f"Neo4j auth failed for {uri}. "
                f"Set NEO4J_USER and NEO4J_PASSWORD env vars if auth is enabled."
            ) from exc
        # This branch only executes if the container is still booting.
        except Exception as exc:  # pragma: no cover
            last_error = exc
            time.sleep(1)
        finally:
            driver.close()

    raise RuntimeError(
        f"Neo4j did not become ready in {timeout_seconds}s"
    ) from last_error


@pytest.fixture(scope="session", autouse=True)
def neo4j_url():
    configured_neo4j_url = os.environ.get("NEO4J_URL")
    if configured_neo4j_url:
        logger.info(
            "Using externally configured Neo4j instance at %s", configured_neo4j_url
        )
        _wait_for_neo4j(configured_neo4j_url)
        yield configured_neo4j_url
        return

    image = settings.get("NEO4J_DOCKER_IMAGE")
    logger.info("Starting Neo4j testcontainer using image %s", image)
    container = (
        DockerContainer(image).with_exposed_ports(7687).with_env("NEO4J_AUTH", "none")
    )

    with container as started_container:
        container_url = (
            f"bolt://{started_container.get_container_host_ip()}:"
            f"{started_container.get_exposed_port(7687)}"
        )
        _wait_for_neo4j(container_url)
        os.environ["NEO4J_URL"] = container_url

        try:
            yield container_url
        finally:
            os.environ.pop("NEO4J_URL", None)


@pytest.fixture(scope="module")
def neo4j_session(neo4j_url):
    driver = _make_driver(neo4j_url)
    with driver.session() as session:
        yield session
        session.run("MATCH (n) DETACH DELETE n;")
    driver.close()
