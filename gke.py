# GKE entrypoint for git inventory workers (image command: python gke.py).
# A spot preemption delivers SIGTERM after the message has already been acked,
# so the in-flight request must be republished to the same request topic.
import copy
import json
import logging
import os
import signal
import sys
import time

from google.api_core.exceptions import NotFound
from google.cloud import pubsub_v1

import utils.logger as lgr
from libraries.pubsublibrary import PubSubLibrary
from main import bitbucket_process_request
from main import github_process_request
from main import gitlab_process_request
from utils.errors import PubSubPublishError
from utils.logger import Logger

CDX_GITHUB_SERVICE = "github"
CDX_BITBUCKET_SERVICE = "bitbucket"
CDX_GITLAB_SERVICE = "gitlab"

CDX_GITHUB_TEMPLATE_TYPE = "GITHUBINVENTORYVIEWS"
CDX_BITBUCKET_TEMPLATE_TYPE = "BITBUCKETINVENTORYVIEWS"
CDX_GITLAB_TEMPLATE_TYPE = "GITLABINVENTORYVIEWS"

# Message pulled from Pub/Sub and not yet finished. Set before ack so a
# SIGTERM during processing can republish the original request.
current_payload = None
# Set by handle_sigterm so the processing loop does not clear current_payload
# or republish a second time while the signal handler is exiting.
sigterm_received = False


def republish_message_to_pubsub(
    message_data: dict,
    template_type: str,
    logger: Logger,
    retry_reason: str = "unknown",
) -> bool:
    """
    Republish a failed message back to the same request topic.

    retry_reason distinguishes SIGTERM (spot preemption) from handler failures
    and unexpected exceptions. The original request is published again; this
    does not publish an inventory result snapshot.
    """
    try:
        retry_count = message_data.get("_retry_count", 0)
        max_retries = int(os.environ.get("CDX_MAX_RETRIES", "3"))

        if retry_count >= max_retries:
            logger.debug(
                f"Message exceeded max retries ({max_retries}). Dropping message.",
                extra={
                    "retry_count": retry_count,
                    "max_retries": max_retries,
                    "template_type": template_type,
                    "retry_reason": retry_reason,
                },
            )
            return False

        message_data["_retry_count"] = retry_count + 1

        # `or {}` covers a missing key and an explicit null metadata value.
        message_data["metadata"] = message_data.get("metadata") or {}
        message_data["metadata"]["retryCount"] = message_data["_retry_count"]
        message_data["metadata"]["retryTimestamp"] = time.time()
        message_data["metadata"]["isRetry"] = True
        message_data["metadata"]["retryReason"] = retry_reason

        topic_mapping: dict = {
            CDX_GITHUB_TEMPLATE_TYPE: message_data.get("requestTopic", None),
            CDX_BITBUCKET_TEMPLATE_TYPE: message_data.get("requestTopic", None),
            CDX_GITLAB_TEMPLATE_TYPE: message_data.get("requestTopic", None),
        }

        topic = topic_mapping.get(template_type)
        if not topic:
            logger.debug(
                "No topic mapping found for template type",
                extra={"template_type": template_type, "retry_reason": retry_reason},
            )
            return False

        pubsub_library = PubSubLibrary()
        pubsub_response = pubsub_library.publish(
            os.environ.get("CDX_PROJECT_ID"),
            json.dumps(message_data),
            topic,
        )

        if pubsub_response:
            logger.info(
                "Successfully republished message to PubSub topic",
                extra={
                    "retry_count": message_data["_retry_count"],
                    "template_type": template_type,
                    "topic": topic,
                    "retry_reason": retry_reason,
                },
            )
            return True

        logger.debug(
            "Failed to republish message to PubSub topic",
            extra={
                "retry_count": message_data["_retry_count"],
                "template_type": template_type,
                "topic": topic,
                "retry_reason": retry_reason,
            },
        )
        return False

    except PubSubPublishError as e:
        logger.error(
            "PubSub publish error when republishing message",
            extra={"template_type": template_type, "error": str(e), "retry_reason": retry_reason},
        )
        return False
    except Exception as e:
        logger.error(
            "Unexpected error republishing message",
            extra={"template_type": template_type, "error": str(e), "retry_reason": retry_reason},
        )
        return False


def handle_sigterm(signum, frame):
    """
    Republish the in-flight inventory request and exit.

    The worker acks as soon as it pulls, so Pub/Sub will not redeliver after
    the node is preempted. Publishing the original request back to requestTopic
    lets another job run the same inventory. An empty result snapshot is not
    published.
    """
    global sigterm_received
    sigterm_received = True

    logging.warning("SIGTERM received. Initiating graceful shutdown.")

    if current_payload is None:
        logging.info("SIGTERM received but no in-flight payload found. Nothing to republish.")
        sys.exit(0)

    template_type = current_payload.get("templateType") or ""
    try:
        logger = lgr.get_logger(os.environ.get("CDX_LOG_LEVEL") or "INFO")
        logger.info(
            "SIGTERM received. Republishing in-flight message for retry",
            extra={
                "template_type": template_type,
                "retry_reason": "sigterm",
                "retry_count": current_payload.get("_retry_count", 0) + 1,
            },
        )
        republish_message_to_pubsub(
            current_payload,
            template_type,
            logger,
            retry_reason="sigterm",
        )
    except Exception as ex:
        logging.error(f"SIGTERM republish failed: {ex}")

    sys.exit(0)


def task_processing_handler(subscriber, subscription_path, received_message):
    """
    Ack one pulled message, run the inventory handler, and republish on failure.
    """
    global current_payload
    message = received_message.message
    ack_id = received_message.ack_id

    try:
        logger = lgr.get_logger(os.environ.get("CDX_LOG_LEVEL"))
        logger.info("cartography sync gcp worker request received via PubSub")

        payload: dict = json.loads(message.data)
        template_type = payload.get("templateType")
        logger.debug("Processing message", extra={"template_type": template_type, "ack_id": ack_id})

        template_handlers = {
            CDX_GITHUB_TEMPLATE_TYPE: github_process_request,
            CDX_BITBUCKET_TEMPLATE_TYPE: bitbucket_process_request,
            CDX_GITLAB_TEMPLATE_TYPE: gitlab_process_request,
        }

        if template_type not in template_handlers:
            logger.debug("Invalid Template Type", extra={"template_type": template_type})
            subscriber.acknowledge(
                request={
                    "subscription": subscription_path,
                    "ack_ids": [ack_id],
                },
            )
            return False

        # Keep the request as pulled. Later neo4j injection must not be published.
        original_payload = copy.deepcopy(payload)
        current_payload = original_payload

        subscriber.acknowledge(
            request={
                "subscription": subscription_path,
                "ack_ids": [ack_id],
            },
        )
        logger.debug(
            "Message acknowledged immediately after pull",
            extra={"template_type": template_type, "ack_id": ack_id},
        )

        neo4j_config = payload.get("neo4j", {})

        neo4j_config.setdefault("uri", os.environ["CDX_APP_NEO4J_URI"])
        neo4j_config.setdefault("user", os.environ["CDX_APP_NEO4J_USER"])
        neo4j_config.setdefault("pwd", os.environ["CDX_APP_NEO4J_PWD"])
        neo4j_config.setdefault("connection_lifetime", 200)

        request_data_center = payload.get("dc", "US")
        if request_data_center == "US":
            neo4j_config["uri"] = os.environ["CDX_APP_NEO4J_URI"]
            neo4j_config["user"] = os.environ["CDX_APP_NEO4J_USER"]
            neo4j_config["pwd"] = os.environ["CDX_APP_NEO4J_PWD"]

        elif request_data_center == "IN":
            neo4j_config["uri"] = os.environ["CDX_IN_APP_NEO4J_URI"]
            neo4j_config["user"] = os.environ["CDX_IN_APP_NEO4J_USER"]
            neo4j_config["pwd"] = os.environ["CDX_IN_APP_NEO4J_PWD"]

        else:
            neo4j_config["uri"] = os.environ["CDX_APP_NEO4J_URI"]
            neo4j_config["user"] = os.environ["CDX_APP_NEO4J_USER"]
            neo4j_config["pwd"] = os.environ["CDX_APP_NEO4J_PWD"]

        payload["neo4j"] = neo4j_config

        try:
            response = template_handlers[template_type](logger, payload)
        finally:
            if not sigterm_received:
                current_payload = None

        logger.debug("Processing finished", extra={"template_type": template_type, "response": response})

        if sigterm_received:
            return False

        if response.get("status") == "success":
            logger.debug("Message processed successfully", extra={"template_type": template_type, "response": response})
            return True

        logger.debug("Message processing failed", extra={"template_type": template_type, "response": response})

        republished = republish_message_to_pubsub(
            original_payload,
            template_type,
            logger,
            retry_reason="handler_failure",
        )
        if republished:
            logger.info("Message republished to PubSub successfully", extra={"template_type": template_type})
        else:
            logger.debug("Failed to republish message to PubSub", extra={"template_type": template_type})

        return False

    except Exception as ex:
        logger.error(f"Failed to process message: {ex}")

        if sigterm_received:
            return False

        current_payload = None

        try:
            payload = json.loads(message.data)
            template_type = payload.get("templateType", "NA")

            if republish_message_to_pubsub(payload, template_type, logger, retry_reason="exception"):
                logger.info("Message republished to PubSub after exception")
            else:
                logger.debug("Failed to republish message to PubSub after exception")

        except Exception as republish_ex:
            logger.error(f"Failed to republish message after exception: {republish_ex}")

        return False


def current_config(env):
    return "config/production.json" if env == "PRODUCTION" else "config/default.json"


def fetch_config(service=None):
    with open(current_config(os.environ.get("CDX_APP_ENV", ""))) as f:
        contents = f.read()

    return json.loads(contents).get(service, {}) if service else json.loads(contents)


def process_messages():
    """
    Pull one inventory message, then exit after the minimum runtime.
    """
    try:
        signal.signal(signal.SIGTERM, handle_sigterm)

        scm_provider_type = os.environ.get("CDX_SCM_PROVIDER_TYPE", "")

        config = fetch_config(service=None)

        if scm_provider_type == CDX_GITHUB_SERVICE:
            pubsub_subscription = config.get("common", {}).get("pubsub", {}).get("githubEventsTopicSubscription")

        elif scm_provider_type == CDX_BITBUCKET_SERVICE:
            pubsub_subscription = config.get("common", {}).get("pubsub", {}).get("bitbucketEventsTopicSubscription")

        elif scm_provider_type == CDX_GITLAB_SERVICE:
            pubsub_subscription = config.get("common", {}).get("pubsub", {}).get("gitlabEventsTopicSubscription")

        else:
            logging.debug("Invalid Provider. Exit Processing!")
            sys.exit(1)

        subscriber = pubsub_v1.SubscriberClient()
        subscription_path = subscriber.subscription_path(
            os.environ.get("CDX_PROJECT_ID"),
            pubsub_subscription,
        )

        logging.debug("Job worker starting with below Configuration:")
        logging.debug(f"SCM Provider: {scm_provider_type}")
        logging.debug(f"PubSub Subscription: {pubsub_subscription}")
        logging.debug(f"PubSub Subscription Path: {subscription_path}")

        min_runtime = int(os.environ.get("CDX_MIN_RUNTIME", 60))
        if min_runtime < 60:
            logging.debug("Minimum runtime must be at least 60 seconds. Setting to 60 seconds.")
            min_runtime = 60

        logging.debug(f"Minimum runtime set to: {min_runtime} seconds")

        start_time = time.time()
        processed_message = False

        with subscriber:
            while True:
                if sigterm_received:
                    break

                response = subscriber.pull(
                    request={
                        "subscription": subscription_path,
                        "max_messages": 1,
                    },
                )

                if response.received_messages:
                    received_message = response.received_messages[0]
                    is_message_processed = task_processing_handler(subscriber, subscription_path, received_message)
                    processed_message = True

                    if is_message_processed:
                        logging.debug("Message processed successfully.")

                    else:
                        logging.debug("Message processing failed.")

                    break

                else:
                    logging.debug("No messages available. Waiting...")

                elapsed_time = time.time() - start_time
                if elapsed_time >= min_runtime:
                    if processed_message:
                        logging.debug(f"Minimum runtime ({min_runtime}s) completed with message processed.")
                        break

                    else:
                        logging.debug(f"Minimum runtime ({min_runtime}s) completed with no messages.")
                        break

                if not response.received_messages:
                    time.sleep(10)

        logging.debug("Process Exiting...")
        sys.exit(0)

    except KeyboardInterrupt:
        logging.debug("Worker interrupted by user. Exiting...")
        sys.exit(0)

    except SystemExit:
        logging.debug("Worker exiting...")
        raise

    except NotFound:
        logging.debug("Pub/Sub subscription not found. Exiting...")
        sys.exit(1)

    except Exception as ex:
        logging.debug(f"Worker crashed with exception: {ex}")
        sys.exit(1)


logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
)

if __name__ == "__main__":
    logging.getLogger("root").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("werkzeug").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("google").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("google.auth").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("google.auth._default").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("urllib3").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("urllib3.connectionpool").setLevel(os.environ.get("CDX_LOG_LEVEL"))

    logging.getLogger("cartography").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("cartography.graph").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("cartography.intel").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("cartography.sync").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("cartography.cartography").setLevel(os.environ.get("CDX_LOG_LEVEL"))
    logging.getLogger("cloudconsolelink.clouds").setLevel(os.environ.get("CDX_LOG_LEVEL"))

    logging.debug("GKE Git Cartography Processing Service started...")

    signal.signal(signal.SIGTERM, handle_sigterm)
    process_messages()
