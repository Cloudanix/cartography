import datetime
import json
import logging
import os
import uuid
from typing import Dict

import azure.functions as func

import cartography.cli
from libraries.eventgridlibrary import EventGridLibrary

logger = logging.getLogger(__name__)


def process_request(msg: Dict):
    logger.info(f'{msg["templateType"]} request received - {msg["eventId"]} - {msg["workspace"]}')

    svcs = []
    for svc in msg.get('services', []):
        page = svc.get('pagination', {}).get('pageSize')
        if page:
            svc['pagination']['pageSize'] = 50000

        svcs.append(svc)

    body = {
        "azure": {
            "client_id": os.environ.get('CDX_AZURE_CLIENT_ID'),
            "client_secret": os.environ.get('CDX_AZURE_CLIENT_SECRET'),
            "redirect_uri": os.environ.get('CDX_AZURE_REDIRECT_URI'),
            "subscription_id": msg.get('workspace', {}).get('account_id'),
            "tenant_id": msg.get('tenantId'),
            "refresh_token": msg.get('refreshToken'),
            "graph_scope": os.environ.get('CDX_AZURE_GRAPH_SCOPE'),
            "azure_scope": os.environ.get('CDX_AZURE_AZURE_SCOPE'),
            "default_graph_scope": os.environ.get('CDX_AZURE_DEFAULT_GRAPH_SCOPE'),
            "vault_scope": os.environ.get('CDX_AZURE_KEY_VAULT_SCOPE'),
        },
        "neo4j": {
            "uri": os.environ['CDX_APP_NEO4J_URI'],
            "user": os.environ['CDX_APP_NEO4J_USER'],
            "pwd": os.environ['CDX_APP_NEO4J_PWD'],
            "connection_lifetime": 200,
        },
        "logging": {
            "mode": "verbose",
        },
        "params": {
            "sessionString": msg.get('sessionString'),
            "eventId": msg.get('eventId'),
            "templateType": msg.get('templateType'),
            "workspace": msg.get('workspace'),
            "groups": msg.get('groups'),
            "subscriptions": msg.get('subscriptions'),
            "actions": msg.get('actions'),
            "resultTopic": msg.get('resultTopic'),
            "requestTopic": msg.get('requestTopic'),
            "partial": msg.get('partial'),
            "services": msg.get('services'),
        },
        "services": svcs,
        "updateTag": msg.get('updateTag'),
    }

    resp = cartography.cli.run_azure(body)

    if 'status' in resp and resp['status'] == 'success':
        if resp.get('pagination', None):
            services = []
            for service, pagination in resp.get('pagination', {}).items():
                if pagination.get('hasNextPage', False):
                    services.append({
                        "name": service,
                        "pagination": {
                            "pageSize": pagination.get('pageSize', 1),
                            "pageNo": pagination.get('pageNo', 0) + 1,
                        },
                    })
            if len(services) > 0:
                resp['services'] = services
            else:
                del resp['updateTag']
            del resp['pagination']

        logger.info(f'successfully processed cartography: {resp}')

    return resp


def main(event: func.EventGridEvent, outputEvent: func.Out[func.EventGridOutputEvent]):
    logger.info('worker request received via EventGrid')

    logging.getLogger('cartography').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.graph').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.intel').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.sync').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.cartography').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cloudconsolelink.clouds').setLevel(os.environ.get('CDX_LOG_LEVEL'))

    try:
        msg = event.get_json()

        logger.info(f'request: {msg}')

        resp = process_request(msg)

        if resp.get('status') == 'success':
            logger.info(f'successfully processed cartography: {msg["eventId"]} - {json.dumps(resp)}')

        else:
            logger.info(f'failed to process cartography: {msg["eventId"]} - {resp["message"]}')

        message = {
            "status": resp.get('status'),
            "params": msg.get('params'),
            "sessionString": msg.get('sessionString'),
            "eventId": msg.get('eventId'),
            "templateType": msg.get('templateType'),
            "workspace": msg.get('workspace'),
            "groups": msg.get('groups'),
            "subscriptions": msg.get('subscriptions'),
            "actions": msg.get('actions'),
            "resultTopic": msg.get('resultTopic'),
            "requestTopic": msg.get('requestTopic'),
            "partial": msg.get('partial'),
            "response": resp,
            "services": resp.get("services", None),
            "updateTag": resp.get("updateTag", None),
        }

        # If cartography processing response object contains `services` object that means pagination is in progress. push the message back to the same queue for continuation.
        if resp.get('services', None):
            if message.get('requestTopic'):
                # Result should be pushed to "requestTopic" passed in the request

                # Push message to Cartography Queue, if refresh is needed
                topic = os.environ.get('CDX_AZURE_CARTOGRAPHY_REQUEST_TOPIC')
                access_key = os.environ.get('CDX_AZURE_CARTOGRAPHY_REQUEST_TOPIC_ACCESS_KEY')

                lib = EventGridLibrary(topic, access_key)
                resp = lib.publish_event(message)

        elif message.get('resultTopic'):
            if message.get('partial'):
                topic = message['resultTopic']
                access_key = msg['resultTopicAccessKey']

                lib = EventGridLibrary(topic, access_key)
                resp = lib.publish_event(message)

            else:
                logger.info('Result not published anywhere. since we want to avoid query when inventory is refreshed')

        else:
            logger.info('publishing results to CDX_CARTOGRAPHY_RESULT_TOPIC')
            outputEvent.set(
                func.EventGridOutputEvent(
                    id=str(uuid.uuid4()),
                    data=message,
                    subject="cartography-response",
                    event_type="inventory",
                    event_time=datetime.datetime.now(datetime.timezone.utc),
                    data_version="1.0",
                ),
            )

        logger.info(f'worker processed successfully: {msg["eventId"]}')

    except Exception as ex:
        logger.error(f"failed to process request from event grid: {ex}", exc_info=True, stack_info=True)
