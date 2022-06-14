# Used by GCP Functions

import base64
import json
import os
import logging

import cartography.cli
from libraries.pubsublibrary import PubSubLibrary
from utils.errors import PubSubPublishError
import utils.logger as lgr

# Used by GCP Functions


def cartography_worker(event, ctx):
    logging.getLogger('cartography').setLevel(os.environ.get('LOG_LEVEL'))
    # logging.getLogger('cartography.intel').setLevel(os.environ.get('LOG_LEVEL'))
    logging.getLogger('cartography.sync').setLevel(os.environ.get('LOG_LEVEL'))
    logging.getLogger('cartography.graph').setLevel(os.environ.get('LOG_LEVEL'))
    logging.getLogger('cartography.cartography').setLevel(os.environ.get('LOG_LEVEL'))

    logger = lgr.get_logger("DEBUG")
    logger.info('inventory sync gcp worker request received via PubSub')

    if 'data' in event:
        message = base64.b64decode(event['data']).decode('utf-8')

    else:
        logger.info('invalid message format in PubSub')
        return {
            "status": 'failure',
            "message": 'unable to parse PubSub message',
        }

    logger.info(f'message from PubSub: {message}')

    try:
        params = json.loads(message)

    except Exception as e:
        logger.error(f'error while parsing request json: {e}')
        return {
            "status": 'failure',
            "message": 'unable to parse request',
        }

    process_request(logger, params)

    return {
        'statusCode': 200,
        'body': json.dumps({
            "status": 'success',
        }),
    }


def process_request(logger, params):
    logger.info(f'{params["templateType"]} request received - {params["eventId"]}')
    logger.info(f'workspace - {params["workspace"]}')

    body = {
        "credentials": {
            'account_email': params['accountEmail'],
            'token_uri': os.environ['CLOUDANIX_TOKEN_URI'],
        },
        "neo4j": {
            "uri": os.environ.get('neo4juri'),
            "user": os.environ.get('neo4juser'),
            "pwd": os.environ.get('neo4jpwd'),
            "connection_lifetime": 3600,
        },
        "logging": {
            "mode": "verbose",
        },
        "params": {
            "sessionString": params['sessionString'],
            "eventId": params['eventId'],
            "templateType": params['templateType'],
            "workspace": params['workspace'],
            "actions": params['actions'],
            "resultTopic": params.get('resultTopic'),
        },
    }

    resp = cartography.cli.run_gcp(body)

    if 'status' in resp and resp['status'] == 'success':
        if resp.get('pagination', None):
            services = []
            for service, pagination in resp.get('pagination', {}).items():
                if pagination.get('hasNextPage', False):
                    services.append({
                        "name": service,
                        "pagination": {
                            "pageSize": pagination.get('pageSize', 1),
                            "pageNo": pagination.get('pageNo', 0) + 1
                        }
                    })
            if len(services) > 0:
                resp['services'] = services
            else:
                del resp['updateTag']
            del resp['pagination']
        logger.info(f'successfully processed cartography: {resp}')

    else:
        logger.info(f'failed to process cartography: {resp["message"]}')

    publish_response(logger, body, resp)

    logger.info(f'inventory sync gcp response - {params["eventId"]}: {json.dumps(resp)}')


def publish_response(logger, req, resp):
    body = {
        "status": resp['status'],
        "params": req['params'],
        "sessionString": req['params']['sessionString'],
        "eventId": req['params']['eventId'],
        "templateType": req['params']['templateType'],
        "workspace": req['params']['workspace'],
        "actions": req['params']['actions'],
        "response": resp,
        "services": resp.get("services", None),
        "updatetag": resp.get("updatetag", None),
    }

    pubsub_helper = PubSubLibrary()

    try:
        if body.get('services', None):
            if 'requestTopic' in req['params']:
                # Result should be pushed to "requestTopic" passed in the request
                status = pubsub_helper.publish(
                    os.environ['CLOUDANIX_PROJECT_ID'], json.dumps(body), req['params']['requestTopic'],
                )

        elif 'resultTopic' in req['params']:
            # Result should be pushed to "resultTopic" passed in the request
            # status = pubsub_helper.publish(
            #     os.environ['CLOUDANIX_PROJECT_ID'], json.dumps(body), req['params']['resultTopic'],
            # )

            logger.info(f'Result not published anywhere. since we want to avoid query when inventory is refreshed')
            status = True

        else:
            status = pubsub_helper.publish(
                os.environ['CLOUDANIX_PROJECT_ID'], json.dumps(body), os.environ['CARTOGRAPHY_RESULT_TOPIC'],
            )

        logger.info(f'result published to PubSub with status: {status}')

    except PubSubPublishError as e:
        logger.error(f'Failed while publishing response to PubSub: {str(e)}')
