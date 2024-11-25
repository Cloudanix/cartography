# Used by AWS Lambda
import json
import logging
import os
import uuid

import cartography.cli
from libraries.authlibrary import AuthLibrary
from libraries.snslibrary import SNSLibrary
from utils.context import AppContext
from utils.logger import get_logger

lambda_init = None
context = None


def current_config(env):
    return "config/production.json" if env == "PRODUCTION" else "config/default.json"


def set_assume_role_keys(context):
    context.assume_role_access_key_key_id = context.assume_role_access_secret_key_id = os.environ['CDX_APP_ASSUME_ROLE_KMS_KEY_ID']
    context.assume_role_access_key_cipher = os.environ['CDX_APP_ASSUME_ROLE_ACCESS_KEY']
    context.assume_role_access_secret_cipher = os.environ['CDX_APP_ASSUME_ROLE_ACCESS_SECRET']
    context.neo4j_uri = os.environ['CDX_APP_NEO4J_URI']
    context.neo4j_user = os.environ['CDX_APP_NEO4J_USER']
    context.neo4j_pwd = os.environ['CDX_APP_NEO4J_PWD']
    context.neo4j_connection_lifetime = 200


def init_lambda(ctx):
    global lambda_init, context

    context = AppContext(
        region=os.environ['CDX_DEFAULT_REGION'],
        log_level=os.environ['CDX_LOG_LEVEL'],
        app_env=os.environ['CDX_APP_ENV'],
    )
    context.logger = get_logger(context.log_level)

    decrypted_value = ''

    # Read from config files in the project
    with open(current_config(context.app_env)) as f:
        decrypted_value = f.read()

    # Cloudanix AWS AccountID
    context.aws_account_id = ctx.invoked_function_arn.split(":")[4]
    context.parse(decrypted_value)

    set_assume_role_keys(context)

    lambda_init = True


def process_request(context, args):
    context.logger.info(f'request - {args.get("templateType")} - {args.get("sessionString")} - {args.get("eventId")} - {args.get("workspace")}')

    svcs = []
    for svc in args.get('services', []):
        page = svc.get('pagination', {}).get('pageSize')
        if page:
            svc['pagination']['pageSize'] = 10000

        svcs.append(svc)

    creds = get_auth_creds(context, args)
    if args.get("dc", "US") == "IN":
        context.neo4j_uri = os.environ['CDX_IN_APP_NEO4J_URI']
        context.neo4j_user = os.environ['CDX_IN_APP_NEO4J_USER']
        context.neo4j_pwd = os.environ['CDX_IN_APP_NEO4J_PWD']
    body = {
        "credentials": creds,
        "neo4j": {
            "uri": context.neo4j_uri,
            "user": context.neo4j_user,
            "pwd": context.neo4j_pwd,
            "connection_lifetime": context.neo4j_connection_lifetime,
        },
        "logging": {
            "mode": "verbose",
        },
        "params": {
            "sessionString": args.get('sessionString'),
            "eventId": args.get('eventId'),
            "templateType": args.get('templateType'),
            "regions": args.get('regions'),
            "workspace": args.get('workspace'),
            "actions": args.get('actions'),
            "resultTopic": args.get('resultTopic'),
            "requestTopic": args.get("requestTopic"),
            "iamEntitlementRequestTopic": args.get('iamEntitlementRequestTopic'),
            "identityStoreIdentifier": args.get('identityStoreIdentifier'),
            "partial": args.get("partial"),
            "services": args.get("services"),
        },
        "services": svcs,
        "updateTag": args.get("updateTag"),
        "refreshEntitlements": args.get("refreshEntitlements"),
        "identityStoreRegion": args.get("identityStoreRegion"),
        "awsInternalAccounts": args.get("awsInternalAccounts"),
    }

    resp = cartography.cli.run_aws(body)

    if resp.get('status', '') == 'success':
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

        context.logger.info(f'successfully processed cartography: {resp}')

    else:
        context.logger.info(f'failed to process cartography: {resp["message"]}')

    publish_response(context, body, resp, args)

    context.logger.info(f'inventory sync aws response - {args["eventId"]}: {json.dumps(resp)}')


def publish_response(context, body, resp, args):
    if context.app_env != 'PRODUCTION':
        try:
            with open('response.json', 'w') as outfile:
                json.dump(resp, outfile, indent=2)

        except Exception as e:
            context.logger.error(f'Failed to write to file: {e}')

    else:
        payload = {
            "status": resp['status'],
            "params": body['params'],
            "sessionString": body.get('params', {}).get('sessionString'),
            "eventId": body.get('params', {}).get('eventId'),
            "templateType": body.get('params', {}).get('templateType'),
            "workspace": body.get('params', {}).get('workspace'),
            "actions": body.get('params', {}).get('actions'),
            "resultTopic": body.get('params', {}).get('resultTopic'),
            "requestTopic": body.get('params', {}).get('requestTopic'),
            "identityStoreIdentifier": body.get('params', {}).get('identityStoreIdentifier'),
            "partial": body.get('params', {}).get("partial"),
            "externalRoleArn": body.get('externalRoleArn'),
            "externalId": body.get('externalId'),
            "response": resp,
            "services": body.get('params', {}).get("services"),
            "updateTag": resp.get("updateTag", None),
            "iamEntitlementRequestTopic": body.get('params', {}).get('iamEntitlementRequestTopic'),
        }

        sns_helper = SNSLibrary(context)
        # If cartography processing response object contains `services` object that means pagination is in progress. push the message back to the same queue for continuation.
        if resp.get('services', None):
            if body.get('params', {}).get('requestTopic'):
                status = sns_helper.publish(json.dumps(payload), body['params']['requestTopic'])

        elif body.get('params', {}).get('resultTopic'):
            if body.get('params', {}).get('partial'):
                # In case of a partial request processing, result should be pushed to "resultTopic" passed in the request
                status = sns_helper.publish(json.dumps(payload), body['params']['resultTopic'])

            else:
                context.logger.info('Result not published anywhere. since we want to avoid query when inventory is refreshed')

            status = True
            publish_request_iam_entitlement(context, args, body)

        else:
            context.logger.info('publishing results to CDX_CARTOGRAPHY_RESULT_TOPIC')
            status = sns_helper.publish(json.dumps(payload), context.aws_inventory_sync_response_topic)
            publish_request_iam_entitlement(context, args, body)

        context.logger.info(f'result published to SNS with status: {status}')


def publish_request_iam_entitlement(context, req, body):
    if req.get('iamEntitlementRequestTopic'):
        sns_helper = SNSLibrary(context)
        del body['credentials']['expiration']
        req['credentials'] = body['credentials']
        if req.get("loggingAccount"):
            req["loggingAccount"] = get_logging_account_auth_creds(context, req)
        context.logger.info('publishing results to IAM_ENTITLEMENT_REQUEST_TOPIC')
        status = sns_helper.publish(json.dumps(req), req['iamEntitlementRequestTopic'])
        context.logger.info(f'result published to SNS with status: {status}')


def get_auth_creds(context, args):
    auth_helper = AuthLibrary(context)

    if context.app_env == 'PRODUCTION' or context.app_env == 'DEBUG':
        auth_params = {
            'aws_access_key_id': auth_helper.get_assume_role_access_key(),
            'aws_secret_access_key': auth_helper.get_assume_role_access_secret(),
            'role_session_name': args.get('sessionString'),
            'role_arn': args.get('externalRoleArn'),
            'external_id': args.get('externalId'),
        }

        auth_creds = auth_helper.assume_role(auth_params)
        auth_creds['type'] = 'assumerole'
        auth_creds['primary_region'] = args.get("primaryRegion", "us-east-1")

    else:
        auth_creds = {
            'type': 'self',
            'aws_access_key_id': args.get('credentials', {}).get('awsAccessKeyID') if 'credentials' in args else None,
            'aws_secret_access_key': args.get('credentials', {}).get('awsSecretAccessKey') if 'credentials' in args else None,
        }

    return auth_creds


def get_logging_account_auth_creds(context, args):
    auth_helper = AuthLibrary(context)
    aws_access_key_id = auth_helper.get_assume_role_access_key()
    aws_secret_access_key = auth_helper.get_assume_role_access_secret()
    logging_account = args.get("loggingAccount", {})

    if context.app_env == 'PRODUCTION' or context.app_env == 'DEBUG':
        auth_params = {
            'aws_access_key_id': aws_access_key_id,
            'aws_secret_access_key': aws_secret_access_key,
            'role_session_name': str(uuid.uuid4()),
            'role_arn': logging_account.get('awsExternalRoleArn'),
            'external_id': logging_account.get('awsExternalId'),
        }

        auth_creds = auth_helper.assume_role(auth_params)
        auth_creds['type'] = 'assumerole'
        auth_creds['primary_region'] = args.get("primaryRegion", "us-east-1")

    else:
        auth_creds = {
            'type': 'self',
            'aws_access_key_id': args.get('credentials', {}).get('awsAccessKeyID') if 'credentials' in args else None,
            'aws_secret_access_key': args.get('credentials', {}).get('awsSecretAccessKey') if 'credentials' in args else None,
        }

    args["loggingAccount"]["creds"] = auth_creds

    return args.get("loggingAccount", {})


def aws_process_cartography(event, ctx):
    global lambda_init, context
    if not lambda_init:
        init_lambda(ctx)

    logging.getLogger('cartography').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.graph').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.intel').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.sync').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cartography.cartography').setLevel(os.environ.get('CDX_LOG_LEVEL'))
    logging.getLogger('cloudconsolelink.clouds').setLevel(os.environ.get('CDX_LOG_LEVEL'))

    record = event['Records'][0]
    message = record['Sns']['Message']

    try:
        params = json.loads(message)

    except Exception as e:
        context.logger.error(f'error while parsing inventory sync aws request json: {e}', exc_info=True, stack_info=True)

        response = {
            "status": 'failure',
            "message": 'unable to parse request',
        }

        return {
            'statusCode': 200,
            "headers": {
                "Content-Type": "application/json",
            },
            'body': json.dumps(response),
        }

    context.logger.info(f"message: {json.dumps(params)}")

    process_request(context, params)

    return {
        'statusCode': 200,
        "headers": {
            "Content-Type": "application/json",
        },
        'body': json.dumps({
            "status": 'success',
        }),
    }
