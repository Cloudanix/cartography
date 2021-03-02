import datetime
import json
import logging
import time

import azure.functions as func


def main(req: func.HttpRequest, outputEvent: func.Out[func.EventGridOutputEvent]) -> func.HttpResponse:
    logging.info('Cartography listener request received via HTTP Request')

    message = None
    try:
        message = req.get_json()

    except Exception as e:
        logging.info(f'failed to parse request body: {str(e)}')

        response = {
            "status": "failure",
            "message": "failed to read request body"
        }

        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json"
        )

    # logging.info(f'request: {message}')

    response = None
    try:
        outputEvent.set(
            func.EventGridOutputEvent(
                id=time.time(),
                data=message,
                subject="cartography-request",
                event_type="inventory",
                event_time=datetime.datetime.utcnow(),
                data_version="1.0"))

        response = {
            "status": "success",
            "message": "successfully published message to event grid"
        }

    except Exception as e:
        logging.info(f'error while generating event grid message: {str(e)}')

        response = {
            "status": "failure",
            "message": "failed to publish message to event grid"
        }

    return func.HttpResponse(
        json.dumps(response),
        mimetype="application/json"
    )
