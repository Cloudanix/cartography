# https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-storage-queue-trigger?tabs=python-v1%2Cisolated-process%2Cnodejs-v4%2Cextensionv5&pivots=programming-language-python
import json
import logging

from azure.storage.queue import BinaryBase64DecodePolicy
from azure.storage.queue import BinaryBase64EncodePolicy
from azure.storage.queue import QueueClient


logger = logging.getLogger(__name__)


class StorageQueueLibrary:
    def __init__(self, connection_string, queue):
        self.connection_string = connection_string
        self.queue = queue

    def publish_event(self, message):

        # authenticate client
        queue_client = QueueClient.from_connection_string(
            conn_str=self.connection_string,
            queue_name=self.queue,
            message_encode_policy=BinaryBase64EncodePolicy(),
            message_decode_policy=BinaryBase64DecodePolicy(),
        )

        try:
            # Add message to the queue
            queue_client.send_message(content=json.dumps(message).encode("utf-8"), time_to_live=43200)

            return {
                "status": "success",
                "message": f"successfully published message to {self.queue}",
            }

        except Exception as e:
            logger.error(f"error while publishing message to queue: {e}", exc_info=True, stack_info=True)

            return {
                "status": "failure",
                "message": "failed to publish message to queue",
            }
