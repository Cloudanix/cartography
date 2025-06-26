# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html
# https://github.com/awsdocs/aws-doc-sdk-examples/tree/master/python/example_code/sqs
import json
import os
import uuid

from boto3.session import Session
from botocore.exceptions import ClientError

from utils.errors import classify_error


class SQSLibrary:
    def __init__(self, context):
        self.context = context

        # Create a Session with the credentials passed
        session = Session()

        self.sqs_client = session.client('sqs', region_name=self.context.region)
        self.aws_cartography_queue_url = context.aws_cartography_queue_url

    def fetch_messages(self, no_of_messages: int = 1, wait_time: int = 10, visibility_timeout: int = 300) -> list[dict]:
        response = self.sqs_client.receive_message(
            QueueUrl=self.aws_cartography_queue_url,
            MaxNumberOfMessages=no_of_messages,  # Pull one message at a time
            WaitTimeSeconds=wait_time,     # Long polling
            VisibilityTimeout=visibility_timeout,    # Ensure message isn't available to other subscribers value is in seconds , I have also configured visibilityTimeout=4600 which will be default and the value given in receive_message will override the default value.
        )
        return response.get('Messages', [])

    def delete_message(self, message_receipt_handle: str) -> bool:
        try:
            self.sqs_client.delete_message(QueueUrl=self.aws_cartography_queue_url, ReceiptHandle=message_receipt_handle)

            return True

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')

            if error_code == "InvalidParameterValue":
                self.context.logger.debug('InvalidParameterValue - Failed to delete message in SQS', exc_info=True, stack_info=True, extra={"message_receipt_handle": message_receipt_handle, "error": str(e)})

            elif 'The receipt handle has expired' in error_message:
                self.context.logger.debug(f"The message receipt handle has expired - {e}")

            else:
                self.context.logger.error('Failed to delete message in SQS', exc_info=True, stack_info=True, extra={"message_receipt_handle": message_receipt_handle, "error": str(e)})

        return False

    def change_message_visibility(self, message_receipt_handle: str, duration: int) -> bool:
        try:
            self.sqs_client.change_message_visibility(QueueUrl=self.aws_cartography_queue_url, ReceiptHandle=message_receipt_handle, VisibilityTimeout=duration)

            return True

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')

            if error_code == "InvalidParameterValue":
                self.context.logger.debug('InvalidParameterValue - Failed to extend visibility timeout for message in SQS', exc_info=True, stack_info=True, extra={"message_receipt_handle": message_receipt_handle, "timeout": duration, "error": str(e)})

            elif 'The receipt handle has expired' in error_message:
                self.context.logger.debug(f"The message receipt handle has expired - {e}")

            elif 'Value for parameter VisibilityTimeout is invalid' in error_message:
                # Adjust visibility timeout if it's out of bounds (0-43200)
                visibility_timeout = min(max(0, duration), 43200)
                self.context.logger.debug(f"Adjusted visibility timeout to: {visibility_timeout} - {e}")

            else:
                # INFO: ignore this error as the message might have been processed by another worker already
                self.context.logger.debug('Failed to extend visibility timeout for message in SQS', extra={"message_receipt_handle": message_receipt_handle, "timeout": duration, "error": str(e)})

            return False

    def publish(self, message: dict, topic: str, attributes: dict = {}) -> bool:
        self.logger.debug(f"attributes: {attributes}")

        if os.environ.get("LOCAL_RUN", "0") == "1":
            self.logger.debug(json.dumps(message))
            return True

        try:
            custom_attributes = {
                "accountString": {
                    "DataType": "String",
                    "StringValue": attributes.get("account_string"),
                },
            }

            # Send message to the SQS queue
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/send_message.html
            response = self.sqs_client.send_message(
                QueueUrl=self.context.cartography_queue_url,
                MessageBody=json.dumps(message),
                MessageGroupId=str(uuid.uuid4()),  # Each message gets a unique group_id as we need to process all messages in parallel
                MessageAttributes=custom_attributes,
            )

            self.context.logger.info("Message published successfully to SQS Queue", extra={"message": json.dumps(message), "topic": topic, "attributes": attributes})

            if response.get('MessageId'):
                return True

            else:
                return False

        except ClientError as e:
            raise classify_error(
                self.context.logger,
                e,
                "Failed to publish message",
                {"topic": topic, "message": message},
            )
