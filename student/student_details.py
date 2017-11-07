import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):


    path_params = event['pathParameters']
    body = {
        "msg": "You have access to %s" % path_params['id'],
        "input": event,
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response

