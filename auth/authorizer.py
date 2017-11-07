import jwt
import logging
from auth_utils import AuthPolicy, HttpVerb

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):

    logger.info("Calling Authorizer")
    # first make sure that we have the token
    token = event.get("authorizationToken", None)

    logger.info("Token %s" % token)
    if token is None:
        # at any point we can just do this.
        raise Exception("Unauthorized1")

    # pull some things that help us set up the policy from the request ARN
    method_arn = event['methodArn'].split(':')
    api_gateway_arn = method_arn[5].split('/')
    aws_account_id = method_arn[4]

    try:
        decoded_token = jwt.decode(token, "a_super_secret_key", algorithms=['HS256'])
    except Exception as e:
        # we can deny access to the resources here. Exceptions can tell us more about why we could
        # not decode the token
        # https://pyjwt.readthedocs.io/en/latest/api.html#exceptions
        logger.info("Except %s" % str(e))

        raise Exception("Unauthorized2")


    # get a unique id for the user from the token (I guess)
    user_id = decoded_token.get('user_id', None)

    # this warrants a bit more looking into
    policy = AuthPolicy(user_id, aws_account_id)
    policy.restApiId = api_gateway_arn[0]
    policy.region = method_arn[3]
    policy.state = api_gateway_arn[1]

    # now we build the auth policy that defines the api endpoints that the user has access to based on the
    # provided JWT
    students = decoded_token.get('student_read', None)

    if students is not None:
        for s in students:
            policy.allowMethod(HttpVerb.GET, "student/%s" % str(s))

    response = policy.build()
    logger.info("%s" % response)
    return response

