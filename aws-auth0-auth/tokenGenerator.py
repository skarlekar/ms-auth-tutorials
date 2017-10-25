"""Lambda used for generating a JWT token from the given request body."""
import json
import tokenizer
import os


def generateToken(event, context):
    """Generate a token using the API key as secret and return it."""
    print('Event is: {}'.format(json.dumps(event)))
    try:
        myDomain = os.environ['AUTH_DOMAIN']
        myClientId = os.environ['AUTH_CLIENT_ID']
        myClientSecret = os.environ['AUTH_CLIENT_SECRET']
        myAudience = os.environ['AUTH_AUDIENCE']
        token = tokenizer.tokenize(myDomain,
                                   myClientId,
                                   myClientSecret,
                                   myAudience)
    except KeyError:
        token = {}
    response = {
        "statusCode": 200,
        "body": token
    }
    print('Response is: {}'.format(json.dumps(response, indent=4)))
    return response
