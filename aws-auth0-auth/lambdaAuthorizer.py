"""Lambda used for authorizing calls to other protected Lambdas."""
import json
import authorizer
import os


def authorize(event, context):
    """Generate a token and return it."""
    print('Event is: {}'.format(json.dumps(event)))
    authorizationToken = event['authorizationToken']
    resource = event['methodArn']
    myDomain = os.environ['AUTH_DOMAIN']
    myAudience = os.environ['AUTH_AUDIENCE']
    policy = authorizer.authorize('user',
                                  authorizationToken,
                                  myDomain,
                                  myAudience,
                                  resource)
    print('Policy is: {}'.format(json.dumps(policy, indent=4)))
    return policy
