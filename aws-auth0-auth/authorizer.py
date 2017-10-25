"""
Policy Generator.

Validate the given token and create an AWS policy.
"""

import tokenizer
import json
import logging
from argparse import ArgumentParser


def authorize(principalId, token, domain, audience, resource):
    """
    Authorize the given resource for the prinicpal if the token is valid.

    1. Use the given secret, validate the token.
    2. If the token is valid, generate a policy to allow the api to Invoke
       the given resource.
    3. If the token is invalid return null.
    """
    print("Token is: {}".format(token))
    authResponse = {}
    payload = None
    payload = tokenizer.detokenize(token, domain, audience)
    logging.info('Detokenized payload: {}'.format(json.dumps(payload,
                                                             indent=4)))
    if (payload):
        authResponse = generatePolicy("Allow", principalId, resource)
    else:
        authResponse = generatePolicy("Deny", principalId, resource)

    return authResponse


def generatePolicy(effect, principalId, resource):
    """Generate a policy based on input."""
    authResponse = {}
    authResponse['principalId'] = principalId
    statementOne = {'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource}
    policyDocument = {'Version': '2012-10-17', 'Statement': [statementOne]}
    authResponse['policyDocument'] = policyDocument
    authResponse['context'] = {'policyGenerator': 'authorizer.authorize'}
    return authResponse


def getArgs():
    """Get the arguments passed from the command line."""
    parser = ArgumentParser(description='Given principal, token, \
                                         secret and resource, generate a AWS \
                                         policy to invoke lambda if the token \
                                         is valid.')
    parser.add_argument('-p', '--principal', required=True)
    parser.add_argument('-s', '--secret', required=True)
    parser.add_argument('-t', '--token', required=True)
    parser.add_argument('-r', '--resource', required=True)
    return parser.parse_args()


def main():
    """Use this when called through command line."""
    args = getArgs()
    logging.basicConfig(level=logging.DEBUG)
    response = authorize(args.principal,
                         args.token,
                         args.secret,
                         args.resource)
    print(json.dumps(response, indent=4, sort_keys=True))


if __name__ == '__main__':
    main()
