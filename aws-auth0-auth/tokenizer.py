"""JWT Tokenizer and Detokenizer."""
from jose import jwt
from jose.exceptions import ExpiredSignatureError
from jose.exceptions import JWSAlgorithmError
from jose.exceptions import JWTClaimsError
import json
import requests
from argparse import ArgumentParser

ALGORITHMS = ["RS256"]


# Error handler
class AuthError(Exception):
    """Authentication Error Handler."""

    def __init__(self, error, status_code):
        """Constructor."""
        self.error = error
        self.status_code = status_code


def tokenize(domain, clientId, clientSecret, audience):
    """Get JWT from Auth0.

    Given a domain, clientId, clientSecret & audience, call Auth0 to get
    a token of type client_credentials granted.
    """
    url = 'https://' + domain + '/oauth/token'
    payload = {
        "client_id": clientId,
        "client_secret": clientSecret,
        "audience": audience,
        "grant_type": "client_credentials"
    }
    print("Url: {}".format(url))
    # print("Payload: {}".format(json.dumps(payload)))
    response = requests.post(url, json=payload)
    responseCode = response.status_code
    responseHeader = response.headers
    responseText = response.text
    print ("Response code: '{}'".format(responseCode))
    print ("Response header: {}".format(responseHeader))
    # print("Response Text: {}".format(json.dumps(responseText)))
    return responseText


def detokenize(token, domain, audience):
    """Use to decode JWT tokens into JSON.

    Given a JWT token, domain and audience detokenize using Auth0.
    """
    payload = None
    url = "https://" + domain + "/.well-known/jwks.json"
    response = requests.get(url, params=None)
    jwks = response.json()
    unverifiedHeader = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverifiedHeader["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        print("RSA Key: {}".format(json.dumps(rsa_key, indent=4)))
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=audience,
                issuer="https://"+domain+"/"
            )
        except ExpiredSignatureError:
            print("ExpiredSignatureError")
            # raise AuthError({"code": "token_expired",
            #                 "description": "token is expired"}, 401)
        except JWTClaimsError:
            print("JWTClaimsError")
            # raise AuthError({"code": "invalid_claims",
            #                 "description":
            #                  "incorrect claims,"
            #                  "please check the audience and issuer"}, 401)
        except JWSAlgorithmError:
            print("InvalidAlgorithmError")
            # raise AuthError({"code": "invalid_algorithm",
            #                 "description": "Invalid Algorithm"}, 401)
        except Exception as e:
            print("Error: ")
            print (e)
            # raise AuthError({"code": "invalid_header",
            #                 "description": e.message}, 400)
    return payload


def getArgs():
    """Get the arguments passed from the command line."""
    parser = ArgumentParser(description='Tokenize or detokenize given a \
                                         payload or JWT and secret key')

    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-ci', '--clientId', required=False)
    parser.add_argument('-cs', '--clientSecret', required=False)
    parser.add_argument('-a', '--audience', required=True)
    parser.add_argument('-t', '--token', required=False)
    parser.add_argument('-o', '--operation', required=True,
                        choices=['tok', 'detok'])
    return parser.parse_args()


def main():
    """Use this when called through command line."""
    args = getArgs()
    noOp = True
    if (args.operation == 'tok'):
        if (args.clientId and args.clientSecret):
            token = tokenize(args.domain,
                             args.clientId,
                             args.clientSecret,
                             args.audience)
            print("Token: {}".format(json.dumps(json.loads(token),
                                                indent=4, sort_keys=True)))
        else:
            print("Pass client_id & client_secret for tokenization")
        noOp = False

    if (args.operation == 'detok'):
        noOp = False
        if (args.token):
            print("Detokenizing...")
            payload = detokenize(args.token, args.domain, args.audience)
            print("Payload is: {}".format(payload))
        else:
            print("Pass a token to detokenize")
    if (noOp):
        print("Operation should be tok or detok")


if __name__ == '__main__':
    main()
