"""Simple helloWorld service."""
import json


def sayHello(event, context):
    """Return a message in the response body."""
    print('Event is: {}'.format(json.dumps(event)))
    body = {
        "message": "Hello! Your Auth0 authorized function executed successfully!"
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response

    # Use this code if you don't use the http event with the LAMBDA-PROXY
    # integration
    """
    return {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "event": event
    }
    """
