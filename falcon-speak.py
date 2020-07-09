# speak with CS Falcon API
# 2020/7/8, v0.1
# by jowabels - twitter.com/jowabels

import config
import requests
import os, sys
import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate", action="store_true", help="generate oauth token. token is valid for 30 minutes")
    parser.add_argument("-d", "--detections", action="store_true", help="retrieve Falcon detections. Returned data is < 10,000 items", default=False)
    parser.add_argument("-i", "--incidents", action="store_true", help="retrieve Falcon incidents. Returned data is < 500 items", default=False)
    args = parser.parse_args()

    if args.generate:
        print("\n[+] Requesting for oauth token...")
        get_token()
        print("\n")

    elif args.detections:
        print("\n[+] Getting list of Falcon detections...")
        detections_list = get_detections_list()
        print("\n[+] Getting full info on the detection items...")
        get_detections_list_info(detections_list)
        print("\n")

    elif args.incidents:
        print("\n[+] Getting list of Falcon incidents...")
        incidents_list = get_incidents_list()
        print("\n[+] Getting full info on the incident items...")
        get_incidents_list_info(incidents_list)
        print("\n")
        
    else:
        parser.print_help(sys.stderr)






def get_token():
    '''
        provided the API account client ID and secret, we request for a token
        which will be used for subsequent API transactions. token is valid
        for 30 minutes
    '''

    if os.path.exists(config.TOKEN_PATH):
        os.remove(config.TOKEN_PATH)

    endpoint_uri = "{}/oauth2/token".format(config.API_URL)
    data = {
        "client_id" : config.CLIENT_ID,
        "client_secret": config.CLIENT_SECRET
    }

    r = requests.post(endpoint_uri, data=data)
    if r.status_code == 201:
        print("\t-- Successful token request...")
        j = r.json()
        token = j["access_token"]

        with open(config.TOKEN_PATH, "w") as fo:
            fo.write(token)
        print("\t-- Successfully stored token to temporary file...")
        print("\t-- With a valid token, you may now use other script arguments...")
    else:
        unsucessful_http_request(r)


def verify_token(offset=0, limit=1):
    '''
        there seems to be no API endpoint specifically for token verification. we
        will use a crude method by simply making an API request (to a pre-defined endppoint)
        and check if response_code is 403 or not. 403 --> forbidden, authentication failed.
        when token verification fails, a new token is simply generated and stored on the temp token file
    '''
    
    with open(config.TOKEN_PATH, "r") as fo:
        token = fo.read()
    print("\t-- Verifying validity of current token...")
    
    endpoint_uri = "{}/detects/queries/detects/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    params = {
        "offset" : offset,
        "limit" : limit
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    if r.status_code == 403:
        print("\t-- Current token already expired. Requesting new one...")
        get_token()
    elif r.status_code == 200:
        print("\t-- Current token is still valid. Proceeding to API requests...")
    else:
        unsucessful_http_request(r)


def read_token():
    '''
        simply read the temporary token file and return its content
    '''

    if not os.path.exists(config.TOKEN_PATH):
        print("\t-- Temporary token file does not seem to exist. Exiting...")
    else:
        with open(config.TOKEN_PATH, "r") as fo:
            token = fo.read()
        return token


def get_detections_list(offset=0, limit=10):
    '''
        this function returns a list object, containing the IDs of the detection events
        in Falcon. this list of IDs are found in the "resources" key in the JSON
        response of the initial GET request
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/detects/queries/detects/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    params = {
        "offset" : offset,
        "limit" : limit
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    # noting here that params=json.dumps(params) does NOT work, params should be a JSON object
    # this is difference to POST where data should be a string, not a JSON object
    if r.status_code == 200:
        print("\t-- Successful request for detection list...")
        j = r.json()

        if not j["resources"]:
            print("\t-- Unfortunately detections list is empty. No detections! Exiting...")
            sys.exit()

        return j["resources"]
    else:
        unsucessful_http_request(r)


def get_detections_list_info(detections_list):
    '''
        from the list object of detection IDs obtained from get_detections_list, we now
        query a different API endpoint for more info on those detections
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/detects/entities/summaries/GET/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    data = {
        "ids" : detections_list
    }

    r = requests.post(endpoint_uri, headers=headers, data=json.dumps(data))
    # noting here that data=data does NOT work, data should be a string NOT a JSON object
    # this is different to GET where params should be a JSON object
    if r.status_code == 200:
        print("\t-- Successful request for detection information...")
        j = r.json()
        print(json.dumps(j, indent=4))
    else:
        unsucessful_http_request(r)


def get_incidents_list(offset=0, limit=10):
    '''
        similar to get_detections_list, this returns a list object
        of incident IDs. the list of IDs is in the "resources" key in
        JSON response
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/incidents/queries/incidents/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    params = {
        "offset" : offset,
        "limit" : limit
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    if r.status_code == 200:
        print("\t-- Successful request for incident list...")
        j = r.json()

        if not j["resources"]:
            print("\t-- Unfortunately incidents list is empty. No incidents! Exiting...")
            sys.exit()
        
        return j["resources"]
    else:
        unsucessful_http_request(r)


def get_incidents_list_info(incidents_list):
    '''
        from the list of incident IDs returned from get_incidents_list
        we now query again for details about those incidents
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/incidents/entities/incidents/GET/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    data = {
        "ids" : incidents_list
    }

    r = requests.post(endpoint_uri, headers=headers, data=data)
    if r.status_code == 200:
        print("\t-- Successful request for incident information...")
        j = r.json()
        print(json.dumps(j, indent=4))
    else:
        unsucessful_http_request()



def unsucessful_http_request(r):
    '''
        generic error message when an API request fails. this
        usually means the response code (r.status_code) of the request
        is not 200, 201 or 403 (403 is different since it is used for token verification)
    '''

    print("\n[+] Unsuccessful request. Exiting...")
    print("\t-- Response code: {}...".format(r.status_code))
    j = r.json()
    errmsg = j["errors"][0]["message"]
    print("\t-- Error message: {}...".format(errmsg))
    sys.exit()





if __name__ == "__main__":
    main()

