'''
    speak with CS Falcon API
    by @jowabels
    v0.2
'''

'''
    some lessons learned:
        - data in data=data, should be a JSON string. otherwise, it won't work
        - params in params=params, should be a JSON object. otherwise, it won't work
        - again, data and params are both JSON but the difference is the type. one is a string, other is an object
        - the API queries searches ALL events. for example, exact search for a hostanme may return multiple items if there other events for that hostname, such as detection events
        - due to previous statement, it is possible for an item search to return multiple IDs
        - choices parameter in argparse allow choices for each argument
'''

import os, sys
import argparse
import json

import config
import requests
import prettytable


LIMIT = 10 # limit of number of query items to return
OFFSET = 0 # start getting query items to return from this offset in endpoint list




def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-g", "--generate", action="store_true", help="generate oauth token. token is valid for 30 minutes")
    parser.add_argument("-d", "--detections", action="store", choices=["default", "all"], help="retrieve {default/all} Falcon detections. default only returns detections that are NEW, IN_PROGRESS or TRUE_POSITIVE", type=str)
    parser.add_argument("-i", "--incidents", action="store", choices=["default", "all"], help="retrieve {default/all} Falcon incidents. default only returns incidents that are NEW, IN_PROGRESS or TRUE_POSITIVE", type=str)
    parser.add_argument("-b", "--behaviors", action="store_true", help="retrieve Falcon behaviors. Returned data is < 500 items", default=False)
    parser.add_argument("-hn", "--hostname", action="store", help="retrieve info from Falcon on specified hostname", type=str)
    args = parser.parse_args()

    if args.generate:
        print("\n[+] Requesting for oAuth token...")
        get_token()
        print_token()
        print("\n")

    elif args.detections:
        if args.detections.lower() == "all":
            filter_option = ""
        elif args.detections.lower() == "default":
            filter_option = "status:'new', status:'in_progress', status:'true_positive'"

        print("\n[+] Getting list of Falcon [{}] detections...".format(args.detections.lower()))
        detections_list = get_detections_list(filter_option)
        print("\n[+] Getting full info on the detection items...")
        get_detections_list_info(detections_list)
        print("\n")

    elif args.incidents:
        if args.incidents.lower() == "all":
            filter_option = ""
        elif args.incidents.lower() == "default":
            filter_option = "status:'new', status:'in_progress', status:'true_positive'"

        print("\n[+] Getting list of Falcon [{}] incidents...".format(args.incidents.lower()))
        incidents_list = get_incidents_list(filter_option)
        print("\n[+] Getting full info on the incident items...")
        get_incidents_list_info(incidents_list)
        print("\n")

    elif args.behaviors:
        print("\n[+] Getting list of Falcon behaviors...")
        behaviors_list = get_behaviors_list()
        print("\n[+] Getting details for those behavior items...")
        get_behaviors_list_info(behaviors_list)
        print("\n")

    elif args.hostname:
        hostname = args.hostname
        print("\n[+] Searching for {} in Falcon...".format(hostname))
        devices_list = get_devices_list(hostname)
        print("\n[+] Getting device details for {}...".format(hostname))
        get_devices_list_info(devices_list)
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


def print_token():
    '''
        simply print out the contents of TOKEN.TEMP. this is to simply
        differentiate the -g/--generate argument
    '''
    
    if os.path.exists(config.TOKEN_PATH):
        with open(config.TOKEN_PATH, "r") as fo:
            print("\t-- Generated token: ")
            print(fo.read())
        


def verify_token(offset=OFFSET, limit=LIMIT):
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


def get_detections_list(filter_option, offset=OFFSET, limit=LIMIT):
    '''
        this function returns a list object, containing the IDs of the detection events
        in Falcon. this list of IDs are found in the 'resources' key in the JSON
        response of the initial GET request

        through filter params and FQL, we only return detections that are tagged
        as NEW, IN_PROGRESS or TRUE_POSITIVE. returned items are sorted for last observed event first
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
        "limit" : limit,
        "sort" : "last_behavior|desc",
        "filter" : filter_option
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    if r.status_code == 200:
        print("\t-- Successful request for detection list...")
        j = r.json()

        if not j["resources"]:
            print("\t-- Detections list is empty! No detections that are NEW, IN_PROGRESS or TRUE_POSITIVE. Exiting...")
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
    if r.status_code == 200:
        print("\t-- Successful request for detection information...")
        j = r.json()
        
        # start looping through the returned list of devices and details, and prettytable print them
        table = prettytable.PrettyTable()
        table.field_names = ["Detection ID", "Detection Technique", "Detected Command", "Filename", "Parent Command", "Last Observed", "Hostname"]
        for i in j["resources"]:
            table.add_row([i["detection_id"], i["behaviors"][0]["technique"], i["behaviors"][0]["cmdline"], i["behaviors"][0]["filename"], i["behaviors"][0]["parent_details"]["parent_cmdline"], i["last_behavior"], i["device"]["hostname"]])

        print("\n")
        print(table)

    else:
        unsucessful_http_request(r)


def get_incidents_list(filter_option, offset=OFFSET, limit=LIMIT):
    '''
        similar to get_detections_list, this returns a list object
        of incident IDs. the list of IDs is in the 'resources' key in
        JSON response

        through filter params and FQL, we only return incidents that are tagged
        as NEW, IN_PROGRESS or TRUE_POSITIVE. returned items are sorted for last observed event first
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
        "limit" : limit,
        "sort" : "last_behavior|desc",
        "filter" : filter_option
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
        unsucessful_http_request(r)


def get_behaviors_list(offset=OFFSET, limit=LIMIT):
    '''
        generic request to query behaviors. similar
        to others, we need the behaviors_list found in the 'resources'
        key in the JSON response
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/incidents/queries/behaviors/v1".format(config.API_URL)
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
        print("\t-- Successful request for behaviors list...")
        j = r.json()

        if not j["resources"]:
            print("\t-- Unfortunately behaviors list is empty. Exiting...")
            sys.exit()
        
        return j["resources"]
    else:
        unsucessful_http_request(r)


def get_behaviors_list_info(behaviors_list):
    '''
        from the list object of detection IDs obtained from get_behaviors_list, we now
        query a different API endpoint for more info on those detections
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/incidents/entities/behaviors/GET/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    data = {
        "ids" : behaviors_list
    }

    r = requests.post(endpoint_uri, headers=headers, data=json.dumps(data))
    if r.status_code == 200:
        print("\t-- Successful request for behaviors information...")
        j = r.json()
        print(json.dumps(j, indent=4))
    else:
        unsucessful_http_request(r)


def get_devices_list(hostname, offset=OFFSET, limit=LIMIT):
    '''
        using the input hostname, we query the host API
        endpoint by using that hostname in an FQL in params.
        query is not an exact matching but rather a LIKE/SIMILAR
        match

        devices that match the input can be found in the 'resources'
        key in the JSON response
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/devices/queries/devices/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    params = {
        "offset" : offset,
        "limit" : limit,
        "filter" : "hostname:'{}'".format(hostname)
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    if r.status_code == 200:
        print("\t-- Successful request for devices list...")
        j = r.json()

        if not j["resources"]:
            print("\t-- Unfortunately devices list is empty. No devices found! Exiting...")
            sys.exit()
        
        return j["resources"]
    else:
        unsucessful_http_request(r)


def get_devices_list_info(devices_list):
    '''
        from the list object of device IDs obtained from get_devices_list, we now
        query a different API endpoint for more info on those devices. note
        that this is different since it is a GET request, unlike other "get more info"
        functions that use a POST request
    '''

    verify_token()
    token = read_token()

    endpoint_uri = "{}/devices/entities/devices/v1".format(config.API_URL)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    params = {
        "ids" : devices_list
    }

    r = requests.get(endpoint_uri, headers=headers, params=params)
    # note here that this "get more info" function uses a GET instead of POST, unlike the others
    if r.status_code == 200:
        print("\t-- Successful request for devices information...")
        j = r.json()

        # start looping through the returned list of devices and details, and prettytable print them
        table = prettytable.PrettyTable()
        table.field_names = ["Device ID", "Hostname", "OS Version", "External IP", "Last Seen", "Product Name"]
        for d in j["resources"]:
            table.add_row([d["device_id"], d["hostname"], d["os_version"], d["external_ip"], d["last_seen"], d["system_product_name"]])

        print("\n")
        print(table)

    else:
        unsucessful_http_request(r)







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

