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
    parser.add_argument("-g", "--generate", action="store_true", help="generate oauth token. token lasts for 30 minutes")
    parser.add_argument("-t", "--token", type=str, help="provide the previously generated ouath token")
    parser.add_argument("-d", "--detections",action="store_true", help="retrieve Falcon detections. Returned data is < 10,000 items", default=False)
    args = parser.parse_args()

    if args.generate:
        print("\n[+] Requesting for oauth token...")
        token = getOauthToken(config.API_URL, config.CLIENT_ID, config.CLIENT_SECRET)
        print("[+] My token: {}".format(token))
    elif args.token:
        if not args.detections:
            print("\n[+] -d/--detections argument is required, of course that token should be used for something. Exiting...")
            sys.exit()
        else:
            print("\n[+] Getting list of Falcon detections...")
            detectionids = getListOfDetections(config.API_URL, args.token)
            print("\n[+] Getting full info on the detection items...")
            getDetectionInfo(config.API_URL, args.token, detectionids)
    else:
        parser.print_help(sys.stderr)


def getOauthToken(apiurl, clientid, clientsecret):
    endpoint = "{}/oauth2/token".format(apiurl)
    data = {
        "client_id" : clientid,
        "client_secret": clientsecret
    }

    r = requests.post(endpoint, data=data)
    if r.status_code == 201:
        print("[+] Successful token request...")
        j = r.json()
        token = j["access_token"]
        return token
    else:
        print("[+] Unsuccessful token request. Exiting...")
        print("[+] Response code: {}...".format(r.status_code))
        j = r.json()
        errmsg = j["errors"][0]["message"]
        print("[+] Error message: {}...".format(errmsg))
        sys.exit()



def getListOfDetections(apiurl, token, offset=0, limit=10):
    '''
    This function returns a list object, containing the IDs of the detection events
    in Falcon. this list of IDs are found in the "resources" key in the JSON
    response of the initial GET request
    '''
    endpoint = "{}/detects/queries/detects/v1".format(apiurl)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    data = {
        "offset" : offset,
        "limit" : limit
    }

    r = requests.get(endpoint, headers=headers, data=data)
    if r.status_code == 200:
        print("[+] Successful request for detection list...")
        j = r.json()
        print(json.dumps(j, indent=4))

        return j["resources"]
    else:
        print("[+] Unsuccessful request. Exiting...")
        print("[+] Response code: {}...".format(r.status_code))
        j = r.json()
        errmsg = j["errors"][0]["message"]
        print("[+] Error message: {}...".format(errmsg))
        sys.exit()


def getDetectionInfo(apiurl, token, detectionids):
    endpoint = "{}/detects/entities/summaries/GET/v1".format(apiurl)
    headers = {
        "Content-type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "Bearer {}".format(token)
    }
    data = {
        "ids" : detectionids
    }

    r = requests.post(endpoint, headers=headers, data=data)
    if r.status_code == 200:
        print("[+] Successful request for detection information...")
        j = r.json()
        print(json.dumps(j, indent=4))
    else:
        print("[+] Unsuccessful request. Exiting...")
        print("[+] Response code: {}...".format(r.status_code))
        j = r.json()
        errmsg = j["errors"][0]["message"]
        print("[+] Error message: {}...".format(errmsg))
        print(json.dumps(j, indent=4))
        sys.exit()


if __name__ == "__main__":
    main()

