# Bot Reaper - Pull Threat Intelligence
# DATE: 2022-04-10
# AUTHORS: Sohrab Boparai, Sean Gordon, Kurt Neuweiler, Josh Nickels

import boto3
import json
import requests # Pull from threat intelligence sites

# Read config file
with open('config.txt') as f:
    for line in f:
        (key, val) = line.split("=")
        config[str(key)] = val.strip()

# Output bucket initialization
s3 = boto3.client('s3')
bucket = config['AWS_BUCKET_NAME']

# Output filepath initialization
fname = 'threat_intel.json'
# Dictionary of all threats, indexed by IP address
threat_registry = {}
threat_attributes = {}
# Allowed characters in IP address, used in basic input validation
ip_characters = '1234567890.'


def lambda_handler(event, context):
    # Error handling for HTTP GET requests: 0 == no error, 1 == error in request
    error_found = 0
    
    # GET Feodotracker TI data
    feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    try:
        feodo_data = requests.get(feodo_url)                                # Try to GET feodotracker data
        feodo_data.raise_for_status()                                       # Check for errors
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        print ("Unable to update Feodotracker data.")
        error_found = 1
    if error_found == 0:                                                    # If there were no errors
        for threat in feodo_data.json():                                    # For every threat in the feodotracker data
            threat_registry[threat["ip_address"]] = threat                  # Add to threat registry at IP address index
    error_found = 0

    # GET Threatview OSINT TI data
    tv_OSINT_url = "https://threatview.io/Downloads/Experimental-IOC-Tweets.txt"
    try:
        tv_OSINT_data = requests.get(tv_OSINT_url)                          # Try to GET threatview OSINT data
        tv_OSINT_data.raise_for_status()                                    # Check for errors
    except (requests.exceptions.RequestException, requestsexceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        print ("Unable to update Threatview OSINT data.")
        error_found = 1
    if error_found == 0:                                                    # If there were no errors
        tv_OSINT_data = tv_OSINT_data.content.decode().split('\n')          # Decode the contents of the HTTP response and split the string by line
        for threat in tv_OSINT_data:                                        # For every threat in the threatview OSINT data
            if all(ch in ip_characters for ch in threat) and threat != '':  # If the line only contains allowed IP address chars, and contains data
                if threat not in threat_registry.keys():                    # If the threat is not already in the registry
                    threat_attributes["ip_address"] = threat                # Create a simple dictonary containing the IP address
                    threat_registry[threat] = threat_attributes.copy()      # Add to threat registry at IP address index
    error_found = 0

    # GET Threatview C2 TI data
    tv_C2_url = "https://threatview.io/Downloads/High-Confidence-CobaltstrikeC2_IP_feed.txt"
    try:
        tv_C2_data = requests.get(tv_C2_url)                                # Try to GET threatview C2 data
        tv_C2_data.raise_for_status()                                       # Check for errors
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        print ("Unable to update Threatview C2 data.")
        error_found = 1
    if error_found == 0:                                                    # If there were no errors
        tv_C2_data = tv_C2_data.content.decode().split('\n')                # Format the input data
        for threat in tv_C2_data:                                           # For every threat in the threatview C2 data
            if all(ch in ip_characters for ch in threat) and threat != '':  # If the line only contains allowed IP address chars, and contains data
                if threat not in threat_registry.keys():                    # If the threat is not already in the registry
                    threat_attributes["ip_address"] = threat                # Create a simple dictonary containing the IP address
                    threat_registry[threat] = threat_attributes.copy()      # Add to threat registry at IP address index
    error_found = 0

    # GET Threatview IP Blocklist TI data
    tv_IPblocklist_url = "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
    try:
        tv_IPblocklist_data = requests.get(tv_IPblocklist_url)              # Try to GET threatview IP blocklist data
        tv_IPblocklist_data.raise_for_status()                              # Check for errors
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        print ("Unable to update Threatview IP Blocklist data.")
        error_found = 1
    if error_found == 0:                                                    # If there were no errors
        tv_IPblocklist_data = tv_IPblocklist_data.content.decode().split('\n') # Format the input data
        for threat in tv_IPblocklist_data:                                  # For every threat in the threatview IP blocklist data
            if all(ch in ip_characters for ch in threat) and threat != '':  # If the line only contains allowed IP address chars, and contains data
                if threat not in threat_registry.keys():                    # If the threat is not already in the registry
                    threat_attributes["ip_address"] = threat                # Create a simple dictonary containing the IP address
                    threat_registry[threat] = threat_attributes.copy()      # Add to threat registry at IP address index
    
    
    # Format as bytestream for upload
    uploadByteStream = bytes(json.dumps(threat_registry).encode('UTF-8'))
    
    # Upload
    s3.put_object(Bucket=bucket, Key=fname, Body=uploadByteStream).
