# Bot Reaper - Threat Parser
# DATE: 2022-04-10
# AUTHORS: Sohrab Boparai, Sean Gordon, Kurt Neuweiler, Josh Nickels
import boto3
import json
import logging                                      # For syslog
import logging.handlers                             # For syslog
import requests                                     # Required for mac_lookup function
import socket                                       # For syslog
import time                                         # Used for time.sleep in mac_lookup - API calls seem to have cooldown

# Read config file
config = {}
with open('config.txt') as f:
    for line in f:
        (key, val) = line.split("=")
        config[str(key)] = val.strip()

#
# Function for pulling vendor of MAC address, mac_address is expected to be a string of the form xx:xx:xx:xx:xx or xxxxxxxxxxxx
#
def mac_lookup(mac_address):
    time.sleep(3)                                   # Increase likelihood of successful API call with delay between calls
    url = "https://api.macvendors.com/"             # The API for the MAC vendor lookup
    try:
        response = requests.get(url + mac_address)  # Make the HTTP GET request to the API
        response.raise_for_status()                 # Check for errors
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        return "Unknown vendor"                     # Return unknown
    return response.content.decode()                # Otherwise return the decoded vendor as a string
#
# Function for formatting a dictionary for one threat
#
def configure_threat_attributes(ct_agent_registry, ct_ip, ct_mac, ct_vendor, ct_priority, ct_malware):
    ct_threat_attributes = {}                                                   # Threat attributes stores temp info about the detected threat
    ct_threat_attributes['ip_address'] = ct_ip                                  # IP
    ct_threat_attributes['vendor'] = ct_vendor                                  # VENDOR - lookup via MAC address
    ct_threat_attributes['priority'] = ct_priority                              # PRIORITY - linked with syslog (0-7)
    if 'ports' in ct_agent_registry[ct_mac]['dests'][ct_ip].keys():             # PORTS - if there are any, otherwise retrun 'no ports'
        if len(ct_agent_registry[ct_mac]['dests'][ct_ip]['ports']) < 100:       #   Only return number of ports if there are more than 100
            ct_threat_attributes['ports'] = ct_agent_registry[ct_mac]['dests'][ct_ip]['ports']
        else:
            ct_threat_attributes['ports'] = str(len(ct_agent_registry[ct_mac]['dests'][ct_ip]['ports'])) + ' ports total'
    else:
        ct_threat_attributes['ports'] = 'No ports'
    ct_threat_attributes['malware'] = ct_malware                                # MALWARE
    return ct_threat_attributes.copy()
# MAIN
def lambda_handler(event, context):
    #
    # Import threat intelligence data
    #
    s3 = boto3.client('s3')                         # Output initialization
    ses = boto3.client('ses')
    threat_data = s3.get_object(Bucket=config['AWS_THREAT_BUCKET'], Key='threat_intel.json')   # Retrieve threat file from bucket
    threat_contents = threat_data['Body'].read().decode()                                           # Read contents of body of file
    threat_registry = json.loads(threat_contents)
    threat_keys = threat_registry.keys()                                                            # Define list of evil IP addresses
    
    #
    # Import agent data
    #
    agent_data = s3.get_object(Bucket=config['AWS_THREAT_BUCKET'], Key=config['AGENT_UPLOAD_FILENAME'])    # Retrieve agent file from bucket
    agent_contents = agent_data['Body'].read().decode()                         # Read contents of body of file
    agent_registry = json.loads(agent_contents)
    threats = {}                                                                # Dictionary to store data related to detected threats
    counter = 0                                                                 # Track how many malicious items are found
    #
    # Agent vs Threat data comparison
    #
    for mac in agent_registry:                                                      # For each key in the first layer of dictionaries (MAC ADDRESS)
        vendor = mac_lookup(mac)                                                    # Get vendor ID from mac address
        for ip in agent_registry[mac]["dests"].keys():                              # For each key within the highest layer of keys
            # If a threat is detected by any means, add entry to threats dictionary recording relevant data
            # Threat IP detection
            if ip in threat_keys:                                                   # If dest IP address is anywhere in threat IP address list
                if 'malware' in threat_registry[ip].keys():                         # If there is information assocaited with the malicious traffic, add it, otherwise unknown
                    malware_type = threat_registry[ip]['malware']
                else:
                    malware_type = 'Unknown malware'
                # Add attributes for the threat to the threats dictionary at index of counter
                threats[counter] = threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'CRITICAL', malware_type)
                counter = counter + 1                                               # Increment threat item counter
            # Port related detection
            if 'ports' in agent_registry[mac]['dests'][ip].keys():                  # If there are no ports, then ignore
                # Port scan detection
                if len(agent_registry[mac]['dests'][ip]['ports']) > 100:            # If there are > 100 ports associated with one IP address
                    threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'CRITICAL', 'Port scan')
                    counter = counter + 1
                else:
            # Vulnerable port usage detection
                    # Chargen - 19
                    if 19 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: Chargen')
                        counter = counter + 1
                    # FTP - 20, 21
                    if (20 in agent_registry[mac]['dests'][ip]['ports']) or (21 in agent_registry[mac]['dests'][ip]['ports']):
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: FTP')
                        counter = counter + 1
                    # Telnet - 23
                    if 23 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: Telnet')
                        counter = counter + 1
                    # RPC - 111
                    if 111 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: RPC')
                        counter = counter + 1
                    # NetBIOS - 137, 138, 139
                    if (137 in agent_registry[mac]['dests'][ip]['ports']) or (138 in agent_registry[mac]['dests'][ip]['ports']) or (139 in agent_registry[mac]['dests'][ip]['ports']):
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: NetBIOS')
                        counter = counter + 1
                    # SNMP - 161, 162
                    if (161 in agent_registry[mac]['dests'][ip]['ports']) or (162 in agent_registry[mac]['dests'][ip]['ports']):
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: SNMP')
                        counter = counter + 1
                    # SMB - 445
                    if 445 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attribute(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: SMB')
                        counter = counter + 1
                    # Remote Desktop - 3389
                    if 3389 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: Remote Desktop')
                        counter = counter + 1
                    # VNC - 5900
                    if 5900 in agent_registry[mac]['dests'][ip]['ports']:
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: VNC')
                        counter = counter + 1
                    # SQL Server or MySQL - 1433, 1434, 3306
                    if (1433 in agent_registry[mac]['dests'][ip]['ports']) or (1434 in agent_registry[mac]['dests'][ip]['ports']) or (3306 in agent_registry[mac]['dests'][ip]['ports']):
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: SQL-based')
                        counter = counter + 1
                    # IRC - 6660-6669, 7000
                    if (6660 in agent_registry[mac]['dests'][ip]['ports']) or (6661 in agent_registry[mac]['dests'][ip]['ports']) or (6662 in agent_registry[mac]['dests'][ip]['ports']) or (6663 in agent_registry[mac]['dests'][ip]['ports']) or (6664 in agent_registry[mac]['dests'][ip]['ports']) or (6665 in agent_registry[mac]['dests'][ip]['ports']) or (6666 in agent_registry[mac]['dests'][ip]['ports']) or (6667 in agent_registry[mac]['dests'][ip]['ports']) or (6668 in agent_registry[mac]['dests'][ip]['ports']) or (6669 in agent_registry[mac]['dests'][ip]['ports']) or (7000 in agent_registry[mac]['dests'][ip]['ports']):
                        threats[counter] = configure_threat_attributes(agent_registry, ip, mac, vendor, 'WARNING', 'Vulnerable Port: IRC')
                        counter = counter + 1
    #
    # If a threat has been found, record information about it and upload to a file 
    #
    if (counter > 0):
        syslog_ip = config['SYSLOG_IP']
        if syslog_ip:
            syslog = logging.getLogger('Syslog')
            syslog.setLevel(logging.INFO) # Threshhold logging level
            syslog_handler = logging.handlers.SysLogHandler(address=(syslog_ip, int(config['SYSLOG_PORT'])), socktype=socket.SOCK_STREAM)
            syslog.addHandler(syslog_handler)
            for mal in threats:
                message = "Bot Reaper " + threats[mal]['priority'] + ": " + threats[mal]['malware'] + " threat detected at " + str(threats[mal]['ip_address']) + " on a(n) " + threats[mal]['vendor'] + " device, using ports " + str(threats[mal]['ports'])
                
                if threats[mal]['priority'] == 'CRITICAL':
                    syslog.critical(message)
                elif threats[mal]['priority'] == 'ERROR':
                    syslog.error(message) 
                elif threats[mal]['priority'] == 'WARNING':
                    syslog.warning(message)
                else:
                    syslog.info(message)

        # Export list of threats found to threat intelligence bucket, this is triggered every time agent data is uploaded
        uploadByteStream = bytes(json.dumps(threats).encode('UTF-8'))           # Uploaded as json until we know more
        s3.put_object(Bucket=config['AWS_THREAT_BUCKET'], Key=config['AGENT_UPLOAD_FILENAME'], Body=uploadByteStream)
    #
    # If a threat is found, send notification to the email address
    #
        body = "Bot Reaper has detected one or more devices acting suspicious on your network. " + str(counter) + " threat(s) found.\n"       
        notif_email = config['NOTIFICATION_EMAIL']
        if notif_email:
            ses.send_email(
                Source = notif_email,
                Destination = {
                    'ToAddresses': [
                        notif_email
                    ]
                },
                Message = {
                    'Subject': {
                        'Data': 'Botreaper - Threat Detected',
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text':{
                            'Data': body,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            )
