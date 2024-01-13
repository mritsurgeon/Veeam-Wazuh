#!/usr/bin/env python3

# Created by Ian Engelbrecht, <mritsurgeon@gmail.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import json
import requests
import logging

# Set up logging to write logs to a file
logging.basicConfig(filename='/var/ossec/logs/integrations.log', level=logging.INFO)

alert_file = sys.argv[1]
user = sys.argv[2].split(':')[0]
password = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]

# Fetch the bearer token
response = requests.post(
    f"https://{hook_url}:9419/api/oauth2/token",
    headers={
        "accept": "application/json",
        "x-api-version": "1.1-rev1",
        "Content-Type": "application/x-www-form-urlencoded",
    },
    data=f"grant_type=password&username={user}&password={password}",
    verify=False,
)

logon = response.json().get("access_token", "")
veeamkey = logon

# Read the content of the alert file
with open(alert_file, "r") as file:
    # Read all lines from the file
    lines = file.readlines()
    
    # Concatenate lines into a single string
    alerts_str = "".join(lines)
    
    # Load multiple JSON objects
    alerts = [json.loads(alert) for alert in alerts_str.split("\n") if alert.strip()]

# Process each alert
for alert_json in alerts:
    # Extract issue fields
    alert_level = alert_json["rule"]["level"]
    ruleid = alert_json["rule"]["id"]
    description = alert_json["rule"]["description"]
    agentid = alert_json["agent"]["id"]
    agentname = alert_json["agent"]["name"]
    agentip = alert_json["agent"]["ip"]
    time = alert_json["timestamp"]

        # Check if "mitre" field exists before accessing its subfields
    if "mitre" in alert_json:
        technique = alert_json["mitre"].get("technique", "N/A")
    else:
        technique = "N/A"

    # Concatenate the details into a single string
    details_string = f"Description: {description} Rule ID: {ruleid} Alert Level: {alert_level} Mitre Technique: {technique}"

    # Post the alert to the Veeam API

    response = requests.post(
        f"https://{hook_url}:9419/api/v1/malwareDetection/events",
        headers={
            "accept": "application/json",
            "x-api-version": "1.1-rev1",
            "Authorization": f"Bearer {veeamkey}",
            "Content-Type": "application/json",
        },
        json={
            "detectionTimeUtc": time,
            "machine": {"fqdn": agentname, "ipv4": agentip},
            "details": details_string ,
            "engine": "Wazuh",
  
        },
        verify=False,  # Assuming you're working with a self-signed certificate
    )

    # Log the response to the file
    logging.info(response.text)

    print(response.text)