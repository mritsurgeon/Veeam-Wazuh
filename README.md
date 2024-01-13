# Veeam-Wazuh

Veeam Custom Integration for Wazuh

## What is Wazuh?

Wazuh is an open-source security information and event management (SIEM) tool designed for log analysis, intrusion detection, vulnerability detection, and overall security monitoring. It acts as a Host-based Intrusion Detection System (HIDS) with agents installed on individual systems, forwarding log data to a central manager. Wazuh is scalable, integrates with other security tools, and is widely used in various environments for enhancing threat detection and incident response capabilities.

## What is Veeam?

Veeam is a software company specializing in data backup, disaster recovery, and intelligent data management solutions for virtualized and cloud environments. Veeam is known for user-friendly solutions that ensure the availability and security of data across various IT environments.

## What is Custom Veeam Integration for Wazuh?

In Veeam V12.1, Veeam released an Incident API, which is part of its new Malware Detection. It allows the use of a third-party antivirus software or security tool to integrate with the REST API and create a malware event that triggers a quick backup. For details on enabling the Incident API, see the [Incident API section](https://helpcenter.veeam.com/docs/backup/vsphere/malware_detection_incident_api.html?ver=120) of the Veeam Backup & Replication User Guide.

Wazuh Custom Integration: The Integrator daemon part of Wazuh allows Wazuh to connect to external APIs and alerting tools such as Slack, PagerDuty, VirusTotal, Shuffle, and Maltiverse. The integrator tool can connect Wazuh with other external software like Veeam and call the Veeam Malware Event API.

### The Pieces
We need to copy 2 files & edit one existing Wazuh config file.

```
└───Wazuh Integration
        custom-veeam
        custom-veeam.py
        ossec.conf
```

- **custom-veeam:** Is a wrapper script used to facilitate the execution of the Python script & pass system variables to Python from Wazuh.
- **custom-veeam.py:** Is a Python script that initiates a login to Veeam Backup & Replication via REST API. The script authenticates with User & Pass and gets Access token. After which, it fetches the Alarm details that were triggered and passes them in the body to Veeam Malware Event API endpoint.
- **ossec.conf:** Is a sample configuration that is added to the Wazuh config file. This config is passed through the Wrapper to Python Script, including information like:
  - Hook_url: The FQDN or IP of Veeam Backup & Replication Server/Endpoint
  - API_Key: The User & Pass Used for initial Basic Auth to REST API endpoint to get Bearer
  - Group/Rules: Groups or Rules That trigger the API
  - Level: Rule Severity that triggers the API

## Installation

Copy `custom-veeam` and `custom-veeam.py` to the `/var/ossec/integrations` Directory on the Wazuh Server. Change the Permissions of the Files.

```bash
# Copy the Permissions of Existing Out of the Box integrations
chmod --reference=slack custom-veeam
chmod --reference=slack custom-veeam.py
```

Sample Permissions:

```bash
-rwxr-x---.  1 root wazuh  1045 Jan 12 18:16 custom-veeam
-rwxr-x---.  1 root wazuh  2711 Jan 12 22:05 custom-veeam.py
# ... (other integrations)
```

Edit the `ossec.conf` file:

```bash
sudo vi /var/ossec/etc/ossec.conf
```

Add the following configuration:

```xml
<integration>
    <name>custom-veeam</name>
    <hook_url>0.0.0.0</hook_url> <!-- VBR IP or FQDN only -->
    <!-- level>12</level --> <!-- Alarms equal to or higher will alert, currently commented out-->
    <!-- group></group --> <!-- Use groups rather than rule IDs, currently commented out  -->
    <rule_id>31100,92217,92052,92032,119999</rule_id> <!-- Use IDs of rules -->
    <api_key>administrator:password</api_key> <!-- Veeam User & Pass Separated by Colon: User:pass -->
    <alert_format>json</alert_format>
    <options>{"data": "Custom data"}</options> <!-- Replace with your custom JSON object -->
</integration>
```

Restart Wazuh Services:

```bash
/var/ossec/bin/wazuh-control restart
```

## Rules

The idea is to align the integration with a Rule ID/S or Group of Rules. Additionally, a Rule might be triggered under different Severity, so setting the Minimum Severity can help only trigger the API on Critical Events.

I used Remote Execution, Remote Shell Indicator Rules to trigger a Malware Event into Veeam & a quick Backup of a Server before it's encrypted.

You can also align this to known Ransomware Indicators of Compromise Rules. A few examples:

- Rule ID 100201 is triggered when CrossLock ransomware drops a ransom note with the file name —CrossLock_readme_To_Decrypt—.
- Rule ID 100111 is triggered when the Blackbit ransomware deletes all the shadow copies of the files and folders on the Windows endpoint.
- Rule ID 100031 is triggered when the Lockbit 3.0 ransomware deletes the Windows defender service possible Ransomware Activity.
- Rule ID 100108 is triggered when BlackCat modifies the registry to change MaxMpxCt settings.

## Debug

Logging has been added to `custom-veeam.py`. The log file is `/var/ossec/logs/integration.log`. To view integrator Daemon logs:

```bash
cat /var/ossec/logs/ossec.log | grep "integratord"
```

Enable Debugging for the integrator Daemon with -d or -dd:

```bash
/var/ossec/bin/wazuh-integratord -dd
```

## Screenshots

### Malware Event in Veeam

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/b5c18185-c724-426b-8c24-cc65a34a725a)

### Wazuh Dashboard

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/d1488535-b0eb-4c3a-9666-1af8120899c7)

### Rule Filter

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/f77a8d10-e727-4e51-ba94-ef5449b16db2)

## Contribute

## Blog

## Enhancements
