# Veeam-Wazuh
Veeam Custom Intergration for Wazuh

## What is wazuh ?

Wazuh is an open-source security information and event management (SIEM) tool designed for log analysis, intrusion detection, vulnerability detection, and overall security monitoring. It acts as a Host-based Intrusion Detection System (HIDS) with agents installed on individual systems, forwarding log data to a central manager. Wazuh is scalable, integrates with other security tools, and is widely used in various environments for enhancing threat detection and incident response capabilities.

## What is Veeam ?

Veeam is a software company specializing in data backup, disaster recovery, and intelligent data management solutions for virtualized and cloud environments.Veeam is known for user-friendly solutions that ensure the availability and security of data across various IT environments.

## Whats is Custom Veeam Intergration for Wazuh ?

In Veeam V12.1 , Veeam released a Incident API which is part of its new Malware Detection , Use a third-party antivirus software  or Secuirty tool and integrate it with the REST API to create a malware event that will trigger quick backup. For details on enabling Incident API, see the Incident API section of the Veeam Backup & Replication User Guide.
https://helpcenter.veeam.com/docs/backup/vsphere/malware_detection_incident_api.html?ver=120

Wazuh Custom Intergation , The Integrator daemon part of Wazuh allows Wazuh to connect to external APIs and alerting tools such as Slack, PagerDuty, VirusTotal, Shuffle, and Maltiverse.
The integrator tool is able to connect Wazuh with other external software like Veeam & call Veeam Malware Event API.

### The Pieces 
We need to copy 2 files & edit one existing Wazuh config file.

└───Wazuh Intergration
        custom-veeam
        custom-veeam.py
        ossec.conf

custom-veeam :
Is a wrapper script used to facilitate the execution of Python script & pass sysytem variables to Python from Wazuh.
custom-veeam.py :
Is a Python script that initiates a login to Veeam Backup & Replication via REST API , Script authenticates with User & Pass & gets Access token , after which it fetches the Alarm details that were triggred and passes thei in the body to Veeam Malware Event API endpoint.
ossec.conf :
Is Sample configuration that is added to Wazuh config file , this config is passed through Warpper to Python Script like :
  Hook_url : The FQDN or IP of Veeam Backup & Replication Server / Endpoint 
  API_Key : The User & Pass Used for initila Basic Auth to REST API endpoint to get Bearer
  Group / Rules : Groups or Rules That trigger the API 
  Level : Rule Severty that triggres the API
  
## Installation 

Copy    custom-veeam
        custom-veeam.py

To the /var/ossec/integrations Directory on teh Wazuh Server 
Change the Permissions of the Files

#### Copy the Permisions of Existing Out of the Box intergartions
chmod --reference=slack custom-veeam
chmod --reference=slack custom-veeam.py

-rwxr-x---.  1 root wazuh  1045 Jan 12 18:16 custom-veeam
-rwxr-x---.  1 root wazuh  2711 Jan 12 22:05 custom-veeam.py
-rwxr-x---.  1 root wazuh  1045 Jan  6 00:07 maltiverse
-rwxr-x---.  1 root wazuh 17358 Jan  6 00:07 maltiverse.py
-rwxr-x---.  1 root wazuh  1045 Jan  6 00:07 pagerduty
-rwxr-x---.  1 root wazuh  7090 Jan  6 00:07 pagerduty.py
-rwxr-x---.  1 root wazuh  1045 Jan  6 00:07 shuffle
-rwxr-x---.  1 root wazuh  7686 Jan  6 00:07 shuffle.py
-rwxr-x---.  1 root wazuh  1045 Jan  6 00:07 slack
-rwxr-x---.  1 root wazuh  7289 Jan  6 00:07 slack.py
-rwxr-x---.  1 root wazuh  1045 Jan  6 00:07 virustotal
-rwxr-x---.  1 root wazuh  9785 Jan  6 00:07 virustotal.py

#### Edit the ossec.conf file 
sudo vi /var/ossec/etc/ossec.conf

Add :

 <integration>
    <name>custom-veeam</name>
    <hook_url>0.0.0.0</hook_url> <!-- VBR IP or FQDN only -->
    <!-- level>12</level --> <!-- Alarms equal to or higher will alert , currently commented out-->
    <!-- group></group --> <!-- Use groups rather than rule IDs , currently commented out  -->
    <rule_id>31100,92217,92052,92032,119999</rule_id> <!-- Use IDs of rules -->
    <api_key>administrator:password</api_key> <!-- Veeam User & Pass Seperated by Colon : User:pass -->
    <alert_format>json</alert_format>
    <options>{"data": "Custom data"}</options> <!-- Replace with your custom JSON object -->
  </integration>

#### Restart Wazuh Services

/var/ossec/bin/wazuh-control restart

#### Rules 

The Idea is that you Align the intergration to a Rule ID/S or Group of Rules , Additionally , a Rule Might be triggered under diffrent Severity  , so setting the MInimum Severity can help only Triger API on Critical Events.

I Used Remote Execution , Remote Shell Indicator Rules , So trigger a Malware Event into Veeam & A quick Backup of a Server Before its Encrypted.

##### You can also Align this to Know Ransomware Indicators of Compromise Rules :
##### Few Examples :

Rule ID 100201 is triggered when CrossLock ransomware drops a ransom note with the file name —CrossLock_readme_To_Decrypt—.
Rule ID 100111 is triggered when the Blackbit ransomware deletes all the shadow copies of the files and folders on the Windows endpoint.
Rule ID 100031 is triggred when the Lockbit 3.0 ransomware deletes Windows defender service Possible Ransomware Activity.
Rule ID 100108 is triggered when BlackCat modifies the registry to change MaxMpxCt settings

#### Debug 

Logging has been added to custom-veeam.py , The log file /var/ossec/logs/integration.log
cat  /var/ossec/logs/ossec.log | grep "integratord"

Enable Debugging to integrator Daemon -d or -dd
/var/ossec/bin/wazuh-integratord  -dd

#### Screen shots 

##### Malware Event in Veeam 

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/b5c18185-c724-426b-8c24-cc65a34a725a)

##### Wazuh Dashboard 

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/d1488535-b0eb-4c3a-9666-1af8120899c7)

##### Rule Filter 

![image](https://github.com/mritsurgeon/Veeam-Wazuh/assets/59644778/f77a8d10-e727-4e51-ba94-ef5449b16db2)

#### Contibute 

#### Blog 

#### Enhancements 
