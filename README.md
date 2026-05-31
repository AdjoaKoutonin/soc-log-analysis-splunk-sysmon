# Detection Use Cases
# 1. PowerShell Network Activity Detection

# Objective: Detect outbound network connections initiated by PowerShell.

MITER ATT&CK: T1059.001 – PowerShell

# Splunk Query:

index=* EventID=3 Image="*powershell.exe*"
| table _time Image User SourceIp DestinationIp DestinationPort

# Activity Performed:

Test-NetConnection google.com -Port 443

# Result:

PowerShell established an HTTPS connection to Google on port 443.
Sysmon Event ID 3 captured the network connection.
Splunk successfully logged and displayed the event.
images/Test-NetConnection_Activity performed.png

# Screenshot:
images/powershell-network-detection.png

# 2. Process Creation Monitoring

# Objective: Monitor process execution activity on endpoints.

MITER ATT&CK: T1059 – Command and Scripting Interpreter

# Splunk Query:

index=* EventID=1 Image="*notepad.exe*"
| table _time User Image ParentImage CommandLine

Activity Performed:

notepad.exe

# Result:

Sysmon Event ID 1 recorded process creation.
Splunk displayed the executed process and parent process relationship.

# Screenshot:
images/process-creation-detection.png

# 3. Failed Login Detection

# Objective: Detect failed authentication attempts.

MITER ATT&CK: T1110 – Brute Force

# Splunk Query:

index=* EventCode=4625

Activity Performed:

Multiple incorrect password attempts were made against a Windows user account.

# Result:

Windows Security Event ID 4625 generated.
Splunk successfully identified failed logon attempts.

# Screenshot:
images/failed-login-detection.png

# 4. Successful Login Detection

# Objective: Monitor successful user authentications.

MITER ATT&CK: T1078 – Valid Accounts

# Splunk Query:

index=* EventCode=4624

Activity Performed:

User successfully logged into the Windows endpoint.

# Result:

Windows Security Event ID 4624 generated.
Splunk recorded successful authentication activity.

# Screenshot:
images/successful-login-detection.png

# 5. User Account Creation Detection

# Objective: Detect creation of new user accounts.

MITER ATT&CK: T1136 – Create Account

# Splunk Query:

index=* EventCode=4720

Activity Performed:

net user soclab Password123! /add

# Result:

Windows Security Event ID 4720 generated.
Splunk detected the creation of a new local user account.

# Screenshot:
images/user-account-creation-detection.png

# Skills Demonstrated
Splunk Enterprise
Sysmon
SIEM Monitoring
Log Analysis
Threat Detection
Incident Investigation
Windows Event Logs
Network Monitoring
Security Operations Center (SOC) Workflows
MITRE ATT&CK Mapping

