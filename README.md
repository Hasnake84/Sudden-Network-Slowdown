## **Sudden Network Slowdown Incident**

## **Incident Investigation Report**

## **Scenario:**
I noticed a significant network performance degradation on some of the older devices attached to the network in the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspects something might be going on internally. All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

## **Objectives:**
- Run a Powershell script on our VM to scan the local network using Powershell script containing a file name **portscan.ps1**
  - Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
- Gather relevant data from logs, network traffic, and endpoints.
- Consider inspecting the logs for excessive successful/failed connections from any devices.  If discovered, pivot and inspect those devices for any suspicious file or process events.
- Ensure data is available from all key sources for analysis.
- Ensure the relevant tables contain recent logs:
  - DeviceNetworkEvents
  - DeviceFileEvents
  - DeviceProcessEvents
- **Test-NetConnection (PowerShell): ongoing PowerShell cmdlet for network testing.**
<a href="https://imgur.com/qphSE1X"><img src="https://i.imgur.com//qphSE1X.png" tB2TqFcLitle="source: imgur.com" /></a>
  
## **Incident Summary and Findings**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionsAttempts desc
```
### By using the above query we see that our VM *port-scanner-vm* was found failing several connection requests against two other hosts on the same network.

<a href="https://imgur.com/V72MMqB"><img src="https://i.imgur.com//V72MMqB.png" tB2TqFcLitle="source: imgur.com" /></a>
## Detail:
<a href="https://imgur.com/AtEpCJh"><img src="https://i.imgur.com//AtEpCJh.png" tB2TqFcLitle="source: imgur.com" /></a>

```kql
let VMName = "port-scanner-vm";
DeviceProcessEvents
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
## We observed the port scan script was launched by AccountName *henoks*. This is not expected behavior and it is not something that was setup by the admins. I isolated the device and ran a malware scan. The malware scan produced no results, so out of caution, following SOP I kept the device isolated and with senior analyst approval i put in a ticket to have workstation re-image/rebuilt. 
<a href="https://imgur.com/3ZlbqwI"><img src="https://i.imgur.com//3ZlbqwI.png" tB2TqFcLitle="source: imgur.com" /></a>

### **Timeline Overview**
1. **port-scanner-vm was found failing several connection requests against two other hosts on the same network.**
2. **Process Analysis:**
   - After observing failed connection requests from a suspected host (`10.0.1.120`) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

   **Detection Query (KQL):**
   ```kql
   let IPInQuestion = "10.0.1.120";
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | where LocalIP == IPInQuestion
   | order by Timestamp desc
   ```
<a href="https://imgur.com/95u1al2"><img src="https://i.imgur.com//95u1al2.png" tB2TqFcLitle="source: imgur.com" /></a>
 
3. **Network Check:**
   - **Observed Behavior:** I pivoted to the `DeviceProcessEvents` table to see if we could see anything that was suspicious around the time the port scan started. We noticed a PowerShell script named `portscan.ps1` launched at `2025-04-01T09:24:18.774381Z`.
<a href="https://imgur.com/DMWTeAZ"><img src="https://i.imgur.com//DMWTeAZ.png" tB2TqFcLitle="source: imgur.com" /></a>

5. **Response:**
   - We observed the port scan script was launched by AccountName *henoks*. This is not expected behavior and it is not something that was setup by the admins. I isolated the device and ran a malware scan. The malware scan produced no results, so out of caution, I kept the device isolated and put in a ticket to have it re-image/rebuilt. Shared findings with the manager, highlighting automated archive creation. Awaiting further instructions.
---

# MITRE ATT&CK Techniques for Incident Notes

| **Tactic**                | **Technique**                                                                                       | **ID**       | **Description**                                                                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Initial Access**         | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)                     | T1210        | Failed connection attempts may indicate an attacker probing for open ports or exploitable services.                                            |
| **Discovery**              | [Network Service Scanning](https://attack.mitre.org/techniques/T1046/)                           | T1046        | Sequential port scans performed using a script (`portscan.ps1`) align with service discovery activity.                                         |
| **Execution**              | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  | T1059.001    | The use of PowerShell (`portscan.ps1`) for conducting network scanning demonstrates script-based execution.                                    |
| **Persistence**            | [Account Manipulation](https://attack.mitre.org/techniques/T1098/)                               | T1098        | Unauthorized use of the SYSTEM account to launch a script indicates potential persistence through credential manipulation.                     |
| **Privilege Escalation**   | [Valid Accounts](https://attack.mitre.org/techniques/T1078/)                                     | T1078        | SYSTEM account execution suggests privilege escalation by leveraging valid but unauthorized credentials.                                       |
| **Defense Evasion**        | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)                    | T1027        | If `portscan.ps1` contained obfuscated commands, this technique may have been used to avoid detection.                                         |
| **Impact**                 | [Network Denial of Service](https://attack.mitre.org/techniques/T1498/)                          | T1498        | The significant network slowdown could be a side effect or an intentional impact of excessive scanning activity.                              |

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---
