# Incident Response Planning and Execution

# Playbook: "Unusual ISP for an OAuth App Detected"

# Summary

### Incident alert:
Unusual ISP for an OAuth App Detected
### Description: 
The OAuth App Backupify exhibited activity from an unusual ISP: Datto LLC. This deviation from expected behavior suggests that the app might be compromised and potentially used for malicious purposes such as phishing, data exfiltration, or lateral movement.

### Required Tools:

<ul>
  <li>VirusTotal: To check for any reputation issues associated with the ISP or IP address.</li>
  <li>Microsoft Defender XDR: For investigating the OAuth app’s activities.</li>
  <li>Azure Sentinel: For monitoring, threat hunting, and logging.</li>
  <li>Azure AD: To review and manage app permissions and OAuth tokens.</li>
  <li>Office 365 Admin Center: To monitor and control app permissions and user activities.</li>
</ul>

### Incident Categorisation:

<ul>
  <li>Severity: High</li>
  <li>Type: OAuth App Compromise, Potential Phishing or Data Exfiltration</li>
</ul>

# Step-by-Step Instructions:

### 1. Identify the OAuth App Activity:

<ul>
  <li>Use Microsoft Defender XDR to identify all activities associated with the OAuth App Backupify, focusing on the ones linked to the unusual ISP, Datto LLC.</li>
</ul>

### 2. Verify the ISP/IP Address:

<ul>
  <li>Run the IP address through VirusTotal to check for any reputational issues or indications of malicious activity.</li>
  <li>Cross-reference with known good and bad ISPs to confirm whether Datto LLC is a legitimate service provider for the app.</li>
</ul>

### 3. Analyze App Permissions and Activities:

<ul>
  <li>Access Azure AD and the Office 365 Admin Center to review permissions granted to Backupify. Check if these permissions align with the app's intended purpose.</li>
  <li>Audit recent activities, such as data access, file downloads, and user interactions with Backupify.</li>
</ul>

### 4. Revoke Unauthorized Access:

<ul>
  <li>If any suspicious or unauthorized activities are detected, immediately revoke the app’s access via Azure AD.</li>
  <li>Force a token reset to prevent further unauthorized activities.</li>
</ul>

### 5. Isolate Affected Users:

<ul>
  <li>Identify any users who interacted with the app while it was linked to the unusual ISP.</li>
  <li>Temporarily suspend their access to sensitive data and accounts until a thorough investigation is complete.</li>
</ul>

### 6. Conduct a Threat Hunt:

<ul>
  <li>Utilize Azure Sentinel to search for any indicators of compromise (IOCs) related to Datto LLC or the affected app. This includes unusual data transfers, phishing attempts, or lateral movement within the network.</li>
  <li>If malicious activities are found, consider further isolating impacted systems and users.</li>
</ul>

### Verification Steps:

<ul>
  <li>Confirm that all suspicious activities related to Backupify have ceased.</li>
  <li>Verify that no further connections to the unusual ISP, Datto LLC, occur.</li>
  <li>Monitor the affected users and systems for signs of residual or recurring threats.</li>
  <li>Ensure that OAuth tokens for Backupify are revoked and reset.</li>
</ul>

### Collaboration Steps:

<ul>
  <li>Incident Reporting: Document the incident thoroughly in Azure Sentinel, detailing the activities detected, steps taken for remediation, and the final resolution.</li>
  <li>Escalation: If the issue persists or if additional suspicious behavior is detected, escalate to the cloud security or incident response team for further analysis and potential containment</li>
  <li>Communication: Notify the affected users and relevant IT teams about the incident, the actions taken, and any follow-up steps required. Provide guidance on best practices for using OAuth apps and recognizing suspicious activity.</li>
</ul>


<ul>
  <li>.</li>
  <li>.</li>
  <li>.</li>
</ul>


# Playbook: "PUP Browser Extension epicunitscan.info on One Host Detected"

# Summary

### Incident alert:
 PUP Browser extension epicunitscan.info on one host detected
### Description: 
DNS Beacons to epicunitscan.info were detected, indicating a potentially unwanted program (PUP) related to a browser extension on one host.



### Required Tools:

<ul>
  <li>VirusTotal: To check the reputation of the identified browser extension.</li>
  <li>Joe Sandbox: For dynamic analysis of any downloaded files or suspicious executables.</li>
  <li>Azure Sentinel: For monitoring and additional threat hunting.</li>
  <li>Microsoft Defender XDR: For in-depth analysis and remediation actions.</li>
 </ul>

### Incident Categorisation:

<ul>
  <li>Severity: Medium</li>
  <li>Type: Potentially Unwanted Program (PUP)</li>
</ul>


# Step-by-Step Instructions:

### 1. Identify the Affected Host:

<ul>
  <li>Use Microsoft Defender XDR to identify the host associated with the DNS beacons to epicunitscan.info.</li>
</ul>

### 2. Analyse the Browser Extension:

<ul>
  <li>Utilize VirusTotal to check the reputation of the browser extension linked to epicunitscan.info.</li>
  <li>If malicious, proceed with the removal; otherwise, continue with further analysis.</li>
</ul>

### 3. Conduct Dynamic Analysis:

<ul>
  <li>If an executable or script was downloaded by the extension, submit it to Joe Sandbox for dynamic analysis.</li>
  <li>Review the sandbox report for any signs of malicious behavior.</li>
</ul>

### 4. Remove the PUP:

<ul>
  <li>If the extension or any associated files are confirmed to be unwanted or malicious, use Microsoft Defender to remove the extension from the affected host.</li>
  <li>Ensure that all traces of the PUP are removed from the system.</li>
</ul>

### 5. Update Security Settings:

<ul>
  <li>Adjust browser security settings to prevent the installation of similar unwanted extensions in the future.</li>
</ul>

###  Verification Steps:

<ul>
  <li>Verify that the DNS beacons to epicunitscan.info have ceased.</li>
  <li>Check the host for any residual signs of the PUP or other related threats.</li>
  </ul>

### Collaboration Steps:

<ul>
  <li>Incident Reporting: Log the incident in Azure Sentinel, including all actions taken and the final resolution.</li>
  <li>Escalation: If further analysis is needed, escalate to the malware analysis team for a deeper investigation.</li>
  <li>Communication: Notify the affected user and provide guidance on avoiding similar threats in the future.</li>
  
</ul>

<ul>
  <li>.</li>
  <li>.</li>
  <li>.</li>
</ul>

# Playbook: "Suspicious LDAP Query Detected".

# Summary

### Incident alert:
 Suspicious LDAP Query Detected.
  
### Description: 
A suspect LDAP query was executed, suggesting potential reconnaissance activity. LDAP queries are often used by attackers to map out an organization’s structure, including administrative users, groups, and critical assets, to plan privilege escalation and lateral movement.

### Required Tools:

<ul>
  <li>Microsoft Defender XDR: For detailed investigation of the LDAP query.</li>
  <li>Azure Sentinel: For monitoring and additional threat hunting.</li>
  <li>Active Directory Users and Computers (ADUC): To review and manage LDAP query logs and user permissions.</li>
  <li>Sysmon: For enhanced logging and monitoring of LDAP activities.</li>
   <li>Wireshark: For network traffic analysis, if deeper investigation is needed.</li>
 </ul>

### Incident Categorisation:

<ul>
  <li>Severity: High</li>
  <li>Type: Reconnaissance, Potential Privilege Escalation</li>
</ul>

# Step-by-Step Instructions:

### 1. Identify the Source of the LDAP Query:

<ul>
  <li>Use Microsoft Defender XDR to trace the origin of the suspicious LDAP query, including the user account, device, and the context of the query.</li>
</ul>

### 2. Review LDAP Query Details:

<ul>
  <li>Inspect the specifics of the LDAP query using ADUC. Determine whether the query was legitimate or if it attempted to access sensitive information that regular users should not need.</li>
</ul>

### 3. Verify User Permissions:

<ul>
  <li>Check the permissions of the account that executed the LDAP query. Use ADUC to confirm if the account has the appropriate level of access for such queries.</li>
  <li>If the account appears to have been compromised, consider resetting its credentials and adjusting permissions to limit further damage.</li>
</ul>

### 4.Implement Enhan ced Monitoring:

<ul>
  <li>Deploy Sysmon to increase visibility into LDAP activities and log detailed events. Ensure all future LDAP queries are logged for closer inspection.</li>
</ul>

### 5. Conduct Network Analysis:

<ul>
  <li>If necessary, use Wireshark to capture and analyze network traffic related to LDAP queries. Look for any signs of unusual or unauthorized traffic.</li>
</ul>

### 6. Isolate Potentially Compromised Systems:

<ul>
  <li>If the query is determined to be malicious, isolate the system that initiated it to prevent further reconnaissance or lateral movement.</li>
</ul>

### 7. Harden LDAP and AD Configurations:

<ul>
  <li> Review and tighten LDAP and Active Directory configurations to reduce exposure. Disable anonymous binds, enforce strong authentication, and limit who can run sensitive queries.</li>
</ul>

### Verification Steps:

<ul>
  <li>Verify that no further suspicious LDAP queries are made from the identified account or system.</li>
  <li>Check that the affected system is clean and free from any malware or backdoors.</li>
  <li>Ensure that enhanced logging and monitoring are capturing all relevant LDAP activities without false positives.</li>
</ul>

### Collaboration Steps:

<ul>
  <li>Incident Reporting: Log all findings, actions, and outcomes in Azure Sentinel. Include detailed analysis of the LDAP query and steps taken to prevent future occurrences.</li>
  <li>Escalation: If the query appears to be part of a broader attack, escalate to the AD security team for a full review of domain security and potential changes.</li>
  <li>Communication: Inform the IT team and relevant stakeholders of the incident, the investigation findings, and any necessary actions they should take, such as user education or system audits.</li>
  
</ul>

<ul>
  <li>.</li>
  <li>.</li>
  <li>.</li>
</ul>




# Playbook: "Initial Access Incident Involving One User"
.

# Summary

### Incident alert:
Initial Access Incident Involving One User
 
### Description: 
 A user account exhibited sign-ins from geographically distant locations, indicating potential credential theft. The machine learning algorithm identified this activity as an "impossible travel" event, suggesting that an attacker might be using the stolen credentials.

### Required Tools:

<ul>
  <li>Microsoft Defender XDR: For identifying and investigating sign-in anomalies.</li>
  <li>Azure Sentinel: For threat detection, investigation, and logging.</li>
  <li>Azure AD: For managing user accounts and reviewing sign-in activity.</li>
  <li>Multi-Factor Authentication (MFA) Tools: To enforce additional authentication layers.</li>
    <li>Geo-IP Lookup Services: To verify the legitimacy of sign-in locations.</li>
 </ul>

### Incident Categorisation:

<ul>
  <li>Severity: High</li>
  <li>Type: Credential Theft, Initial Access</li>
</ul>

# Step-by-Step Instructions:

### 1. Analse Sign-In Anomalies:

<ul>
  <li>Use Microsoft Defender XDR and Azure AD to review the anomalous sign-ins, focusing on the locations, IP addresses, and devices used.</li>
  <li>Verify if the locations are legitimately used by the user or if they are indeed geographically distant and impossible to reconcile.</li>
</ul>

### 2. Conduct Geo-IP Verification:

<ul>
  <li>Use a Geo-IP Lookup Service to check the exact locations of the sign-ins and determine if they are known malicious locations or associated with VPN services.</li>
  <li></li>
</ul>

### 3. Reset User Credentials:

<ul>
  <li>Immediately reset the user’s credentials in Azure AD to prevent further unauthorized access.</li>
  <li>Enforce the use of Multi-Factor Authentication (MFA) if not already in place.</li>
</ul>

### 4. Review and Revoke Sessions:

<ul>
  <li>End all active sessions for the user across all devices in Azure AD to ensure that any unauthorized sessions are terminated.</li>
  <li>Check for any suspicious OAuth tokens or app permissions that could have been used by the attacker.</li>
</ul>

### 5. Monitor for Additional Activity:

<ul>
  <li>Use Azure Sentinel to monitor the user account for any further unusual activities, such as attempted sign-ins, access to sensitive data, or lateral movement.</li>
</ul>

### 6. Educate the User:

<ul>
  <li>Inform the affected user about the incident, the importance of secure passwords, and the necessity of recognizing phishing attempts and other credential theft tactics.</li>
</ul>

### Verification Steps:

<ul>
  <li>Confirm that no further suspicious sign-ins or activities are detected for the user.</li>
  <li>Verify that MFA is properly configured and enforced for the user account.</li>
  <li>Ensure that the user’s credentials have been securely reset and that no unauthorized sessions are active.</li>
</ul>

### Collaboration Steps:

<ul>
  <li>Incident Reporting: Record the incident in Azure Sentinel with detailed notes on the anomalous sign-ins, investigation steps, and remediation actions.</li>
  <li>Escalation: If additional signs of compromise are detected, escalate to the identity management team for further analysis.</li>
  <li>Communication: Notify the user and relevant IT personnel of the incident, provide recommendations for maintaining secure accounts, and highlight any additional security measures implemented.</li>
  
</ul>


