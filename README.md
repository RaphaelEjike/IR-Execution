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


ul>
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

### 

<ul>
  <li></li>
  <li></li>
  <li></li>
  <li></li>
</ul>

### Collaboration Steps:

<ul>
  <li></li>
  <li></li>
  <li></li>
  
</ul>






# Playbook: .

# Summary

### Incident alert:
 .
### Description: 
 .



### Required Tools:

<ul>
  <li></li>
  <li></li>
  <li></li>
  <li></li>
 </ul>

### 

<ul>
  <li></li>
  <li></li>
</ul>


# Step-by-Step Instructions:

### 1. 

<ul>
  <li></li>
</ul>

### 2. 

<ul>
  <li></li>
  <li></li>
</ul>

### 3. 

<ul>
  <li></li>
  <li></li>
</ul>

### 4.

<ul>
  <li></li>
  <li></li>
</ul>

### 5. 

<ul>
  <li></li>
  <li></li>
</ul>

### 6. 

<ul>
  <li></li>
  <li></li>
</ul>

### 

<ul>
  <li></li>
  <li></li>
  <li></li>
  <li></li>
</ul>

### 

<ul>
  <li></li>
  <li></li>
  <li></li>
  
</ul>














