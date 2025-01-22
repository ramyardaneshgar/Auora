# THM-Writeup-Auora
Writeup for TryHackMe Aurora EDR - Aurora EDR: Sigma-based threat detection, response automation, and advanced endpoint security analysis.

---

### **Deployment and Initialization**

Aurora was pre-installed on the target system but not operational. I initiated the agent by executing the batch file provided on the desktop, ensuring it was properly configured to monitor events via **Event Tracing for Windows (ETW)**.

#### Command:
```cmd
C:\Users\Administrator\Desktop\start_aurora.bat
```

To verify functionality, I accessed the **Windows Event Viewer**, filtered logs under the **Application** category, and confirmed that Aurora was actively generating event-based detections.

---

### **Event ID 1: Process Creation Reconnaissance**

The first detection I analyzed was a **Process Creation Alert** logged with **Event ID: 1**. This event highlighted the execution of `wmic.exe`, a legitimate Windows binary often misused during adversary reconnaissance.

#### Event Details:
- **Sigma Rule Title:** *Process Reconnaissance via Wmic.EXE*
- **Rule ID:** `221b251a-357a-49a9-920a-271802777cc0`
- **Severity Level:** Medium

#### Analysis:
`wmic.exe` is commonly leveraged during the **Discovery** phase of the **MITRE ATT&CK Framework**, specifically **T1049: System Network Connections Discovery**. Attackers utilize this utility to enumerate system information, network configurations, and active processes. Aurora successfully matched the behavior to a Sigma rule, demonstrating its capability to flag suspicious execution patterns in real time.

---

### **Event ID 11: Suspicious File Creation**

The second detection involved **Event ID: 11**, which flagged anomalous file creation activity on the desktop. This event was indicative of potential ransomware behavior.

#### Event Details:
- **Sigma Rule Title:** *Suspicious Creation TXT File in User Desktop*
- **Activity Mapped:** Ransomware Payload Delivery
- **Severity Level:** High

#### Analysis:
The creation of a `.txt` file on the desktop aligns with post-encryption activities commonly associated with ransomware attacks. These files often contain ransom demands and are part of the **Impact** phase of the **MITRE ATT&CK Framework**, particularly **T1486: Data Encrypted for Impact**. Aurora’s rule-based detection identified this activity, underscoring its effectiveness in recognizing malicious indicators of compromise (IoCs).

---

### **Simulated Response Actions**

Aurora supports predefined and custom response actions to mitigate threats. Although response actions were disabled in this scenario, I simulated them to evaluate their functionality in containing adversarial behavior.

#### Command:
```cmd
aurora-agent.exe --simulate
```

#### Simulated Actions:
- **Process Termination:** Identified ransomware-related processes were terminated.
- **Process Suspension:** Malicious processes were suspended to prevent further execution.
- **Activity Logging:** Generated detailed logs for audit and forensic analysis.

#### Observations:
These automated response capabilities align with best practices for active threat containment, effectively reducing the attack surface and minimizing dwell time.

---

### **Detection Gaps**

Despite Aurora’s robust capabilities, several gaps were identified in its detection surface:

1. **Named Pipes:**
   Aurora does not natively capture named pipe events, which can be exploited for interprocess communication during attacks. This limitation stems from ETW’s lack of native support for these events.
   - **Mitigation:** Complement Aurora with **Sysmon** for enhanced named pipe monitoring.

2. **Registry Event Noise:**
   Aurora struggles with the high volume of registry events, making it challenging to isolate malicious activity.
   - **Mitigation:** Employ **Intense Configuration** or integrate with Sysmon for granular registry monitoring.

3. **ETW Tampering:**
   Sophisticated adversaries may disable ETW to evade detection.
   - **Mitigation:** Leverage Aurora’s **ETW Canary** module (commercial version) to identify tampering and monitor dropped events.

---

### **Key Takeaways**

1. **Behavioral Threat Detection:**
   Aurora leverages Sigma rules to identify suspicious behaviors rather than relying solely on static signatures, enhancing its capability to detect novel threats.

2. **Efficient Resource Utilization:**
   Aurora’s lightweight design ensures low system overhead, making it ideal for environments where performance is critical.

3. **Advanced Threat Containment:**
   Automated response actions such as process termination and suspension provide proactive defense against active threats.

4. **Integration with MITRE ATT&CK:**
   Aurora’s detections are mapped to MITRE tactics and techniques, offering contextual insights into adversarial behavior.

5. **Complementary Tooling:**
   While effective, Aurora benefits significantly from integration with tools like Sysmon to address gaps in detection and logging.
