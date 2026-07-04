# 🛡️ SOC Detection Engineering Lab

A hands-on Security Operations Center (SOC) Detection Engineering Lab built using **Splunk Enterprise**, **Windows 10**, **Ubuntu Linux**, **Sysmon**, and the **Splunk Universal Forwarder**. This project demonstrates how to collect, monitor, detect, investigate, and correlate security events across Windows and Linux systems using real log sources and detection logic.

---

# 📌 Project Overview

The goal of this project is to simulate an enterprise SOC environment by collecting logs from multiple operating systems, creating detection rules, correlating suspicious activity, mapping detections to the MITRE ATT&CK framework, and visualizing security events through Splunk dashboards.

This repository showcases practical skills in:

* SOC Monitoring
* Detection Engineering
* Threat Hunting
* Security Log Analysis
* Incident Investigation
* MITRE ATT&CK Mapping
* Splunk Dashboard Development

---

# 🎯 Objectives

* Build a centralized logging environment using Splunk Enterprise.
* Collect Windows and Linux logs in real time.
* Configure Sysmon for enhanced Windows telemetry.
* Create SPL-based detection rules.
* Build correlation searches for suspicious activities.
* Develop SOC dashboards for security monitoring.
* Document detections with investigation steps and MITRE ATT&CK mapping.

---

# 🏗️ Lab Architecture

```
Windows 10 VM
(Sysmon + Splunk Universal Forwarder)
            │
            │ Forwarded Events
            ▼
     Splunk Enterprise
        (Ubuntu VM)
            │
 ┌──────────┼──────────┐
 │          │          │
 ▼          ▼          ▼
Detection  Dashboard  Investigation
Rules      Visuals    & Alerts
```

---

# ⚙️ Technologies Used

* Splunk Enterprise
* Splunk Universal Forwarder
* Sysmon
* Ubuntu Linux
* Windows 10
* Oracle VirtualBox
* SPL (Search Processing Language)
* Git
* GitHub

---

# 📂 Repository Structure

```
SOC-Detection-Engineering-Lab
│
├── architecture
├── docs
├── detections
│   ├── linux
│   └── windows
├── correlation_searches
├── dashboards
├── screenshots
│   ├── linux
│   ├── windows
│   ├── dashboard
│   └── alerts
├── sample_logs
│   ├── linux
│   └── windows
└── alerts
```

---

# 🔍 Detection Use Cases

## Windows

* PowerShell Execution Monitoring
* Process Creation Monitoring
* Network Connection Monitoring
* DNS Query Monitoring
* Registry Modification Detection
* File Creation Monitoring
* Persistence Detection

## Linux

* SSH Authentication Monitoring
* Failed Login Detection
* Successful Login Detection
* SSH Brute Force Detection
* Authentication Log Analysis

---

# 🔗 Correlation Searches

This project includes correlation searches that combine multiple security events to identify suspicious behavior, including:

* SSH Brute Force → Successful Login
* PowerShell Execution → Network Connection
* Registry Modification → Process Execution
* PowerShell Activity → DNS Resolution

---

# 🎯 MITRE ATT&CK Coverage

Example techniques covered in this project include:

* Command and Scripting Interpreter
* PowerShell
* System Information Discovery
* Network Service Discovery
* Registry Modification
* Valid Accounts
* Brute Force
* Remote Services

Additional mappings will be documented alongside each detection.

---

# 📊 Dashboards

The project includes dashboards for monitoring:

* Windows Security Events
* Linux Authentication Events
* PowerShell Activity
* DNS Queries
* Network Connections
* Registry Changes
* SSH Activity
* SOC Overview

---

# 🚨 Sample Alerts

Examples of alerts implemented:

* Excessive Failed SSH Logins
* PowerShell Execution Detection
* Suspicious Network Connections
* Registry Persistence Detection
* Brute Force Correlation Alert

---

# 📸 Screenshots

Screenshots of the following components will be included:

* Splunk Dashboards
* Detection Searches
* Correlation Searches
* Windows Monitoring
* Linux Monitoring
* Alert Generation

---

# 📈 Skills Demonstrated

* Splunk Enterprise Administration
* SIEM Monitoring
* Detection Engineering
* Security Log Analysis
* Threat Hunting
* Windows Security Monitoring
* Linux Security Monitoring
* Sysmon Configuration
* SPL Query Development
* MITRE ATT&CK Mapping
* Incident Investigation
* Security Dashboard Development

---

# 🚀 Future Enhancements

Planned improvements include:

* Sigma Rule Integration
* Detection-as-Code
* Custom Splunk Apps
* Threat Intelligence Integration
* Additional Correlation Searches
* Automated Alerting
* IOC Enrichment
* SOAR Integration

---

# 📄 License

This project is shared for educational and portfolio purposes.

