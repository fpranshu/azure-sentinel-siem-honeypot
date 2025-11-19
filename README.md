# Azure Sentinel SIEM – Live Attack Monitoring Project

A custom-built **Azure Sentinel SIEM** project that detects, parses, and visualizes real-time attacks on a deliberately vulnerable Windows VM. It displays the attacker’s **IP, country, event ID, timestamp**, and plots attacks on a **world map workbook** using Azure Analytics Workbooks.

---

## 🚀 Project Overview
This project simulates real-world cyber attacks by exposing a controlled vulnerable VM to the internet. Windows event logs are forwarded to **Azure Log Analytics**, parsed with **KQL**, and visualized through a custom **Attack Map Workbook**.

This project demonstrates:
- SIEM configuration  
- Custom log parsing  
- Threat detection  
- Visualization dashboards  
- Log correlation using KQL  
- Cloud security monitoring on Azure  

---

## 🏗 Architecture Diagram
```
Attacker → Public IP → Azure VM (RDP open)  
           ↓  
Windows Event Logs  
           ↓  
Azure Log Analytics Workspace  
           ↓  
Azure Sentinel (SIEM)  
           ↓  
KQL Parsing → Map Visualization (Workbook)
```

---

## ⚙️ Azure Setup Summary

### 1️⃣ Create a Log Analytics Workspace
- Enable **Azure Defender** (optional)
- Note Workspace ID + Key

### 2️⃣ Deploy a Windows VM
- Intentionally exposed (RDP 3389 open)
- Install Sysmon (optional)
- Configure log forwarding

### 3️⃣ Connect VM to Log Analytics
- Logs appear under *SecurityEvent*, *Sysmon*, *Heartbeat*

### 4️⃣ Create Custom Workbook  
- New → Workbook  
- Add map visualization  
- Insert KQL queries below

---

## 🛠 KQL Queries Used  

### 🔍 Detect RDP Brute Force Attempts
```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IPAddress = IpAddress, Account = TargetAccount, bin(TimeGenerated, 1h)
| order by Attempts desc
```

### 🌍 World Map – Attacker Geolocation  
```kql
SecurityEvent
| where EventID == 4625 or EventID == 4624
| extend IP = IpAddress
| invoke externaldata(geoData:dynamic)
[
    h@"https://ipgeolocation.abstractapi.com/v1/?api_key=YOUR_API_KEY&ip_address=" + IP
]
with(format="json")
| extend Country = tostring(geoData.country), Lat = todouble(geoData.latitude), Lon = todouble(geoData.longitude)
| summarize count() by Country, Lat, Lon
```

### 👤 Successful Logins  
```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account = TargetAccount, IP = IpAddress
```

---

## 📊 Dashboards Built
- 🌍 **World Attack Map**
- 🧑‍🦱 Failed vs Successful Login Attempts  
- ⚠️ High-frequency attacker IPs  
- 🕒 Time-series attack timeline  
- 🔐 RDP brute force detection panel  

---

## 🎯 Skills Demonstrated
- Azure Sentinel  
- Log Analytics  
- KQL (Kusto Query Language)  
- Security Operations  
- Attack detection  
- Event log parsing  
- Workbook creation  
- Real-world incident simulation  

---

## 📘 Conclusion
This project replicates a **real-world SIEM environment** using Azure’s cloud-native security tools. It highlights the process of collecting logs, parsing attacker activity, and creating actionable dashboards for SOC operations.

---
