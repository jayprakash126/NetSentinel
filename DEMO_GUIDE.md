# NetSentinel — Project Demonstration Guide

## 1. Project Overview

**Project:** NetSentinel — Network Intrusion Detection and Security Monitoring System

NetSentinel is a network security monitoring system that combines Suricata-based signature detection with behavioral analysis to identify suspicious network activity.

### Technology Stack

- **Frontend:** React, Vite
- **Backend:** Node.js, Express.js
- **Database:** PostgreSQL
- **Network IDS:** Suricata
- **Real-time communication:** Socket.IO
- **Test traffic generation:** Python, Scapy
- **Deployment support:** Docker

## 2. Main Features

1. Network event collection through Suricata EVE JSON logs.
2. Signature-based intrusion detection using custom Suricata rules.
3. Behavioral detection of possible TCP and UDP port scans.
4. Detection of unusually high connection rates.
5. SQL injection pattern detection in inspectable HTTP requests.
6. Centralized alert storage in PostgreSQL.
7. Duplicate event and behavioral alert prevention.
8. Real-time alert and network-event updates through Socket.IO.
9. Monitoring dashboard and alert history.

## 3. System Architecture

```text
              NETWORK TRAFFIC
                     |
                     v
                SURICATA IDS
                     |
                     v
              EVE JSON LOG FILE
                     |
                     v
             NODE.JS BACKEND
                     |
          +----------+----------+
          |                     |
          v                     v
    EVENT INGESTION       BEHAVIORAL ANALYSIS
          |                     |
          +----------+----------+
                     |
                     v
               POSTGRESQL
                     |
                     v
              EXPRESS REST API
                     |
                     v
             REACT DASHBOARD
                     |
                     v
             SOCKET.IO UPDATES
```

## 4. Demonstration Preparation

### Step 1 — Start PostgreSQL

Verify that the PostgreSQL container is running:

```powershell
docker ps
```

If it is stopped:

```powershell
docker start netsentinel-postgres
```

### Step 2 — Start the Backend

Open PowerShell:

```powershell
cd C:\Users\cse12\NetSentinel\backend
npm install
npm test
npm start
```

Check the health endpoint:

```text
http://localhost:5000/api/health
```

### Step 3 — Start the Frontend

Open a separate PowerShell terminal:

```powershell
cd C:\Users\cse12\NetSentinel\frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

### Step 4 — Generate SQL Injection Test PCAP

From the project root:

```powershell
python sample-data/generate_sqli_test.py
```

This creates:

```text
sample-data/sqli_test.pcap
```

### Step 5 — Validate Suricata Rules

Use the installed Suricata executable and your actual configuration and rule paths. Validate the configuration before processing the PCAP.

Example command pattern:

```powershell
& "C:\Program Files\Suricata\suricata.exe" -T -c "C:\Users\cse12\NetSentinel\suricata\windows\suricata.yaml"
```

Confirm that the configuration loads the NetSentinel custom rule file before proceeding.

### Step 6 — Process the Test PCAP

Use the configuration and custom rules that passed validation. Run Suricata in offline PCAP mode against:

```text
sample-data/sqli_test.pcap
```

Write the resulting EVE JSON output to a separate test output directory so that the existing production EVE log is not overwritten.

Inspect the resulting EVE JSON for the two SQL injection signatures.

### Step 7 — Import Test Events

Only after confirming that the test EVE output contains the expected alerts, place or copy the test events into the configured ingestion input in a controlled manner.

Then invoke the backend ingestion endpoint:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:5000/api/ingestion/import" `
  -Method POST
```

Verify that the dashboard displays the imported alerts.

**Note:** The current backend reads `suricata/logs/eve.json`. The separate Windows capture log and test PCAP output are not automatically connected to that input. Do not overwrite existing evidence or logs during the demonstration.

## 5. Important API Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Backend status |
| `GET /api/health` | Server and database health |
| `GET /api/db-test` | Database connectivity |
| `GET /api/monitoring` | Monitoring statistics |
| `POST /api/ingestion/import` | Manual log ingestion |
| `GET /api/alerts` | Retrieve alerts |
| `GET /api/network-events` | Retrieve network events |

## 6. Suggested Demonstration Sequence

1. Introduce the problem of network intrusion and suspicious traffic.
2. Explain the NetSentinel architecture.
3. Show the React dashboard.
4. Explain how Suricata produces EVE JSON events.
5. Demonstrate the custom detection rules.
6. Show the SQL injection test PCAP and its generated alerts.
7. Demonstrate behavioral port-scan detection.
8. Show alerts stored in PostgreSQL.
9. Explain duplicate prevention and real-time updates.
10. Conclude with limitations and future improvements.

## 7. Important Technical Limitations

- SQL injection signatures are pattern-based and can produce false positives or miss unknown attack patterns.
- HTTPS payload inspection requires suitable TLS decryption; ordinary encrypted traffic cannot be inspected for these URI patterns.
- Offline PCAP processing is different from live network capture.
- The current backend imports from its configured EVE JSON file. Native Windows capture output must be connected to that ingestion path separately.
- Behavioral detection depends on the flow events available in PostgreSQL and the configured detection thresholds.

## 8. Future Scope

- Direct integration of native Windows live capture with backend ingestion.
- More advanced behavioral anomaly detection.
- Machine-learning-based traffic classification.
- Improved SQL injection and web-attack detection.
- User authentication and role-based access control.
- Automated incident response and alert notifications.

## 9. Closing Statement

NetSentinel demonstrates how signature-based intrusion detection and behavioral network analysis can be combined with a centralized database and real-time dashboard to provide a unified network security monitoring solution.