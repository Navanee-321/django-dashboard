# Vulnerabilities Dashboard

## Overview

The Vulnerabilities Dashboard is a Django-based application that provides a centralized view of security findings from multiple sources.

The dashboard currently supports:

* Source Code Security Findings
* Docker Security Findings
* AWS Security Findings

Each finding supports drill-down functionality for detailed investigation.

---

## Deployment

The application is deployed on an on-premises server using Docker Compose.

Server Access:

ssh optit@10.10.30.93

Application Deployment:

docker compose up -d --build

---

## Application Stack

### Django (Python)

Backend application framework responsible for dashboard rendering, data processing, and drill-down functionality.

### PostgreSQL

Stores security findings and inventory data consumed by the dashboard.

### Docker Compose

Used to deploy and manage application services.

### HTML / Bootstrap

Used to build the dashboard user interface.

---

## Application Workflow

Security Findings Data
→ PostgreSQL
→ Django Application
→ Vulnerabilities Dashboard

The dashboard retrieves findings from PostgreSQL and presents them through a web-based interface.

---

## Supported Modules

### Source Code

Displays source code security findings.

### Docker

Displays Docker security findings.

### AWS

Displays AWS security findings with detailed drill-down views for investigation.

---

## Version

Current Version: 1.0

