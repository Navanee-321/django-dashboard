# Vulnerabilities Dashboard

## Overview

The Vulnerabilities Dashboard is a Django-based web application that provides a centralized view of security findings from multiple security domains.

The dashboard consolidates findings from different sources and presents them through a user-friendly interface with drill-down capabilities for detailed investigation.

## Features

### Source Code Security

* Displays source code vulnerability findings.
* Provides visibility into application security issues.

### Docker Security

* Displays Docker image vulnerability findings.
* Categorizes vulnerabilities based on severity levels.
* Supports drill-down analysis of affected images and packages.

### AWS Security

* Displays AWS security findings collected from cloud resources.
* Provides visibility into cloud security risks and misconfigurations.
* Supports drill-down analysis for detailed investigation of findings.

## Architecture

### Frontend

* HTML
* Bootstrap

### Backend

* Django (Python)

### Database

* PostgreSQL

### Containerization

* Docker
* Docker Compose

### Cloud Inventory Source

* Steampipe AWS Plugin

## Data Flow

Security Data Sources
↓
PostgreSQL
↓
Django Application
↓
Vulnerabilities Dashboard

The dashboard retrieves security findings from PostgreSQL and presents them through an interactive web interface.

## Drill-Down Functionality

Each finding displayed on the dashboard supports detailed investigation.

Example:

Dashboard
→ Security Findings
→ Selected Finding
→ Detailed Resource Information

This enables users to move from high-level summaries to resource-level details for analysis and remediation.

## Project Structure

django-dashboard/

* dashboard/

  * templates/
  * views.py
  * models.py
  * admin.py

* vuln_dashboard/

  * settings.py
  * urls.py
  * wsgi.py

* docker-compose.yml

* Dockerfile

* requirements.txt

* manage.py

## Key Components

### views.py

Contains the application logic and database queries used to retrieve and display findings.

### templates/

Contains HTML templates used for dashboard pages and detailed findings views.

### urls.py

Defines application routing and navigation.

### PostgreSQL

Stores vulnerability and cloud inventory data.

### Docker Compose

Used for application deployment and service orchestration.

## Future Enhancements

* Additional security integrations
* Risk scoring and prioritization
* User authentication and authorization
* Export and reporting capabilities
* Historical trend analysis

## Version

Current Release: 1.0

