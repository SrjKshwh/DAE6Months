# GRC Portal

A comprehensive Governance, Risk, and Compliance (GRC) web application built with Flask and Python. This portal provides tools for managing security incidents, compliance reports, risk assessments, and forensic analysis.

## Features

- **Incident Management**: Report and track security incidents with detailed playbooks
- **Compliance Monitoring**: Upload and analyze compliance reports (e.g., ISO, COPPA)
- **Risk Assessment**: Evaluate and document organizational risks
- **Forensic Analysis**: Perform security scans and generate reports
- **User Authentication**: Secure login and registration system
- **Dashboard**: Centralized view of all GRC activities

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite (via SQLAlchemy)
- **Frontend**: HTML, CSS, JavaScript
- **Security Tools**: Bandit for vulnerability scanning
- **Documentation**: Markdown-based playbooks and guides

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd grcPortal
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser to `http://localhost:5000`

## Usage

- Navigate to the home page to access different modules
- Use the incident reporting feature to log security events
- Upload compliance documents for analysis
- Review generated reports in the reports folder

## Documentation

Detailed documentation is available in the `docs/` folder, including:
- Security incident response playbooks
- File upload procedures
- Incident reporting guides

