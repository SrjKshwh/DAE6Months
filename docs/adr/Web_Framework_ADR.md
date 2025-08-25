# ADR 001 – Choosing Flask as the Web Framework

## Context:
We need a lightweight framework to build a secure prototype web application for uploading, storing, and scanning Cybersecurity GRC policy files. The framework should be simple to learn, widely supported, and allow integration with security best practices (authentication, session management, file handling).

## Decision:
We chose Flask (Python) as the framework.

## Consequences:

### Positive:

- Lightweight, easy to understand and implement for a student project.

- Large ecosystem of extensions (Flask-Login, Flask-SQLAlchemy).

- Simple deployment on local machines or cloud services.

### Negative:

- Lacks built-in components compared to Django (e.g., admin panel, ORM).

- Security features (CSRF, HTTPS enforcement) must be explicitly configured.

## Alternative Options:

- Django: Full-featured but heavier for a small project.

- Node.js + Express: Also lightweight, but would require learning JavaScript/Node ecosystem.

## References:
[Flask Documentation](https://flask.palletsprojects.com/en/stable/)
[12-Factor App Guidelines](https://12factor.net/)