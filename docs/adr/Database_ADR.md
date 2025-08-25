# ADR 003 – Using SQLite for Database Storage

## Context:
The application requires a database to manage users, authentication, and uploaded cybersecurity policy files. The database should be simple to set up, work seamlessly with Flask, and not introduce heavy deployment complexity (e.g., no database server setup for development).

## Decision:
Use SQLite as the primary database for the project.

## Rationale

- Built-in with Python, requires no external setup.

- Ideal for lightweight apps with minimal concurrency.

- Easy integration with Flask and SQLAlchemy.

## Consequences:

### Positive:

- Zero-configuration and file-based (no separate DB server needed).

- Natively supported by Python via SQLAlchemy.

- Portable: the database is stored as a single file (instance/app.db).

- Lightweight, ideal for prototypes and student projects.

### Negative:

- Not designed for heavy concurrency (write bottlenecks).

- Limited scalability compared to PostgreSQL or MySQL.

- Security: File-based DB means permissions on the host filesystem must be carefully set.

## Alternative Options:

- PostgreSQL: Stronger security, scalability, ACID compliance, but requires setup and hosting.

- MySQL/MariaDB: Widely used, good performance, but adds deployment overhead.

- In-memory (Redis): Fast but volatile; not suitable for storing user accounts or compliance files.

## References:

[SQLite vs PostgreSQL](https://www.sqlite.org/whentouse.html)

[SQLite Official Documentation](https://sqlite.org/docs.html)

[SQLAlchemy ORM with Flask](https://flask-sqlalchemy.palletsprojects.com/)

[OWASP Database Security](https://owasp.org/www-community/Database_Security)