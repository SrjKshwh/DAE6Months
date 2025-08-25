# ADR-002: Security Measures

## Context
As a GRC project, we need to demonstrate best practices in authentication and input validation. The system must prevent common security risks (XSS, SQL Injection, session hijacking).

## Decision
Implement the following:

- Password Hashing with Werkzeug’s bcrypt.

- Session Security with Flask secret key.

- Input Validation for email and file uploads.

- Secure Filenames via secure_filename().

## Rationale
These practices align with NIST and OWASP guidelines for secure application development.

## Consequences

### Positive: 
Users’ credentials and uploaded data are protected. Demonstrates compliance awareness.

### Negative: 
Adds coding complexity (must handle hashing, validation manually).

## Alternative Options

- Use Django for built-in security features.

- Add a Web Application Firewall (WAF) for input sanitization.

## References

[OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)