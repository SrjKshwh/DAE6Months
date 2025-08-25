# ADR-004: File Upload Handling

## Context
Users will upload cybersecurity GRC policies (PDF, DOCX, TXT). The files must be stored securely before scanning.

## Decision
Store files in an uploads/ folder with restricted permissions, only allowing specific extensions.

## Rationale

- Prevents malicious uploads (scripts, executables).

- Simple storage model, easy retrieval for OpenAI scanning.

## Consequences

### Positive:
Minimizes attack surface, controlled file types.

### Negative:
Limited flexibility (does not handle large storage or cloud integration).

## Alternative Options

- Use Amazon S3 / Google Cloud Storage for secure cloud storage.

- Store file contents directly in the database (not scalable).

## References

[Werkzeug File Handling](https://werkzeug.palletsprojects.com/en/2.3.x/utils/#werkzeug.utils.secure_filename)

[OWASP File Upload Guidelines](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)