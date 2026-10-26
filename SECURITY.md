# Security Policy

CycloneDXKit encodes and decodes CycloneDX documents that security tools consume. Security issues include crashes or unbounded resource use when decoding malformed documents, and encoding bugs that produce documents that misrepresent their input (for example dropped or altered results, or invalid output that downstream tools silently ignore).

## Supported versions

Only the latest release receives fixes while the project is at 0.x.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on https://github.com/d-date/swift-cyclonedx (private vulnerability reporting).

Include a minimal reproducing input (base64 or a generator script is fine), the observed behaviour, and the platform and Swift version.

You can expect an acknowledgement within 7 days. Once a fix is released, an advisory will be published with credit, unless you prefer to stay anonymous.
