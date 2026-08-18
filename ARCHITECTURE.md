# Agent separation and trust model

The design intentionally avoids a single all-powerful prompt.

- **Triage Router** has minimal authority and cannot claim source vulnerabilities from manifest metadata.
- **Line Highlighting Agent** can assert findings only from a bounded exact source snapshot and must return exact spans.
- **Security Diff Agent** can propose text but has no write capability.
- **Diff Verifier** is prompted independently and treats the proposed patch as hostile data.
- **Local validators** sit between model stages, so model-to-model agreement is not sufficient on its own.

This makes the pipeline closer to a sequence of independently constrained security principals than a chain of free-form agents.
