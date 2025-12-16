# Deployment Notes (If You Must)

Running this software is discouraged. If you still choose to do so for controlled research with consent, follow these cautions:

## Scope and consent
- Only monitor accounts you own or have explicit, written permission to test.
- Keep a record of consent and test scope.

## Environment
- Prefer isolated lab networks; do not run on shared or production networks.
- Protect volumes (`sqlite-data`, `wa-auth`, `signal-data`) and the SQLite database; they contain presence and auth material.
- Rotate and revoke credentials after tests; clear volumes when done.

## Operation
- Review and respect platform rate limits and terms of service.
- Disable or restrict external access to the API/UI; require auth if exposed.
- Monitor logs for unintended data collection and stop promptly if observed.

## Data handling
- Encrypt backups (or avoid them); securely delete data after the research window.
- Do not share captured presence data with unauthorized parties.

If any of these controls cannot be met, do not run the stack.
